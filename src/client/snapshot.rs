use std::collections::BTreeSet;

use super::{
    Client, MAX_NODES_PER_READ, NAMESPACE_ARRAY, ReadError, ReadMetadata, ReadSession,
    SERVER_ARRAY, Sample, definition::decode_data_type, sample::Quality, ua,
};
use crate::{
    NodeId,
    commissioning::{
        Contract, Error, Evidence, SignalObservation, SignalRequirement, Snapshot,
        SnapshotCollector,
    },
};

/// Native snapshot acquisition failed before a complete validated document was available.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SnapshotReadError {
    /// The reviewed user differs from the authenticated session user.
    #[error("snapshot contract principal differs from the authenticated session")]
    Principal,
    /// The contract selects a different server application from the pinned client.
    #[error("snapshot contract ApplicationUri differs from the pinned server")]
    ServerIdentity,
    /// A selected signal aliases a standard node whose Value is required for session bootstrap.
    #[error("snapshot signals[{index}] selects a reserved session bootstrap node")]
    BootstrapNode {
        /// Zero-based index in the supplied contract.
        index: usize,
    },
    /// Session identity, namespace discovery or acquisition of the read guard failed.
    #[error("could not prepare the snapshot session: {0}")]
    Session(#[source] ReadError),
    /// A server service or structural metadata check failed for this request.
    #[error("snapshot signals[{index}]: {source}")]
    Signal {
        /// Zero-based index in the supplied contract.
        index: usize,
        /// Operation or decoding error.
        #[source]
        source: ReadError,
    },
    /// Including this row would exceed the aggregate document limit.
    #[error("snapshot signals[{index}]: compact snapshot and newline exceed 4 MiB")]
    OutputLimit {
        /// Zero-based index of the first row that did not fit.
        index: usize,
    },
    /// The completed capture or its scope envelope failed document validation.
    #[error("invalid snapshot evidence: {0}")]
    Evidence(#[source] Error),
}

fn evidence<T>(sample: Sample<T>) -> Evidence<T> {
    Evidence {
        status: sample.status,
        value: sample.value,
    }
}

fn protected_signals<'a>(
    contract: &'a Contract,
    server_uri: &str,
    principal: &str,
) -> Result<BTreeSet<&'a NodeId>, SnapshotReadError> {
    if contract.principal() != principal {
        return Err(SnapshotReadError::Principal);
    }
    if contract.application_uri() != server_uri {
        return Err(SnapshotReadError::ServerIdentity);
    }
    contract.validate_capture_nodes()?;
    Ok(contract.signals().iter().map(|s| &s.node).collect())
}

impl Contract {
    /// Check that live acquisition will not read application evidence from reserved session bootstrap nodes.
    /// This can be used before connecting or as part of offline preparation.
    pub fn validate_capture_nodes(&self) -> Result<(), SnapshotReadError> {
        for (index, signal) in self.signals().iter().enumerate() {
            let node = &signal.node;
            if node.namespace() == "http://opcfoundation.org/UA/"
                && node
                    .identifier()
                    .strip_prefix("i=")
                    .and_then(|id| id.parse::<u32>().ok())
                    .is_some_and(|id| {
                        matches!(id, SERVER_ARRAY | NAMESPACE_ARRAY | MAX_NODES_PER_READ)
                    })
            {
                return Err(SnapshotReadError::BootstrapNode { index });
            }
        }
        Ok(())
    }
}

impl Client {
    /// Observe only the commissioned declarations and requested standard unit properties.
    /// The snapshot preserves the contract order and actual operation status, including a
    /// Good status without a value. A missing namespace yields a row with just the identity.
    /// The compact document plus newline is bounded at 4 MiB before appending each row.
    /// Service-response decoding occurs before this application-level output check.
    /// ServerArray, NamespaceArray and MaxNodesPerRead are reserved session bootstrap nodes.
    /// Selecting one in the contract fails before the client reads any of those Values.
    ///
    /// ```
    /// # async fn inspect(client: &opcua_kit::Client, contract: &opcua_kit::commissioning::Contract)
    /// # -> Result<(), Box<dyn std::error::Error>> {
    /// let snapshot = client.read_snapshot(contract).await?;
    /// let report = opcua_kit::commissioning::assess(contract, &snapshot)?;
    /// println!("{:?}", report.decision);
    /// # Ok(()) }
    /// ```
    pub async fn read_snapshot(&self, contract: &Contract) -> Result<Snapshot, SnapshotReadError> {
        let protected = protected_signals(contract, &self.server_uri, &self.principal)?;
        let mut output = SnapshotCollector::new(contract).map_err(SnapshotReadError::Evidence)?;
        let (mut session, metadata) = self
            .read_session()
            .await
            .map_err(SnapshotReadError::Session)?;
        for (index, signal) in contract.signals().iter().enumerate() {
            let row = self
                .snapshot_signal(&mut session, metadata, signal, &protected)
                .await
                .map_err(|source| SnapshotReadError::Signal { index, source })?;
            output
                .push(row)
                .map_err(|_| SnapshotReadError::OutputLimit { index })?;
        }
        self.check_channel().map_err(SnapshotReadError::Session)?;
        drop(session);
        output.finish(contract).map_err(SnapshotReadError::Evidence)
    }

    async fn snapshot_signal(
        &self,
        session: &mut ReadSession,
        metadata: &ReadMetadata,
        signal: &SignalRequirement,
        protected: &BTreeSet<&NodeId>,
    ) -> Result<SignalObservation, ReadError> {
        let mut row = SignalObservation::new(signal.name.clone(), signal.node.clone());
        if !metadata
            .namespaces
            .by_uri
            .contains_key(signal.node.namespace())
        {
            return Ok(row);
        }
        let quality = Quality::GoodSeverity;
        let data_type = if signal.value_rank.is_some() {
            let definition = self
                .definition_locked(session, metadata, &signal.node, quality)
                .await?;
            row.value_rank = Some(evidence(definition.value_rank?));
            definition.data_type?
        } else {
            let wire = metadata.namespaces.wire_node(&signal.node, 0)?;
            let raw = self
                .one_attribute(session, wire, ua::AttributeId::DataType)
                .await?;
            decode_data_type(&metadata.namespaces, &raw, quality)?
        };
        row.data_type = Some(evidence(data_type));
        if signal.engineering_units.is_some() {
            let unit = self
                .units_locked(
                    session,
                    &metadata.namespaces,
                    &signal.node,
                    quality,
                    |property| !protected.contains(property),
                )
                .await?;
            row.engineering_units = Some(evidence(unit.sample));
        }
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::{MAX_DOCUMENT_BYTES, Unit, parse_contract};

    #[test]
    fn reject_bootstrap_aliases_in_any_position_before_preparing_session() {
        let base = parse_contract(include_bytes!("../../fixtures/meter/contract.json")).unwrap();
        for id in ["i=002254", "i=002255", "i=11705"] {
            let mut a = base.signals()[0].clone();
            a.node = NodeId::new("urn:vendor", id).unwrap();
            let mut b = a.clone();
            b.name = "bootstrap".into();
            b.node = NodeId::new("http://opcfoundation.org/UA/", id).unwrap();
            let new = |rows| Contract::new("site", "urn:server", "anonymous", rows).unwrap();
            let c = new(vec![a.clone()]);
            assert!(
                protected_signals(&c, "urn:server", "anonymous")
                    .unwrap()
                    .contains(&a.node)
            );
            let c = new(vec![a, b]);
            assert!(matches!(
                protected_signals(&c, "urn:server", "anonymous"),
                Err(SnapshotReadError::BootstrapNode { index: 1 })
            ));
            assert!(matches!(
                protected_signals(&c, "urn:other", "anonymous"),
                Err(SnapshotReadError::ServerIdentity)
            ));
        }
    }

    #[test]
    fn rows_just_fit_or_fail_including_escaped_text_separator_and_newline() {
        let fixture = parse_contract(include_bytes!("../../fixtures/meter/contract.json")).unwrap();
        let mut other = fixture.signals()[0].clone();
        other.name = "other".into();
        other.node = NodeId::new("urn:site", "s=Other").unwrap();
        let c = Contract::new(
            "site",
            "urn:server",
            "anonymous",
            vec![fixture.signals()[0].clone(), other],
        )
        .unwrap();
        let row = |i: usize, suffix: usize| {
            let required = &c.signals()[i];
            let mut row = SignalObservation::new(required.name.clone(), required.node.clone());
            row.data_type = Some(Evidence {
                status: 0,
                value: Some(required.data_type.clone()),
            });
            row.value_rank = Some(Evidence {
                status: 0,
                value: Some(-1),
            });
            row.engineering_units = Some(Evidence {
                status: 0,
                value: Some(Unit {
                    namespace_uri: format!("urn:unit:\"温{}", "x".repeat(suffix)),
                    unit_id: 1,
                }),
            });
            row
        };
        let baseline = Snapshot::new(
            c.device(),
            c.application_uri(),
            c.principal(),
            vec![row(0, 0), row(1, 0)],
        )
        .unwrap();
        let room = MAX_DOCUMENT_BYTES - 1 - serde_json::to_vec(&baseline).unwrap().len();
        let mut output = SnapshotCollector::new(&c).unwrap();
        output.push(row(0, 0)).unwrap();
        output.push(row(1, room)).unwrap();
        let exact = output.finish(&c).unwrap();
        assert_eq!(
            serde_json::to_vec(&exact).unwrap().len() + 1,
            MAX_DOCUMENT_BYTES
        );
        let mut output = SnapshotCollector::new(&c).unwrap();
        output.push(row(0, 0)).unwrap();
        assert!(output.push(row(1, room + 1)).is_err());
    }
}
