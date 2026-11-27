//! Discover endpoints and browse, read or monitor nodes over a pinned OPC UA session.
//!
//! Reuse one [`Client`] across polling cycles. Node identifiers retain their
//! namespace URI when a server reassigns numeric indexes. Check each result's status and wire type
//! before using a value. Raw reads preserve the source and server timestamps,
//! including their optional 10 ps increments. Use the commissioning API to assess a signal’s declared metadata.

mod array;
pub use array::ArrayValue;
mod browse;
#[cfg(feature = "control")]
mod conditions;
mod connection;
#[cfg(feature = "control")]
pub use conditions::{ConditionComment, ConditionError};
#[cfg(feature = "control")]
mod control;
#[cfg(feature = "control")]
pub use control::{CallOutcome, Control, ControlError};
mod definition;
mod events;
pub use events::{EventError, EventField, Events, PublishError, Sequenced, SequencedDataChanges};
mod history;
pub use history::{HistoricalRead, HistoryError};
mod wire;
pub use crate::discovery::{EndpointInfo, EndpointToken, discover_endpoints};
#[cfg(feature = "cems")]
mod meter;
mod recovery;
mod sample;
#[cfg(feature = "commissioning")]
mod snapshot;
mod subscription;
mod units;
pub use crate::EngineeringUnit;
pub use crate::ua;
pub use browse::{BrowseEntry, BrowseError, BrowseName};
pub use connection::{
    CertificateRollover, Client, ConnectError, ConnectionConfig, ConnectionOptions, SecurityPolicy,
    UserIdentity,
};
pub use definition::{ReadAttribute, ReadOperand, VariableDefinition};
#[cfg(feature = "cems")]
pub use meter::MeterReadError;
pub use recovery::{RecoveredSession, RecoveringClient, RecoveryError, SessionState};
pub use sample::{FixedScalar, Sample, SampleTimestamp, Scalar, TimestampError};
#[cfg(feature = "commissioning")]
pub use snapshot::SnapshotReadError;
pub use subscription::{
    DataChange, DataChanges, MAX_MONITORED_NODES, MonitoredDataChanges, MonitoredNode,
    SubscriptionError,
};
pub use ua::DataValue;
pub use units::{EngineeringUnitEvidence, UnitStage};

use std::{collections::BTreeMap, sync::Arc};

use crate::NodeId;

/// Maximum number of attribute operands in one logical client read.
pub const MAX_READ_NODES: usize = 1024;
const MAX_NAMESPACE_BYTES: usize = 4 * 1024 * 1024;
const SERVER_ARRAY: u32 = 2254;
const NAMESPACE_ARRAY: u32 = 2255;
const MAX_NODES_PER_READ: u32 = 11705;

/// A service, identity, or scalar-decoding error. Each successful result carries its node status.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The Value is a scalar or an array of a different built-in type.
    #[error("expected an array of the requested OPC UA element type")]
    ArrayTypeMismatch,
    /// Invalid dimensions or array size exceeds the client limits.
    #[error("invalid array shape or array exceeds 65536 elements or 16 dimensions")]
    InvalidArray,
    /// Batch exceeds the client read limit.
    #[error("a read accepts at most {MAX_READ_NODES} attribute operands")]
    TooManyNodes,
    /// Cannot use this connection's mapping after a channel change.
    #[error("the secure channel changed; reconnect and retry the read")]
    ChannelChanged,
    /// A previous service request failed or its future was cancelled after dispatch.
    #[error("the previous read was interrupted; open a fresh session")]
    SessionInterrupted,
    /// The authenticated server reported a different application identity.
    #[error("the server application URI differs from the configured identity")]
    ServerIdentity,
    /// The server did not supply usable, unambiguous namespace metadata.
    #[error("unusable server or namespace array")]
    InvalidServerMetadata,
    /// The server advertised a read limit with the wrong type or rank.
    #[error("MaxNodesPerRead must be a scalar UInt32")]
    InvalidReadLimit,
    /// A returned DataType identifier is invalid or its namespace is absent from the session.
    #[error("declared DataType is not a valid node in this session's namespace table")]
    InvalidDataType,
    /// The server supplied an Int32 outside the OPC UA ValueRank range.
    #[error("ValueRank must be -3 or greater")]
    InvalidValueRank,
    /// The property lookup was incomplete, ambiguous, remote, or inconsistent.
    #[error(
        "EngineeringUnits must resolve completely to one distinct local Variable through HasProperty"
    )]
    InvalidUnitReference,
    /// A resolved unit property would read a signal protected by the capture contract.
    #[error("EngineeringUnits aliases a contracted signal")]
    UnitAliasesSignal,
    /// A property declaration or a Good property value does not match scalar EUInformation.
    #[error(
        "EngineeringUnits must declare and contain scalar EUInformation with a valid namespace URI"
    )]
    InvalidUnitProperty,
    /// The selected namespace is absent in the session.
    #[error("namespace for operand at index {index} is absent from this session")]
    UnknownNamespace {
        /// Position in the caller's slice.
        index: usize,
    },
    /// A present Good value has a different OPC UA type or is an array.
    #[error("expected an OPC UA {expected} scalar")]
    ScalarTypeMismatch {
        /// OPC UA built-in type name corresponding to the requested Rust type.
        expected: &'static str,
    },
    /// DateTime cannot be represented in the supported Rust calendar range.
    #[error("OPC UA DateTime is outside the Rust calendar range")]
    DateTimeRange,
    /// The underlying OPC UA service failed.
    #[error("OPC UA service failed: {0}")]
    Service(#[from] ua::StatusCode),
}

fn string(value: &ua::Variant) -> Option<&str> {
    if let ua::Variant::String(text) = value {
        text.value().as_deref()
    } else {
        None
    }
}

fn strings(value: &DataValue) -> Result<&[ua::Variant], ReadError> {
    if value
        .status
        .is_some_and(|status| status != ua::StatusCode::Good)
    {
        return Err(ReadError::InvalidServerMetadata);
    }
    match value.value.as_ref() {
        Some(ua::Variant::Array(array))
            if array.value_type == ua::VariantScalarTypeId::String
                && array.dimensions.is_none() =>
        {
            Ok(&array.values)
        }
        _ => Err(ReadError::InvalidServerMetadata),
    }
}

struct Namespaces {
    by_uri: BTreeMap<Arc<str>, u16>,
    by_index: Vec<Arc<str>>,
}

impl Namespaces {
    fn wire_node(&self, node: &NodeId, index: usize) -> Result<ua::NodeId, ReadError> {
        let ns = self
            .by_uri
            .get(node.namespace())
            .ok_or(ReadError::UnknownNamespace { index })?;
        // Preserve string identifiers literally, including semicolons, '=' and percent signs.
        if let Some(text) = node.identifier().strip_prefix("s=") {
            Ok(ua::NodeId::new(*ns, text))
        } else {
            format!("ns={ns};{}", node.identifier())
                .parse()
                .map_err(|_| ReadError::InvalidDataType)
        }
    }
}

fn namespace_map(table: &[ua::Variant]) -> Result<Namespaces, ReadError> {
    if table.len() > usize::from(u16::MAX) + 1
        || table.first().and_then(string) != Some("http://opcfoundation.org/UA/")
    {
        return Err(ReadError::InvalidServerMetadata);
    }
    let mut remaining = MAX_NAMESPACE_BYTES;
    let mut by_uri = BTreeMap::new();
    let mut by_index = Vec::with_capacity(table.len());
    for (i, entry) in table.iter().enumerate() {
        let index = u16::try_from(i).map_err(|_| ReadError::InvalidServerMetadata)?;
        let uri = string(entry)
            .filter(|s| !s.trim().is_empty() && !s.chars().any(char::is_control))
            .ok_or(ReadError::InvalidServerMetadata)?;
        remaining = remaining
            .checked_sub(uri.len())
            .ok_or(ReadError::InvalidServerMetadata)?;
        let uri: Arc<str> = uri.into();
        if by_uri.insert(Arc::clone(&uri), index).is_some() {
            return Err(ReadError::InvalidServerMetadata);
        }
        by_index.push(uri);
    }
    Ok(Namespaces { by_uri, by_index })
}

fn read_limit(value: &DataValue) -> Result<usize, ReadError> {
    // Optional in Part 5 §6.3.11. A singleton is safe without a usable advertisement.
    if value.status.is_some_and(|status| !status.is_good()) {
        return Ok(1);
    }
    let limit = match value.value.as_ref() {
        None | Some(ua::Variant::Empty) => return Ok(1),
        Some(ua::Variant::UInt32(n)) => *n,
        _ => return Err(ReadError::InvalidReadLimit),
    };
    Ok(usize::try_from(limit)
        .unwrap_or(usize::MAX)
        .clamp(1, MAX_READ_NODES))
}

struct ReadMetadata {
    namespaces: Namespaces,
    max_nodes_per_read: usize,
}

// A cancelled request may still be in flight. Retire its namespace mapping
// before allowing a new operation to use the session.
#[derive(Default)]
struct ReadSession {
    interrupted: bool,
}

impl ReadSession {
    async fn request<T>(
        &mut self,
        operation: impl Future<Output = Result<T, ReadError>>,
    ) -> Result<T, ReadError> {
        if self.interrupted {
            return Err(ReadError::SessionInterrupted);
        }
        self.interrupted = true;
        let result = operation.await?;
        self.interrupted = false;
        Ok(result)
    }
}

impl Client {
    fn check_channel(&self) -> Result<(), ReadError> {
        if self.initial_channel() {
            Ok(())
        } else {
            Err(ReadError::ChannelChanged)
        }
    }

    async fn read_wire(
        &self,
        session: &mut ReadSession,
        operands: &[(ua::NodeId, ua::AttributeId)],
    ) -> Result<Vec<DataValue>, ReadError> {
        let request = ua::ReadRequest {
            nodes_to_read: Some(
                operands
                    .iter()
                    .map(|(node, attribute)| ua::ReadValueId {
                        node_id: node.clone(),
                        attribute_id: *attribute as u32,
                        ..Default::default()
                    })
                    .collect(),
            ),
            timestamps_to_return: ua::TimestampsToReturn::Both,
            ..Default::default()
        };
        let response = self.guarded(session, self.inner.request(request)).await?;
        let values = response.results.unwrap_or_default();
        if values.len() != operands.len() {
            session.interrupted = true;
            return Err(ReadError::InvalidServerMetadata);
        }
        Ok(values)
    }

    async fn guarded<T>(
        &self,
        session: &mut ReadSession,
        operation: impl Future<Output = Result<T, ua::StatusCode>>,
    ) -> Result<T, ReadError> {
        self.check_channel()?;
        let result = session.request(async { Ok(operation.await?) }).await?;
        self.check_channel()?;
        Ok(result)
    }

    async fn one_attribute(
        &self,
        session: &mut ReadSession,
        node: ua::NodeId,
        attribute: ua::AttributeId,
    ) -> Result<DataValue, ReadError> {
        self.read_wire(session, &[(node, attribute)])
            .await?
            .pop()
            .ok_or(ReadError::InvalidServerMetadata)
    }

    async fn read_metadata_value(
        &self,
        session: &mut ReadSession,
        id: u32,
    ) -> Result<DataValue, ReadError> {
        self.one_attribute(session, ua::NodeId::new(0, id), ua::AttributeId::Value)
            .await
    }

    async fn load_metadata(&self, session: &mut ReadSession) -> Result<ReadMetadata, ReadError> {
        // The server may accept only one operand, including during discovery.
        let servers = self.read_metadata_value(session, SERVER_ARRAY).await?;
        if strings(&servers)?.first().and_then(string) != Some(self.server_uri.as_str()) {
            return Err(ReadError::ServerIdentity);
        }
        let namespaces = self.read_metadata_value(session, NAMESPACE_ARRAY).await?;
        let namespaces = namespace_map(strings(&namespaces)?)?;
        let capability = self
            .read_metadata_value(session, MAX_NODES_PER_READ)
            .await?;
        Ok(ReadMetadata {
            namespaces,
            max_nodes_per_read: read_limit(&capability)?,
        })
    }

    /// Read a single Value attribute, including its raw status and both clock fields.
    pub async fn read(&self, node: &NodeId) -> Result<DataValue, ReadError> {
        self.read_many(std::slice::from_ref(node))
            .await?
            .pop()
            .ok_or(ReadError::InvalidServerMetadata)
    }

    /// Read an exact OPC UA scalar as its native Rust type, preserving node status and clocks.
    pub async fn read_scalar<T: Scalar>(&self, node: &NodeId) -> Result<Sample<T>, ReadError> {
        Sample::from_raw(&self.read(node).await?)
    }

    /// Read a batch as one Rust scalar type. Results follow input order, including duplicates.
    /// A scalar-decoding error affects only its entry. A node with Bad or Uncertain
    /// status yields a sample with its status and an absent value. A service or
    /// namespace error fails the entire batch.
    pub async fn read_scalars<T: Scalar>(
        &self,
        nodes: &[NodeId],
    ) -> Result<Vec<Result<Sample<T>, ReadError>>, ReadError> {
        self.read_batch(nodes.iter().map(ReadOperand::value), |raw| {
            Sample::from_raw(&raw)
        })
        .await
    }

    /// Read up to [`MAX_READ_NODES`] Value attributes in order, including repeated nodes.
    /// The client splits requests at the session's advertised MaxNodesPerRead and
    /// uses singleton requests when the limit is unavailable or zero. Each request
    /// can observe a different instant. A failed service returns no partial batch.
    /// An empty slice succeeds without contacting the server.
    pub async fn read_many(&self, nodes: &[NodeId]) -> Result<Vec<DataValue>, ReadError> {
        self.read_batch(nodes.iter().map(ReadOperand::value), std::convert::identity)
            .await
    }

    // Project each response before requesting the next chunk. A numeric poll only
    // retains its samples and item errors, even if a misconfigured node is an array.
    async fn read_batch<'a, T>(
        &self,
        requested: impl ExactSizeIterator<Item = ReadOperand<'a>>,
        project: impl FnMut(DataValue) -> T,
    ) -> Result<Vec<T>, ReadError> {
        let count = requested.len();
        if count > MAX_READ_NODES {
            return Err(ReadError::TooManyNodes);
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        let (mut session, metadata) = self.read_session().await?;
        self.read_locked(&mut session, metadata, requested, project)
            .await
    }

    async fn read_locked<'a, T>(
        &self,
        session: &mut ReadSession,
        metadata: &ReadMetadata,
        requested: impl ExactSizeIterator<Item = ReadOperand<'a>>,
        mut project: impl FnMut(DataValue) -> T,
    ) -> Result<Vec<T>, ReadError> {
        let mut operands = Vec::with_capacity(requested.len());
        for (index, ReadOperand { node, attribute }) in requested.enumerate() {
            let wire = metadata.namespaces.wire_node(node, index)?;
            operands.push((wire, attribute));
        }
        let mut values = Vec::with_capacity(operands.len());
        for chunk in operands.chunks(metadata.max_nodes_per_read) {
            let response = self.read_wire(session, chunk).await?;
            values.extend(response.into_iter().map(&mut project));
        }
        Ok(values)
    }

    async fn read_session(
        &self,
    ) -> Result<(tokio::sync::MutexGuard<'_, ReadSession>, &ReadMetadata), ReadError> {
        let mut session = self.reads.lock().await;
        if session.interrupted {
            return Err(ReadError::SessionInterrupted);
        }
        self.check_channel()?;
        let metadata = self
            .metadata
            .get_or_try_init(|| self.load_metadata(&mut session))
            .await?;
        Ok((session, metadata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_nodes_per_read_is_a_positive_bounded_uint32_or_a_safe_fallback() {
        for (advertised, expected) in [(0, 1), (1, 1), (2, 2), (1024, 1024), (u32::MAX, 1024)] {
            let value = ua::DataValue::value_only(ua::Variant::UInt32(advertised));
            assert_eq!(read_limit(&value).unwrap(), expected);
        }
        assert_eq!(read_limit(&ua::DataValue::default()).unwrap(), 1);
        let qualified = ua::DataValue {
            status: Some(ua::StatusCode::GoodClamped),
            ..ua::DataValue::value_only(ua::Variant::UInt32(3))
        };
        assert_eq!(read_limit(&qualified).unwrap(), 3);
        let wrong_type = ua::DataValue::value_only(ua::Variant::UInt64(2));
        for status in [
            ua::StatusCode::BadNodeIdUnknown,
            ua::StatusCode::BadUserAccessDenied,
            ua::StatusCode::UncertainLastUsableValue,
        ] {
            let unavailable = ua::DataValue {
                status: Some(status),
                ..wrong_type.clone()
            };
            assert_eq!(read_limit(&unavailable).unwrap(), 1);
        }
        assert!(matches!(
            read_limit(&wrong_type),
            Err(ReadError::InvalidReadLimit)
        ));
        let array = ua::DataValue::value_only(ua::Variant::from(vec![2u32]));
        assert!(matches!(
            read_limit(&array),
            Err(ReadError::InvalidReadLimit)
        ));
    }

    #[test]
    fn interrupted_service_requests_retire_the_namespace_mapping() {
        use std::future::{pending, ready};
        use std::task::{Context, Poll, Waker};

        let mut session = ReadSession::default();
        let mut cx = Context::from_waker(Waker::noop());
        let mut request = Box::pin(session.request(pending::<Result<(), ReadError>>()));
        assert!(request.as_mut().poll(&mut cx).is_pending());
        drop(request);
        assert!(matches!(
            Box::pin(session.request(ready(Ok(()))))
                .as_mut()
                .poll(&mut cx),
            Poll::Ready(Err(ReadError::SessionInterrupted))
        ));

        let mut session = ReadSession::default();
        let expired = ReadError::Service(ua::StatusCode::BadSessionIdInvalid);
        assert!(matches!(
            Box::pin(session.request(ready(Err::<(), _>(expired))))
                .as_mut()
                .poll(&mut cx),
            Poll::Ready(Err(ReadError::Service(_)))
        ));
        assert!(session.interrupted);
    }

    // A URI must identify one usable entry within the session limit.
    #[test]
    fn namespace_table_requires_unique_usable_uris_and_a_bounded_size() {
        let standard = "http://opcfoundation.org/UA/";
        let table = |uris: &[&str]| {
            uris.iter()
                .map(|uri| ua::Variant::String((*uri).into()))
                .collect::<Vec<_>>()
        };
        for uris in [
            vec![],
            vec!["urn:other"],
            vec![standard, standard],
            vec![standard, ""],
            vec![standard, "  "],
            vec![standard, "urn:bad\nuri"],
        ] {
            assert!(matches!(
                namespace_map(&table(&uris)),
                Err(ReadError::InvalidServerMetadata)
            ));
        }
        let mut last = "a".repeat(MAX_NAMESPACE_BYTES - standard.len());
        assert_eq!(
            namespace_map(&table(&[standard, &last])).unwrap().by_uri[last.as_str()],
            1
        );
        last.push('a');
        assert!(matches!(
            namespace_map(&table(&[standard, &last])),
            Err(ReadError::InvalidServerMetadata)
        ));
    }
}
