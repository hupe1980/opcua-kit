use time::OffsetDateTime;

use super::sample::Quality;
use super::{
    Client, EngineeringUnitEvidence, ReadAttribute, ReadError, Sample, UnitStage,
    VariableDefinition, ua,
};
use crate::commissioning::{
    Contract, Error, Outcome, SignalRequirement,
    meter::{MeterReading, meter_signal},
};

/// A reviewed meter could not be verified or its DataValue could not be recorded exactly.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MeterReadError {
    /// The supplied contract is outside the supported single-register profile.
    #[error("invalid meter contract: {0}")]
    Contract(#[source] Error),
    /// The reviewed user differs from the authenticated session user.
    #[error("meter principal differs from the authenticated session")]
    Principal,
    /// The contract selects a different server from the pinned client.
    #[error("meter contract ApplicationUri differs from the pinned server")]
    ServerIdentity,
    /// A service, session, node resolution or attribute decoding failed.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// Required metadata was missing, different, or lacked an unqualified Good status.
    #[error("meter {attribute:?}: {outcome:?} (status 0x{status:08X})")]
    Definition {
        /// Mismatch for a confirmed contradiction, Unverified for incomplete evidence.
        outcome: Outcome,
        /// The attribute that failed the gate.
        attribute: ReadAttribute,
        /// Original server operation status.
        status: u32,
    },
    /// The verified standard property did not confirm watt-hours with status zero.
    #[error("meter engineering units at {stage:?}: {outcome:?} (status 0x{status:08X})")]
    Units {
        /// Mismatch for a confirmed different unit, Unverified for incomplete evidence.
        outcome: Outcome,
        /// Where the independent property lookup stopped.
        stage: UnitStage,
        /// Original operation status at that stage.
        status: u32,
    },
    /// A Good-severity Value response omitted the register payload.
    #[error("Good meter DataValue has no scalar payload")]
    MissingValue,
    /// A clock cannot be represented in the meter document without losing information.
    #[error("meter {clock} is outside the supported UTC range or precision")]
    InvalidTimestamp {
        /// Name of the clock field in the evidence document.
        clock: &'static str,
    },
    /// The resulting document failed the commissioning evidence validator or size limit.
    #[error("invalid meter evidence: {0}")]
    Evidence(#[source] Error),
}

fn require<T: PartialEq>(
    attribute: ReadAttribute,
    observed: Sample<T>,
    expected: &T,
) -> Result<(), MeterReadError> {
    match observed.value {
        Some(value) if observed.status == 0 && value == *expected => Ok(()),
        value => Err(MeterReadError::Definition {
            attribute,
            status: observed.status,
            outcome: if observed.status == 0 && value.is_some() {
                Outcome::Mismatch
            } else {
                Outcome::Unverified
            },
        }),
    }
}

fn verify_definition(
    signal: &SignalRequirement,
    declaration: VariableDefinition,
) -> Result<(), MeterReadError> {
    require(
        ReadAttribute::DataType,
        declaration.data_type?,
        &signal.data_type,
    )?;
    require(ReadAttribute::ValueRank, declaration.value_rank?, &-1)
}

fn verify_units(evidence: EngineeringUnitEvidence) -> Result<(), MeterReadError> {
    let unit = evidence.sample.value.filter(|unit| {
        evidence.stage == UnitStage::Value && evidence.sample.status == 0 && unit.is_identified()
    });
    match unit {
        Some(unit) if unit.is_watt_hour() => Ok(()),
        other => Err(MeterReadError::Units {
            stage: evidence.stage,
            status: evidence.sample.status,
            outcome: if other.is_some() {
                Outcome::Mismatch
            } else {
                Outcome::Unverified
            },
        }),
    }
}

impl Client {
    /// Read one approved import register as a serializable commissioning meter reading.
    ///
    /// Each call checks the pinned server, the register's DataType and scalar rank, and
    /// its independently resolved watt-hour property before requesting the process Value.
    /// The caller supplies and reviews the site's register identity and import direction.
    ///
    /// ```
    /// # async fn poll(client: &opcua_kit::Client, contract: &opcua_kit::commissioning::Contract)
    /// # -> Result<(), Box<dyn std::error::Error>> {
    /// let reading = client.read_meter(contract).await?;
    /// let json = serde_json::to_string(&reading)?;
    /// println!("{json}");
    /// # Ok(()) }
    /// ```
    pub async fn read_meter(&self, contract: &Contract) -> Result<MeterReading, MeterReadError> {
        let signal = meter_signal(contract).map_err(MeterReadError::Contract)?;
        if contract.principal() != self.principal {
            return Err(MeterReadError::Principal);
        }
        if contract.application_uri() != self.server_uri {
            return Err(MeterReadError::ServerIdentity);
        }
        let (mut session, metadata) = self.read_session().await?;
        let definition = self
            .definition_locked(&mut session, metadata, &signal.node, Quality::ExactGood)
            .await?;
        verify_definition(signal, definition)?;
        let units = self
            .units_locked(
                &mut session,
                &metadata.namespaces,
                &signal.node,
                Quality::ExactGood,
                |_| true,
            )
            .await?;
        verify_units(units)?;
        let wire = metadata.namespaces.wire_node(&signal.node, 0)?;
        let raw = self
            .one_attribute(&mut session, wire, ua::AttributeId::Value)
            .await?;
        let received_at = OffsetDateTime::now_utc();
        drop(session);
        MeterReading::from_live(contract, signal, &raw, received_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EngineeringUnit;

    fn sample<T>(status: u32, value: Option<T>) -> Sample<T> {
        Sample {
            status,
            value,
            source_timestamp: None,
            server_timestamp: None,
        }
    }

    #[test]
    fn exact_good_metadata_distinguishes_contradiction_from_unavailable_evidence() {
        for (status, rank, expected) in [
            (0, Some(-1), None),
            (0, Some(1), Some(Outcome::Mismatch)),
            (0, None, Some(Outcome::Unverified)),
            (1, Some(-1), Some(Outcome::Unverified)),
            (1, Some(1), Some(Outcome::Unverified)),
        ] {
            let outcome = match require(ReadAttribute::ValueRank, sample(status, rank), &-1) {
                Ok(()) => None,
                Err(MeterReadError::Definition {
                    attribute: ReadAttribute::ValueRank,
                    status: observed,
                    outcome,
                }) => {
                    assert_eq!(observed, status);
                    Some(outcome)
                }
                Err(error) => panic!("{error}"),
            };
            assert_eq!(outcome, expected);
        }
        let wh = EngineeringUnit {
            namespace_uri: "http://www.opcfoundation.org/UA/units/un/cefact".into(),
            unit_id: 0x574852,
        };
        let other = EngineeringUnit {
            namespace_uri: "urn:vendor".into(),
            unit_id: wh.unit_id,
        };
        let unknown = EngineeringUnit {
            namespace_uri: "urn:vendor".into(),
            unit_id: -1,
        };
        for (stage, status, unit, expected) in [
            (UnitStage::Value, 0, Some(wh.clone()), None),
            (UnitStage::Value, 0, Some(other), Some(Outcome::Mismatch)),
            (
                UnitStage::Value,
                0,
                Some(unknown),
                Some(Outcome::Unverified),
            ),
            (UnitStage::Value, 0, None, Some(Outcome::Unverified)),
            (UnitStage::Value, 1, Some(wh), Some(Outcome::Unverified)),
            (UnitStage::Browse, 0, None, Some(Outcome::Unverified)),
        ] {
            let evidence = EngineeringUnitEvidence {
                stage,
                property: None,
                sample: sample(status, unit),
            };
            let outcome = match verify_units(evidence) {
                Ok(()) => None,
                Err(MeterReadError::Units {
                    stage: observed_stage,
                    status: observed_status,
                    outcome,
                }) => {
                    assert_eq!((observed_stage, observed_status), (stage, status));
                    Some(outcome)
                }
                Err(error) => panic!("{error}"),
            };
            assert_eq!(outcome, expected);
        }
    }
}
