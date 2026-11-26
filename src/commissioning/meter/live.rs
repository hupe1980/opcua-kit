use open62541::{DataType, DataValue, ua};

use super::{Contract, Expected, FloatingBits, Instant, MeterReading, OffsetDateTime, Reading};
use crate::{MeterReadError, Sample, SampleTimestamp, Scalar, Severity, status_severity};

// OPC UA DateTime counts 100 ns ticks since 1601-01-01 UTC.
const UA_EPOCH_UNIX_NANOS: i128 = -11_644_473_600_000_000_000;

fn clock(
    base: Option<&ua::DateTime>,
    increments: Option<u16>,
    name: &'static str,
) -> Result<Option<Instant>, MeterReadError> {
    let Some(base) = base else { return Ok(None) };
    let nanos = base.as_unix_timestamp_nanos();
    // Part 6 §5.2.2.5 and §5.2.2.17. DateTime.MinValue means the clock is
    // absent. An orphaned picoseconds field supplies no independent instant.
    if nanos == UA_EPOCH_UNIX_NANOS {
        return Ok(None);
    }
    if nanos < UA_EPOCH_UNIX_NANOS {
        return Err(MeterReadError::InvalidTimestamp { clock: name });
    }
    SampleTimestamp {
        base_unix_nanos: nanos,
        ten_picoseconds: increments,
    }
    .to_datetime()
    .ok()
    .and_then(Instant::utc)
    .map(Some)
    .ok_or(MeterReadError::InvalidTimestamp { clock: name })
}

fn scalar<T: Scalar>(raw: &DataValue<ua::Variant>) -> Result<T, MeterReadError> {
    Sample::<T>::from_raw(raw)?
        .value
        .ok_or(MeterReadError::MissingValue)
}

fn payload(
    dtype: &str,
    raw: &DataValue<ua::Variant>,
    status: u32,
) -> Result<(Option<u64>, Option<FloatingBits>), MeterReadError> {
    // OPC UA Part 4 §7.11.1. Keep the operation status and clocks even when
    // the unusable process Value has an unrelated wire type.
    if status_severity(status) != Severity::Good {
        return Ok((None, None));
    }
    // Float words come directly from the exact wire scalar, without widening or arithmetic.
    let fields = match dtype {
        "i=7" => (Some(u64::from(scalar::<u32>(raw)?)), None),
        "i=9" => (Some(scalar::<u64>(raw)?), None),
        "i=10" => (
            None,
            Some(FloatingBits::Float(scalar::<f32>(raw)?.to_bits())),
        ),
        "i=11" => (
            None,
            Some(FloatingBits::Double(scalar::<f64>(raw)?.to_bits())),
        ),
        _ => unreachable!("the reviewed meter contract has a supported DataType"),
    };
    Ok(fields)
}

impl MeterReading {
    pub(crate) fn from_live(
        contract: &Contract,
        signal: &Expected,
        raw: &DataValue<ua::Variant>,
        received_at: OffsetDateTime,
    ) -> Result<Self, MeterReadError> {
        let status = raw.status().map_or(0, DataType::into_raw);
        let (value, value_bits) = payload(signal.data_type.identifier(), raw, status)?;
        let reading = Reading {
            schema_version: 1,
            device: contract.device().to_owned(),
            application_uri: contract.application_uri().to_owned(),
            principal: contract.principal().to_owned(),
            name: signal.name.clone(),
            node: signal.node.clone(),
            data_type: signal.data_type.clone(),
            value_rank: -1,
            engineering_units: signal
                .engineering_units
                .clone()
                .expect("validated meter contract includes watt-hours"),
            received_at: Instant::utc(received_at).ok_or(MeterReadError::InvalidTimestamp {
                clock: "receivedAt",
            })?,
            source_at: clock(raw.source_timestamp(), raw.source_picoseconds(), "sourceAt")?,
            server_at: clock(raw.server_timestamp(), raw.server_picoseconds(), "serverAt")?,
            status,
            value,
            value_bits,
        };
        Self::checked(contract, signal, reading).map_err(MeterReadError::Evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReadError;
    use crate::commissioning::{
        NodeId,
        meter::{meter_signal, parse_meter_reading},
        parse_contract,
    };

    fn contract(dtype: &str) -> Contract {
        let fixture =
            parse_contract(include_bytes!("../../../fixtures/meter/contract.json")).unwrap();
        let mut signal = fixture.signals()[0].clone();
        signal.data_type = NodeId::new(super::super::UA, dtype).unwrap();
        Contract::new(
            fixture.device(),
            fixture.application_uri(),
            fixture.principal(),
            vec![signal],
        )
        .unwrap()
    }

    fn from_raw(c: &Contract, raw: ua::DataValue) -> Result<MeterReading, MeterReadError> {
        MeterReading::from_live(
            c,
            meter_signal(c).unwrap(),
            &raw.cast(),
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn live_evidence_round_trips_all_exact_wire_widths_and_full_status() {
        let float_word = 0xffc1_2345;
        let double_word = 0xfff8_0000_0000_1234;
        for (dtype, payload, integer, single, double) in [
            (
                "i=7",
                ua::Variant::scalar(ua::UInt32::new(u32::MAX)),
                Some(u64::from(u32::MAX)),
                None,
                None,
            ),
            (
                "i=9",
                ua::Variant::scalar(ua::UInt64::new(u64::MAX)),
                Some(u64::MAX),
                None,
                None,
            ),
            (
                "i=10",
                ua::Variant::scalar(ua::Float::new(f32::from_bits(float_word))),
                None,
                Some(float_word),
                None,
            ),
            (
                "i=11",
                ua::Variant::scalar(ua::Double::new(f64::from_bits(double_word))),
                None,
                None,
                Some(double_word),
            ),
            (
                "i=11",
                ua::Variant::scalar(ua::Double::new(-0.0)),
                None,
                None,
                Some((-0.0f64).to_bits()),
            ),
        ] {
            let c = contract(dtype);
            let source = ua::DateTime::try_from_unix_timestamp_nanos(-100).unwrap();
            let server = ua::DateTime::try_from_unix_timestamp_nanos(200).unwrap();
            let raw = ua::DataValue::new(payload)
                .with_status(&ua::StatusCode::GOODCLAMPED)
                .with_source_timestamp(&source)
                .with_source_picoseconds(9900)
                .with_server_timestamp(&server)
                .with_server_picoseconds(100);
            let valid = from_raw(&c, raw).unwrap();
            let encoded = serde_json::to_vec(&valid).unwrap();
            let parsed = parse_meter_reading(&c, &encoded).unwrap();
            assert_eq!(
                (parsed.value(), parsed.value_bits(), parsed.double_bits()),
                (integer, single, double)
            );
            assert_eq!(parsed.status(), ua::StatusCode::GOODCLAMPED.into_raw());
            assert_eq!(parsed.source_at().unwrap().unix_timestamp_nanos(), -1);
            assert_eq!(parsed.server_at().unwrap().unix_timestamp_nanos(), 201);
            assert_eq!(parsed.received_at(), OffsetDateTime::UNIX_EPOCH);
            assert_eq!(serde_json::to_vec(&parsed).unwrap(), encoded);
        }
    }

    #[test]
    fn native_evidence_reserves_one_byte_for_the_line_delimiter() {
        let c = contract("i=9");
        let value = || ua::DataValue::new(ua::Variant::scalar(ua::UInt64::new(u64::MAX)));
        let baseline = serde_json::to_vec(&from_raw(&c, value()).unwrap())
            .unwrap()
            .len();
        let extra = crate::commissioning::MAX_DOCUMENT_BYTES - baseline;
        let expand = |len| {
            Contract::new(
                format!("{}{}", c.device(), "a".repeat(len)),
                c.application_uri(),
                c.principal(),
                c.signals().to_vec(),
            )
            .unwrap()
        };
        let fitting = expand(extra - 1);
        assert!(from_raw(&fitting, value()).is_ok());
        let too_large = expand(extra);
        assert!(
            matches!(from_raw(&too_large, value()), Err(MeterReadError::Evidence(e)) if e.to_string().contains("newline exceed 4 MiB"))
        );
    }

    #[test]
    fn non_good_omits_payload_and_malformed_or_absent_good_payload_fails() {
        let c = contract("i=9");
        for status in [
            ua::StatusCode::UNCERTAINLASTUSABLEVALUE,
            ua::StatusCode::BADNODEIDUNKNOWN,
            ua::StatusCode::raw_ref(&0xc000_0400).clone(),
        ] {
            for raw in [
                ua::DataValue::init(),
                ua::DataValue::new(ua::Variant::scalar(ua::UInt64::new(19))),
                ua::DataValue::new(ua::Variant::array(ua::Array::from_slice(&[
                    ua::Int64::new(19),
                ]))),
            ] {
                let instant = ua::DateTime::try_from_unix_timestamp_nanos(100).unwrap();
                let reading =
                    from_raw(&c, raw.with_source_timestamp(&instant).with_status(&status)).unwrap();
                assert_eq!(reading.source_at().unwrap().unix_timestamp_nanos(), 100);
                assert!(reading.server_at().is_none());
                assert_eq!(reading.status(), status.clone().into_raw());
                let encoded = serde_json::to_value(reading).unwrap();
                assert!(encoded.get("value").is_none() && encoded.get("valueBits").is_none());
            }
        }
        assert!(matches!(
            from_raw(&c, ua::DataValue::init()),
            Err(MeterReadError::MissingValue)
        ));
        let wrong_rank = ua::DataValue::new(ua::Variant::array(ua::Array::from_slice(&[
            ua::UInt64::new(4),
        ])));
        assert!(matches!(
            from_raw(&c, wrong_rank),
            Err(MeterReadError::Read(ReadError::ScalarTypeMismatch { .. }))
        ));
    }

    #[test]
    fn meter_clock_ignores_missing_or_zero_base_and_rejects_inexact_or_sentinel_time() {
        assert!(clock(None, Some(1), "sourceAt").unwrap().is_none());
        let timestamp = |nanos| ua::DateTime::try_from_unix_timestamp_nanos(nanos).unwrap();
        assert!(
            clock(
                Some(&timestamp(UA_EPOCH_UNIX_NANOS)),
                Some(9999),
                "sourceAt"
            )
            .unwrap()
            .is_none()
        );
        for (base, increments) in [
            (UA_EPOCH_UNIX_NANOS - 100, None),
            (UA_EPOCH_UNIX_NANOS + i128::from(i64::MAX) * 100, None),
            (0, Some(1)),
            (0, Some(10000)),
        ] {
            assert!(matches!(
                clock(Some(&timestamp(base)), increments, "serverAt"),
                Err(MeterReadError::InvalidTimestamp { clock: "serverAt" })
            ));
        }
        assert_eq!(
            clock(Some(&timestamp(0)), None, "sourceAt")
                .unwrap()
                .unwrap()
                .0,
            OffsetDateTime::UNIX_EPOCH
        );
    }
}
