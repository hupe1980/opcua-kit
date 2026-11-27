use time::OffsetDateTime;

use super::{DataValue, ReadError, ua};
use crate::{Severity, status_severity};

/// One clock reported by the server, including its optional sub-tick precision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleTimestamp {
    /// UTC nanoseconds since 1970-01-01, from the 100 ns OPC UA DateTime field.
    pub base_unix_nanos: i128,
    /// Additional 10 ps intervals supplied with this clock, if present.
    pub ten_picoseconds: Option<u16>,
}

/// The original timestamp cannot be represented exactly by the application clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TimestampError {
    /// The timestamp falls between two whole nanoseconds.
    #[error("OPC UA timestamp has sub-nanosecond precision")]
    Subnanosecond,
    /// The timestamp exceeds the calendar range of `time::OffsetDateTime`.
    #[error("OPC UA timestamp is outside the representable calendar range")]
    OutOfRange,
}

impl SampleTimestamp {
    pub(super) fn from_parts(base: Option<&ua::DateTime>, increments: Option<u16>) -> Option<Self> {
        base.map(|base| Self {
            base_unix_nanos: base.unix_timestamp_nanos(),
            ten_picoseconds: increments,
        })
    }

    /// Convert to UTC when the complete timestamp is exactly representable in nanoseconds.
    pub fn to_datetime(self) -> Result<OffsetDateTime, TimestampError> {
        // OPC UA Part 6 §5.2.2.17 defines any wire increment >= 10000 as 9999.
        let increments = self.ten_picoseconds.unwrap_or(0).min(9999);
        if !increments.is_multiple_of(100) {
            return Err(TimestampError::Subnanosecond);
        }
        let nanos = self
            .base_unix_nanos
            .checked_add(i128::from(increments / 100))
            .ok_or(TimestampError::OutOfRange)?;
        OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| TimestampError::OutOfRange)
    }
}

/// One typed Value attribute, with its per-node status and optional source and server timestamps.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample<T> {
    /// OPC UA StatusCode, including subcodes and flags. An omitted status means Good (0).
    pub status: u32,
    /// A scalar of the requested wire type, present only for Good severity and a non-null value.
    pub value: Option<T>,
    /// Source timestamp reported by the server.
    pub source_timestamp: Option<SampleTimestamp>,
    /// Server timestamp reported by the server.
    pub server_timestamp: Option<SampleTimestamp>,
}

/// Exact Good is required to qualify a meter. General reads retain qualified Good data.
#[derive(Clone, Copy)]
pub(super) enum Quality {
    GoodSeverity,
    #[cfg(feature = "cems")]
    ExactGood,
}

impl Quality {
    pub(super) fn accepts(self, status: u32) -> bool {
        match self {
            Self::GoodSeverity => status_severity(status) == Severity::Good,
            #[cfg(feature = "cems")]
            Self::ExactGood => status == 0,
        }
    }
}

impl<T: Scalar> Sample<T> {
    /// Decode one raw result, including a member of a heterogeneous [`super::Client::read_many`] batch.
    pub fn from_raw(raw: &DataValue) -> Result<Self, ReadError> {
        Self::from_raw_with(raw, Quality::GoodSeverity)
    }

    pub(super) fn from_raw_with(raw: &DataValue, quality: Quality) -> Result<Self, ReadError> {
        Self::decode_with(raw, quality, T::decode)
    }
}

impl<T> Sample<T> {
    pub(super) fn decode_with(
        raw: &DataValue,
        quality: Quality,
        decode: impl FnOnce(&ua::Variant) -> Result<Option<T>, ReadError>,
    ) -> Result<Self, ReadError> {
        let status = raw.status.map_or(0, |s| s.bits());
        let value = match raw.value.as_ref() {
            Some(v) if quality.accepts(status) && !matches!(v, ua::Variant::Empty) => decode(v)?,
            _ => None,
        };
        Ok(Self {
            status,
            value,
            source_timestamp: SampleTimestamp::from_parts(
                raw.source_timestamp.as_ref(),
                raw.source_picoseconds,
            ),
            server_timestamp: SampleTimestamp::from_parts(
                raw.server_timestamp.as_ref(),
                raw.server_picoseconds,
            ),
        })
    }
}

pub(super) fn decode_borrowed<T>(
    raw: &DataValue,
    decode: impl FnOnce(&ua::Variant) -> Result<Option<T>, ReadError>,
) -> Result<Sample<T>, ReadError> {
    Sample::decode_with(raw, Quality::GoodSeverity, decode)
}

pub(super) fn exact_datetime(time: time::OffsetDateTime) -> Option<ua::DateTime> {
    let ns = time.unix_timestamp_nanos();
    // UA Binary reserves both the 1601 epoch and the last second of year 9999.
    if ns % 100 != 0
        || ns <= -11_644_473_600_000_000_000
        || time.unix_timestamp() >= 253_402_300_799
    {
        return None;
    }
    ua::DateTime::from_unix_timestamp_nanos(ns)
}

/// A Rust type with an exact built-in OPC UA scalar mapping.
///
/// Supported types are `bool`, signed and unsigned 8/16/32/64-bit integers,
/// `f32`, `f64`, UTF-8 `String`, ByteString (`Vec<u8>`), Guid ([`uuid::Uuid`]), and DateTime ([`time::OffsetDateTime`]).
pub trait Scalar: sealed::Decode {
    /// Decode one Variant with this exact wire type. A null Variant or null string/bytes yields None.
    fn from_variant(value: &ua::Variant) -> Result<Option<Self>, ReadError> {
        if matches!(value, ua::Variant::Empty) {
            return Ok(None);
        }
        Self::decode(value)
    }

    /// Encode a scalar for a Write value or a method input argument.
    #[cfg(feature = "control")]
    fn into_variant(self) -> Result<ua::Variant, super::ControlError> {
        self.encode()
    }
}
impl<T: sealed::Decode> Scalar for T {}

/// Fixed-width numeric and Boolean types supported by arrays and raw history reads.
pub trait FixedScalar: Scalar + sealed::Element {}
impl<T: Scalar + sealed::Element> FixedScalar for T {}

mod sealed {
    pub trait Element {
        const TYPE: ua::VariantScalarTypeId;
    }
    use super::{ReadError, ua};

    pub trait Decode: Sized {
        fn decode(value: &ua::Variant) -> Result<Option<Self>, ReadError>;
        #[cfg(feature = "control")]
        fn encode(self) -> Result<ua::Variant, super::super::ControlError>;
    }

    macro_rules! scalars {
        ($($rust:ty => $wire:ident),+ $(,)?) => {$(
            impl Element for $rust {
                const TYPE: ua::VariantScalarTypeId = ua::VariantScalarTypeId::$wire;
            }
            impl Decode for $rust {
                #[cfg(feature = "control")]
                fn encode(self) -> Result<ua::Variant, super::super::ControlError> {
                    Ok(ua::Variant::$wire(self))
                }
                fn decode(value: &ua::Variant) -> Result<Option<Self>, ReadError> {
                    match value { ua::Variant::$wire(v) => Ok(Some(*v)), _ => Err(ReadError::ScalarTypeMismatch { expected: stringify!($wire) }) }
                }
            }
        )+};
    }

    scalars! {
        bool => Boolean, i8 => SByte, u8 => Byte, i16 => Int16, u16 => UInt16,
        i32 => Int32, u32 => UInt32, i64 => Int64, u64 => UInt64,
        f32 => Float, f64 => Double,
    }

    impl Decode for Vec<u8> {
        #[cfg(feature = "control")]
        fn encode(self) -> Result<ua::Variant, super::super::ControlError> {
            use super::super::control::{ControlError, MAX_BYTES};
            if self.len() > MAX_BYTES - 5 {
                return Err(ControlError::InputLimit);
            }
            Ok(ua::Variant::ByteString(self.into()))
        }
        fn decode(value: &ua::Variant) -> Result<Option<Self>, ReadError> {
            match value {
                ua::Variant::ByteString(bytes) => Ok(bytes.value.clone()),
                _ => Err(ReadError::ScalarTypeMismatch {
                    expected: "ByteString",
                }),
            }
        }
    }

    impl Decode for uuid::Uuid {
        #[cfg(feature = "control")]
        fn encode(self) -> Result<ua::Variant, super::super::ControlError> {
            Ok(ua::Variant::Guid(Box::new(self)))
        }
        fn decode(value: &ua::Variant) -> Result<Option<Self>, ReadError> {
            match value {
                ua::Variant::Guid(id) => Ok(Some(**id)),
                _ => Err(ReadError::ScalarTypeMismatch { expected: "Guid" }),
            }
        }
    }

    impl Decode for time::OffsetDateTime {
        #[cfg(feature = "control")]
        fn encode(self) -> Result<ua::Variant, super::super::ControlError> {
            super::exact_datetime(self)
                .map(|v| ua::Variant::DateTime(Box::new(v)))
                .ok_or(super::super::ControlError::InvalidDateTime)
        }
        fn decode(value: &ua::Variant) -> Result<Option<Self>, ReadError> {
            let ua::Variant::DateTime(date) = value else {
                return Err(ReadError::ScalarTypeMismatch {
                    expected: "DateTime",
                });
            };
            Self::from_unix_timestamp_nanos(date.unix_timestamp_nanos())
                .map(Some)
                .map_err(|_| ReadError::DateTimeRange)
        }
    }

    impl Decode for String {
        #[cfg(feature = "control")]
        fn encode(self) -> Result<ua::Variant, super::super::ControlError> {
            use super::super::control::{ControlError, MAX_BYTES};
            if self.len() > MAX_BYTES - 5 {
                return Err(ControlError::InputLimit);
            }
            Ok(ua::Variant::String(self.into()))
        }
        fn decode(value: &ua::Variant) -> Result<Option<Self>, ReadError> {
            match value {
                ua::Variant::String(s) => Ok(s.value().clone()),
                _ => Err(ReadError::ScalarTypeMismatch { expected: "String" }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Preserve the wire quality and independent clocks.
    #[test]
    fn typed_results_preserve_qualified_status_and_clock_evidence() {
        let base = ua::DateTime::from_unix_timestamp_nanos(100).unwrap();
        let value = ua::DataValue {
            source_timestamp: Some(base),
            source_picoseconds: Some(201),
            server_picoseconds: Some(600),
            ..ua::DataValue::value_only(ua::Variant::UInt64(u64::MAX))
        };
        let good = Sample::<u64>::from_raw(&ua::DataValue {
            status: Some(ua::StatusCode::GoodClamped),
            ..value.clone()
        })
        .unwrap();
        assert_eq!(good.status, ua::StatusCode::GoodClamped.bits());
        assert_eq!(good.value, Some(u64::MAX));
        assert_eq!(good.source_timestamp.unwrap().ten_picoseconds, Some(201));
        assert_eq!(
            good.source_timestamp.unwrap().to_datetime(),
            Err(TimestampError::Subnanosecond)
        );
        assert_eq!(good.server_timestamp, None);
        for status in [
            ua::StatusCode::UncertainLastUsableValue,
            ua::StatusCode::BadNodeIdUnknown,
        ] {
            let raw = ua::DataValue {
                status: Some(status),
                ..value.clone()
            };
            let result = Sample::<u64>::from_raw(&raw).unwrap();
            assert_eq!(result.status, status.bits());
            assert_eq!(result.value, None);
            assert_eq!(result.source_timestamp, good.source_timestamp);
        }
    }

    #[test]
    fn exact_wire_type_distinguishes_arrays_null_strings_and_empty_strings() {
        let null = ua::DataValue::value_only(ua::Variant::from(ua::UAString::null()));
        assert_eq!(Sample::<String>::from_raw(&null).unwrap().value, None);
        let empty = ua::DataValue::value_only(ua::Variant::from(ua::UAString::from("")));
        assert_eq!(
            Sample::<String>::from_raw(&empty).unwrap().value.as_deref(),
            Some("")
        );
        let array = vec![1u32];
        let raw = ua::DataValue::value_only(ua::Variant::from(array));
        assert!(matches!(
            Sample::<u32>::from_raw(&raw),
            Err(ReadError::ScalarTypeMismatch { expected: "UInt32" })
        ));
        let bits = 0xfff8_0000_0000_0001;
        let raw = ua::DataValue::value_only(ua::Variant::Double(f64::from_bits(bits)));
        assert_eq!(
            Sample::<f64>::from_raw(&raw)
                .unwrap()
                .value
                .unwrap()
                .to_bits(),
            bits
        );
    }

    #[test]
    fn clock_conversion_requires_the_exact_tick_and_fraction() {
        let base = ua::DateTime::from_unix_timestamp_nanos(-100).unwrap();
        for (increments, expected) in [(None, -100), (Some(100), -99), (Some(9900), -1)] {
            let stamp = SampleTimestamp::from_parts(Some(&base), increments).unwrap();
            assert_eq!(stamp.ten_picoseconds, increments);
            assert_eq!(
                stamp.to_datetime().unwrap().unix_timestamp_nanos(),
                expected
            );
        }
        for increments in [1, 9999, 10000, u16::MAX] {
            let stamp = SampleTimestamp::from_parts(Some(&base), Some(increments)).unwrap();
            assert_eq!(stamp.to_datetime(), Err(TimestampError::Subnanosecond));
        }
        assert!(SampleTimestamp::from_parts(None, Some(100)).is_none());
        let future = SampleTimestamp {
            base_unix_nanos: i128::from(i64::MAX) * 100,
            ten_picoseconds: None,
        };
        assert_eq!(future.to_datetime(), Err(TimestampError::OutOfRange));
    }
}
