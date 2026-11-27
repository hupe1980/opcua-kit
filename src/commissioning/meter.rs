//! Evidence for one approved cumulative grid-import register and its CEMS trace.
//!
//! A metadata snapshot contains no register values. Select a single scalar
//! UInt32, UInt64, Float or Double in watt-hours and use a separate meter reading document.
//! The site must confirm import direction and the source clock's meaning.
//! Projection preserves observed instants and never invents a quarter boundary.
//!
//! Good-severity evidence carries an unsigned register in `value`, or the raw
//! floating-point word in `valueBits`. A Float word is a JSON UInt32. A Double
//! word is a string of 16 lowercase hex digits, most significant digit first.
//! Floating-point readings qualify as whole Wh only in `[0, 2²⁴)` for Float
//! and `[0, 2⁵³)` for Double, under the same status and timestamp rules.

use std::{fmt, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub use time::OffsetDateTime;
use time::{Duration, UtcOffset, format_description::well_known::Rfc3339};

use super::{ByteBudget, Contract, Error, Expected, MAX_DOCUMENT_BYTES, NodeId, Unit, present};
use crate::{Severity, status_severity};

const UA: &str = "http://opcfoundation.org/UA/";

#[cfg(feature = "client")]
mod live;

mod projection;
pub use projection::{MeterProjector, MeterWindow, project_meter_trace};

pub(crate) fn meter_signal(contract: &Contract) -> Result<&Expected, Error> {
    if contract.0.principal != "anonymous"
        && !contract
            .0
            .principal
            .strip_prefix("username:")
            .is_some_and(|name| !name.trim().is_empty() && name.len() <= 256)
    {
        return Err(Error::new(
            "expected anonymous or username:<account> for the meter principal",
        ));
    }
    let [signal] = contract.0.signals.as_slice() else {
        return Err(Error::new(
            "meter contract must select exactly one grid-import register",
        ));
    };
    if signal.data_type.namespace() != UA
        || !matches!(
            signal.data_type.identifier(),
            "i=7" | "i=9" | "i=10" | "i=11"
        )
    {
        return Err(Error::new(
            "meter contract requires standard UInt32, UInt64, Float or Double DataType",
        ));
    }
    if signal.value_rank != Some(-1) {
        return Err(Error::new("meter contract requires scalar valueRank -1"));
    }
    if !signal
        .engineering_units
        .as_ref()
        .is_some_and(Unit::is_watt_hour)
    {
        return Err(Error::new(
            "meter contract requires UN/CEFACT watt-hours (WHR)",
        ));
    }
    Ok(signal)
}

/// Check that a reviewed contract selects exactly one supported grid-import register.
pub fn validate_meter_contract(contract: &Contract) -> Result<(), Error> {
    meter_signal(contract).map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Instant(OffsetDateTime);

impl Instant {
    fn utc(time: OffsetDateTime) -> Option<Self> {
        time.checked_to_offset(UtcOffset::UTC)
            .filter(|utc| (0..=9999).contains(&utc.year()))
            .map(Self)
    }

    fn aligned(self) -> bool {
        self.0.nanosecond() == 0 && self.0.unix_timestamp().rem_euclid(900) == 0
    }
}

impl<'de> Deserialize<'de> for Instant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = text.as_bytes();
        // RFC 3339 parsers can normalize leap seconds and truncate subseconds.
        // Reject either before parsing so distinct evidence cannot collapse.
        let excess_precision = bytes.get(19) == Some(&b'.')
            && bytes
                .get(20..30)
                .is_some_and(|digits| digits.iter().all(u8::is_ascii_digit));
        if excess_precision
            || bytes.get(17..19) == Some(b"60")
            || !matches!(bytes.get(10), Some(b'T' | b't'))
            || text.ends_with("-00:00")
        {
            return Err(de::Error::custom(
                "expected RFC 3339 with known offset and at most nanosecond precision",
            ));
        }
        let local = OffsetDateTime::parse(&text, &Rfc3339)
            .map_err(|_| de::Error::custom("invalid RFC 3339 timestamp"))?;
        Self::utc(local)
            .ok_or_else(|| de::Error::custom("timestamp outside four-digit UTC year range"))
    }
}

impl Serialize for Instant {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = self.0.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&text)
    }
}

/// One scope-checked DataValue. Serialize this to retain its independent clocks,
/// raw UInt32 status, and the original integer or floating-point bit pattern on Good severity.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct MeterReading {
    row: Reading,
    #[serde(skip)]
    line_bytes: usize,
}

// The wire parser and native reader validate the same evidence representation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reading {
    schema_version: u32,
    device: String,
    application_uri: String,
    principal: String,
    name: String,
    #[serde(deserialize_with = "object")]
    node: NodeId,
    #[serde(deserialize_with = "object")]
    data_type: NodeId,
    value_rank: i32,
    #[serde(deserialize_with = "object")]
    engineering_units: Unit,
    received_at: Instant,
    // An explicit null records that a server did not return this clock.
    #[serde(deserialize_with = "Option::deserialize")]
    source_at: Option<Instant>,
    #[serde(deserialize_with = "Option::deserialize")]
    server_at: Option<Instant>,
    status: u32,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    value: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    value_bits: Option<FloatingBits>,
}

// A 32-bit word is exactly representable by JSON consumers using binary64.
// A 64-bit word uses hexadecimal text so even its least significant bit survives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FloatingBits {
    Float(u32),
    Double(u64),
}

impl<'de> Deserialize<'de> for FloatingBits {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Word;
        impl de::Visitor<'_> for Word {
            type Value = FloatingBits;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("UInt32 or 16 lowercase hexadecimal digits")
            }

            fn visit_u64<E: de::Error>(self, word: u64) -> Result<Self::Value, E> {
                u32::try_from(word)
                    .map(FloatingBits::Float)
                    .map_err(E::custom)
            }

            fn visit_str<E: de::Error>(self, word: &str) -> Result<Self::Value, E> {
                if word.len() != 16 || !word.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                {
                    return Err(E::custom("expected 16 lowercase hexadecimal digits"));
                }
                u64::from_str_radix(word, 16)
                    .map(FloatingBits::Double)
                    .map_err(E::custom)
            }
        }
        // Restrict the JSON token to a scalar before constructing any payload.
        d.deserialize_any(Word)
    }
}

impl Serialize for FloatingBits {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Float(bits) => s.serialize_u32(*bits),
            Self::Double(bits) => s.collect_str(&format_args!("{bits:016x}")),
        }
    }
}

impl FloatingBits {
    fn whole_wh(self) -> Result<u64, MeterExclusionReason> {
        // Widening a binary32 is exact. Each cutoff is the first magnitude at
        // which the next larger value of its original wire type is 2 Wh away.
        let (wh, limit) = match self {
            Self::Float(bits) => (f64::from(f32::from_bits(bits)), 16_777_216.0),
            Self::Double(bits) => (f64::from_bits(bits), 9_007_199_254_740_992.0),
        };
        if !wh.is_finite() {
            Err(MeterExclusionReason::NonFiniteWh)
        } else if wh < 0.0 {
            Err(MeterExclusionReason::NegativeWh)
        } else if wh >= limit {
            Err(MeterExclusionReason::InsufficientResolution)
        } else if wh.fract() != 0.0 {
            Err(MeterExclusionReason::FractionalWh)
        } else {
            Ok(wh as u64)
        }
    }
}

impl MeterReading {
    fn checked(contract: &Contract, signal: &Expected, row: Reading) -> Result<Self, Error> {
        validate_reading(contract, signal, &row)?;
        let line_bytes = compact_line_bytes(&row)?;
        Ok(Self { row, line_bytes })
    }

    /// Cached byte size of this compact UTF-8 JSON reading plus one LF.
    /// This is the exact input charge for [`MeterProjector::push`].
    pub fn compact_line_bytes(&self) -> usize {
        self.line_bytes
    }

    /// Full OPC UA Value read status, including subcode and information bits.
    pub fn status(&self) -> u32 {
        self.row.status
    }

    /// Original UInt32 or UInt64 register value when the wire status has Good severity.
    pub fn value(&self) -> Option<u64> {
        self.row.value
    }

    /// Original binary32 bits for a Float register when the wire status has Good severity.
    pub fn value_bits(&self) -> Option<u32> {
        match self.row.value_bits {
            Some(FloatingBits::Float(bits)) => Some(bits),
            _ => None,
        }
    }

    /// Original binary64 bits for a Double register when the wire status has Good severity.
    pub fn double_bits(&self) -> Option<u64> {
        match self.row.value_bits {
            Some(FloatingBits::Double(bits)) => Some(bits),
            _ => None,
        }
    }

    /// Original source clock, normalized to UTC at its supplied precision.
    pub fn source_at(&self) -> Option<OffsetDateTime> {
        self.row.source_at.map(|at| at.0)
    }

    /// Original server clock when the read included it.
    pub fn server_at(&self) -> Option<OffsetDateTime> {
        self.row.server_at.map(|at| at.0)
    }

    /// UTC receipt time measured by the reader.
    pub fn received_at(&self) -> OffsetDateTime {
        self.row.received_at.0
    }
}

// serde's default derived struct decoder also accepts positional JSON arrays.
// The document contracts use named object members, including on nested points.
fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    struct Named<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Named<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }
    d.deserialize_map(Named(PhantomData))
}

#[derive(Deserialize)]
#[serde(transparent, bound(deserialize = "T: Deserialize<'de>"))]
struct JsonObject<T>(#[serde(deserialize_with = "object")] T);

fn decode<T: de::DeserializeOwned>(bytes: &[u8], kind: &str) -> Result<T, Error> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::new(format!("{kind} exceeds 4 MiB")));
    }
    // Parser diagnostics can quote an entire register value or an unknown key.
    serde_json::from_slice::<JsonObject<T>>(bytes)
        .map(|wrapped| wrapped.0)
        .map_err(|e| {
            Error::new(format!(
                "invalid {kind} at line {}, column {}: check required fields, types and timestamps",
                e.line(),
                e.column()
            ))
        })
}

fn validate_reading(
    contract: &Contract,
    signal: &Expected,
    reading: &Reading,
) -> Result<(), Error> {
    if reading.schema_version != 1 {
        return Err(Error::new(
            "unsupported meter reading schemaVersion (expected 1)",
        ));
    }
    if reading.device != contract.0.device
        || reading.application_uri != contract.0.application_uri
        || reading.principal != contract.0.principal
        || reading.name != signal.name
        || reading.node != signal.node
    {
        return Err(Error::new(
            "meter reading scope or register identity differs from the contract",
        ));
    }
    if reading.data_type != signal.data_type
        || Some(reading.value_rank) != signal.value_rank
        || Some(&reading.engineering_units) != signal.engineering_units.as_ref()
    {
        return Err(Error::new(
            "meter reading DataType, ValueRank or EngineeringUnits differs from the contract",
        ));
    }
    let valid_payload = match status_severity(reading.status) {
        Severity::Good => match signal.data_type.identifier() {
            "i=10" => {
                reading.value.is_none()
                    && matches!(reading.value_bits, Some(FloatingBits::Float(_)))
            }
            "i=11" => {
                reading.value.is_none()
                    && matches!(reading.value_bits, Some(FloatingBits::Double(_)))
            }
            _ => reading.value.is_some() && reading.value_bits.is_none(),
        },
        _ => reading.value.is_none() && reading.value_bits.is_none(),
    };
    if !valid_payload {
        return Err(Error::new(
            "Good integer readings require value, Float requires UInt32 valueBits, and Double requires 16 lowercase hex digits in valueBits. Other severities omit both fields",
        ));
    }
    if signal.data_type.identifier() == "i=7"
        && reading.value.is_some_and(|v| v > u64::from(u32::MAX))
    {
        return Err(Error::new(
            "meter reading value exceeds the approved UInt32 DataType",
        ));
    }
    Ok(())
}

// Check the encoded document including room for its NDJSON delimiter.
fn compact_line_bytes(document: &impl Serialize) -> Result<usize, Error> {
    let mut budget = ByteBudget(MAX_DOCUMENT_BYTES - 1);
    serde_json::to_writer(&mut budget, document).map_err(|error| {
        if error.is_io() {
            Error::new("encoded meter document and newline exceed 4 MiB")
        } else {
            Error::new("could not encode meter document")
        }
    })?;
    Ok(MAX_DOCUMENT_BYTES - budget.0)
}

/// Parse one strict reading and verify it belongs to the reviewed meter contract.
pub fn parse_meter_reading(contract: &Contract, bytes: &[u8]) -> Result<MeterReading, Error> {
    MeterReading::checked(
        contract,
        meter_signal(contract)?,
        decode(bytes, "meter reading")?,
    )
}

/// A UTC instant and an exact watt-hour amount in the CEMS trace.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeterPoint {
    at: Instant,
    /// Cumulative register or independently closed interval energy, in watt-hours.
    pub wh: u64,
}

impl MeterPoint {
    /// UTC source instant for a register reading, or start instant of a close.
    pub fn at(&self) -> OffsetDateTime {
        self.at.0
    }
}

// The site maps the independent close feed to the commissioned register.
// This binding is checked locally and omitted from the consumer's trace.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowMeter {
    device: String,
    application_uri: String,
    #[serde(deserialize_with = "object")]
    node: NodeId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    #[serde(deserialize_with = "object")]
    meter: WindowMeter,
    start: Instant,
    end: Instant,
    tolerance_wh: u64,
    closed: Vec<JsonObject<MeterPoint>>,
}

/// A ready-to-serialize input to `cemsd reconcile`. Reconciliation itself
/// remains with CEMS, including its handling of counter decreases and gaps.
#[derive(Debug, Serialize)]
pub struct MeterTrace {
    start: Instant,
    end: Instant,
    tolerance_wh: u64,
    /// Usable source observations, ordered by UTC instant.
    pub register: Vec<MeterPoint>,
    /// Independent closes keyed by the start of the UTC quarter.
    pub closed: Vec<MeterPoint>,
}

impl MeterTrace {
    /// Inclusive start of the comparison window, normalized to UTC.
    pub fn start(&self) -> OffsetDateTime {
        self.start.0
    }

    /// Inclusive end of register coverage, normalized to UTC. Closes must start before this instant.
    pub fn end(&self) -> OffsetDateTime {
        self.end.0
    }

    /// Largest accepted absolute difference between the two energy series, in Wh.
    pub fn tolerance_wh(&self) -> u64 {
        self.tolerance_wh
    }
}

/// Why an observation failed to qualify as a register point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MeterExclusionReason {
    /// Nonzero OPC UA StatusCode, including all qualifier and information bits.
    Status(u32),
    /// The meter supplied no source timestamp.
    MissingSourceTime,
    /// The source instant is later than local receipt.
    SourceAfterReceipt,
    /// The floating-point register contains NaN or infinity.
    NonFiniteWh,
    /// The cumulative register is finite and below zero.
    NegativeWh,
    /// The nonnegative register contains a fraction of a watt-hour.
    FractionalWh,
    /// The next larger value in the register's wire type is more than 1 Wh away.
    InsufficientResolution,
}

impl fmt::Display for MeterExclusionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(code) => write!(f, "OPC UA status 0x{code:08X}"),
            Self::MissingSourceTime => f.write_str("missing source timestamp"),
            Self::SourceAfterReceipt => f.write_str("source timestamp is after receipt"),
            Self::NonFiniteWh => f.write_str("non-finite register value"),
            Self::NegativeWh => f.write_str("negative cumulative Wh"),
            Self::FractionalWh => f.write_str("fractional Wh"),
            Self::InsufficientResolution => f.write_str("register cannot resolve 1 Wh increments"),
        }
    }
}

/// Location and cause of a single rejected observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeterExclusion {
    /// One-based NDJSON line number (including blank lines), or one-based push number.
    pub input_position: usize,
    /// Meter source time in UTC, when supplied.
    pub source_at: Option<OffsetDateTime>,
    /// The first failed eligibility check for this observation.
    pub reason: MeterExclusionReason,
}

/// Result of projecting evidence into a CEMS trace.
#[derive(Debug)]
pub struct MeterProjection {
    /// Write this compactly as one JSON document for CEMS.
    pub trace: MeterTrace,
    /// Rows with a nonzero status, including qualified Good statuses.
    pub skipped_status: usize,
    /// Unqualified Good rows with missing source time or source time after receipt.
    pub skipped_source_time: usize,
    /// Otherwise eligible Float or Double rows without a nonnegative whole Wh
    /// value below the original type's 1 Wh resolution limit (2²⁴ or 2⁵³).
    pub skipped_precision: usize,
    /// First observation in input order counted by any of the three `skipped_*` counters.
    /// Outside-window observations and usable duplicates do not set this field.
    pub first_exclusion: Option<MeterExclusion>,
    /// Timed rows outside the requested window (regardless of status).
    pub outside_window: usize,
    /// Additional usable rows with the same source instant and exact value.
    pub duplicate_readings: usize,
}
