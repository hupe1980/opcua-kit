use std::collections::{BTreeMap, btree_map::Entry};

use super::{
    Contract, Duration, Error, Expected, FloatingBits, Instant, JsonObject, MAX_DOCUMENT_BYTES,
    MeterExclusion, MeterExclusionReason, MeterPoint, MeterProjection, MeterReading, MeterTrace,
    NodeId, OffsetDateTime, Reading, Window, compact_line_bytes, decode, meter_signal,
    validate_reading,
};

// Every minimally encoded wire close already takes over 32 bytes. Check the supplied
// count before indexing, even if every entry describes exactly the same quarter.
const MAX_CLOSES: usize = MAX_DOCUMENT_BYTES / 32;

/// A site's independently bound CEMS comparison window, supplied to [`MeterProjector::new`].
#[derive(Clone, Copy, Debug)]
pub struct MeterWindow<'a> {
    /// Device to which the independent close feed belongs.
    pub device: &'a str,
    /// ApplicationUri of that meter's OPC UA server.
    pub application_uri: &'a str,
    /// URI-qualified identity of the corresponding register.
    pub node: &'a NodeId,
    /// Inclusive, quarter-hour-aligned comparison start.
    pub start: OffsetDateTime,
    /// Inclusive register end and exclusive close start limit, at most 31 days after start.
    pub end: OffsetDateTime,
    /// Largest accepted absolute difference in watt-hours.
    pub tolerance_wh: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    status: u32,
    value: Option<u64>,
    bits: Option<FloatingBits>,
    usable_wh: Option<u64>,
}

/// A bounded projector for a stream of already validated readings. The projector
/// borrows only the contract. It retains the raw facts needed to detect in-window
/// conflicts and charges every push its compact JSON size plus one newline.
///
/// ```
/// use opcua_kit::commissioning::{Contract, Error, meter::{
///     MeterProjection, MeterProjector, MeterReading, MeterWindow, OffsetDateTime,
/// }};
///
/// fn reconcile_input(
///     contract: &Contract,
///     window: MeterWindow<'_>,
///     readings: impl IntoIterator<Item = MeterReading>,
///     independent_closes: &[(OffsetDateTime, u64)],
/// ) -> Result<MeterProjection, Error> {
///     let mut projector = MeterProjector::new(contract, window)?;
///     for reading in readings {
///         projector.push(&reading)?;
///     }
///     projector.finish(independent_closes)
/// }
/// ```
#[derive(Debug)]
pub struct MeterProjector<'a> {
    contract: &'a Contract,
    signal: &'a Expected,
    result: MeterProjection,
    observations: BTreeMap<Instant, Observation>,
    remaining_bytes: usize,
    pushes: usize,
    failure: Option<Error>,
}

fn utc(at: OffsetDateTime) -> Result<Instant, Error> {
    Instant::utc(at).ok_or_else(|| Error::new("timestamp outside four-digit UTC year range"))
}

impl<'a> MeterProjector<'a> {
    /// Bind the independently configured close feed and validate the comparison window.
    pub fn new(contract: &'a Contract, window: MeterWindow<'_>) -> Result<Self, Error> {
        Self::bind(contract, meter_signal(contract)?, window)
    }

    fn bind(
        contract: &'a Contract,
        signal: &'a Expected,
        window: MeterWindow<'_>,
    ) -> Result<Self, Error> {
        if window.device != contract.device()
            || window.application_uri != contract.application_uri()
            || window.node != &signal.node
        {
            return Err(Error::new(
                "CEMS window meter differs from the reviewed device, application URI or register node",
            ));
        }
        let start = utc(window.start)?;
        let end = utc(window.end)?;
        let span = end.0 - start.0;
        if !start.aligned() || !end.aligned() || span <= Duration::ZERO || span > Duration::days(31)
        {
            return Err(Error::new(
                "use a positive UTC quarter-hour-aligned window of at most 31 days",
            ));
        }
        Ok(Self {
            contract,
            signal,
            result: MeterProjection {
                trace: MeterTrace {
                    start,
                    end,
                    tolerance_wh: window.tolerance_wh,
                    closed: Vec::new(),
                    register: Vec::new(),
                },
                skipped_status: 0,
                skipped_source_time: 0,
                skipped_precision: 0,
                first_exclusion: None,
                outside_window: 0,
                duplicate_readings: 0,
            },
            observations: BTreeMap::new(),
            remaining_bytes: MAX_DOCUMENT_BYTES,
            pushes: 0,
            failure: None,
        })
    }

    /// Remaining typed reading budget in bytes. Compare with [`MeterReading::compact_line_bytes`]
    /// before pushing. A failed push leaves zero usable bytes.
    pub fn remaining_input_bytes(&self) -> usize {
        self.remaining_bytes
    }

    /// Validate the reading against this contract and add it to the projection.
    /// The first error is terminal and is returned by later pushes and [`Self::finish`].
    /// The total compact size including one newline per push must fit in 4 MiB.
    pub fn push(&mut self, reading: &MeterReading) -> Result<(), Error> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        self.pushes += 1;
        let result = if let Some(remaining) = self
            .remaining_bytes
            .checked_sub(reading.compact_line_bytes())
        {
            self.remaining_bytes = remaining;
            self.ingest(&reading.row, self.pushes)
        } else {
            Err(Error::new("meter readings exceed 4 MiB"))
        };
        result.map_err(|error| {
            let error = error.at(&format!("reading {}", self.pushes));
            self.failure = Some(error.clone());
            self.remaining_bytes = 0;
            error
        })
    }

    fn ingest(&mut self, row: &Reading, input_position: usize) -> Result<(), Error> {
        validate_reading(self.contract, self.signal, row)?;
        let result = &mut self.result;
        if row
            .source_at
            .is_some_and(|at| at < result.trace.start || at > result.trace.end)
        {
            result.outside_window += 1;
            return Ok(());
        }
        let eligibility = match row.source_at {
            _ if row.status != 0 => Err(MeterExclusionReason::Status(row.status)),
            None => Err(MeterExclusionReason::MissingSourceTime),
            Some(at) if at > row.received_at => Err(MeterExclusionReason::SourceAfterReceipt),
            Some(_) => match row.value_bits {
                Some(bits) => bits.whole_wh().map(Some),
                None => Ok(row.value),
            },
        };
        let usable_wh = match eligibility {
            Ok(wh) => wh,
            Err(reason) => {
                use MeterExclusionReason::*;
                match reason {
                    Status(_) => result.skipped_status += 1,
                    MissingSourceTime | SourceAfterReceipt => result.skipped_source_time += 1,
                    NonFiniteWh | NegativeWh | FractionalWh | InsufficientResolution => {
                        result.skipped_precision += 1;
                    }
                }
                result.first_exclusion.get_or_insert(MeterExclusion {
                    input_position,
                    source_at: row.source_at.map(|at| at.0),
                    reason,
                });
                None
            }
        };
        if let Some(at) = row.source_at {
            let evidence = Observation {
                status: row.status,
                value: row.value,
                bits: row.value_bits,
                usable_wh,
            };
            match self.observations.entry(at) {
                Entry::Vacant(entry) => {
                    entry.insert(evidence);
                }
                Entry::Occupied(entry) if *entry.get() != evidence => {
                    return Err(Error::new(
                        "conflicting meter evidence at the same source instant",
                    ));
                }
                Entry::Occupied(_) if usable_wh.is_some() => result.duplicate_readings += 1,
                Entry::Occupied(_) => {}
            }
        }
        Ok(())
    }

    fn set_closes(
        &mut self,
        closed: impl ExactSizeIterator<Item = (OffsetDateTime, u64)>,
    ) -> Result<(), Error> {
        if closed.len() > MAX_CLOSES {
            return Err(Error::new(
                "CEMS window exceeds 131072 independent close entries",
            ));
        }
        let mut values = BTreeMap::new();
        for (at, wh) in closed {
            let at = utc(at)?;
            if !at.aligned() || at < self.result.trace.start || at >= self.result.trace.end {
                return Err(Error::new(
                    "closed energy must use a quarter-hour start inside the window",
                ));
            }
            if values.insert(at, wh).is_some_and(|prior| prior != wh) {
                return Err(Error::new(
                    "conflicting independent closes at the same instant",
                ));
            }
        }
        self.result.trace.closed = values
            .into_iter()
            .map(|(at, wh)| MeterPoint { at, wh })
            .collect();
        Ok(())
    }

    /// Supply the independent closes for the meter bound at construction, then
    /// return its sorted trace, omission counts and first exclusion. An empty slice leaves all closes missing.
    /// Each pair is the UTC quarter start (or its offset equivalent) and interval energy
    /// in Wh. Accepts up to 131,072 entries including duplicates. Identical closes coalesce.
    /// The compact trace and its trailing newline must fit in 4 MiB.
    pub fn finish(mut self, closed: &[(OffsetDateTime, u64)]) -> Result<MeterProjection, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        self.set_closes(closed.iter().copied())?;
        self.complete()
    }

    fn complete(mut self) -> Result<MeterProjection, Error> {
        self.result.trace.register = self
            .observations
            .into_iter()
            .filter_map(|(at, evidence)| evidence.usable_wh.map(|wh| MeterPoint { at, wh }))
            .collect();
        compact_line_bytes(&self.result.trace)?;
        Ok(self.result)
    }
}

/// Project newline-delimited meter readings and a separate CEMS window with
/// independent `closed` energy. The window must identify the same device,
/// application URI and register node. Both inputs are limited to 4 MiB. Unusable
/// readings are counted and omitted. Incompatible scope or conflicting evidence
/// at an in-window source instant rejects the whole projection.
pub fn project_meter_trace(
    contract: &Contract,
    readings_ndjson: &[u8],
    window_json: &[u8],
) -> Result<MeterProjection, Error> {
    let signal = meter_signal(contract)?;
    if readings_ndjson.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::new("meter readings exceed 4 MiB"));
    }
    let window: Window = decode(window_json, "CEMS window")?;
    let binding = MeterWindow {
        device: &window.meter.device,
        application_uri: &window.meter.application_uri,
        node: &window.meter.node,
        start: window.start.0,
        end: window.end.0,
        tolerance_wh: window.tolerance_wh,
    };
    let mut projector = MeterProjector::bind(contract, signal, binding)?;
    projector.set_closes(
        window
            .closed
            .into_iter()
            .map(|JsonObject(point)| (point.at.0, point.wh)),
    )?;
    for (index, line) in readings_ndjson.split(|b| *b == b'\n').enumerate() {
        if line.iter().all(|b| matches!(b, b' ' | b'\t' | b'\r')) {
            continue;
        }
        // This replay is already bounded by the original physical byte count.
        decode(line, "meter reading")
            .and_then(|row| projector.ingest(&row, index + 1))
            .map_err(|err| err.at(&format!("readings line {}", index + 1)))?;
    }
    projector.complete()
}
