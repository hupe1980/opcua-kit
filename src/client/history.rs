//! Bounded forward raw history for one configured measurement.
mod wire;
use super::{Client, FixedScalar, ReadError, ReadSession, Sample};
use crate::NodeId;
use open62541::{DataType, ua};
use time::OffsetDateTime;
use wire::{Details, HistoryData, Response};

/// Historical values returned in server order, with the raw per-page operation statuses.
#[derive(Clone, Debug, PartialEq)]
pub struct HistoricalRead<T> {
    /// Samples as reported. Present source clocks are ordered and inside the requested window.
    pub samples: Vec<Sample<T>>,
    /// One OPC UA operation status per successful response page.
    pub page_statuses: Vec<u32>,
}

/// A raw history request could not be completed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HistoryError {
    /// Time or requested row count is outside the supported bounds.
    #[error("expected an increasing UTC window on 100 ns boundaries and a limit of 1–4096 samples")]
    Window,
    /// Service failure or stale session.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// The server returned a non-Good per-node history operation status.
    #[error("history operation status 0x{0:08X}")]
    Status(u32),
    /// Node result, continuation point or data shape is invalid.
    #[error("invalid HistoryRead response")]
    InvalidResponse,
    /// A returned source time fell outside the window or went backwards.
    #[error("historical source timestamp outside the requested window or out of order")]
    InvalidTimestamp,
    /// More pages or values would be needed than the configured bound.
    #[error("history exceeds sample or page limit")]
    Limit,
    /// The SDK could not allocate the service operand.
    #[error("could not allocate history request")]
    Allocation,
}

fn tick(time: OffsetDateTime) -> Result<i64, HistoryError> {
    super::sample::exact_datetime(time)
        .map(DataType::into_raw)
        .ok_or(HistoryError::Window)
}

fn result(response: &Response) -> Result<&open62541_sys::UA_HistoryReadResult, HistoryError> {
    // SAFETY: borrow one SDK-decoded per-node result for the lifetime of its response.
    let [r] = unsafe { super::wire::slice(response.0.results, response.0.resultsSize, 1) }
        .ok_or(HistoryError::InvalidResponse)?
    else {
        return Err(HistoryError::InvalidResponse);
    };
    Ok(r)
}

fn cursor(r: &open62541_sys::UA_HistoryReadResult) -> Result<&[u8], HistoryError> {
    let bytes = ua::ByteString::raw_ref(&r.continuationPoint)
        .as_bytes()
        .unwrap_or_default();
    if bytes.len() > 65536 {
        Err(HistoryError::InvalidResponse)
    } else {
        Ok(bytes)
    }
}

impl Client {
    async fn history_request(
        &self,
        session: &mut ReadSession,
        node: &ua::NodeId,
        details: &Details,
        point: &[u8],
        release: bool,
    ) -> Result<Response, HistoryError> {
        let req = wire::request(node, details, point, release).inspect_err(|_| {
            if !point.is_empty() {
                session.interrupted = true;
            }
        })?;
        Ok(self
            .guarded(session, self.inner.service_request(req))
            .await?)
    }

    /// Read raw historical Boolean or numeric values with both timestamps, without interpolation.
    /// The server must support raw HistoryRead for the chosen variable. Requests up to 256 values
    /// per page, 64 pages and 4096 total samples. A truncated interval returns an error.
    pub async fn read_history<T: FixedScalar>(
        &self,
        node: &NodeId,
        start: OffsetDateTime,
        end: OffsetDateTime,
        limit: usize,
    ) -> Result<HistoricalRead<T>, HistoryError> {
        let mut details = Details::init();
        details.0.startTime = tick(start)?;
        details.0.endTime = tick(end)?;
        if start >= end || !(1..=4096).contains(&limit) {
            return Err(HistoryError::Window);
        }
        details.0.numValuesPerNode = (limit + 1).min(256) as u32;
        let (mut session, metadata) = self.read_session().await?;
        let node = metadata.namespaces.wire_node(node, 0)?;
        let mut out = HistoricalRead {
            samples: Vec::new(),
            page_statuses: Vec::new(),
        };
        let mut point = Vec::new();
        let mut timestamps = SourceWindow {
            earliest: start.unix_timestamp_nanos() * 100,
            end: end.unix_timestamp_nanos() * 100,
        };
        loop {
            let response = self
                .history_request(&mut session, &node, &details, &point, false)
                .await?;
            let (r, next) = match result(&response).and_then(|r| Ok((r, cursor(r)?))) {
                Ok(data) => data,
                Err(err) => {
                    session.interrupted = true;
                    return Err(err);
                }
            };
            point.clear();
            point.extend_from_slice(next);
            let appended = append(
                &mut out,
                r,
                limit,
                details.0.numValuesPerNode as usize,
                &mut timestamps,
            );
            if let Err(err) = appended.and_then(|()| {
                if !point.is_empty()
                    && (out.samples.len() == limit || out.page_statuses.len() == 64)
                {
                    Err(HistoryError::Limit)
                } else {
                    Ok(())
                }
            }) {
                if !point.is_empty() {
                    let released = self
                        .history_request(&mut session, &node, &details, &point, true)
                        .await?;
                    // An unconfirmed release retires the session so its teardown frees the cursor.
                    if !result(&released)
                        .is_ok_and(|r| r.statusCode == 0 && cursor(r).is_ok_and(|p| p.is_empty()))
                    {
                        session.interrupted = true;
                        return Err(HistoryError::InvalidResponse);
                    }
                }
                return Err(err);
            }
            if point.is_empty() {
                return Ok(out);
            }
        }
    }
}

// Bounds in 10 ps units. Advancing the lower bound also orders samples across pages.
struct SourceWindow {
    earliest: i128,
    end: i128,
}
impl SourceWindow {
    fn accept(&mut self, clock: super::SampleTimestamp) -> Result<(), HistoryError> {
        let point =
            clock.base_unix_nanos * 100 + i128::from(clock.ten_picoseconds.unwrap_or(0).min(9999));
        if !(self.earliest..=self.end).contains(&point) {
            return Err(HistoryError::InvalidTimestamp);
        }
        self.earliest = point;
        Ok(())
    }
}
fn append<T: FixedScalar>(
    out: &mut HistoricalRead<T>,
    r: &open62541_sys::UA_HistoryReadResult,
    limit: usize,
    page_size: usize,
    timestamps: &mut SourceWindow,
) -> Result<(), HistoryError> {
    if r.statusCode >> 30 != 0 {
        return Err(HistoryError::Status(r.statusCode));
    }
    let data = ua::ExtensionObject::raw_ref(&r.historyData)
        .decoded_content::<HistoryData>()
        .ok_or(HistoryError::InvalidResponse)?;
    if data.0.dataValuesSize > limit - out.samples.len() {
        return Err(HistoryError::Limit);
    }
    // SAFETY: data borrows the SDK response, which remains alive until all elements are decoded.
    let values = unsafe { super::wire::slice(data.0.dataValues, data.0.dataValuesSize, page_size) }
        .ok_or(HistoryError::InvalidResponse)?;
    for v in values {
        let raw = ua::DataValue::raw_ref(v);
        if raw.source_timestamp().is_none() && raw.server_timestamp().is_none() {
            return Err(HistoryError::InvalidResponse);
        }
        let sample = super::sample::decode_borrowed(raw, T::decode)?;
        if let Some(source) = sample.source_timestamp {
            timestamps.accept(source)?;
        }
        out.samples.push(sample);
    }
    out.page_statuses.push(r.statusCode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_windows_require_exact_non_sentinel_timestamps() {
        let utc = OffsetDateTime::from_unix_timestamp_nanos;
        for value in [
            1,
            99,
            -11_644_473_600_000_000_000,
            253_402_300_799_000_000_000,
        ] {
            assert!(tick(utc(value).unwrap()).is_err());
        }
        assert!(tick(utc(100).unwrap()).is_ok());
        assert!(tick(utc(253_402_300_798_999_999_900).unwrap()).is_ok());
    }
}
