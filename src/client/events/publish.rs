//! One outstanding Publish on a dedicated session, with bounded in-order same-session recovery.
use super::{EventError, MAX_WAIT, wire};
use crate::client::{Client, ReadError, SubscriptionError, ua, wire::slice};
use open62541::DataType;
use open62541_sys::UA_NotificationMessage;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::task::JoinHandle;

/// One observation with the sequence number of its enclosing OPC UA NotificationMessage.
#[derive(Debug)]
pub struct Sequenced<T> {
    /// Sequence numbers are nonzero and wrap from u32::MAX to 1. A message may contain multiple observations.
    pub sequence: u32,
    /// True when this observation came from a retained message recovered with Republish.
    pub republished: bool,
    /// Ordered event fields or one indexed data change.
    pub value: T,
}

const MAX_MISSING: usize = 8;
const MAX_ROUND_BYTES: usize = 4 * 1024 * 1024;

pub(super) type Decode<T> =
    fn(&ua::ExtensionObject, usize, &mut usize, &mut Vec<T>) -> Result<(), EventError>;
struct Round<T> {
    expected: u32,
    acks: Vec<u32>,
    values: VecDeque<Sequenced<T>>,
}

pub(super) struct Stream<T: Send + 'static> {
    runtime: tokio::runtime::Handle,
    pub(super) client: Option<Arc<Client>>,
    pub(super) subscription: u32,
    pub(super) ended: bool,
    timeout: u32,
    count: usize,
    decode: Decode<T>,
    request: Option<JoinHandle<Result<Round<T>, EventError>>>,
    pending: VecDeque<Sequenced<T>>,
}

impl<T: Send + 'static> Stream<T> {
    pub(super) fn new(
        client: Client,
        subscription: u32,
        timeout: u32,
        count: usize,
        decode: Decode<T>,
    ) -> Self {
        let mut stream = Self {
            runtime: tokio::runtime::Handle::current(),
            client: Some(Arc::new(client)),
            subscription,
            ended: false,
            timeout,
            count,
            decode,
            request: None,
            pending: VecDeque::new(),
        };
        stream.start(1, Vec::new());
        stream
    }
    fn start(&mut self, expected: u32, acks: Vec<u32>) {
        self.request = Some(tokio::spawn(round(
            Arc::clone(self.client.as_ref().expect("active session")),
            self.subscription,
            self.timeout,
            self.count,
            self.decode,
            expected,
            acks,
        )));
    }
    async fn receive(&mut self) -> Result<Sequenced<T>, EventError> {
        loop {
            if !self.pending.is_empty() {
                // A control operation on an event session can retire the session while these
                // observations are buffered. Keep the item until its session is checked.
                let client = self.client.as_ref().expect("active session");
                let _session = client.read_session().await?;
                return Ok(self.pending.pop_front().expect("buffer is nonempty"));
            }
            let response = self.request.as_mut().expect("pending Publish").await;
            self.request = None;
            let response = response.map_err(|_| SubscriptionError::Ended)??;
            self.pending = response.values;
            self.start(response.expected, response.acks);
        }
    }
    pub(super) async fn next(&mut self, wait: Duration) -> Result<Sequenced<T>, EventError> {
        if self.ended {
            return Err(SubscriptionError::Ended.into());
        }
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(SubscriptionError::InvalidWait.into());
        }
        match tokio::time::timeout(wait, self.receive()).await {
            Err(_) => Err(SubscriptionError::Timeout.into()),
            Ok(result) => {
                self.ended = result.is_err();
                result
            }
        }
    }
    pub(super) async fn disconnect(mut self) {
        if let Some(client) = self.client.take() {
            close(client, self.request.take()).await;
        }
    }
}
async fn close<T>(client: Arc<Client>, task: Option<JoinHandle<Result<Round<T>, EventError>>>) {
    if let Some(task) = task {
        task.abort();
        let _ = task.await;
    }
    if let Ok(client) = Arc::try_unwrap(client) {
        client.disconnect().await;
    }
}
impl<T: Send + 'static> Drop for Stream<T> {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            // Closing the authenticated session also deletes its server subscription. Keep the
            // SDK alive until the outstanding service future releases its last Arc.
            self.runtime.spawn(close(client, self.request.take()));
        }
    }
}

fn successor(sequence: u32) -> u32 {
    sequence.wrapping_add(1).max(1)
}
fn missing(expected: u32, actual: u32, available: &[u32]) -> Result<Vec<u32>, EventError> {
    let mut result = Vec::new();
    let mut n = expected;
    while n != actual {
        if actual == 0 || result.len() >= MAX_MISSING || !available.contains(&n) {
            return Err(EventError::SequenceGap {
                expected: n,
                actual,
            });
        }
        result.push(n);
        n = successor(n);
    }
    Ok(result)
}

async fn round<T: Send>(
    client: Arc<Client>,
    sub: u32,
    timeout: u32,
    count: usize,
    decode: Decode<T>,
    expected: u32,
    previous: Vec<u32>,
) -> Result<Round<T>, EventError> {
    drop(client.read_session().await?);
    let request = wire::publish(sub, &previous, timeout).ok_or(EventError::InvalidNotification)?;
    // Publish carries only this dedicated subscription ID. Leave the session lock free while
    // waiting so ConditionRefresh can run on the same authenticated session. Check retirement
    // on both sides of the wait and retire the session on an unconfirmed service failure.
    let response = client.inner.service_request(request).await;
    let mut session = client.reads.lock().await;
    client.check_channel()?;
    if session.interrupted {
        return Err(ReadError::SessionInterrupted.into());
    }
    let reply = response.map_err(|e| {
        session.interrupted = true;
        ReadError::Service(e)
    })?;
    if reply.0.subscriptionId != sub || reply.0.resultsSize != previous.len() {
        return Err(EventError::InvalidNotification);
    }
    // SAFETY: the SDK owns the decoded arrays through this response.
    let statuses = unsafe { slice(reply.0.results, reply.0.resultsSize, MAX_MISSING + 1) }
        .ok_or(EventError::InvalidNotification)?;
    if let Some(&status) = statuses.iter().find(|s| **s >> 30 != 0) {
        return Err(EventError::Status(status));
    }
    let available = unsafe {
        slice(
            reply.0.availableSequenceNumbers,
            reply.0.availableSequenceNumbersSize,
            4096,
        )
    }
    .ok_or(EventError::InvalidNotification)?;
    let actual = reply.0.notificationMessage.sequenceNumber;
    let needed = missing(expected, actual, available)?;
    let ack_current =
        available.contains(&actual) && reply.0.notificationMessage.notificationDataSize > 0;
    let mut budget = MAX_ROUND_BYTES;
    let live = message(
        &reply.0.notificationMessage,
        count,
        decode,
        false,
        &mut budget,
    )?;
    let next = if live.is_empty() {
        actual
    } else {
        successor(actual)
    };
    drop(reply);
    let mut values = VecDeque::new();
    let mut acks = Vec::with_capacity(needed.len() + 1);
    for seq in needed {
        let mut request = wire::Republish::init();
        request.0.subscriptionId = sub;
        request.0.retransmitSequenceNumber = seq;
        let reply = client
            .guarded(&mut session, client.inner.service_request(request))
            .await
            .map_err(|err| match &err {
                ReadError::Service(error)
                    if [
                        ua::StatusCode::BADMESSAGENOTAVAILABLE,
                        ua::StatusCode::BADSEQUENCENUMBERUNKNOWN,
                    ]
                    .contains(&error.status_code()) =>
                {
                    EventError::SequenceGap {
                        expected: seq,
                        actual,
                    }
                }
                _ => err.into(),
            })?;
        if reply.0.notificationMessage.sequenceNumber != seq
            || reply.0.notificationMessage.notificationDataSize == 0
        {
            return Err(EventError::SequenceGap {
                expected: seq,
                actual,
            });
        }
        values.extend(message(
            &reply.0.notificationMessage,
            count,
            decode,
            true,
            &mut budget,
        )?);
        acks.push(seq);
    }
    values.extend(live);
    if ack_current {
        acks.push(actual)
    }
    Ok(Round {
        expected: next,
        acks,
        values,
    })
}

fn message<T>(
    m: &UA_NotificationMessage,
    count: usize,
    decode: Decode<T>,
    republished: bool,
    budget: &mut usize,
) -> Result<Vec<Sequenced<T>>, EventError> {
    let notes = unsafe { slice(m.notificationData, m.notificationDataSize, 32) }
        .ok_or(EventError::InvalidNotification)?;
    let mut values = Vec::new();
    for note in notes {
        let note = ua::ExtensionObject::raw_ref(note);
        if let Some(status) = note.decoded_content::<wire::StatusChange>() {
            return Err(EventError::Status(status.0.status));
        }
        decode(note, count, budget, &mut values)?;
    }
    if !notes.is_empty() && values.is_empty() {
        return Err(EventError::InvalidNotification);
    }
    Ok(values
        .into_iter()
        .map(|value| Sequenced {
            sequence: m.sequenceNumber,
            republished,
            value,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_retention_checked_across_wrap_and_keepalive() {
        assert!(missing(45, 45, &[]).unwrap().is_empty());
        assert_eq!(missing(u32::MAX, 2, &[1, u32::MAX]).unwrap(), [u32::MAX, 1]);
        assert_eq!(missing(1, 9, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap().len(), 8);
        assert!(missing(1, 10, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).is_err());
        assert!(matches!(
            missing(4, 7, &[4, 6, 7]),
            Err(EventError::SequenceGap {
                expected: 5,
                actual: 7
            })
        ));
        assert!(missing(3, 2, &[2]).is_err());
        assert!(missing(1, 0, &[]).is_err());
    }
}
