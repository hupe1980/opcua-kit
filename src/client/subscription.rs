use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use super::events::wire;
use tokio::sync::{SemaphorePermit, mpsc};

use super::{Client, DataValue, ReadError, ua};
use crate::NodeId;

/// Maximum number of requested Value attributes in one subscription.
pub const MAX_MONITORED_NODES: usize = 32;
const CAPACITY: usize = 32;
const MAX_VALUE_BYTES: usize = 128 * 1024;
const MIN_INTERVAL: Duration = Duration::from_millis(10);
const MAX_WAIT: Duration = Duration::from_secs(60);

/// Setup or reception of an authenticated sampled Value notification failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubscriptionError {
    /// Transport, namespace, or original pinned session is unavailable.
    #[error(transparent)]
    Session(#[from] ReadError),
    /// Requested sample/publish interval is outside 10 milliseconds to 60 seconds.
    #[error("subscription interval must be between 10 milliseconds and 60 seconds")]
    InvalidInterval,
    /// Wait must be positive and at most one minute.
    #[error("notification wait must be positive and at most 60 seconds")]
    InvalidWait,
    /// One subscription takes between one and 32 nodes.
    #[error("a subscription requires 1 to {MAX_MONITORED_NODES} nodes")]
    ItemCount,
    /// The peer rejected an individual monitored item during setup.
    #[error("monitored item {index} was rejected: {source}")]
    ItemRejected {
        /// Zero-based position in the supplied list.
        index: usize,
        /// Original OPC UA status for the item.
        #[source]
        source: ua::StatusCode,
    },
    /// Eight active subscriptions already exist on this client.
    #[error("client already has eight active subscriptions")]
    Limit,
    /// Server did not supply usable revised intervals and a queue of 2–32 entries.
    #[error("unusable revised subscription or monitored item parameters")]
    InvalidRevision,
    /// The peer supplied an unusable sampling interval or queue for this member.
    #[error("unusable revised parameters for monitored item {index}")]
    ItemRevision {
        /// Zero-based position in the supplied list.
        index: usize,
    },
    /// The bounded notification queue filled. Create a fresh subscription.
    #[error("local notification buffer overflowed; resynchronize the value")]
    LocalOverflow,
    /// A notification's Variant exceeded 128 KiB of UA binary data or could not be measured.
    #[error(
        "notification Variant exceeds the supported 128 KiB limit or has no valid binary encoding"
    )]
    ValueLimit,
    /// A group member's Variant exceeded the supported binary size or could not be measured.
    #[error("notification for item {index} exceeds 128 KiB or has no valid binary encoding")]
    ItemValueLimit {
        /// Zero-based position in the supplied list.
        index: usize,
    },
    /// The peer indicated its monitored item queue overflowed; includes the full raw status.
    #[error("server notification queue overflowed (status 0x{0:08X}); resynchronize the value")]
    ServerOverflow(u32),
    /// A group member reported its server-side queue overflow.
    #[error(
        "server queue overflowed for item {index} (status 0x{status:08X}); resynchronize the group"
    )]
    ItemOverflow {
        /// Zero-based position in the supplied list.
        index: usize,
        /// Full OPC UA StatusCode.
        status: u32,
    },
    /// A Publish response skipped or repeated a sequence number.
    #[error("data-change sequence gap: expected {expected}, got {actual}")]
    SequenceGap {
        /// Next sequence expected on this subscription.
        expected: u32,
        /// Sequence returned by the server.
        actual: u32,
    },
    /// No notification arrived within this caller-selected wait. The handle remains usable.
    #[error("timed out waiting for a data change")]
    Timeout,
    /// The monitored item or client stopped delivering, or a terminal error was already reported.
    #[error("data-change subscription ended; resynchronize on a fresh session")]
    Ended,
}

#[derive(Default)]
struct Loss {
    local: AtomicBool,
    gap: OnceLock<(u32, u32)>,
    server: OnceLock<(usize, u32)>,
    closed: AtomicBool,
    value_limit: OnceLock<usize>,
}

impl Loss {
    fn check(&self) -> Result<(), SubscriptionError> {
        if let Some(&(expected, actual)) = self.gap.get() {
            return Err(SubscriptionError::SequenceGap { expected, actual });
        }
        if let Some(&(index, status)) = self.server.get() {
            return Err(SubscriptionError::ItemOverflow { index, status });
        }
        if let Some(&index) = self.value_limit.get() {
            return Err(SubscriptionError::ItemValueLimit { index });
        }
        if self.local.load(Ordering::Acquire) {
            return Err(SubscriptionError::LocalOverflow);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(SubscriptionError::Ended);
        }
        Ok(())
    }

    fn deliver(&self, tx: &mpsc::Sender<Option<DataChange>>, index: usize, value: &DataValue) {
        if self.check().is_err() {
            return;
        }
        let status = value.status.unwrap_or_default().bits();
        // StatusCode InfoType=DataValue (bits 10–11) and Overflow (bit 7).
        let message = if status & 0x0000_0c80 == 0x0000_0480 {
            let _ = self.server.set((index, status));
            None
        } else if value.value.as_ref().is_some_and(|variant| {
            super::wire::variant_size(variant).is_none_or(|bytes| bytes > MAX_VALUE_BYTES)
        }) {
            let _ = self.value_limit.set(index);
            None
        } else {
            Some(DataChange {
                index,
                value: value.clone(),
            })
        };
        if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(message) {
            self.local.store(true, Ordering::Release);
        }
    }
}

/// Source position and unmodified OPC UA DataValue for one notification.
#[derive(Debug)]
pub struct DataChange {
    /// Index into [`MonitoredDataChanges::items`] in the original request order.
    pub index: usize,
    /// Original status, clocks and Variant emitted by the peer.
    pub value: DataValue,
}

/// Stable identity and revised monitoring parameters for one group member.
#[derive(Debug)]
pub struct MonitoredNode {
    /// Namespace URI and identifier supplied by the application.
    pub node: NodeId,
    /// Server-revised sampling interval.
    pub sampling_interval: Duration,
    /// Server-revised monitored item queue capacity.
    pub queue_size: u32,
}

/// One OPC UA subscription monitoring multiple Value attributes on the original session.
/// Drop requests deletion of all items and the subscription. A loss on any item ends the group.
/// Use a dedicated sequenced stream when you need retransmission or per-message provenance.
pub struct MonitoredDataChanges<'a> {
    client: &'a Client,
    receiver: mpsc::Receiver<Option<DataChange>>,
    pending: Option<DataChange>,
    loss: Arc<Loss>,
    ended: bool,
    items: Vec<MonitoredNode>,
    publishing: Duration,
    _registration: Registration,
    _permit: SemaphorePermit<'a>,
}

/// Single-node convenience handle returned by [`Client::subscribe`].
pub struct DataChanges<'a>(MonitoredDataChanges<'a>);

/// Publish responses can carry notifications for any subscription on the session.
#[derive(Clone, Default)]
pub(super) struct PublishGroups(Arc<Mutex<GroupState>>);

#[derive(Default)]
struct GroupState {
    routes: BTreeMap<u32, Route>,
    running: bool,
    changes: u64,
}

struct Route {
    sender: mpsc::Sender<Option<DataChange>>,
    loss: Arc<Loss>,
    count: usize,
    expected: u32,
    timeout_ms: u32,
}

impl Route {
    fn end(&self) {
        self.loss.closed.store(true, Ordering::Release);
        let _ = self.sender.try_send(None);
    }

    fn receive(&mut self, message: &ua::NotificationMessage) {
        let notes = message.notification_data.as_deref().unwrap_or_default();
        if self.expected != message.sequence_number {
            let _ = self.loss.gap.set((self.expected, message.sequence_number));
            self.end();
            return;
        }
        if notes.is_empty() {
            return;
        }
        self.expected = self.expected.wrapping_add(1).max(1);
        let mut changes = Vec::new();
        if notes.len() > CAPACITY {
            self.end();
            return;
        }
        for note in notes {
            let Some(data) = note.inner_as::<ua::DataChangeNotification>() else {
                self.end();
                return;
            };
            let items = data.monitored_items.as_deref().unwrap_or_default();
            if items.is_empty() || items.len() > CAPACITY - changes.len() {
                self.end();
                return;
            }
            for item in items {
                let Some(index) = item
                    .client_handle
                    .checked_sub(1)
                    .map(|n| n as usize)
                    .filter(|&n| n < self.count)
                else {
                    self.end();
                    return;
                };
                changes.push((index, &item.value));
            }
        }
        for (index, data) in changes {
            self.loss.deliver(&self.sender, index, data);
        }
    }
}

struct Registration {
    groups: PublishGroups,
    id: u32,
    session: Arc<super::connection::Session>,
    runtime: tokio::runtime::Handle,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut state = self.groups.0.lock().expect("publish routes");
        state.routes.remove(&self.id);
        state.changes = state.changes.wrapping_add(1);
        drop(state);
        let session = self.session.clone();
        let id = self.id;
        self.runtime.spawn(async move {
            let _ = session
                .request(ua::DeleteSubscriptionsRequest {
                    subscription_ids: Some(vec![id]),
                    ..Default::default()
                })
                .await;
        });
    }
}

impl GroupState {
    fn stop(&mut self) {
        for route in self.routes.values() {
            route.end();
        }
        self.running = false;
    }
}

impl PublishGroups {
    fn register(
        &self,
        session: &Arc<super::connection::Session>,
        id: u32,
        route: Route,
    ) -> Result<Registration, SubscriptionError> {
        let mut state = self.0.lock().expect("publish routes");
        if state.routes.contains_key(&id) {
            return Err(SubscriptionError::InvalidRevision);
        }
        state.routes.insert(id, route);
        state.changes = state.changes.wrapping_add(1);
        if !state.running {
            state.running = true;
            tokio::spawn(self.clone().run(session.clone()));
        }
        Ok(Registration {
            groups: self.clone(),
            id,
            session: session.clone(),
            runtime: tokio::runtime::Handle::current(),
        })
    }

    async fn run(self, session: Arc<super::connection::Session>) {
        let mut ack = None;
        loop {
            let (timeout, changes) = {
                let mut state = self.0.lock().expect("publish routes");
                let Some(timeout) = state.routes.values().map(|r| r.timeout_ms).max() else {
                    state.running = false;
                    return;
                };
                (timeout, state.changes)
            };
            let sent: Option<ua::SubscriptionAcknowledgement> = ack.take();
            let req = wire::publish(sent.iter().cloned().collect(), timeout);
            let result = session.request(req).await;
            let mut state = self.0.lock().expect("publish routes");
            match result {
                Ok(reply) => {
                    let statuses = reply.results.as_deref().unwrap_or_default();
                    if statuses.len() != usize::from(sent.is_some()) {
                        state.stop();
                        return;
                    }
                    if let Some(ack) = sent
                        && !statuses[0].is_good()
                        && let Some(route) = state.routes.get(&ack.subscription_id)
                    {
                        route.end();
                    }
                    if let Some(route) = state.routes.get_mut(&reply.subscription_id) {
                        let seq = reply.notification_message.sequence_number;
                        let available = reply
                            .available_sequence_numbers
                            .as_deref()
                            .unwrap_or_default();
                        if available.len() > 4096 {
                            route.end();
                            continue;
                        }
                        route.receive(&reply.notification_message);
                        if reply
                            .notification_message
                            .notification_data
                            .as_ref()
                            .is_some_and(|n| !n.is_empty())
                            && available.contains(&seq)
                        {
                            ack = Some(ua::SubscriptionAcknowledgement {
                                subscription_id: reply.subscription_id,
                                sequence_number: seq,
                            });
                        }
                    }
                }
                Err(ua::StatusCode::BadNoSubscription) if changes != state.changes => continue,
                Err(_) => {
                    state.stop();
                    return;
                }
            }
        }
    }
}

impl Client {
    /// Subscribe to sampled data changes for one selected Value. The supplied interval
    /// applies to sampling and publishing (10 ms to 60 s); inspect the revised intervals
    /// on the returned handle. Up to eight handles can be active per client.
    pub async fn subscribe(
        &self,
        node: &NodeId,
        interval: Duration,
    ) -> Result<DataChanges<'_>, SubscriptionError> {
        self.subscribe_many(std::slice::from_ref(node), interval)
            .await
            .map(DataChanges)
            .map_err(|error| match error {
                SubscriptionError::ItemRejected { source, .. } => ReadError::Service(source).into(),
                SubscriptionError::ItemRevision { .. } => SubscriptionError::InvalidRevision,
                other => other,
            })
    }

    /// Monitor 1–32 nodes in one subscription. Each result refers to the corresponding
    /// input index, including repeated nodes. All namespaces are resolved before creation.
    /// An item rejection fails the entire setup and releases any accepted siblings.
    /// A timeout leaves the subscription usable. After a terminal loss, resynchronize all
    /// values and create a fresh subscription. The shared local queue holds 32 notifications.
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use opcua_kit::{Client, NodeId, SubscriptionError};
    /// # async fn observe(client: &Client, pressure: NodeId, fan: NodeId) -> Result<(), SubscriptionError> {
    /// let mut changes = client.subscribe_many(&[pressure, fan], Duration::from_millis(250)).await?;
    /// let change = changes.next(Duration::from_secs(5)).await?;
    /// let source = &changes.items()[change.index].node;
    /// println!("{}: {:?}", source.identifier(), change.value);
    /// # Ok(()) }
    /// ```
    pub async fn subscribe_many(
        &self,
        nodes: &[NodeId],
        interval: Duration,
    ) -> Result<MonitoredDataChanges<'_>, SubscriptionError> {
        if !(1..=MAX_MONITORED_NODES).contains(&nodes.len()) {
            return Err(SubscriptionError::ItemCount);
        }
        if !(MIN_INTERVAL..=MAX_WAIT).contains(&interval) {
            return Err(SubscriptionError::InvalidInterval);
        }
        let permit = self
            .subscriptions
            .try_acquire()
            .map_err(|_| SubscriptionError::Limit)?;
        let (mut session, metadata) = self.read_session().await?;
        let wire_nodes = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| metadata.namespaces.wire_node(node, index))
            .collect::<Result<Vec<_>, _>>()?;
        let sub = wire::create_subscription(self, &mut session, interval).await?;
        let (sender, receiver) = mpsc::channel(CAPACITY);
        let loss = Arc::new(Loss::default());
        let registration = self.publish_groups.register(
            &self.inner,
            sub.id,
            Route {
                sender,
                loss: loss.clone(),
                expected: 1,
                count: nodes.len(),
                timeout_ms: sub.timeout_ms,
            },
        )?;
        let requests = wire_nodes
            .into_iter()
            .enumerate()
            .map(|(i, node)| wire::item(node, 13, (i + 1) as u32, interval, Default::default()))
            .collect();
        let results = wire::create_items(self, &mut session, sub.id, requests).await?;
        let items = match wire::revisions(nodes, &results) {
            Ok(items) => items,
            Err(error) => {
                let accepted: Vec<_> = results
                    .iter()
                    .filter(|r| r.status_code.is_good() && r.monitored_item_id != 0)
                    .map(|r| r.monitored_item_id)
                    .collect();
                if !accepted.is_empty() {
                    let cleanup = ua::DeleteMonitoredItemsRequest {
                        subscription_id: sub.id,
                        monitored_item_ids: Some(accepted),
                        ..Default::default()
                    };
                    let _ = self
                        .guarded(&mut session, self.inner.request(cleanup))
                        .await;
                }
                return Err(error);
            }
        };
        Ok(MonitoredDataChanges {
            client: self,
            receiver,
            pending: None,
            loss,
            ended: false,
            items,
            publishing: sub.interval,
            _registration: registration,
            _permit: permit,
        })
    }
}

impl DataChanges<'_> {
    /// Revised interval at which the server samples the variable.
    pub const fn sampling_interval(&self) -> Duration {
        self.0.items.as_slice()[0].sampling_interval
    }
    /// Revised interval at which the server checks for publishable notifications.
    pub const fn publishing_interval(&self) -> Duration {
        self.0.publishing_interval()
    }
    /// Revised monitored item queue size at the peer.
    pub const fn server_queue_size(&self) -> u32 {
        self.0.items.as_slice()[0].queue_size
    }

    /// Wait for one DataValue. A timeout is retryable, and cancellation preserves a dequeued value.
    pub async fn next(&mut self, wait: Duration) -> Result<DataValue, SubscriptionError> {
        match self.0.next(wait).await {
            Ok(change) => Ok(change.value),
            Err(SubscriptionError::ItemValueLimit { .. }) => Err(SubscriptionError::ValueLimit),
            Err(SubscriptionError::ItemOverflow { status, .. }) => {
                Err(SubscriptionError::ServerOverflow(status))
            }
            Err(other) => Err(other),
        }
    }
}

impl MonitoredDataChanges<'_> {
    /// Monitored identities and revised parameters in original input order.
    pub fn items(&self) -> &[MonitoredNode] {
        &self.items
    }
    /// Revised interval shared by this subscription.
    pub const fn publishing_interval(&self) -> Duration {
        self.publishing
    }

    fn healthy(&self) -> Result<(), SubscriptionError> {
        self.client.check_channel()?;
        if !self.client.inner.is_alive() {
            return Err(SubscriptionError::Ended);
        }
        if self
            .client
            .reads
            .try_lock()
            .is_ok_and(|session| session.interrupted)
        {
            return Err(ReadError::SessionInterrupted.into());
        }
        self.loss.check()
    }

    async fn receive(&mut self) -> Result<DataChange, SubscriptionError> {
        self.healthy()?;
        if self.pending.is_none() {
            self.pending = self.receiver.recv().await.ok_or(SubscriptionError::Ended)?;
            self.loss.check()?;
        }
        // Keep the dequeued value in self across this await; cancelling next cannot
        // silently consume a value. Serialize delivery with retiring a service session.
        let guard = self.client.reads.lock().await;
        if guard.interrupted {
            return Err(ReadError::SessionInterrupted.into());
        }
        self.healthy()?;
        Ok(self.pending.take().expect("received notification"))
    }

    /// Wait for one indexed DataValue, including its status and original clocks. A timeout is
    /// retryable. An overflow, invalidated session or closed subscription terminates delivery.
    /// A cancelled wait retains any notification dequeued before cancellation.
    pub async fn next(&mut self, wait: Duration) -> Result<DataChange, SubscriptionError> {
        if self.ended {
            return Err(SubscriptionError::Ended);
        }
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(SubscriptionError::InvalidWait);
        }
        let result = match tokio::time::timeout(wait, self.receive()).await {
            Ok(result) => result,
            Err(_) => match self.healthy() {
                Ok(()) => return Err(SubscriptionError::Timeout),
                Err(error) => Err(error),
            },
        };
        if result.is_err() {
            self.ended = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_and_binary_size_bounds_report_loss_without_delivering_an_oversized_payload() {
        let bytes = |count| ua::DataValue::from(ua::Variant::ByteString(vec![0x5a; count].into()));
        let (tx, mut rx) = mpsc::channel(1);
        let loss = Loss::default();
        loss.deliver(&tx, 0, &bytes(MAX_VALUE_BYTES - 5));
        assert!(loss.check().is_ok());
        assert!(rx.try_recv().unwrap().is_some());
        loss.deliver(&tx, 0, &bytes(MAX_VALUE_BYTES - 4));
        assert!(matches!(
            loss.check(),
            Err(SubscriptionError::ItemValueLimit { index: 0 })
        ));
        assert!(rx.try_recv().unwrap().is_none());
        let loss = Loss::default();
        loss.deliver(&tx, 0, &bytes(0));
        loss.deliver(&tx, 0, &bytes(0));
        assert!(matches!(
            loss.check(),
            Err(SubscriptionError::LocalOverflow)
        ));
    }

    #[test]
    fn removed_member_ends_the_group_while_another_sender_is_alive() {
        let (sender, mut rx) = mpsc::channel(2);
        let loss = Arc::new(Loss::default());
        let route = Route {
            sender: sender.clone(),
            loss: loss.clone(),
            count: 2,
            expected: 1,
            timeout_ms: 1000,
        };
        route.end();
        assert!(rx.try_recv().unwrap().is_none());
        assert!(matches!(loss.check(), Err(SubscriptionError::Ended)));
        loss.deliver(&sender, 0, &ua::DataValue::default());
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn keepalive_and_notifications_advance_only_their_subscription_sequence() {
        let (sender, mut rx) = mpsc::channel(2);
        let loss = Arc::new(Loss::default());
        let mut route = Route {
            sender,
            loss: loss.clone(),
            count: 2,
            expected: u32::MAX,
            timeout_ms: 1000,
        };
        let mut message = ua::NotificationMessage {
            sequence_number: u32::MAX,
            ..Default::default()
        };
        route.receive(&message);
        assert_eq!(route.expected, u32::MAX);
        assert!(rx.try_recv().is_err());
        message.notification_data =
            Some(vec![ua::ExtensionObject::new(ua::DataChangeNotification {
                monitored_items: Some(vec![ua::MonitoredItemNotification {
                    client_handle: 2,
                    value: ua::DataValue::from(17u32),
                }]),
                ..Default::default()
            })]);
        route.receive(&message);
        let change = rx.try_recv().unwrap().unwrap();
        assert_eq!(change.index, 1);
        assert_eq!(change.value.value, Some(ua::Variant::UInt32(17)));
        assert_eq!(route.expected, 1);
        route.receive(&message);
        assert!(matches!(
            loss.check(),
            Err(SubscriptionError::SequenceGap {
                expected: 1,
                actual: u32::MAX
            })
        ));
        assert!(rx.try_recv().unwrap().is_none());
    }

    #[test]
    fn overflow_only_applies_to_the_data_value_info_type() {
        for (status, overflow) in [(0x80, false), (0x480, true), (0x4090_4480, true)] {
            let (tx, mut rx) = mpsc::channel(1);
            let loss = Loss::default();
            let raw = ua::DataValue {
                status: Some(ua::StatusCode::from(status)),
                ..Default::default()
            };
            loss.deliver(&tx, 7, &raw);
            assert_eq!(
                matches!(loss.check(), Err(SubscriptionError::ItemOverflow { index: 7, status: code }) if code == status),
                overflow
            );
            assert_eq!(rx.try_recv().unwrap().is_none(), overflow);
        }
    }
}
