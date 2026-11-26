use std::{
    num::NonZeroU32,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use open62541::{
    AsyncSubscription, DataType, MonitoredItemCreateRequestBuilder, MonitoredItemHandle,
    SubscriptionBuilder,
};
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
        /// Original SDK error for the item.
        #[source]
        source: open62541::Error,
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
    /// The bounded callback-to-consumer queue filled. Create a fresh subscription.
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
    server: OnceLock<(usize, u32)>,
    closed: AtomicBool,
    value_limit: OnceLock<usize>,
}

impl Loss {
    fn check(&self) -> Result<(), SubscriptionError> {
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

    fn deliver(
        &self,
        tx: &mpsc::Sender<Option<DataChange>>,
        index: usize,
        value: DataValue<ua::Variant>,
    ) {
        if self.check().is_err() {
            return;
        }
        let status = value.status().map_or(0, DataType::into_raw);
        // StatusCode InfoType=DataValue (bits 10–11) and Overflow (bit 7).
        let message = if status & 0x0000_0c80 == 0x0000_0480 {
            let _ = self.server.set((index, status));
            None
        } else if value.value().is_some_and(|variant| {
            super::wire::variant_size(variant).is_none_or(|bytes| bytes > MAX_VALUE_BYTES)
        }) {
            let _ = self.value_limit.set(index);
            None
        } else {
            Some(DataChange { index, value })
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
    pub value: DataValue<ua::Variant>,
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
/// The callback does not expose Publish sequence numbers or Republish.
pub struct MonitoredDataChanges<'a> {
    client: &'a Client,
    receiver: mpsc::Receiver<Option<DataChange>>,
    pending: Option<DataChange>,
    loss: Arc<Loss>,
    ended: bool,
    items: Vec<MonitoredNode>,
    publishing: Duration,
    // Items must be dropped before their owning subscription.
    _handles: Vec<MonitoredItemHandle>,
    _subscription: AsyncSubscription,
    _permit: SemaphorePermit<'a>,
}

/// Single-node convenience handle returned by [`Client::subscribe`].
pub struct DataChanges<'a>(MonitoredDataChanges<'a>);

struct Callback {
    sender: mpsc::Sender<Option<DataChange>>,
    loss: Arc<Loss>,
    index: usize,
}

impl Callback {
    fn deliver(&self, value: DataValue<ua::Variant>) {
        self.loss.deliver(&self.sender, self.index, value);
    }
}

impl Drop for Callback {
    fn drop(&mut self) {
        // Removal of even one callback invalidates group coverage. Wake an idle consumer.
        self.loss.closed.store(true, Ordering::Release);
        let _ = self.sender.try_send(None);
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
        let builder = SubscriptionBuilder::default()
            .requested_publishing_interval(Some(interval))
            .requested_max_keep_alive_count(NonZeroU32::new(10))
            .requested_lifetime_count(60)
            .max_notifications_per_publish(NonZeroU32::new(CAPACITY as u32));
        let (reply, subscription) = self
            .guarded(&mut session, builder.create(&self.inner))
            .await?;
        let publishing = reply
            .revised_publishing_interval()
            .map_err(|_| SubscriptionError::InvalidRevision)?;
        if publishing.is_zero() || publishing > MAX_WAIT {
            return Err(SubscriptionError::InvalidRevision);
        }
        let request = MonitoredItemCreateRequestBuilder::new(wire_nodes)
            .sampling_interval(Some(interval))
            .queue_size(CAPACITY as u32)
            .discard_oldest(true);
        let (tx, receiver) = mpsc::channel(CAPACITY);
        let loss = Arc::new(Loss::default());
        let callback = |index| {
            let context = Callback {
                sender: tx.clone(),
                loss: Arc::clone(&loss),
                index,
            };
            move |value| context.deliver(value)
        };
        let results = self
            .guarded(
                &mut session,
                subscription.create_monitored_items_callback(request, callback),
            )
            .await?;
        // The backend can omit a Good item with a missing ID. Never associate
        // a subsequent result with the wrong node or expose a partial group.
        if results.len() != nodes.len() {
            return Err(SubscriptionError::InvalidRevision);
        }
        let mut items = Vec::with_capacity(nodes.len());
        let mut handles = Vec::with_capacity(nodes.len());
        for (index, (node, result)) in nodes.iter().zip(results).enumerate() {
            let (reply, handle) =
                result.map_err(|source| SubscriptionError::ItemRejected { index, source })?;
            let sampling_interval = reply
                .revised_sampling_interval()
                .map_err(|_| SubscriptionError::ItemRevision { index })?;
            let queue_size = reply.revised_queue_size();
            // A revised queue of one coalesces without setting the Overflow info bit.
            if sampling_interval.is_zero()
                || sampling_interval > MAX_WAIT
                || !(2..=CAPACITY as u32).contains(&queue_size)
            {
                return Err(SubscriptionError::ItemRevision { index });
            }
            items.push(MonitoredNode {
                node: node.clone(),
                sampling_interval,
                queue_size,
            });
            handles.push(handle);
        }
        Ok(MonitoredDataChanges {
            client: self,
            receiver,
            pending: None,
            loss,
            ended: false,
            items,
            publishing,
            _handles: handles,
            _subscription: subscription,
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
    pub async fn next(
        &mut self,
        wait: Duration,
    ) -> Result<DataValue<ua::Variant>, SubscriptionError> {
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
        if self.client.inner.state().connect_status != ua::StatusCode::GOOD {
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
    /// retryable. An overflow, invalidated session or closed callback terminates delivery.
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
        let bytes = |count| {
            let data = ua::ByteString::new(&vec![0x5a; count]);
            ua::DataValue::new(ua::Variant::scalar(data)).cast()
        };
        let (tx, mut rx) = mpsc::channel(1);
        let loss = Loss::default();
        loss.deliver(&tx, 0, bytes(MAX_VALUE_BYTES - 5));
        assert!(loss.check().is_ok());
        assert!(rx.try_recv().unwrap().is_some());
        loss.deliver(&tx, 0, bytes(MAX_VALUE_BYTES - 4));
        assert!(matches!(
            loss.check(),
            Err(SubscriptionError::ItemValueLimit { index: 0 })
        ));
        assert!(rx.try_recv().unwrap().is_none());
        let loss = Loss::default();
        loss.deliver(&tx, 0, bytes(0));
        loss.deliver(&tx, 0, bytes(0));
        assert!(matches!(
            loss.check(),
            Err(SubscriptionError::LocalOverflow)
        ));
    }

    #[test]
    fn removed_member_ends_the_group_while_another_sender_is_alive() {
        let (sender, mut rx) = mpsc::channel(2);
        let loss = Arc::new(Loss::default());
        let callback = Callback {
            sender: sender.clone(),
            index: 1,
            loss: Arc::clone(&loss),
        };
        drop(callback);
        assert!(rx.try_recv().unwrap().is_none());
        assert!(matches!(loss.check(), Err(SubscriptionError::Ended)));
        loss.deliver(&sender, 0, ua::DataValue::init().cast());
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn overflow_only_applies_to_the_data_value_info_type() {
        for (status, overflow) in [(0x80, false), (0x480, true), (0x4090_4480, true)] {
            let (tx, mut rx) = mpsc::channel(1);
            let loss = Loss::default();
            let raw = ua::DataValue::init().with_status(ua::StatusCode::raw_ref(&status));
            loss.deliver(&tx, 7, raw.cast());
            assert_eq!(
                matches!(loss.check(), Err(SubscriptionError::ItemOverflow { index: 7, status: code }) if code == status),
                overflow
            );
            assert_eq!(rx.try_recv().unwrap().is_none(), overflow);
        }
    }
}
