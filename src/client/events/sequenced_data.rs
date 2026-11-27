//! Dedicated multi-node data-change subscription with same-session retransmission.
use super::{MAX_WAIT, PublishError, Sequenced, publish, wire};
use crate::client::{ua, wire::variant_size};
use crate::{
    CertificateRollover, Client, ConnectionConfig, ConnectionOptions, DataChange, MonitoredNode,
    NodeId, RecoveringClient, SubscriptionError,
};
use std::time::Duration;

/// One dedicated, pinned session for changes from 1–32 ordered variables. This owner
/// explicitly manages Publish and Republish. Each arrival includes its original message
/// sequence, source index, DataValue, clocks and retransmission provenance.
///
/// ```
/// use opcua_kit::{Sample, SequencedDataChanges};
/// use std::time::Duration;
///
/// async fn poll(stream: &mut SequencedDataChanges) -> Result<(), Box<dyn std::error::Error>> {
///     let update = stream.next(Duration::from_secs(2)).await?;
///     let node = &stream.items()[update.value.index].node;
///     let sample = Sample::<u64>::from_raw(&update.value.value)?;
///     println!("{} sequence={} value={:?}", node.identifier(), update.sequence, sample.value);
///     Ok(())
/// }
/// ```
pub struct SequencedDataChanges {
    stream: publish::Stream<DataChange>,
    items: Vec<MonitoredNode>,
}
impl SequencedDataChanges {
    /// Open a stream with one server monitored item per supplied stable node.
    pub async fn connect(
        config: ConnectionConfig<'_>,
        options: ConnectionOptions<'_>,
        nodes: &[NodeId],
        interval: Duration,
    ) -> Result<Self, PublishError> {
        Self::open(RecoveringClient::new(config, options), nodes, interval).await
    }
    /// Apply the same reviewed successor certificate policy as the ordinary client.
    pub async fn connect_with_rollover(
        config: ConnectionConfig<'_>,
        options: ConnectionOptions<'_>,
        rollover: CertificateRollover<'_>,
        nodes: &[NodeId],
        interval: Duration,
    ) -> Result<Self, PublishError> {
        Self::open(
            RecoveringClient::new_with_rollover(config, options, rollover),
            nodes,
            interval,
        )
        .await
    }
    async fn open(
        owner: RecoveringClient<'_>,
        nodes: &[NodeId],
        interval: Duration,
    ) -> Result<Self, PublishError> {
        if !(1..=32).contains(&nodes.len()) {
            return Err(SubscriptionError::ItemCount.into());
        }
        if !(Duration::from_millis(10)..=MAX_WAIT).contains(&interval) {
            return Err(SubscriptionError::InvalidInterval.into());
        }
        let client = owner.into_client().await?;
        let (sub, timeout, items) = match setup(&client, nodes, interval).await {
            Ok(v) => v,
            Err(e) => {
                client.disconnect().await;
                return Err(e);
            }
        };
        Ok(Self {
            stream: publish::Stream::new(client, sub, timeout, nodes.len(), decode),
            items,
        })
    }
    /// Original stable node identities and peer-revised settings, in request order.
    pub fn items(&self) -> &[MonitoredNode] {
        &self.items
    }
    /// Receive an indexed change. A cancelled or expired wait preserves in-flight recovery.
    pub async fn next(&mut self, wait: Duration) -> Result<Sequenced<DataChange>, PublishError> {
        self.stream.next(wait).await
    }
    /// Complete shutdown of this dedicated session.
    pub async fn disconnect(self) {
        self.stream.disconnect().await
    }
}
async fn setup(
    client: &Client,
    nodes: &[NodeId],
    interval: Duration,
) -> Result<(u32, u32, Vec<MonitoredNode>), PublishError> {
    let (mut session, metadata) = client.read_session().await?;
    let mut requests = Vec::with_capacity(nodes.len());
    for (index, node) in nodes.iter().enumerate() {
        let node = metadata.namespaces.wire_node(node, index)?;
        requests.push(wire::item(
            node,
            13,
            (index + 1) as u32,
            interval,
            Default::default(),
        ));
    }
    let sub = wire::create_subscription(client, &mut session, interval).await?;
    let results = wire::create_items(client, &mut session, sub.id, requests).await?;
    Ok((sub.id, sub.timeout_ms, wire::revisions(nodes, &results)?))
}
fn decode(
    note: &ua::ExtensionObject,
    count: usize,
    budget: &mut usize,
    values: &mut Vec<DataChange>,
) -> Result<(), PublishError> {
    let list = note
        .inner_as::<ua::DataChangeNotification>()
        .ok_or(PublishError::InvalidNotification)?;
    let changes = list.monitored_items.as_deref().unwrap_or_default();
    if changes.len() > 32 - values.len() {
        return Err(PublishError::InvalidNotification);
    }
    for change in changes {
        let index = change
            .client_handle
            .checked_sub(1)
            .ok_or(PublishError::InvalidNotification)? as usize;
        if index >= count {
            return Err(PublishError::InvalidNotification);
        }
        let raw = &change.value;
        let status = raw.status.unwrap_or_default().bits();
        if status & 0x0c80 == 0x0480 {
            return Err(SubscriptionError::ItemOverflow { index, status }.into());
        }
        if let Some(value) = &raw.value {
            let bytes = variant_size(value)
                .filter(|n| *n <= 128 * 1024)
                .ok_or(SubscriptionError::ItemValueLimit { index })?;
            *budget = budget
                .checked_sub(bytes)
                .ok_or(PublishError::InvalidNotification)?;
        }
        values.push(DataChange {
            index,
            value: raw.clone(),
        });
    }
    Ok(())
}
