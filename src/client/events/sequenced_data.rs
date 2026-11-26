//! Dedicated multi-node data-change subscription with same-session retransmission.
use super::{MAX_WAIT, PublishError, Sequenced, publish, wire};
use crate::client::{
    ua,
    wire::{slice, variant_size},
};
use crate::{
    CertificateRollover, Client, ConnectionConfig, ConnectionOptions, DataChange, MonitoredNode,
    NodeId, RecoveringClient, SubscriptionError,
};
use open62541::DataType;
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
        let mut item = ua::MonitoredItemCreateRequest::init()
            .with_node_id(&node)
            .with_attribute_id(&ua::AttributeId::VALUE)
            .with_monitoring_mode(&ua::MonitoringMode::REPORTING)
            .with_sampling_interval(Some(interval))
            .with_queue_size(32)
            .with_discard_oldest(true);
        // SAFETY: item is exclusively owned. Handle zero is reserved.
        unsafe { item.as_mut() }.requestedParameters.clientHandle = (index + 1) as u32;
        requests.push(item);
    }
    let (sub, timeout) = wire::create_subscription(client, &mut session, interval).await?;
    let reply = wire::create_items(client, &mut session, sub, &requests).await?;
    // SAFETY: the response owns all monitored item results for this scope.
    let results = unsafe { slice(reply.0.results, reply.0.resultsSize, nodes.len()) }
        .ok_or(PublishError::InvalidNotification)?;
    if results.len() != nodes.len() {
        return Err(PublishError::InvalidNotification);
    }
    let mut revisions = Vec::with_capacity(nodes.len());
    let mut ids = std::collections::BTreeSet::new();
    for (index, (result, node)) in results.iter().zip(nodes).enumerate() {
        let status = ua::StatusCode::clone_raw(&result.statusCode);
        if !status.is_good() {
            return Err(SubscriptionError::ItemRejected {
                index,
                source: open62541::Error::Server(status),
            }
            .into());
        }
        let revised = Duration::try_from_secs_f64(result.revisedSamplingInterval / 1000.)
            .map_err(|_| SubscriptionError::ItemRevision { index })?;
        if result.monitoredItemId == 0
            || !ids.insert(result.monitoredItemId)
            || revised > MAX_WAIT
            || !(2..=32).contains(&result.revisedQueueSize)
        {
            return Err(SubscriptionError::ItemRevision { index }.into());
        }
        revisions.push(MonitoredNode {
            node: node.clone(),
            sampling_interval: revised,
            queue_size: result.revisedQueueSize,
        });
    }
    Ok((sub, timeout, revisions))
}
fn decode(
    note: &ua::ExtensionObject,
    count: usize,
    budget: &mut usize,
    values: &mut Vec<DataChange>,
) -> Result<(), PublishError> {
    let list = note
        .decoded_content::<wire::DataChangeList>()
        .ok_or(PublishError::InvalidNotification)?;
    let changes = unsafe {
        slice(
            list.0.monitoredItems,
            list.0.monitoredItemsSize,
            32 - values.len(),
        )
    }
    .ok_or(PublishError::InvalidNotification)?;
    for change in changes {
        let index = change
            .clientHandle
            .checked_sub(1)
            .ok_or(PublishError::InvalidNotification)? as usize;
        if index >= count {
            return Err(PublishError::InvalidNotification);
        }
        let raw = ua::DataValue::raw_ref(&change.value);
        let status = raw.status().map_or(0, DataType::into_raw);
        if status & 0x0c80 == 0x0480 {
            return Err(SubscriptionError::ItemOverflow { index, status }.into());
        }
        if let Some(value) = raw.value() {
            let bytes = variant_size(value)
                .filter(|n| *n <= 128 * 1024)
                .ok_or(SubscriptionError::ItemValueLimit { index })?;
            *budget = budget
                .checked_sub(bytes)
                .ok_or(PublishError::InvalidNotification)?;
        }
        values.push(DataChange {
            index,
            value: raw.clone().cast(),
        });
    }
    Ok(())
}
