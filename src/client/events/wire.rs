//! Service request construction and validation shared by subscription clients.
use crate::client::{ReadSession, ua};
use crate::{Client, MonitoredNode, NodeId, SubscriptionError};
use std::{collections::BTreeSet, time::Duration};

pub(in crate::client) struct Created {
    pub id: u32,
    pub interval: Duration,
    pub timeout_ms: u32,
}

pub(in crate::client) fn publish(
    acks: Vec<ua::SubscriptionAcknowledgement>,
    timeout_ms: u32,
) -> ua::PublishRequest {
    ua::PublishRequest {
        request_header: ua::RequestHeader {
            timeout_hint: timeout_ms,
            ..Default::default()
        },
        subscription_acknowledgements: Some(acks),
    }
}

pub(in crate::client) async fn create_subscription(
    client: &Client,
    session: &mut ReadSession,
    interval: Duration,
) -> Result<Created, SubscriptionError> {
    let reply = client
        .guarded(
            session,
            client.inner.request(ua::CreateSubscriptionRequest {
                requested_publishing_interval: interval.as_secs_f64() * 1000.,
                requested_lifetime_count: 60,
                requested_max_keep_alive_count: 5,
                max_notifications_per_publish: 32,
                publishing_enabled: true,
                ..Default::default()
            }),
        )
        .await?;
    let keep_alive =
        reply.revised_publishing_interval * f64::from(reply.revised_max_keep_alive_count);
    if reply.subscription_id == 0
        || !(0.0..=60_000.).contains(&reply.revised_publishing_interval)
        || !(0.0..=600_000.).contains(&keep_alive)
        || keep_alive == 0.
        || reply.revised_lifetime_count < reply.revised_max_keep_alive_count.saturating_mul(3)
    {
        return Err(SubscriptionError::InvalidRevision);
    }
    Ok(Created {
        id: reply.subscription_id,
        interval: Duration::from_secs_f64(reply.revised_publishing_interval / 1000.),
        timeout_ms: (keep_alive.ceil() as u32) * 2 + 1000,
    })
}

pub(in crate::client) async fn create_items(
    client: &Client,
    session: &mut ReadSession,
    subscription_id: u32,
    items: Vec<ua::MonitoredItemCreateRequest>,
) -> Result<Vec<ua::MonitoredItemCreateResult>, SubscriptionError> {
    let count = items.len();
    let response = client
        .guarded(
            session,
            client.inner.request(ua::CreateMonitoredItemsRequest {
                subscription_id,
                timestamps_to_return: ua::TimestampsToReturn::Both,
                items_to_create: Some(items),
                ..Default::default()
            }),
        )
        .await?;
    response
        .results
        .filter(|r| r.len() == count)
        .ok_or(SubscriptionError::InvalidRevision)
}

pub(in crate::client) fn item(
    node_id: ua::NodeId,
    attribute_id: u32,
    client_handle: u32,
    interval: Duration,
    filter: ua::ExtensionObject,
) -> ua::MonitoredItemCreateRequest {
    ua::MonitoredItemCreateRequest {
        item_to_monitor: ua::ReadValueId {
            node_id,
            attribute_id,
            ..Default::default()
        },
        monitoring_mode: ua::MonitoringMode::Reporting,
        requested_parameters: ua::MonitoringParameters {
            client_handle,
            sampling_interval: interval.as_secs_f64() * 1000.,
            filter,
            queue_size: 32,
            discard_oldest: true,
        },
    }
}

pub(in crate::client) fn revisions(
    nodes: &[NodeId],
    results: &[ua::MonitoredItemCreateResult],
) -> Result<Vec<MonitoredNode>, SubscriptionError> {
    let mut ids = BTreeSet::new();
    nodes
        .iter()
        .zip(results)
        .enumerate()
        .map(|(index, (node, r))| {
            if !r.status_code.is_good() {
                return Err(SubscriptionError::ItemRejected {
                    index,
                    source: r.status_code,
                });
            }
            let sampling_interval =
                Duration::try_from_secs_f64(r.revised_sampling_interval / 1000.)
                    .map_err(|_| SubscriptionError::ItemRevision { index })?;
            if r.monitored_item_id == 0
                || !ids.insert(r.monitored_item_id)
                || sampling_interval > Duration::from_secs(60)
                || !(2..=32).contains(&r.revised_queue_size)
            {
                return Err(SubscriptionError::ItemRevision { index });
            }
            Ok(MonitoredNode {
                node: node.clone(),
                sampling_interval,
                queue_size: r.revised_queue_size,
            })
        })
        .collect()
}
