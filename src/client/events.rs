//! Ordered event notifications and Publish acknowledgement on a dedicated pinned session.
mod publish;
mod sequenced_data;
pub use sequenced_data::SequencedDataChanges;
mod wire;
use super::wire::slice;
use super::{
    BrowseName, CertificateRollover, Client, ConnectionConfig, ConnectionOptions, ReadError,
    RecoveringClient, RecoveryError, SubscriptionError,
};
use crate::NodeId;
use open62541::{DataType, ua};
pub use publish::Sequenced;
use std::time::Duration;

/// One select clause. The type identifies the event declaring the field. An empty
/// path selects the NodeId attribute of the event instance (for example ConditionId).
#[derive(Debug, Clone)]
pub struct EventField {
    /// Stable event type NodeId, such as BaseEventType (i=2041).
    pub type_definition: NodeId,
    /// Relative qualified field names. Up to eight components.
    pub path: Vec<BrowseName>,
}

impl EventField {
    /// Select the reported ConditionId (the NodeId attribute of ConditionType, empty browse path).
    /// For an instance outside the standard namespace, normalize the returned NodeId with
    /// [`Events::stable_node`] before using it on another session.
    pub fn condition_id() -> Self {
        Self {
            type_definition: NodeId::new("http://opcfoundation.org/UA/", "i=2782")
                .expect("standard node"),
            path: Vec::new(),
        }
    }

    /// Select one field of BaseEventType, such as EventId, Time, Message or Severity.
    pub fn base(name: &str) -> Result<Self, super::BrowseError> {
        let namespace = "http://opcfoundation.org/UA/";
        Ok(Self {
            type_definition: NodeId::new(namespace, "i=2041").expect("standard node"),
            path: vec![BrowseName::new(namespace, name)?],
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// Dedicated Publish stream setup, delivery and retransmission failures.
pub enum PublishError {
    #[error(transparent)]
    /// Failed to establish a dedicated pinned session.
    Connect(#[from] RecoveryError),
    #[error("subscription service status 0x{0:08X}")]
    /// The server rejected the monitored item, event field, acknowledgement or subscription.
    Status(u32),
    #[error("subscription sequence cannot be recovered: expected {expected}, got {actual}")]
    /// A skipped message was unavailable, exceeded the recovery window, or the sequence was repeated.
    SequenceGap {
        /// Expected nonzero Publish sequence number.
        expected: u32,
        /// Observed sequence number.
        actual: u32,
    },
    #[error(transparent)]
    /// Channel, namespace or service failure.
    Session(#[from] ReadError),
    #[error(transparent)]
    /// Invalid interval/revision, wait timeout or loss of delivery.
    Subscription(#[from] SubscriptionError),
    #[error("select 1 to 32 event fields, each with up to eight valid browse names")]
    /// Invalid local selection.
    InvalidSelection,
    #[error("invalid or oversized OPC UA notification or subscription response")]
    /// The response has invalid shape, routing, or encoded size.
    InvalidNotification,
    #[error("the server reported an EventQueueOverflowEventType; resynchronize events")]
    /// The server reported lost events.
    ServerOverflow,
}

/// Error returned by an event stream and its condition operations.
pub type EventError = PublishError;

/// An event stream on a dedicated pinned session. Each notification contains the selected
/// Variants in caller order. Keep a pending Publish alive across cancelled or timed-out waits.
/// The server buffers events between calls; poll regularly within its subscription lifetime.
pub struct Events(publish::Stream<Vec<ua::Variant>>);

const OVERFLOW_EVENT: u32 = 3035;
const INTERNAL_FIELDS: [&str; 3] = ["EventType", "SourceNode", "SourceName"];
const MAX_WAIT: Duration = Duration::from_secs(60);

fn selected_values<'a>(
    mut fields: impl Iterator<Item = &'a ua::Variant> + Clone,
) -> Result<Vec<ua::Variant>, EventError> {
    let all = fields.clone();
    let ty = fields
        .next()
        .and_then(ua::Variant::as_scalar::<ua::NodeId>)
        .filter(|node| !node.is_null())
        .ok_or(EventError::InvalidNotification)?;
    if ty.as_ns0() == Some(OVERFLOW_EVENT) {
        return Err(EventError::ServerOverflow);
    }
    // Part 5 §6.4.34 makes EventQueueOverflowEventType abstract. Its concrete
    // subtypes report this standard source, regardless of the subtype namespace.
    let source_node = fields.next().ok_or(EventError::InvalidNotification)?;
    let source_name = fields.next().ok_or(EventError::InvalidNotification)?;
    let node = source_node.as_scalar::<ua::NodeId>();
    let name = source_name.as_scalar::<ua::String>();
    if (!source_node.is_empty() && node.is_none()) || (!source_name.is_empty() && name.is_none()) {
        return Err(EventError::InvalidNotification);
    }
    if node.and_then(ua::NodeId::as_ns0) == Some(open62541_sys::UA_NS0ID_SERVER)
        && name.and_then(ua::String::as_str) == Some("Internal/EventQueueOverflow")
    {
        return Err(EventError::ServerOverflow);
    }
    let mut left = 128 * 1024usize;
    for field in all {
        let bytes = super::wire::variant_size(field).ok_or(EventError::InvalidNotification)?;
        left = left
            .checked_sub(bytes)
            .ok_or(EventError::InvalidNotification)?;
    }
    Ok(fields.cloned().collect())
}

impl Events {
    /// Translate a raw NodeId from an event delivered by this session to a URI-qualified identity.
    pub fn stable_node(&self, node: &ua::NodeId) -> Result<NodeId, EventError> {
        let metadata = self
            .0
            .client
            .as_ref()
            .and_then(|client| client.metadata.get())
            .ok_or(EventError::InvalidNotification)?;
        Ok(metadata.namespaces.stable_node(node)?)
    }

    #[cfg(feature = "control")]
    pub(super) fn condition_session(&self) -> Option<(&Client, u32)> {
        if self.0.ended {
            return None;
        }
        self.0
            .client
            .as_deref()
            .map(|client| (client, self.0.subscription))
    }

    /// Open a fresh authenticated session dedicated to one event notifier, and select 1–32
    /// ordered fields. Publishing interval: 10 ms to 60 s. Hidden EventType, SourceNode and
    /// SourceName fields recognize queue overflow notifications and concrete subtypes. The host can use a separate client for reads.
    pub async fn connect(
        config: ConnectionConfig<'_>,
        options: ConnectionOptions<'_>,
        notifier: &NodeId,
        fields: &[EventField],
        interval: Duration,
    ) -> Result<Self, EventError> {
        Self::open(
            RecoveringClient::new(config, options),
            notifier,
            fields,
            interval,
        )
        .await
    }

    /// Open an event session with an independently reviewed successor leaf and a deadline on
    /// the original leaf. Pin selection uses the same checks as [`Client::connect_with_rollover`].
    pub async fn connect_with_rollover(
        config: ConnectionConfig<'_>,
        options: ConnectionOptions<'_>,
        rollover: CertificateRollover<'_>,
        notifier: &NodeId,
        fields: &[EventField],
        interval: Duration,
    ) -> Result<Self, EventError> {
        Self::open(
            RecoveringClient::new_with_rollover(config, options, rollover),
            notifier,
            fields,
            interval,
        )
        .await
    }

    async fn open(
        owner: RecoveringClient<'_>,
        notifier: &NodeId,
        fields: &[EventField],
        interval: Duration,
    ) -> Result<Self, EventError> {
        if !(1..=32).contains(&fields.len())
            || fields
                .iter()
                .any(|f| f.path.len() > 8 || f.path.iter().any(|n| n.validate().is_err()))
        {
            return Err(EventError::InvalidSelection);
        }
        if !(Duration::from_millis(10)..=MAX_WAIT).contains(&interval) {
            return Err(SubscriptionError::InvalidInterval.into());
        }
        let client = owner.into_client().await?;
        let setup = Self::setup(&client, notifier, fields, interval).await;
        let (subscription, timeout_ms) = match setup {
            Ok(result) => result,
            Err(error) => {
                client.disconnect().await;
                return Err(error);
            }
        };
        Ok(Self(publish::Stream::new(
            client,
            subscription,
            timeout_ms,
            fields.len(),
            decode_events,
        )))
    }

    async fn setup(
        client: &Client,
        notifier: &NodeId,
        fields: &[EventField],
        interval: Duration,
    ) -> Result<(u32, u32), EventError> {
        let (mut session, metadata) = client.read_session().await?;
        let ns = &metadata.namespaces;
        let node = ns.wire_node(notifier, 0)?;
        let mut clauses: Vec<_> = INTERNAL_FIELDS
            .iter()
            .map(|&name| {
                ua::SimpleAttributeOperand::init()
                    .with_type_definition_id(ua::NodeId::ns0(2041))
                    .with_browse_path(&[ua::QualifiedName::ns0(name)])
                    .with_attribute_id(&ua::AttributeId::VALUE)
            })
            .collect();
        for (index, field) in fields.iter().enumerate() {
            let ty = ns.wire_node(&field.type_definition, index)?;
            let path = field
                .path
                .iter()
                .map(|name| {
                    let ns_index = ns
                        .by_uri
                        .get(name.namespace.as_str())
                        .ok_or(ReadError::UnknownNamespace { index })?;
                    Ok::<_, ReadError>(ua::QualifiedName::new(*ns_index, &name.name))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let attribute = if path.is_empty() {
                ua::AttributeId::NODEID
            } else {
                ua::AttributeId::VALUE
            };
            clauses.push(
                ua::SimpleAttributeOperand::init()
                    .with_type_definition_id(ty)
                    .with_browse_path(&path)
                    .with_attribute_id(&attribute),
            );
        }
        let (subscription, timeout_ms) =
            wire::create_subscription(client, &mut session, interval).await?;
        let mut item = ua::MonitoredItemCreateRequest::init()
            .with_node_id(&node)
            .with_attribute_id(&ua::AttributeId::EVENTNOTIFIER)
            .with_monitoring_mode(&ua::MonitoringMode::REPORTING)
            .with_sampling_interval(Some(Duration::ZERO))
            .with_queue_size(32)
            .with_discard_oldest(true)
            .with_filter(&ua::EventFilter::init().with_select_clauses(&clauses));
        // SAFETY: we own the initialized item. The handle identifies this single notifier on Publish.
        unsafe { item.as_mut() }.requestedParameters.clientHandle = 1;
        let resp = wire::create_items(client, &mut session, subscription, &[item]).await?;
        // SAFETY: the SDK response owns these decoded result arrays for this scope.
        let [result] = (unsafe { slice(resp.0.results, resp.0.resultsSize, 1) })
            .ok_or(EventError::InvalidNotification)?
        else {
            return Err(EventError::InvalidNotification);
        };
        if result.statusCode >> 30 != 0 {
            return Err(EventError::Status(result.statusCode));
        }
        if result.monitoredItemId == 0 || !(1..=32).contains(&result.revisedQueueSize) {
            return Err(SubscriptionError::InvalidRevision.into());
        }
        validate_filter(
            ua::ExtensionObject::raw_ref(&result.filterResult),
            clauses.len(),
        )?;
        Ok((subscription, timeout_ms))
    }

    /// Wait for the next ordered event. Eligible retained messages are recovered via Republish.
    pub async fn next(&mut self, wait: Duration) -> Result<Vec<ua::Variant>, EventError> {
        Ok(self.next_with_sequence(wait).await?.value)
    }

    /// Return the Publish sequence and whether the event was recovered from the server's retransmission queue.
    pub async fn next_with_sequence(
        &mut self,
        wait: Duration,
    ) -> Result<Sequenced<Vec<ua::Variant>>, EventError> {
        self.0.next(wait).await
    }

    /// Cancel the outstanding request and close the dedicated subscription and session.
    pub async fn disconnect(self) {
        self.0.disconnect().await;
    }
}

fn validate_filter(filter: &ua::ExtensionObject, count: usize) -> Result<(), EventError> {
    if let Some(filter) = filter.decoded_content::<wire::FilterResult>() {
        let statuses = unsafe {
            slice(
                filter.0.selectClauseResults,
                filter.0.selectClauseResultsSize,
                count,
            )
        }
        .ok_or(EventError::InvalidNotification)?;
        if !statuses.is_empty() && statuses.len() != count {
            return Err(EventError::InvalidNotification);
        }
        if let Some(status) = statuses.iter().find(|s| **s >> 30 != 0) {
            return Err(EventError::Status(*status));
        }
    } else if unsafe { filter.as_ref() }.encoding
        != open62541_sys::UA_ExtensionObjectEncoding::UA_EXTENSIONOBJECT_ENCODED_NOBODY
        || !filter.encoded_type_id().is_some_and(ua::NodeId::is_null)
    {
        return Err(EventError::InvalidNotification);
    }
    Ok(())
}

fn decode_events(
    note: &ua::ExtensionObject,
    count: usize,
    budget: &mut usize,
    events: &mut Vec<Vec<ua::Variant>>,
) -> Result<(), EventError> {
    let invalid = || EventError::InvalidNotification;
    let list = note
        .decoded_content::<wire::EventList>()
        .ok_or_else(invalid)?;
    for event in
        unsafe { slice(list.0.events, list.0.eventsSize, 32 - events.len()) }.ok_or_else(invalid)?
    {
        if event.clientHandle != 1 || event.eventFieldsSize != count + INTERNAL_FIELDS.len() {
            return Err(invalid());
        }
        let raw = unsafe {
            slice(
                event.eventFields,
                event.eventFieldsSize,
                32 + INTERNAL_FIELDS.len(),
            )
        }
        .ok_or_else(invalid)?;
        let values = raw.iter().map(ua::Variant::raw_ref);
        for value in values.clone() {
            *budget = budget
                .checked_sub(super::wire::variant_size(value).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
        }
        events.push(selected_values(values)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unexpected_filter_result_type_is_rejected() {
        assert!(validate_filter(&ua::ExtensionObject::init(), 1).is_ok());
        let other = ua::ExtensionObject::new(&ua::UInt32::new(1));
        assert!(matches!(
            validate_filter(&other, 1),
            Err(EventError::InvalidNotification)
        ));
    }

    #[test]
    fn concrete_overflow_uses_both_standard_source_fields() {
        let ty = ua::Variant::scalar(ua::NodeId::numeric(2, 2000));
        let server = ua::Variant::scalar(ua::NodeId::ns0(open62541_sys::UA_NS0ID_SERVER));
        let other = ua::Variant::scalar(ua::NodeId::numeric(2, 2001));
        let name = ua::Variant::scalar(ua::String::new("Internal/EventQueueOverflow").unwrap());
        let absent = ua::Variant::init();
        assert!(matches!(
            selected_values([&ty, &server, &name].into_iter()),
            Err(EventError::ServerOverflow)
        ));
        assert!(
            selected_values([&ty, &other, &name].into_iter())
                .unwrap()
                .is_empty()
        );
        assert!(
            selected_values([&ty, &server, &absent].into_iter())
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            selected_values([&ty, &name, &server].into_iter()),
            Err(EventError::InvalidNotification)
        ));
    }

    #[test]
    fn event_type_and_exact_aggregate_budget_are_checked_before_copying_fields() {
        let ty = ua::Variant::scalar(ua::NodeId::ns0(2041));
        let source = ua::Variant::scalar(ua::NodeId::ns0(open62541_sys::UA_NS0ID_SERVER));
        let name = ua::Variant::scalar(ua::String::new("Server").unwrap());
        let hidden_bytes = [&ty, &source, &name]
            .iter()
            .map(|field| super::super::wire::variant_size(field).unwrap())
            .sum::<usize>();
        let capacity = 128 * 1024 - hidden_bytes - 5;
        let value = |size| ua::Variant::scalar(ua::ByteString::new(&vec![0; size]));
        assert_eq!(
            selected_values([&ty, &source, &name, &value(capacity)].into_iter())
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            selected_values([&ty, &source, &name, &value(capacity + 1)].into_iter()),
            Err(EventError::InvalidNotification)
        ));
        assert!(matches!(
            selected_values([&ua::Variant::scalar(ua::NodeId::ns0(0))].into_iter()),
            Err(EventError::InvalidNotification)
        ));
        assert!(matches!(
            selected_values([&ua::Variant::scalar(ua::NodeId::ns0(3035))].into_iter()),
            Err(EventError::ServerOverflow)
        ));
    }
}
