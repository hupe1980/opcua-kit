//! Ordered event notifications and Publish acknowledgement on a dedicated pinned session.
mod publish;
mod sequenced_data;
pub use sequenced_data::SequencedDataChanges;
pub(super) mod wire;
use super::ua;
use super::{
    BrowseName, CertificateRollover, Client, ConnectionConfig, ConnectionOptions, ReadError,
    RecoveringClient, RecoveryError, SubscriptionError,
};
use crate::NodeId;
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
    let Some(ua::Variant::NodeId(ty)) = fields.next() else {
        return Err(EventError::InvalidNotification);
    };
    if ty.is_null() {
        return Err(EventError::InvalidNotification);
    }
    if **ty == ua::NodeId::new(0, OVERFLOW_EVENT) {
        return Err(EventError::ServerOverflow);
    }
    // Part 5 §6.4.34 assigns this source to concrete overflow event subtypes.
    let server = match fields.next() {
        Some(ua::Variant::NodeId(node)) => **node == ua::NodeId::new(0, 2253),
        Some(ua::Variant::Empty) => false,
        _ => return Err(EventError::InvalidNotification),
    };
    match fields.next() {
        Some(ua::Variant::String(name))
            if server && name.as_ref() == "Internal/EventQueueOverflow" =>
        {
            return Err(EventError::ServerOverflow);
        }
        Some(ua::Variant::String(_) | ua::Variant::Empty) => (),
        _ => return Err(EventError::InvalidNotification),
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
            .map(|&name| ua::SimpleAttributeOperand {
                type_definition_id: ua::NodeId::new(0, 2041),
                browse_path: Some(vec![ua::QualifiedName::new(0, name)]),
                attribute_id: 13,
                ..Default::default()
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
                    Ok::<_, ReadError>(ua::QualifiedName::new(*ns_index, name.name.as_str()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            clauses.push(ua::SimpleAttributeOperand {
                type_definition_id: ty,
                attribute_id: if path.is_empty() { 1 } else { 13 },
                browse_path: Some(path),
                ..Default::default()
            });
        }
        let count = clauses.len();
        let subscription = wire::create_subscription(client, &mut session, interval).await?;
        let filter = ua::ExtensionObject::new(ua::EventFilter {
            select_clauses: Some(clauses),
            ..Default::default()
        });
        let item = wire::item(node, 12, 1, Duration::ZERO, filter);
        let results = wire::create_items(client, &mut session, subscription.id, vec![item]).await?;
        let result = &results[0];
        if !result.status_code.is_good() {
            return Err(EventError::Status(result.status_code.bits()));
        }
        if result.monitored_item_id == 0 || !(1..=32).contains(&result.revised_queue_size) {
            return Err(SubscriptionError::InvalidRevision.into());
        }
        validate_filter(&result.filter_result, count)?;
        Ok((subscription.id, subscription.timeout_ms))
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
    if filter.is_null() {
        return Ok(());
    }
    let result = filter
        .inner_as::<ua::EventFilterResult>()
        .ok_or(EventError::InvalidNotification)?;
    let statuses = result.select_clause_results.as_deref().unwrap_or_default();
    if !statuses.is_empty() && statuses.len() != count {
        return Err(EventError::InvalidNotification);
    }
    if let Some(s) = statuses.iter().find(|s| !s.is_good()) {
        return Err(EventError::Status(s.bits()));
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
        .inner_as::<ua::EventNotificationList>()
        .ok_or_else(invalid)?;
    let rows = list.events.as_deref().unwrap_or_default();
    if rows.len() > 32 - events.len() {
        return Err(invalid());
    }
    for event in rows {
        let fields = event.event_fields.as_deref().unwrap_or_default();
        if event.client_handle != 1 || fields.len() != count + INTERNAL_FIELDS.len() {
            return Err(invalid());
        }
        let values = fields.iter();
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
        assert!(validate_filter(&ua::ExtensionObject::default(), 1).is_ok());
        let other = ua::ExtensionObject::new(ua::EventFilter::default());
        assert!(matches!(
            validate_filter(&other, 1),
            Err(EventError::InvalidNotification)
        ));
    }

    #[test]
    fn concrete_overflow_uses_both_standard_source_fields() {
        let ty = ua::Variant::from(ua::NodeId::new(2, 2000));
        let server = ua::Variant::from(ua::NodeId::new(0, 2253));
        let other = ua::Variant::from(ua::NodeId::new(2, 2001));
        let name = ua::Variant::from("Internal/EventQueueOverflow");
        let absent = ua::Variant::Empty;
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
        let ty = ua::Variant::from(ua::NodeId::new(0, 2041));
        let source = ua::Variant::from(ua::NodeId::new(0, 2253));
        let name = ua::Variant::from("Server");
        let hidden_bytes = [&ty, &source, &name]
            .iter()
            .map(|field| super::super::wire::variant_size(field).unwrap())
            .sum::<usize>();
        let capacity = 128 * 1024 - hidden_bytes - 5;
        let value = |size| ua::Variant::ByteString(vec![0; size].into());
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
            selected_values([&ua::Variant::from(ua::NodeId::new(0, 0))].into_iter()),
            Err(EventError::InvalidNotification)
        ));
        assert!(matches!(
            selected_values([&ua::Variant::from(ua::NodeId::new(0, 3035))].into_iter()),
            Err(EventError::ServerOverflow)
        ));
    }
}
