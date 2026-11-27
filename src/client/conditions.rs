//! Standard OPC UA Part 9 methods for a retained state or a specific condition event.
use super::{CallOutcome, Control, ControlError, Events, ua};
use crate::NodeId;

const UA: &str = "http://opcfoundation.org/UA/";

fn standard(id: &str) -> NodeId {
    NodeId::new(UA, id).expect("standard numeric NodeId")
}

/// Optional localized operator comment applied to the state identified by an EventId.
/// Pass `None` to preserve the existing comment, or a locale with empty text to clear it.
#[derive(Clone, Copy, Debug)]
pub struct ConditionComment<'a> {
    /// Locale identifier of the supplied text, for example `"en-US"`.
    pub locale: &'a str,
    /// Operator comment in the supplied locale.
    pub text: &'a str,
}

/// A condition method could not be prepared or its Call response could not be obtained.
/// An operation-level rejection from the server is returned in [`CallOutcome::status`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConditionError {
    /// A standard condition type was supplied where the method requires a condition instance.
    #[error("use the ConditionId of the reported condition instance")]
    InvalidCondition,
    /// EventIds are opaque and must contain one through 65,536 bytes.
    #[error("a condition EventId must contain 1 to 65536 bytes")]
    InvalidEventId,
    /// The encoded comment strings contain NUL or exceed the combined 16 KiB limit.
    #[error("the comment must be NUL-free and its locale and text must fit in 16 KiB")]
    InvalidComment,
    /// The event subscription has already failed. Recreate it before requesting refresh.
    #[error("the event stream has ended")]
    Ended,
    /// The standard Call failed locally or has an indeterminate remote outcome.
    #[error(transparent)]
    Call(#[from] ControlError),
}

impl Control<'_> {
    /// Acknowledge the reported branch state by its condition instance and opaque EventId.
    /// Supply the ConditionId and EventId from the same notification on this server where
    /// AckedState/Id was false. The separate BranchId identifies a retained branch.
    /// A server can reject an unknown EventId or an already acknowledged state.
    ///
    /// ```
    /// use opcua_kit::{Client, ConditionComment, ConditionError, Control, NodeId};
    ///
    /// async fn acknowledge(client: &Client, condition: &NodeId, event_id: &[u8])
    ///     -> Result<u32, ConditionError>
    /// {
    ///     let comment = ConditionComment { locale: "en", text: "Operator reviewed" };
    ///     let result = Control::new(client)
    ///         .acknowledge_condition(condition, event_id, Some(comment))
    ///         .await?;
    ///     Ok(result.status)
    /// }
    /// ```
    pub async fn acknowledge_condition(
        &self,
        condition: &NodeId,
        event_id: &[u8],
        comment: Option<ConditionComment<'_>>,
    ) -> Result<CallOutcome, ConditionError> {
        self.condition_method("i=9111", condition, event_id, comment)
            .await
    }

    /// Confirm the reported branch state by its condition instance and opaque EventId.
    /// Use the EventId for the state whose ConfirmedState/Id was false, including when the
    /// server issued a new EventId after acknowledgement. Confirm requires server support.
    pub async fn confirm_condition(
        &self,
        condition: &NodeId,
        event_id: &[u8],
        comment: Option<ConditionComment<'_>>,
    ) -> Result<CallOutcome, ConditionError> {
        self.condition_method("i=9113", condition, event_id, comment)
            .await
    }

    async fn condition_method(
        &self,
        method: &str,
        condition: &NodeId,
        event_id: &[u8],
        comment: Option<ConditionComment<'_>>,
    ) -> Result<CallOutcome, ConditionError> {
        if condition.namespace() == UA
            && matches!(condition.identifier(), "i=2782" | "i=2881" | "i=2915")
        {
            return Err(ConditionError::InvalidCondition);
        }
        if !(1..=65536).contains(&event_id.len()) {
            return Err(ConditionError::InvalidEventId);
        }
        let text = match comment {
            Some(c) => {
                if c.locale.len().saturating_add(c.text.len()) > 16 * 1024
                    || c.locale.contains('\0')
                    || c.text.contains('\0')
                {
                    return Err(ConditionError::InvalidComment);
                }
                ua::LocalizedText::new(c.locale, c.text)
            }
            None => ua::LocalizedText::default(),
        };
        let arguments = [
            ua::Variant::ByteString(ua::ByteString::from(event_id.to_vec())),
            ua::Variant::LocalizedText(Box::new(text)),
        ];
        Ok(self
            .call_method(condition, &standard(method), &arguments)
            .await?)
    }
}

impl Events {
    /// Request retained condition events for this subscription on its own authenticated session.
    /// It can run while an outstanding Publish waits for a notification or keepalive.
    /// A Good method result accepts the request. Observe RefreshStart and RefreshEnd events and
    /// retained notifications through [`Events::next`] to complete a refresh.
    pub async fn refresh_conditions(&mut self) -> Result<CallOutcome, ConditionError> {
        let (client, subscription) = self.condition_session().ok_or(ConditionError::Ended)?;
        let args = [ua::Variant::UInt32(subscription)];
        Ok(Control::new(client)
            .call_method(&standard("i=2782"), &standard("i=3875"), &args)
            .await?)
    }
}
