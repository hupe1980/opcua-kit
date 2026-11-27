//! Explicit control capability for an authenticated session. The server enforces permissions.

use super::{Client, ReadError, ReadSession, Scalar, ua, wire};
use crate::{NodeId, Severity, status_severity};

const MAX_ARGS: usize = 64;
pub(super) const MAX_BYTES: usize = 128 * 1024;

/// A local preflight failure or an operation whose effects need reconciliation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// The operation was never submitted. The session or stable target identity was unusable.
    #[error("control preflight failed: {0}")]
    Preflight(#[source] ReadError),
    /// The request exceeded 64 arguments or 128 KiB of encoded Variants, or could not be encoded.
    #[error("control input exceeds the argument or encoded size limit")]
    InputLimit,
    /// The timestamp has no exact, non-sentinel OPC UA DateTime representation.
    #[error("timestamp must be representable as a non-sentinel 100 ns OPC UA DateTime")]
    InvalidDateTime,
    /// A usable reply could not be obtained after entering dispatch. The operation may have executed.
    #[error("control outcome is unknown after dispatch: {0}")]
    Indeterminate(#[source] ReadError),
    /// The response was malformed or too large. The session is retired and effects may have occurred.
    #[error("control response was malformed or exceeded the result limit; verify the effect")]
    InvalidResponse,
}

/// One Call result in wire order. Check the operation status before interpreting outputs.
#[derive(Debug)]
#[must_use]
pub struct CallOutcome {
    /// Full operation-level StatusCode, including flags and qualified Good results.
    pub status: u32,
    /// Per-input status codes, when provided by the server.
    pub input_statuses: Vec<u32>,
    /// Output Variants with their original types and shapes.
    pub outputs: Vec<ua::Variant>,
}

/// Borrow a pinned client for explicit value writes and method calls.
///
/// Each call dispatches at most once. A dropped future after dispatch retires the session.
/// If the reply is lost, inspect application state on a new session before deciding what to do.
///
/// ```
/// use opcua_kit::{Client, Control, ControlError, NodeId};
/// # async fn set_value(client: &Client, node: &NodeId) -> Result<(), ControlError> {
/// let status = Control::new(client).write_scalar(node, 42_u32).await?;
/// if status != 0 {
///     eprintln!("write returned 0x{status:08X}");
/// }
/// # Ok(()) }
/// ```
pub struct Control<'a>(&'a Client);

impl<'a> Control<'a> {
    /// Use the existing session's credentials, authority, namespace map and service guard.
    pub const fn new(client: &'a Client) -> Self {
        Self(client)
    }

    /// Write one Rust scalar with its exact OPC UA type and return the full operation status.
    pub async fn write_scalar<T: Scalar>(
        &self,
        node: &NodeId,
        value: T,
    ) -> Result<u32, ControlError> {
        self.write_value(node, &value.into_variant()?).await
    }

    /// Write the Value attribute only. The Variant retains its exact type and dimensions.
    /// The request supplies no data quality or timestamps. Limit: 128 KiB encoded Variant.
    pub async fn write_value(
        &self,
        node: &NodeId,
        value: &ua::Variant,
    ) -> Result<u32, ControlError> {
        check_values(std::iter::once(value)).ok_or(ControlError::InputLimit)?;
        let (mut session, metadata) = self
            .0
            .read_session()
            .await
            .map_err(ControlError::Preflight)?;
        let node = metadata
            .namespaces
            .wire_node(node, 0)
            .map_err(ControlError::Preflight)?;
        let request = ua::WriteRequest {
            nodes_to_write: Some(vec![ua::WriteValue {
                node_id: node,
                attribute_id: ua::AttributeId::Value as u32,
                value: ua::DataValue::value_only(value.clone()),
                ..Default::default()
            }]),
            ..Default::default()
        };
        self.dispatch(
            &mut session,
            self.0.inner.request(request),
            |reply| match reply.results.as_deref() {
                Some([status]) => Some(status.bits()),
                _ => None,
            },
        )
        .await
    }

    /// Call one method on the supplied object. The wire inputs and outputs may be heterogeneous.
    /// Up to 64 arguments and 128 KiB in aggregate encoded Variant data are accepted per direction.
    /// Returns the server's operation status even for a rejected method or invalid input argument.
    ///
    /// ```
    /// use opcua_kit::{Client, Control, NodeId, Scalar};
    /// # async fn example(client: &Client, object: &NodeId, method: &NodeId) -> Result<(), Box<dyn std::error::Error>> {
    /// let args = [42_u64.into_variant()?];
    /// let reply = Control::new(client).call_method(object, method, &args).await?;
    /// if reply.status == 0 && let [result] = reply.outputs.as_slice() {
    ///     let value = u64::from_variant(result)?;
    ///     println!("method returned {value:?}");
    /// }
    /// # Ok(()) }
    /// ```
    pub async fn call_method(
        &self,
        object: &NodeId,
        method: &NodeId,
        inputs: &[ua::Variant],
    ) -> Result<CallOutcome, ControlError> {
        check_values(inputs.iter()).ok_or(ControlError::InputLimit)?;
        let (mut session, metadata) = self
            .0
            .read_session()
            .await
            .map_err(ControlError::Preflight)?;
        let object = metadata
            .namespaces
            .wire_node(object, 0)
            .map_err(ControlError::Preflight)?;
        let method = metadata
            .namespaces
            .wire_node(method, 1)
            .map_err(ControlError::Preflight)?;
        let request = ua::CallRequest {
            methods_to_call: Some(vec![ua::CallMethodRequest {
                object_id: object,
                method_id: method,
                input_arguments: Some(inputs.to_vec()),
            }]),
            ..Default::default()
        };
        self.dispatch(&mut session, self.0.inner.request(request), |reply| {
            call_outcome(reply, inputs.len())
        })
        .await
    }

    async fn dispatch<R, T>(
        &self,
        session: &mut ReadSession,
        request: impl Future<Output = Result<R, ua::StatusCode>>,
        decode: impl FnOnce(&R) -> Option<T>,
    ) -> Result<T, ControlError> {
        self.0.check_channel().map_err(ControlError::Preflight)?;
        // Keep the session retired if this future is cancelled, if dispatch fails, or if
        // the reply cannot be tied to exactly one operation on the original channel.
        session.interrupted = true;
        let response = request
            .await
            .map_err(|e| ControlError::Indeterminate(ReadError::Service(e)))?;
        self.0
            .check_channel()
            .map_err(ControlError::Indeterminate)?;
        let result = decode(&response).ok_or(ControlError::InvalidResponse)?;
        session.interrupted = false;
        Ok(result)
    }
}

fn check_values<'a>(values: impl ExactSizeIterator<Item = &'a ua::Variant>) -> Option<()> {
    if values.len() > MAX_ARGS {
        return None;
    }
    let mut left = MAX_BYTES;
    for value in values {
        left = left.checked_sub(wire::variant_size(value)?)?;
    }
    Some(())
}

fn call_outcome(reply: &ua::CallResponse, inputs: usize) -> Option<CallOutcome> {
    let [result] = reply.results.as_deref()? else {
        return None;
    };
    let statuses = result.input_argument_results.as_deref().unwrap_or_default();
    if !statuses.is_empty() && statuses.len() != inputs {
        return None;
    }
    let outputs = result.output_arguments.as_deref().unwrap_or_default();
    if status_severity(result.status_code.bits()) == Severity::Bad && !outputs.is_empty() {
        return None;
    }
    check_values(outputs.iter())?;
    Some(CallOutcome {
        status: result.status_code.bits(),
        input_statuses: statuses.iter().map(|s| s.bits()).collect(),
        outputs: outputs.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_budgets_count_all_encoded_arguments() {
        let bytes = |n| ua::Variant::ByteString(vec![0; n].into());
        let at_limit = bytes(MAX_BYTES - 5);
        assert!(check_values([&at_limit].into_iter()).is_some());
        assert!(check_values([&at_limit, &bytes(0)].into_iter()).is_none());
        assert!(check_values([&bytes(MAX_BYTES - 4)].into_iter()).is_none());
        let values = (0..=MAX_ARGS).map(|_| bytes(0)).collect::<Vec<_>>();
        assert!(check_values(values[..MAX_ARGS].iter()).is_some());
        assert!(check_values(values.iter()).is_none());
    }
}
