//! SDK bindings for the Part 11 raw HistoryRead service. The pinned high-level
//! wrapper exposes generic requests; its sys dependency supplies these UA types.
use open62541::{DataType, ServiceRequest, ServiceResponse, ua};
use open62541_sys as sys;

use crate::client::wire::owned;
owned!(Request, UA_HistoryReadRequest, UA_TYPES_HISTORYREADREQUEST);
owned!(
    Response,
    UA_HistoryReadResponse,
    UA_TYPES_HISTORYREADRESPONSE
);
owned!(
    Details,
    UA_ReadRawModifiedDetails,
    UA_TYPES_READRAWMODIFIEDDETAILS
);
owned!(HistoryData, UA_HistoryData, UA_TYPES_HISTORYDATA);

impl ServiceRequest for Request {
    type Response = Response;
    fn request_header(&self) -> &ua::RequestHeader {
        ua::RequestHeader::raw_ref(&self.0.requestHeader)
    }
    fn request_header_mut(&mut self) -> &mut ua::RequestHeader {
        ua::RequestHeader::raw_mut(&mut self.0.requestHeader)
    }
}
impl ServiceResponse for Response {
    type Request = Request;
    fn response_header(&self) -> &ua::ResponseHeader {
        ua::ResponseHeader::raw_ref(&self.0.responseHeader)
    }
}

pub(super) fn request(
    node: &ua::NodeId,
    details: &Details,
    point: &[u8],
    release: bool,
) -> Result<Request, super::HistoryError> {
    let mut req = Request::init();
    ua::ExtensionObject::new(details).move_into_raw(&mut req.0.historyReadDetails);
    req.0.timestampsToReturn = sys::UA_TimestampsToReturn::UA_TIMESTAMPSTORETURN_BOTH;
    req.0.releaseContinuationPoints = release;
    // SAFETY: UA_Array_new initializes one UA_HistoryReadValueId. Request owns it until UA_clear.
    let operand =
        unsafe { sys::UA_Array_new(1, &sys::UA_TYPES[sys::UA_TYPES_HISTORYREADVALUEID as usize]) }
            .cast::<sys::UA_HistoryReadValueId>();
    let operand = unsafe { operand.as_mut() }.ok_or(super::HistoryError::Allocation)?;
    req.0.nodesToRead = operand;
    req.0.nodesToReadSize = 1;
    node.clone_into_raw(&mut operand.nodeId);
    if !point.is_empty() {
        ua::ByteString::new(point).move_into_raw(&mut operand.continuationPoint);
    }
    Ok(req)
}
