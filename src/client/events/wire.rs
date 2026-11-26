//! Typed service envelopes for services the high-level SDK does not expose.
use crate::client::wire::owned;
use open62541::{DataType, ServiceRequest, ServiceResponse, ua};
use open62541_sys as sys;

macro_rules! service {
    ($req:ident, $raw_req:ident, $req_ty:ident, $res:ident, $raw_res:ident, $res_ty:ident) => {
        owned!($req, $raw_req, $req_ty);
        owned!($res, $raw_res, $res_ty);
        impl ServiceRequest for $req {
            type Response = $res;
            fn request_header(&self) -> &ua::RequestHeader {
                ua::RequestHeader::raw_ref(&self.0.requestHeader)
            }
            fn request_header_mut(&mut self) -> &mut ua::RequestHeader {
                ua::RequestHeader::raw_mut(&mut self.0.requestHeader)
            }
        }
        impl ServiceResponse for $res {
            type Request = $req;
            fn response_header(&self) -> &ua::ResponseHeader {
                ua::ResponseHeader::raw_ref(&self.0.responseHeader)
            }
        }
    };
}
service!(
    CreateSubscription,
    UA_CreateSubscriptionRequest,
    UA_TYPES_CREATESUBSCRIPTIONREQUEST,
    CreatedSubscription,
    UA_CreateSubscriptionResponse,
    UA_TYPES_CREATESUBSCRIPTIONRESPONSE
);
service!(
    CreateItems,
    UA_CreateMonitoredItemsRequest,
    UA_TYPES_CREATEMONITOREDITEMSREQUEST,
    CreatedItems,
    UA_CreateMonitoredItemsResponse,
    UA_TYPES_CREATEMONITOREDITEMSRESPONSE
);
service!(
    Publish,
    UA_PublishRequest,
    UA_TYPES_PUBLISHREQUEST,
    Published,
    UA_PublishResponse,
    UA_TYPES_PUBLISHRESPONSE
);
owned!(
    EventList,
    UA_EventNotificationList,
    UA_TYPES_EVENTNOTIFICATIONLIST
);
owned!(
    StatusChange,
    UA_StatusChangeNotification,
    UA_TYPES_STATUSCHANGENOTIFICATION
);
owned!(
    FilterResult,
    UA_EventFilterResult,
    UA_TYPES_EVENTFILTERRESULT
);

service!(
    Republish,
    UA_RepublishRequest,
    UA_TYPES_REPUBLISHREQUEST,
    Republished,
    UA_RepublishResponse,
    UA_TYPES_REPUBLISHRESPONSE
);
owned!(
    DataChangeList,
    UA_DataChangeNotification,
    UA_TYPES_DATACHANGENOTIFICATION
);
pub(super) fn publish(subscription: u32, acks: &[u32], timeout_ms: u32) -> Option<Publish> {
    let mut req = Publish::init();
    req.0.requestHeader.timeoutHint = timeout_ms;
    if !acks.is_empty() {
        // SAFETY: the request takes ownership of exactly acks.len() initialized SDK records.
        let p = unsafe {
            sys::UA_Array_new(
                acks.len(),
                &sys::UA_TYPES[sys::UA_TYPES_SUBSCRIPTIONACKNOWLEDGEMENT as usize],
            )
        }
        .cast::<sys::UA_SubscriptionAcknowledgement>();
        if p.is_null() {
            return None;
        }
        req.0.subscriptionAcknowledgements = p;
        req.0.subscriptionAcknowledgementsSize = acks.len();
        for (entry, &sequence) in unsafe { std::slice::from_raw_parts_mut(p, acks.len()) }
            .iter_mut()
            .zip(acks)
        {
            entry.subscriptionId = subscription;
            entry.sequenceNumber = sequence;
        }
    }
    Some(req)
}

pub(super) async fn create_subscription(
    client: &crate::Client,
    session: &mut crate::client::ReadSession,
    interval: std::time::Duration,
) -> Result<(u32, u32), super::EventError> {
    use crate::SubscriptionError;
    let mut create = CreateSubscription::init();
    create.0.requestedPublishingInterval = interval.as_secs_f64() * 1000.;
    create.0.requestedLifetimeCount = 60;
    create.0.requestedMaxKeepAliveCount = 5;
    create.0.maxNotificationsPerPublish = 32;
    create.0.publishingEnabled = true;
    let reply = client
        .guarded(session, client.inner.service_request(create))
        .await?;
    let r = &reply.0;
    let keep_alive_ms = r.revisedPublishingInterval * f64::from(r.revisedMaxKeepAliveCount);
    if r.subscriptionId == 0
        || !(0.0..=60_000.).contains(&r.revisedPublishingInterval)
        || r.revisedPublishingInterval == 0.
        || !(0.0..=600_000.).contains(&keep_alive_ms)
        || keep_alive_ms == 0.
        || r.revisedLifetimeCount < r.revisedMaxKeepAliveCount.saturating_mul(3)
    {
        return Err(SubscriptionError::InvalidRevision.into());
    }
    Ok((r.subscriptionId, (keep_alive_ms.ceil() as u32) * 2 + 1000))
}
pub(super) async fn create_items(
    client: &crate::Client,
    session: &mut crate::client::ReadSession,
    subscription: u32,
    items: &[ua::MonitoredItemCreateRequest],
) -> Result<CreatedItems, super::EventError> {
    let mut request = ua::CreateMonitoredItemsRequest::init().with_items_to_create(items);
    // SAFETY: this request owns its initialized wrapper and item array.
    let r = unsafe { request.as_mut() };
    r.subscriptionId = subscription;
    r.timestampsToReturn = sys::UA_TimestampsToReturn::UA_TIMESTAMPSTORETURN_BOTH;
    Ok(client
        .guarded(
            session,
            client
                .inner
                .service_request(CreateItems(request.into_raw())),
        )
        .await?)
}
