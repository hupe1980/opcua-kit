use super::{
    Host,
    services::{Envelope, encode, operations},
};
use crate::ua::*;
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration as Period, Instant},
};

type Result<T> = std::result::Result<T, StatusCode>;
const MAX_SUBSCRIPTIONS: usize = 4;
const MAX_ITEMS: usize = 16;
const MAX_QUEUE: u32 = 8;
const RETAINED: usize = 8;
const MAX_SAMPLE: usize = 8192;

#[derive(Default)]
pub(super) struct Subscriptions {
    next_id: u32,
    last_published: u32,
    subscriptions: BTreeMap<u32, Subscription>,
    pending: VecDeque<Pending>,
}

struct Pending {
    id: u32,
    handle: u32,
    expires: Option<Instant>,
    results: Vec<StatusCode>,
}

struct Timing {
    period: Period,
    keepalive: u32,
    lifetime: u32,
    maximum: usize,
}

impl Timing {
    fn new(interval: f64, keepalive: u32, lifetime: u32, maximum: u32) -> Result<Self> {
        Ok(Self {
            period: interval_duration(interval)?,
            keepalive: keepalive.clamp(1, 1000),
            lifetime: lifetime.min(10000).max(keepalive.clamp(1, 1000) * 3),
            maximum: if maximum == 0 {
                16
            } else {
                maximum.min(16) as usize
            },
        })
    }

    fn milliseconds(&self) -> f64 {
        self.period.as_secs_f64() * 1000.0
    }
}

fn interval_duration(ms: f64) -> Result<Period> {
    if !ms.is_finite() {
        return Err(StatusCode::BadInvalidArgument);
    }
    Ok(Period::from_secs_f64(ms.clamp(10.0, 60_000.0) / 1000.0))
}

struct Subscription {
    priority: u8,
    timing: Timing,
    enabled: bool,
    due: Instant,
    keepalive: Instant,
    expires: Instant,
    next_item: u32,
    next_sequence: u32,
    items: BTreeMap<u32, Item>,
    retained: VecDeque<NotificationMessage>,
}

struct Item {
    target: ReadValueId,
    mode: MonitoringMode,
    timestamps: TimestampsToReturn,
    client_handle: u32,
    sampling_interval: Period,
    due: Instant,
    capacity: usize,
    discard_oldest: bool,
    previous: Option<DataValue>,
    queue: VecDeque<DataValue>,
}

fn error_value(status: StatusCode) -> DataValue {
    DataValue {
        status: Some(status),
        ..DataValue::null()
    }
}

impl Item {
    fn sample(&mut self, host: &Host, now: Instant, ctx: &Context<'_>) {
        if self.mode == MonitoringMode::Disabled || self.due > now {
            return;
        }
        self.due = now + self.sampling_interval;
        let mut value = host
            .read(self.target.clone(), self.timestamps)
            .unwrap_or_else(error_value);
        if !value.encoded_len(ctx).is_ok_and(|size| size <= MAX_SAMPLE) {
            value = error_value(StatusCode::BadEncodingLimitsExceeded);
        }
        // The default data change trigger compares Status and Value.
        if self.previous.as_ref().is_some_and(|last| {
            last.status.unwrap_or_default() == value.status.unwrap_or_default()
                && last.value == value.value
        }) {
            return;
        }
        self.previous = Some(value.clone());
        if self.queue.len() == self.capacity {
            if self.discard_oldest || self.capacity == 1 {
                self.queue.pop_front();
                if let Some(next) = self.queue.front_mut() {
                    mark_overflow(next);
                }
            } else {
                self.queue.pop_back();
                mark_overflow(&mut value);
            }
        }
        self.queue.push_back(value);
    }

    fn configure(
        &mut self,
        params: MonitoringParameters,
        interval: Period,
        timestamps: TimestampsToReturn,
    ) -> Result<()> {
        if !params.filter.is_null() {
            return Err(StatusCode::BadFilterNotAllowed);
        }
        if !params.sampling_interval.is_finite() {
            return Err(StatusCode::BadInvalidArgument);
        }
        self.sampling_interval = if params.sampling_interval < 0.0 {
            interval
        } else {
            interval_duration(params.sampling_interval)?
        };
        self.timestamps = timestamps;
        self.client_handle = params.client_handle;
        self.capacity = params.queue_size.clamp(1, MAX_QUEUE) as usize;
        self.discard_oldest = params.discard_oldest;
        while self.queue.len() > self.capacity {
            if self.discard_oldest {
                self.queue.pop_front();
            } else {
                self.queue.pop_back();
            }
        }
        Ok(())
    }
}

fn mark_overflow(value: &mut DataValue) {
    // DataValue information type (bit 10) and Overflow (bit 7), Part 4 §7.38.
    value.status = Some(StatusCode::from(
        value.status.unwrap_or_default().bits() | 0x480,
    ));
}

impl Subscription {
    fn add_item(
        &mut self,
        host: &Host,
        item: MonitoredItemCreateRequest,
        timestamps: TimestampsToReturn,
        ctx: &Context<'_>,
    ) -> Result<MonitoredItemCreateResult> {
        if self.items.len() >= MAX_ITEMS {
            return Err(StatusCode::BadTooManyMonitoredItems);
        }
        if item.item_to_monitor.attribute_id != 13 {
            return Err(StatusCode::BadAttributeIdInvalid);
        }
        host.read(item.item_to_monitor.clone(), timestamps)?;
        let now = Instant::now();
        let mut monitor = Item {
            target: item.item_to_monitor,
            mode: item.monitoring_mode,
            timestamps,
            client_handle: 0,
            sampling_interval: self.timing.period,
            due: now,
            capacity: 1,
            discard_oldest: true,
            previous: None,
            queue: VecDeque::new(),
        };
        monitor.configure(item.requested_parameters, self.timing.period, timestamps)?;
        monitor.sample(host, now, ctx);
        let id = self
            .next_item
            .checked_add(1)
            .ok_or(StatusCode::BadTooManyMonitoredItems)?;
        self.next_item = id;
        let result = MonitoredItemCreateResult {
            status_code: StatusCode::Good,
            monitored_item_id: id,
            revised_sampling_interval: monitor.sampling_interval.as_secs_f64() * 1000.0,
            revised_queue_size: monitor.capacity as u32,
            filter_result: ExtensionObject::null(),
        };
        self.items.insert(id, monitor);
        Ok(result)
    }

    fn publish(&mut self, now: Instant) -> Option<(NotificationMessage, bool)> {
        if self.due > now {
            return None;
        }
        self.due = now + self.timing.period;
        let mut notifications = Vec::new();
        if self.enabled {
            for item in self
                .items
                .values_mut()
                .filter(|i| i.mode == MonitoringMode::Reporting)
            {
                let count = item
                    .queue
                    .len()
                    .min(self.timing.maximum - notifications.len());
                notifications.extend(item.queue.drain(..count).map(|value| {
                    MonitoredItemNotification {
                        client_handle: item.client_handle,
                        value,
                    }
                }));
                if notifications.len() == self.timing.maximum {
                    break;
                }
            }
        }
        let message = if notifications.is_empty() {
            if self.keepalive > now {
                return None;
            }
            NotificationMessage {
                sequence_number: self.next_sequence,
                publish_time: DateTime::now(),
                notification_data: None,
            }
        } else {
            let message = NotificationMessage {
                sequence_number: self.next_sequence,
                publish_time: DateTime::now(),
                notification_data: Some(vec![ExtensionObject::new(DataChangeNotification {
                    monitored_items: Some(notifications),
                    diagnostic_infos: None,
                })]),
            };
            self.next_sequence = self.next_sequence.checked_add(1).unwrap_or(1);
            if self.retained.len() == RETAINED {
                self.retained.pop_front();
            }
            self.retained.push_back(message.clone());
            message
        };
        let more = self.enabled
            && self
                .items
                .values()
                .any(|i| i.mode == MonitoringMode::Reporting && !i.queue.is_empty());
        if more {
            self.due = now;
        }
        self.keepalive = now + self.timing.period * self.timing.keepalive;
        Some((message, more))
    }
}

impl Subscriptions {
    fn get(&mut self, id: u32) -> Result<&mut Subscription> {
        self.subscriptions
            .get_mut(&id)
            .ok_or(StatusCode::BadSubscriptionIdInvalid)
    }

    pub fn request(
        &mut self,
        host: &Host,
        req: Envelope<'_>,
        ctx: &Context<'_>,
    ) -> Result<Vec<u8>> {
        use ObjectId::*;
        let response_header = ResponseHeader::new_good(req.handle);
        match req.id.ok_or(StatusCode::BadServiceUnsupported)? {
            CreateSubscriptionRequest_Encoding_DefaultBinary => {
                if self.subscriptions.len() >= MAX_SUBSCRIPTIONS {
                    return Err(StatusCode::BadTooManySubscriptions);
                }
                let r: CreateSubscriptionRequest = req.request(ctx)?;
                let timing = Timing::new(
                    r.requested_publishing_interval,
                    r.requested_max_keep_alive_count,
                    r.requested_lifetime_count,
                    r.max_notifications_per_publish,
                )?;
                let id = self
                    .next_id
                    .checked_add(1)
                    .ok_or(StatusCode::BadTooManySubscriptions)?;
                self.next_id = id;
                let now = Instant::now();
                let response = CreateSubscriptionResponse {
                    response_header,
                    subscription_id: id,
                    revised_publishing_interval: timing.milliseconds(),
                    revised_lifetime_count: timing.lifetime,
                    revised_max_keep_alive_count: timing.keepalive,
                };
                self.subscriptions.insert(
                    id,
                    Subscription {
                        priority: r.priority,
                        due: now + timing.period,
                        keepalive: now,
                        expires: now + timing.period * timing.lifetime,
                        timing,
                        enabled: r.publishing_enabled,
                        next_item: 0,
                        next_sequence: 1,
                        items: BTreeMap::new(),
                        retained: VecDeque::new(),
                    },
                );
                encode(response, ctx)
            }
            ModifySubscriptionRequest_Encoding_DefaultBinary => {
                let r: ModifySubscriptionRequest = req.request(ctx)?;
                let sub = self.get(r.subscription_id)?;
                sub.timing = Timing::new(
                    r.requested_publishing_interval,
                    r.requested_max_keep_alive_count,
                    r.requested_lifetime_count,
                    r.max_notifications_per_publish,
                )?;
                sub.priority = r.priority;
                let now = Instant::now();
                sub.due = now + sub.timing.period;
                sub.keepalive = now + sub.timing.period * sub.timing.keepalive;
                sub.expires = now + sub.timing.period * sub.timing.lifetime;
                encode(
                    ModifySubscriptionResponse {
                        response_header,
                        revised_publishing_interval: sub.timing.milliseconds(),
                        revised_lifetime_count: sub.timing.lifetime,
                        revised_max_keep_alive_count: sub.timing.keepalive,
                    },
                    ctx,
                )
            }
            CreateMonitoredItemsRequest_Encoding_DefaultBinary => {
                let r: CreateMonitoredItemsRequest = req.request(ctx)?;
                let sub = self.get(r.subscription_id)?;
                validate_timestamps(r.timestamps_to_return)?;
                let results = operations(r.items_to_create)?
                    .into_iter()
                    .map(|item| {
                        sub.add_item(host, item, r.timestamps_to_return, ctx)
                            .unwrap_or_else(|status_code| MonitoredItemCreateResult {
                                status_code,
                                monitored_item_id: 0,
                                revised_sampling_interval: 0.0,
                                revised_queue_size: 0,
                                filter_result: ExtensionObject::null(),
                            })
                    })
                    .collect();
                encode(
                    CreateMonitoredItemsResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )
            }
            ModifyMonitoredItemsRequest_Encoding_DefaultBinary => {
                let r: ModifyMonitoredItemsRequest = req.request(ctx)?;
                let sub = self.get(r.subscription_id)?;
                validate_timestamps(r.timestamps_to_return)?;
                let results = operations(r.items_to_modify)?
                    .into_iter()
                    .map(|item| {
                        let result = sub
                            .items
                            .get_mut(&item.monitored_item_id)
                            .ok_or(StatusCode::BadMonitoredItemIdInvalid)
                            .and_then(|monitor| {
                                monitor.configure(
                                    item.requested_parameters,
                                    sub.timing.period,
                                    r.timestamps_to_return,
                                )?;
                                Ok((
                                    monitor.sampling_interval.as_secs_f64() * 1000.0,
                                    monitor.capacity as u32,
                                ))
                            });
                        let (status_code, interval, size) = match result {
                            Ok((i, s)) => (StatusCode::Good, i, s),
                            Err(e) => (e, 0.0, 0),
                        };
                        MonitoredItemModifyResult {
                            status_code,
                            revised_sampling_interval: interval,
                            revised_queue_size: size,
                            filter_result: ExtensionObject::null(),
                        }
                    })
                    .collect();
                encode(
                    ModifyMonitoredItemsResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )
            }
            SetPublishingModeRequest_Encoding_DefaultBinary => {
                let r: SetPublishingModeRequest = req.request(ctx)?;
                let results = operations(r.subscription_ids)?
                    .into_iter()
                    .map(|id| match self.get(id) {
                        Ok(s) => {
                            s.enabled = r.publishing_enabled;
                            StatusCode::Good
                        }
                        Err(e) => e,
                    })
                    .collect();
                encode(
                    SetPublishingModeResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )
            }
            SetMonitoringModeRequest_Encoding_DefaultBinary => {
                let r: SetMonitoringModeRequest = req.request(ctx)?;
                let sub = self.get(r.subscription_id)?;
                let results = operations(r.monitored_item_ids)?
                    .into_iter()
                    .map(|id| {
                        let Some(item) = sub.items.get_mut(&id) else {
                            return StatusCode::BadMonitoredItemIdInvalid;
                        };
                        item.mode = r.monitoring_mode;
                        if item.mode == MonitoringMode::Disabled {
                            item.queue.clear();
                            item.previous = None;
                        } else {
                            item.due = Instant::now();
                        }
                        StatusCode::Good
                    })
                    .collect();
                encode(
                    SetMonitoringModeResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )
            }
            DeleteMonitoredItemsRequest_Encoding_DefaultBinary => {
                let r: DeleteMonitoredItemsRequest = req.request(ctx)?;
                let sub = self.get(r.subscription_id)?;
                let results = operations(r.monitored_item_ids)?
                    .into_iter()
                    .map(|id| {
                        if sub.items.remove(&id).is_some() {
                            StatusCode::Good
                        } else {
                            StatusCode::BadMonitoredItemIdInvalid
                        }
                    })
                    .collect();
                encode(
                    DeleteMonitoredItemsResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )
            }
            DeleteSubscriptionsRequest_Encoding_DefaultBinary => {
                let r: DeleteSubscriptionsRequest = req.request(ctx)?;
                let results = operations(r.subscription_ids)?
                    .into_iter()
                    .map(|id| {
                        if self.subscriptions.remove(&id).is_some() {
                            StatusCode::Good
                        } else {
                            StatusCode::BadSubscriptionIdInvalid
                        }
                    })
                    .collect();
                encode(
                    DeleteSubscriptionsResponse {
                        response_header,
                        results: Some(results),
                        diagnostic_infos: None,
                    },
                    ctx,
                )
            }
            RepublishRequest_Encoding_DefaultBinary => {
                let r: RepublishRequest = req.request(ctx)?;
                let notification_message = self
                    .get(r.subscription_id)?
                    .retained
                    .iter()
                    .find(|m| m.sequence_number == r.retransmit_sequence_number)
                    .ok_or(StatusCode::BadMessageNotAvailable)?
                    .clone();
                encode(
                    RepublishResponse {
                        response_header,
                        notification_message,
                    },
                    ctx,
                )
            }
            _ => Err(StatusCode::BadServiceUnsupported),
        }
    }

    pub fn enqueue(&mut self, id: u32, r: PublishRequest) -> Result<()> {
        if self.subscriptions.is_empty() {
            return Err(StatusCode::BadNoSubscription);
        }
        if self.pending.len() >= 8 {
            return Err(StatusCode::BadTooManyPublishRequests);
        }
        let results = r
            .subscription_acknowledgements
            .unwrap_or_default()
            .into_iter()
            .map(|ack| {
                let Ok(sub) = self.get(ack.subscription_id) else {
                    return StatusCode::BadSubscriptionIdInvalid;
                };
                match sub
                    .retained
                    .iter()
                    .position(|m| m.sequence_number == ack.sequence_number)
                {
                    Some(pos) => {
                        sub.retained.remove(pos);
                        StatusCode::Good
                    }
                    None => StatusCode::BadSequenceNumberUnknown,
                }
            })
            .collect();
        let timeout = r.request_header.timeout_hint;
        self.pending.push_back(Pending {
            id,
            handle: r.request_header.request_handle,
            expires: (timeout != 0).then(|| Instant::now() + Period::from_millis(timeout.into())),
            results,
        });
        Ok(())
    }

    pub fn next_wake(&self) -> Option<Instant> {
        if self.subscriptions.is_empty() && !self.pending.is_empty() {
            return Some(Instant::now());
        }
        self.subscriptions
            .values()
            .flat_map(|s| {
                s.items
                    .values()
                    .filter(|i| i.mode != MonitoringMode::Disabled)
                    .map(|i| i.due)
                    .chain([s.expires])
                    .chain((!self.pending.is_empty()).then_some(s.due))
            })
            .chain(self.pending.iter().filter_map(|p| p.expires))
            .min()
    }

    pub fn poll(
        &mut self,
        host: &Host,
        ctx: &Context<'_>,
        limit: usize,
    ) -> Result<Option<(u32, Vec<u8>)>> {
        let now = Instant::now();
        if let Some(i) = self
            .pending
            .iter()
            .position(|p| p.expires.is_some_and(|t| t <= now))
        {
            let p = self.pending.remove(i).unwrap();
            return Ok(Some((p.id, fault(p.handle, StatusCode::BadTimeout, ctx)?)));
        }
        self.subscriptions
            .retain(|_, s| s.expires > now || !self.pending.is_empty());
        let ready = !self.pending.is_empty();
        let mut selected = None;
        for (&id, sub) in &mut self.subscriptions {
            for item in sub.items.values_mut() {
                item.sample(host, now, ctx);
            }
            if !ready {
                continue;
            }
            sub.expires = now + sub.timing.period * sub.timing.lifetime;
            if sub.due > now {
                continue;
            }
            let queued = sub.enabled
                && sub
                    .items
                    .values()
                    .any(|i| i.mode == MonitoringMode::Reporting && !i.queue.is_empty());
            if !queued && sub.keepalive > now {
                sub.due = now + sub.timing.period;
                continue;
            }
            // Round-robin among subscriptions with equal priority.
            let key = (
                sub.priority,
                id > self.last_published,
                std::cmp::Reverse(id),
            );
            if selected.is_none_or(|prev| key > prev) {
                selected = Some(key);
            }
        }
        let Some(p) = self.pending.front() else {
            return Ok(None);
        };
        let response = if let Some((_, _, std::cmp::Reverse(id))) = selected {
            self.last_published = id;
            let sub = self
                .subscriptions
                .get_mut(&id)
                .ok_or(StatusCode::BadInternalError)?;
            let (message, more) = sub.publish(now).ok_or(StatusCode::BadInternalError)?;
            encode(
                PublishResponse {
                    response_header: ResponseHeader::new_good(p.handle),
                    subscription_id: id,
                    more_notifications: more,
                    notification_message: message,
                    available_sequence_numbers: Some(
                        self.subscriptions[&id]
                            .retained
                            .iter()
                            .map(|m| m.sequence_number)
                            .collect(),
                    ),
                    results: Some(p.results.clone()),
                    diagnostic_infos: None,
                },
                ctx,
            )?
        } else if self.subscriptions.is_empty() {
            fault(p.handle, StatusCode::BadNoSubscription, ctx)?
        } else {
            return Ok(None);
        };
        let p = self.pending.pop_front().unwrap();
        Ok(Some((
            p.id,
            if response.len() > limit {
                fault(p.handle, StatusCode::BadResponseTooLarge, ctx)?
            } else {
                response
            },
        )))
    }
}

fn validate_timestamps(timestamps: TimestampsToReturn) -> Result<()> {
    if timestamps == TimestampsToReturn::Invalid {
        return Err(StatusCode::BadTimestampsToReturnInvalid);
    }
    Ok(())
}

pub(super) fn fault(handle: u32, status: StatusCode, ctx: &Context<'_>) -> Result<Vec<u8>> {
    encode(
        ServiceFault {
            response_header: ResponseHeader::new_service_result(handle, status),
        },
        ctx,
    )
}
