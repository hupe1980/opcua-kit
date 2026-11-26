+++
title = "Browse and subscribe"
description = "Find a node by browse path and receive sampled changes through a bounded subscription."
weight = 2
[extra]
keywords = "browse_children resolve_path subscribe NodeId data changes"
group = "Embed the library"
+++

Use a pinned `Client` to find a local node by a namespace-qualified browse name and subscribe to its sampled Value. Store the resulting URI-qualified `NodeId` when commissioning the device. Namespace indexes and display labels can change between servers or sessions.

## Find a child

`browse_children` lists one level of forward `HierarchicalReferences`, including subtypes such as `Organizes`, `HasComponent` and `HasProperty`. Each entry includes the stable target, qualified browse name, reference type and node class. The browse-name namespace can differ from the target NodeId namespace. The operation uses metadata services and leaves process Values untouched.

```rust
use opcua_kit::{BrowseError, BrowseName, Client, NodeId};

async fn find_counter(client: &Client, device: &NodeId) -> Result<NodeId, BrowseError> {
    let selected = [
        BrowseName::new("urn:plant:line-1", "Measurements")?,
        BrowseName::new("urn:plant:line-1", "PartsProduced")?,
    ];
    client.resolve_path(device, &selected).await
}
```

Use one to sixteen components. Matching is case-sensitive and requires exactly one matching reference per component. `NotFound(index)` and `Ambiguous(index)` identify the zero-based component. For interactive selection, use `browse_children` and inspect each returned name and node class.

A listing accepts up to 256 references and 1 MiB of retained identifier/name text. A complete path shares a limit of 256 pages. The client follows continuation points on the same session and releases an outstanding point on a rejected page where possible. A nonzero Browse operation status, remote target, unusable reference or exceeded limit fails the operation. [OPC UA Browse and BrowseNext](https://reference.opcfoundation.org/specs/OPC-10000-4/5.9)

## Observe a sampled Value

```rust
use opcua_kit::{Client, NodeId, Sample, SubscriptionError};
use std::time::Duration;

async fn watch(client: &Client, counter: &NodeId) -> Result<(), SubscriptionError> {
    let mut updates = client.subscribe(counter, Duration::from_millis(250)).await?;
    loop {
        match updates.next(Duration::from_secs(5)).await {
            Ok(raw) => {
                let sample = Sample::<u64>::from_raw(&raw)?;
                println!("status=0x{:08X} value={:?}", sample.status, sample.value);
            }
            Err(SubscriptionError::Timeout) => continue,
            Err(error) => return Err(error),
        }
    }
}
```

The requested interval sets both sampling and publishing and accepts 10 milliseconds through 60 seconds. Inspect `sampling_interval()`, `publishing_interval()` and `server_queue_size()` for the negotiated settings. The first notification normally reports the initial value or status. A subsequent quiet period can simply mean the sampled value is unchanged. Each raw DataValue retains the status and clocks supplied by the peer. Drop the handle to request deletion of the monitored item and subscription. Disconnect the client explicitly at shutdown.

Use `subscribe_many` to monitor up to 32 items on one subscription. Notifications identify the original input position. [Group monitoring](@/services.md#observe-a-group-of-signals)

One client permits eight active handles and each local queue holds 32 notifications. A Variant larger than 128 KiB in UA binary encoding ends the handle with `ValueLimit` before it enters the queue. This bounds retained payloads after the SDK decodes a notification. The peer receives a request for a 32-entry monitored-item queue. Its revised size must be between 2 and 32 because a server queue of one can replace values without signaling overflow. A full local queue produces `LocalOverflow`. A peer's DataValue Overflow flag produces `ServerOverflow(raw_status)`. Either terminates that handle. Closure and detected session loss also terminate delivery. Drop the handle, establish a fresh session after a session failure, and read a current value before monitoring again. [OPC UA monitored-item queuing](https://reference.opcfoundation.org/specs/OPC-10000-4/5.13.1.5)

**Delivery scope.** A sampled notification stream can miss physical transitions between samples. The SDK's monitored-item callback supplies a DataValue and omits the Publish sequence number and available retransmission numbers. The application therefore cannot verify continuity of Publish messages, detect every upstream gap, or perform sequence-aware Republish through this API. [OPC UA Publish](https://reference.opcfoundation.org/specs/OPC-10000-4/5.14.5) · [OPC UA Republish](https://reference.opcfoundation.org/specs/OPC-10000-4/5.14.6)

Use the [sequenced data-change API](@/services.md#preserve-notification-sequence-and-recover-retained-messages) when an application needs Publish sequence numbers and bounded same-session Republish.

For alarm events and condition handling, see the [event stream guide](@/services.md#receive-events-and-alarm-transitions).
