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

Each client supports eight active handles. Each local queue holds 32 notifications. The server must grant a queue size of 2–32 so it can signal overflow. A Variant exceeding 128 KiB ends the stream with `ValueLimit` before queuing.

`LocalOverflow` means the application fell behind. `ServerOverflow(raw_status)` means the server reported discarded changes. Both end the handle. Read the current value before resubscribing. If the session failed, reconnect first. [OPC UA monitored-item queuing](https://reference.opcfoundation.org/specs/OPC-10000-4/5.13.1.5)

**Delivery scope.** A sampled notification stream can miss physical transitions between samples. The sequenced data-change API exposes Publish sequence numbers and can recover notifications retained on the same subscription. [OPC UA Publish](https://reference.opcfoundation.org/specs/OPC-10000-4/5.14.5) · [OPC UA Republish](https://reference.opcfoundation.org/specs/OPC-10000-4/5.14.6)

[Sequenced data-change example](@/services.md#preserve-notification-sequence-and-recover-retained-messages) · [Alarm events and condition handling](@/services.md#receive-events-and-alarm-transitions)
