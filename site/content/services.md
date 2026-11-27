+++
title = "Protocol roles and services"
description = "Monitor events, issue a Write or Call, host read-only variables and encode a UADP dataset."
weight = 3
[extra]
keywords = "pubsub server control UADP Republish Events ConditionRefresh Acknowledge Confirm monitored items subscribe_many"
group = "Embed the library"
+++

The default build implements discovery and UADP in Rust. Enable the `client` feature to browse and observe a server. Add `control` when application code needs Write or Method Call. Enable the `server` feature to expose host-owned variables. An application can combine these features. CEMS adds its meter contract and interval logic independently.

## Observe a group of signals

Start one subscription for the group. The index identifies the exact input position, even when two entries select the same node. Construction either returns the complete group or releases the items created before a rejection.

```rust
use opcua_kit::{Client, NodeId, SubscriptionError};
use std::time::Duration;

async fn sample(client: &Client, nodes: &[NodeId]) -> Result<(), SubscriptionError> {
    let mut group = client.subscribe_many(nodes, Duration::from_millis(250)).await?;
    let change = group.next(Duration::from_secs(5)).await?;
    println!("{} {:?}", nodes[change.index].identifier(), change.value);
    Ok(())
}
```

Select 1–32 items per group. Inspect `items()` for the revised sampling parameters. Each client supports eight active groups. A wait timeout leaves the group usable. Local queue overflow, an oversized value, a server overflow report or loss of the session ends the stream. Resubscribe and record the gap. Each change identifies its monitored item. Use a sequenced subscription when the application needs Publish sequence numbers. [Subscription delivery](@/navigation.md)

### Preserve notification sequence and recover retained messages

Use `SequencedDataChanges::connect(config, options, nodes, interval).await` when the host needs the OPC UA NotificationMessage sequence as well as the input index. This opens a dedicated pinned session. Its `next(wait)` returns a `Sequenced<DataChange>` containing the sequence number, a `republished` flag and the indexed value. Several values can share a sequence number. Events expose the same provenance through `next_with_sequence`.

When a Publish response identifies a gap, the stream requests up to eight consecutive retained messages through Republish and delivers them in order. An unavailable message or a larger gap yields `PublishError::SequenceGap`. Each response supports 32 notifications of up to 128 KiB each, with a 4 MiB total projection budget per repair round.

Republish can recover a lost message only while the server retains it on the same subscription. Monitor item queue overflow separately. After an endpoint restart or certificate cutover, reconnect and reconcile the gap. Use `disconnect().await` to wait for closure. Dropping a stream schedules best-effort cleanup on its creating runtime. [OPC UA Republish](https://reference.opcfoundation.org/specs/OPC-10000-4/5.14.6)

## Inspect metadata and values

`client.read_attributes` accepts 27 standard node attributes. Select `DisplayName`, `AccessLevel` and `Historizing` to inspect a variable before reading it. Check each returned status because attributes depend on the node class and the session’s access rights. Typed scalar reads also support ByteString as `Vec<u8>`, Guid as `uuid::Uuid` and DateTime as `time::OffsetDateTime`. Raw reads retain the original Variant for custom types.

## Write a value or call a method

Run `cargo add opcua-kit --features control` and construct a `Control` from an authenticated client. Stable node IDs resolve on the same session. Each invocation dispatches at most one Write or Call.

```rust
use opcua_kit::{Client, Control, ControlError, NodeId};

async fn update_label(client: &Client, label: &NodeId) -> Result<u32, ControlError> {
    Control::new(client).write_scalar(label, String::from("Line A")).await
}
```

The returned integer is the full operation StatusCode. For a method, call `control.call_method(&object, &method, &inputs)` and inspect its status, input statuses and outputs. Enabling the feature does not grant server permissions. An indeterminate result means the server may already have applied the request. Reconcile application state before deciding whether to retry. Cancellation after dispatch also leaves the outcome unknown. [OPC UA Write](https://reference.opcfoundation.org/specs/OPC-10000-4/5.11.4) · [OPC UA Call](https://reference.opcfoundation.org/specs/OPC-10000-4/5.12.2)

## Rotate a server certificate

Provision the successor DER leaf independently, verify its host and application URI, and set the last UTC second when the old pin may establish a new connection. Pass `CertificateRollover { replacement_der, original_valid_until }` to `Client::connect_with_rollover` or `RecoveringClient::new_with_rollover`. Both leaves are checked against their own validity periods. The selected leaf stays fixed throughout each handshake. The deadline governs new handshakes. The host can disconnect existing sessions when its deployment requires immediate cutover.

## Serve a host-owned variable

Run the local example with `cargo run --locked --no-default-features --features server --example local_server`. Browse the application namespace with a second OPC UA client. Enter a UInt64 on stdin to update the counter. EOF requests shutdown. The loopback endpoint accepts local anonymous reads. Peers can browse, read and monitor the counter. The host controls its value through the typed variable handle.

For an encrypted listener, construct `Server::secure` with a `SecureServerConfig`. Supply an explicit bind address, the server application URI, its DER certificate and private key, and a separately reviewed client application URI and leaf. It serves Basic256Sha256 with SignAndEncrypt. Use `Server::secure_with_policy` to select an AES128 or AES256 RSA policy for the listener. Clients authenticate with their application certificates and use an anonymous user token. Local and secure servers both expose host-owned, read-only variables. Review accepted client identities before changing deployment configuration.

## Exchange a UADP dataset

UA Datagram Protocol (UADP) encodes OPC UA PubSub messages for transmission. To try one key frame locally, run this command in your Rust binary project.

```sh
cargo add opcua-kit --no-default-features --features pubsub
```

Put the following in `src/main.rs` and run `cargo run`. The example encodes a running flag and a parts counter, then decodes both from the resulting bytes.

```rust
use opcua_kit::pubsub::{DataSetId, Field, FrameError, KeyFrame};
use std::num::NonZeroU16;

fn main() -> Result<(), FrameError> {
    let frame = KeyFrame {
        id: DataSetId {
            publisher: NonZeroU16::new(12).unwrap(),
            writer_group: NonZeroU16::new(34).unwrap(),
            writer: NonZeroU16::new(56).unwrap(),
        },
        sequence: 1,
        fields: vec![Field::Boolean(true), Field::UInt64(42)],
    };
    let bytes = frame.encode()?;
    assert_eq!(KeyFrame::decode(&bytes)?, frame);
    Ok(())
}
```

The codec builds with `no_std` and an allocator. Construct a `pubsub::KeyFrame` with nonzero UInt16 publisher, writer-group and writer IDs, a wrapping UInt16 sequence, and 1–64 ordered Boolean or numeric fields. `encode()` produces a complete datagram and `KeyFrame::decode(bytes)` validates the entire frame. The maximum encoded size is 591 bytes.

The host agrees on field order and types, verifies routing identifiers, tracks sequence and supplies transport security. The unsigned key-frame profile provides no sender authentication. Additional headers, signed messages, deltas and metadata frames return errors. The `uadp` example and independent peer exchange both directions over local UDP. [OPC UA Part 14](https://reference.opcfoundation.org/specs/OPC-10000-14/7.2.4.5.5)

## Receive events and alarm transitions

Construct an `EventField` for each field your application needs. For standard fields use `EventField::base("EventId")?`, `EventField::base("Time")?` or `EventField::base("Severity")?`. For alarm-specific fields supply the declaring type and a relative path, for example the AlarmConditionType and the qualified path `ActiveState/Id`. An empty path requests the instance’s NodeId. Servers can return null for an inapplicable selected field.

```rust
use opcua_kit::{ConnectionConfig, ConnectionOptions, EventField, Events, NodeId};
use std::time::Duration;

async fn next_severity(
    config: ConnectionConfig<'_>, notifier: &NodeId,
) -> Result<(), Box<dyn std::error::Error>> {
    let fields = [EventField::base("Severity")?];
    let mut events = Events::connect(
        config, ConnectionOptions::default(), notifier, &fields, Duration::from_millis(100),
    ).await?;
    let values = events.next(Duration::from_secs(5)).await?;
    println!("severity = {:?}", values[0]);
    events.disconnect().await;
    Ok(())
}
```

The stream establishes its own pinned session for Publish and acknowledgements. Use `Events::connect_with_rollover` during a planned certificate replacement. It checks sequence continuity, recognizes a standard event queue overflow and ends on malformed or oversized data. Consume it regularly. An idle wait timeout is retryable and cancellation retains an outstanding Publish request. Reconnect and reconcile after an explicit gap. Same-session Republish can recover a bounded set of retained messages. Subscription transfer across sessions is outside this implementation. [OPC UA Publish](https://reference.opcfoundation.org/specs/OPC-10000-4/5.14.5)

### Refresh or acknowledge a condition

Select `EventField::condition_id()` alongside `EventField::base("EventId")?`. Resolve the returned condition NodeId with `events.stable_node(...)` while its originating event session is live. Keep the opaque EventId from the particular event or branch the operator selected. A later transition can issue a different EventId for the same condition.

With the `control` feature, call `events.refresh_conditions().await` on the event subscription to request retained conditions. Refresh start and end notifications delimit the response. Use `Control::acknowledge_condition` or `Control::confirm_condition` with the condition instance, its event ID and an optional localized comment. Inspect the method’s returned StatusCode. A lost response requires checking current condition state before attempting another action. [OPC UA Alarms and Conditions](https://reference.opcfoundation.org/specs/OPC-10000-9/5.7.3)
