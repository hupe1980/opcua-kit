# opcua-kit

Embed OPC Unified Architecture (OPC UA) in a Rust application. Use the client to browse an address space, read typed signals, subscribe to changes and events, or retrieve raw history. Optional features add control, server hosting and PubSub. The client and server use open62541. The standalone UADP codec runs on Rust targets with `no_std` and an allocator.

[Documentation](https://hupe1980.github.io/opcua-kit/documentation/) · [API reference](https://docs.rs/opcua-kit) · [Runnable examples](https://github.com/hupe1980/opcua-kit/tree/main/examples)

## Read a variable

Building the native client or server requires Rust 1.88+, a C toolchain, CMake, Python 3 and libclang.

```sh
cargo add opcua-kit
```

```rust
use opcua_kit::{Client, NodeId, ReadError, Sample};

async fn parts_produced(client: &Client, counter: &NodeId) -> Result<Sample<u64>, ReadError> {
    client.read_scalar(counter).await
}
```

Identify the counter with its namespace URI and an identifier such as `s=PartsProduced`. The client resolves the server’s numeric namespace index for each session. A sample retains the full status, optional value and available source and server timestamps.

To run the read example from the opcua-kit repository, supply its approved certificate and application URI, your client credentials and a UInt64 node. The example opens an encrypted session, reads the node and disconnects. [Connection guide](site/content/client.md) · [Example source](examples/read.rs)

```sh
cargo run --locked --example read -- opc.tcp://plc.example:4840 urn:plant:server \
  server.der urn:factory:dashboard client.der client-key.der urn:factory:line-1 s=PartsProduced
```

## Choose Cargo features

| Feature | Use it for |
| --- | --- |
| `client` (default) | Authenticated OPC TCP sessions, reads, browsing, subscriptions, events and history |
| `control` | Writes, method calls and alarm acknowledgement or confirmation on a client session |
| `server` | Hosting read-only variables that your application updates |
| `pubsub` | Encoding and decoding unsigned UADP scalar key frames over a host-provided transport |
| `commissioning` | Checking types, dimensions and engineering units against a signal contract |
| `cems` | Collecting import-meter readings and reconciling them with independent interval closes |
| `cli` | Running the client and commissioning commands from a terminal |

Pass `--no-default-features` to `cargo add` for standalone server, codec or offline builds. With every feature disabled, the crate exposes a dependency-free `no_std` status classifier. Browse the API for your selected features with `cargo doc -p opcua-kit --open`.

## Run an example offline

```sh
cargo install opcua-kit --locked --features cli
opcua-kit demo --scenario units
```

The demo’s example sensor changes from Celsius to Fahrenheit while keeping its Double type. The comparison reports the mismatch and exits 2. [Signal contracts](site/content/authoring.md) · [CI decisions](site/content/automation.md)

For meter commands, install with `--features cli,cems`. The projection example runs entirely in process. [Meter guide](site/content/meter.md) · [Rust example](examples/project_meter.rs)

For peer interoperability tests, dependency provenance and packaged builds, see [Contributing](CONTRIBUTING.md).
