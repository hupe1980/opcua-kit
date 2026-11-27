# opcua-kit

Embed OPC UA in a Rust application. Connect to a PLC over an encrypted UA TCP session, subscribe to changes, or expose your application's variables through a read-only server. The protocol stack is implemented in Rust. Endpoint discovery and the UADP codec have no third-party dependencies.

[Documentation](https://hupe1980.github.io/opcua-kit/documentation/) · [API reference](https://docs.rs/opcua-kit) · [Examples](https://github.com/hupe1980/opcua-kit/tree/main/examples)

## Read a variable

Enable the client in a project using Rust 1.88 or newer.

```sh
cargo add opcua-kit --features client
```

Open a session with the approved server certificate and your application's credentials. Reuse that client for subsequent reads. Identify a variable by its namespace URI so the same code works if the server assigns a different namespace index after a restart.

```rust
use opcua_kit::{Client, NodeId, Sample};
use std::error::Error;

async fn parts_produced(client: &Client) -> Result<Sample<u64>, Box<dyn Error>> {
    let counter = NodeId::new("urn:factory:line-1", "s=PartsProduced")?;
    Ok(client.read_scalar(&counter).await?)
}
```

The returned sample carries the OPC UA status, optional value, and any source and server timestamps. The runnable example includes certificate setup, a batch read, and session shutdown. [Connection guide](https://hupe1980.github.io/opcua-kit/client/) · [Read example](examples/read.rs)

## Choose a protocol role

`cargo add opcua-kit` enables `discovery` and `pubsub`. Select other features for the services your application uses.

| Feature | What it provides |
| --- | --- |
| `discovery` | List endpoints and their advertised security and user-token policies. |
| `pubsub` | Encode and decode unsigned UADP scalar key frames over a transport you supply. |
| `client` | Open certificate-pinned sessions, browse nodes, read values and history, and subscribe to data changes and events. |
| `control` | Write values, call methods, and acknowledge or confirm alarms through an authenticated client. |
| `server` | Serve read-only variables that your application updates and clients can monitor. |
| `commissioning` | Check declared types, ranks, and engineering units against a signal contract. |
| `cems` | Build an interval trace from import-meter readings and independent closes. Add `client` for live acquisition. |
| `cli` | Inspect endpoints, capture metadata, and check contracts from the terminal. |

For an embedded UADP codec, use `cargo add opcua-kit --no-default-features --features pubsub`. This build supports `no_std` with an allocator. With every feature disabled, the crate exposes a dependency-free status classifier.

## Try the CLI offline

```sh
cargo install opcua-kit --locked --features cli
opcua-kit demo --scenario units
```

The demo changes a sensor's engineering unit from Celsius to Fahrenheit while its data type stays the same. Exit code 2 means the check detected the mismatch. For a live device, use `capture --preflight` to check the contract and credentials locally before collecting metadata. Install with `--features cli,cems` for meter commands. [Capture guide](https://hupe1980.github.io/opcua-kit/capture/) · [Meter guide](https://hupe1980.github.io/opcua-kit/meter/)

## License

You may use the project's original code under either the MIT License or the Apache License, Version 2.0. [MIT](LICENSE-MIT) · [Apache-2.0](LICENSE-APACHE)

The generated OPC UA service definitions and status codes use data from the OPC Foundation's UA-Nodeset schema. The crate includes the upstream copyright and MIT permission notice for that material. [OPC Foundation notice](LICENSE-OPC-Foundation) · [Upstream schema](https://github.com/OPCFoundation/UA-Nodeset/blob/ed0b821f6a6f1f0c440c442ed95a9146ae8b7f8d/Schema/Opc.Ua.Types.bsd)
