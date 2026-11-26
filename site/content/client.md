+++
title = "Connect a Rust client"
description = "Open a certificate-pinned session, read a typed variable and interpret its quality and timestamps."
weight = 1
[extra]
keywords = "read_scalar read_scalars read_many read_attributes read_definition read_engineering_units read_snapshot NodeId certificate DER"
group = "Embed the library"
+++

Use one client per authenticated server. The application owns credentials, scheduling, retries and shutdown. The default crate needs Rust 1.88+, a C compiler, CMake, Python 3 and libclang at build time. The deployed read path runs within the Rust process.

## Open a session

Add opcua-kit to your application. This guide targets version 0.1.

```sh
cargo add opcua-kit
```

Connect at startup or run the synchronous handshake on a blocking worker. Load the approved server leaf certificate, client application certificate and matching unencrypted private key as DER bytes.

```rust
use opcua_kit::{Client, ConnectError, ConnectionConfig};
use std::time::Duration;

fn connect(server_der: &[u8], client_der: &[u8], key_der: &[u8]) -> Result<Client, ConnectError> {
    Client::connect(ConnectionConfig {
        endpoint: "opc.tcp://plc.example:4840",
        server_application_uri: "urn:plant:server",
        server_certificate_der: server_der,
        client_application_uri: "urn:factory:dashboard",
        client_certificate_der: client_der,
        client_private_key_der: key_der,
        timeout: Duration::from_secs(5),
    })
}
```

This example uses the default Basic256Sha256 policy with SignAndEncrypt and an anonymous user. For named users, other supported RSA policies, and restart handling, use the [recovery guide](@/recovery.md). The server must permit that identity and trust the client application certificate. Match the URL host and configured application URIs to the appropriate certificate subject alternative names. Obtain a rotated server leaf through the site's trust process. Credentials are limited to 64 KiB each. The configured response timeout accepts 1 ms through 60 s. Set an application deadline separately when the complete polling cycle has a time budget.

## Read once or in a batch

```rust
use opcua_kit::{Client, NodeId, ReadError, Sample};

async fn poll(client: &Client, node: &NodeId) -> Result<Sample<u64>, ReadError> {
    client.read_scalar::<u64>(node).await
}
```

A NodeId identifies a node within a namespace. Store the namespace URI because a server can assign it a different numeric index after a restart. Construct nodes once with `NodeId::new(namespace_uri, identifier)?`. Identifiers accept `i=`, `s=`, `g=` and `b=`. `read_scalar` supports Boolean, signed and unsigned 8/16/32/64-bit integers, Float, Double, UTF-8 String, ByteString, Guid and DateTime. A Good value of the wrong scalar type produces a typed error. Float and Double preserve their respective precision.

## Inspect a variable before polling

Call `client.read_definition(&node).await?` to read the variable’s declared DataType and ValueRank. This uses the same pinned session and requests only those two attributes of the target. Each field carries its own outcome, full status and available clocks. A custom type is identified by namespace URI and identifier even when the server changes namespace indexes between sessions.

```rust
use opcua_kit::{Client, NodeId, ReadError};

async fn declares_scalar_u64(client: &Client, node: &NodeId) -> Result<bool, ReadError> {
    let definition = client.read_definition(node).await?;
    let ty = definition.data_type?;
    let rank = definition.value_rank?;
    Ok(ty.status == 0 && rank.status == 0 && rank.value == Some(-1)
        && ty.value.as_ref().is_some_and(|id|
            id.namespace() == "http://opcfoundation.org/UA/" && id.identifier() == "i=9"))
}
```

This example requires exact Good status and the standard UInt64 declaration. Sites using a custom DataType can compare the returned identity with their reviewed mapping. A wire-type error in one field leaves the other field available on `VariableDefinition`. A Bad or Uncertain field carries its status and an absent value. A server can declare several permitted shapes. ValueRank `-1` specifies a scalar, while `-2` permits any rank. [OPC UA Variable attributes](https://reference.opcfoundation.org/specs/OPC-10000-3/5.6.2)

For a point list with different attribute requirements, build `ReadOperand::new(&node, ReadAttribute::DataType)` or select any other standard node attribute. Pass the operands to `client.read_attributes(&operands).await?`. Results follow operand order and retain the SDK's raw wire types. Choose `read_definition` when persisting a declared type so the stored identifier has a namespace URI. Each attribute counts as one operation toward the 1,024-operand application limit and the server's per-request limit.

## Inspect engineering units

A temperature sensor can switch from Celsius to Fahrenheit while keeping the same Double wire type. Read its standard EngineeringUnits property during commissioning. The default Rust client returns an `EngineeringUnitEvidence` with the property’s stable node identity, the stage that supplied the result, and a sample containing the raw status, available clocks and programmatic unit.

```rust
use opcua_kit::{Client, EngineeringUnit, NodeId, ReadError};

async fn identified_unit(client: &Client, node: &NodeId) -> Result<Option<EngineeringUnit>, ReadError> {
    let evidence = client.read_engineering_units(node).await?;
    if evidence.sample.status != 0 {
        return Ok(None);
    }
    Ok(evidence.sample.value.filter(EngineeringUnit::is_identified))
}
```

This example returns `None` for incomplete evidence under a plain Good status policy. A returned unit can match the contract or identify a definite mismatch. Compare `namespace_uri` and `unit_id` with the reviewed mapping. An empty namespace or a unit ID of −1 means the server supplied insufficient identity information. The localized display name can vary with the server’s language. The namespace and signed ID are the fields defined for programmatic identification. [OPC UA Part 8, EUInformation](https://reference.opcfoundation.org/specs/OPC-10000-8/5.6.4.3)

| Result stage | What the client observed |
| --- | --- |
| `Browse` | The lookup ended before selecting a property. Good status with no property means the completed browse found no matching standard property. |
| `DataType` or `ValueRank` | The property was found, but a required declaration was unavailable. Its status and any clocks identify the affected read. |
| `Value` | The client verified scalar EUInformation and read the property value. Check status and identity before accepting its unit. |

The client follows one forward HasProperty relationship to the standard namespace-zero EngineeringUnits name. It checks for a unique local target and verifies its declared type and scalar rank before requesting its Value. The lookup follows continuation points from servers with small browse pages. It inspects at most 256 references across at most 256 pages. A search that exceeds either limit fails before accepting a property value. Continuation tokens are limited to 64 KiB. A malformed result envelope or oversized token retires the session. Disconnect and reconnect before the next inspection. These limits apply after the SDK decodes the response. The signal’s process value is outside this operation. A conflicting declaration or ambiguous target fails the inspection. The application supplies the physical meaning of the variable.

## Inspect a signal contract

With the default client and the `commissioning` feature, parse the gateway’s reviewed contract once and use the pinned session to collect a schema-v1 snapshot. A contract can describe any combination of variables, such as a fan state, pressure and supply temperature.

```rust
use opcua_kit::{Client, SnapshotReadError};
use opcua_kit::commissioning::{Contract, Snapshot};

async fn commission(client: &Client, contract: &Contract) -> Result<Snapshot, SnapshotReadError> {
    client.read_snapshot(contract).await
}
```

The contract must select the authenticated server application URI and the session principal (anonymous or `username:<account>`). Results follow contract order. DataType is always requested for resolved signals. ValueRank and the standard EngineeringUnits property are inspected when the contract requests them. Before reading a unit property's Value, the client verifies its identity, declared type and rank, and checks it against every contracted process node. The three standard bootstrap nodes ServerArray, NamespaceArray and MaxNodesPerRead are reserved.

Pass the result to `commissioning::assess`, or save it with Serde for a follow-up comparison. A missing namespace yields an identity-only row. A completed operation with no usable payload retains its status. A malformed response, unsafe property, session failure or size overflow returns a typed error and discards the partial capture. The compact snapshot including its final newline fits 4 MiB. This limit applies after SDK decoding. Reads share a serialized session and can observe changes between requests. A host can set its own deadline around the future. [Field workflow](@/capture.md#capture-with-the-native-client) · [Evidence schema](@/automation.md)

## Poll several variables

Use `read_scalars::<T>` when the configured points share a wire type. The outer result represents the polling call. The inner result represents decoding that particular node. A missing node in a known namespace returns a sample carrying its original status. A Good value of another wire type returns an item error. The caller can still use its siblings.

```rust
use opcua_kit::{Client, NodeId, ReadError};

async fn inspect(client: &Client, nodes: &[NodeId]) -> Result<(), ReadError> {
    let readings = client.read_scalars::<u64>(nodes).await?;
    for (node, reading) in nodes.iter().zip(readings) {
        let id = node.identifier().escape_debug();
        match reading {
            Ok(sample) => println!("{id} status=0x{:08X} value={:?}", sample.status, sample.value),
            Err(error) => eprintln!("{id} {error}"),
        }
    }
    Ok(())
}
```

For mixed wire types, call `client.read_many(&nodes).await?` and decode each member with `Sample::<T>::from_raw`. Both APIs accept up to 1,024 nodes per call, preserve duplicates and return results in input order. This count bounds operations. Raw reads retain the complete returned values, including arrays. For fixed-width registers, typed polling releases each raw response after decoding its samples. An empty input succeeds locally. The client resolves every namespace before the first target read. An unknown namespace reports its input index.

The client discovers `MaxNodesPerRead` for the authenticated session and splits the call into sequential Read requests. A server advertising two operations receives five target reads in groups of two, two and one. A missing value, zero limit, or Uncertain or Bad item status selects one request per point. A present limit with Good severity must be a UInt32 scalar. A different type fails discovery before any target is read. Different requests can observe different instants. Use each node's clocks when correlating signals. [OPC UA operation limits](https://reference.opcfoundation.org/specs/OPC-10000-5/6.3.11)

A failed service request discards accumulated results. After a service failure, channel change, or cancellation during dispatch, reconnect before retrying. A per-node Bad status leaves the session usable. The response timeout applies to individual requests. If the plant needs a deadline for the entire poll, wrap the call in the application's timeout. Call `client.disconnect().await` at shutdown.

## Interpret a sample

| Field | Meaning for the application |
| --- | --- |
| `status` | Full unsigned 32-bit StatusCode, including informational flags. Omitted wire status maps to Good (0). |
| `value` | A scalar at its wire precision. A missing value or Uncertain/Bad severity yields `None`. Apply the quality policy appropriate to the signal. |
| `source_timestamp` | Optional source clock. Use the source's measurement time when correlating values across devices. |
| `server_timestamp` | Optional server clock. Keep it distinct from source and application receipt time. |

Both timestamp fields retain the base in Unix nanoseconds and the optional increment in 10 ps units. Call `to_datetime()` to get an exact UTC `time::OffsetDateTime`; it returns an error when the instant falls between nanoseconds or outside its range. The wire fields remain available for your own storage policy. [OPC UA DataValue](https://reference.opcfoundation.org/specs/OPC-10000-4/7.11)

## Try the same session from a terminal

Install the field tool with `cargo install opcua-kit --locked --features cli`.

```sh
opcua-kit read --endpoint opc.tcp://plc.example:4840 \
  --server-uri urn:plant:server --server-cert server.der \
  --client-uri urn:factory:dashboard --client-cert client.der --client-key client-key.der \
  --namespace urn:plant:line-1 --id s=PartsProduced
```

The command prints one JSON record for a present UInt64 with status 0. Any other status, missing value, type mismatch or connection error exits 1 with a diagnostic on stderr and leaves stdout empty. Applications using the library can apply their own policy to the full status. Keep the value as an integer when decoding JSON, especially above 2⁵³. Use the commissioning collector to capture a contract’s metadata. [Capture guide](@/capture.md)

To inspect a mapping without sampling its process value, use `opcua-kit describe` with the same connection and node arguments. A complete response for a standard scalar UInt64 looks like this.

```json
{"dataType":{"status":0,"value":{"namespace":"http://opcfoundation.org/UA/","id":"i=9"}},"valueRank":{"status":0,"value":-1}}
```

Exit 0 means both attributes were available. Exit 3 prints the same JSON shape with a null value and the original status for each unavailable field. Exit 1 means configuration, connection, service or decoding failed and stdout is empty.

To inspect the units on a supply temperature sensor, run the following command.

```sh
opcua-kit describe --units --endpoint opc.tcp://plc.example:4840 \
  --server-uri urn:plant:server --server-cert server.der \
  --client-uri urn:factory:dashboard --client-cert client.der --client-key client-key.der \
  --namespace urn:plant:line-1 --id s=SupplyTemperature
```

The additional `engineeringUnits` object contains the stage, property NodeId, raw status and value. For example, a Celsius property can return this object.

```json
{"stage":"value","property":{"namespace":"urn:plant:line-1","id":"s=SupplyTemperature.EngineeringUnits"},"status":0,"value":{"namespaceUri":"http://www.opcfoundation.org/UA/units/un/cefact","unitId":4408652}}
```

With `--units`, exit 0 requires an identified unit and both definition fields. Exit 3 preserves incomplete evidence, including a missing property or an unidentified unit. Exit 1 leaves stdout empty when the inspection fails.
