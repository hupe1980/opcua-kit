+++
title = "Recovery and history"
description = "Reconnect after a PLC restart, read retained history and request part of an array."
weight = 4
[extra]
keywords = "RecoveringClient HistoryRead NumericRange read_history read_array_range discovery username"
group = "Embed the library"
+++

A restarted server can assign new namespace indexes and lose its subscriptions. Open a fresh session, then use retained history to fill gaps when the variable supports it.

## Choose the endpoint and account

Run discovery on the operator’s explicit OPC TCP address. It uses a discovery channel without opening a user session. The returned URLs, security policies, application URIs, and user-token policies are advertised information. Verify the selected server’s identity and certificate through the site’s trust process.

```sh
opcua-kit discover --endpoint opc.tcp://plc.example:4840
```

For a PLC requiring a named operator, put its UTF-8 password in a restricted file. The CLI removes one trailing LF or CRLF. Browse one level underneath Objects with the selected policy. Each child has a stable node ID and a namespace-qualified browse name.

```sh
opcua-kit browse --endpoint opc.tcp://plc.example:4840 --server-uri urn:plant:plc \
  --server-cert server.der --client-uri urn:factory:dashboard --client-cert client.der \
  --client-key client-key.der --username plant-reader --password-file reader.secret \
  --security-policy Aes256_Sha256_RsaPss --namespace http://opcfoundation.org/UA/ --id i=85
```

`Client::connect_with` accepts `ConnectionOptions` for the same policy and user choices. The supported RSA channel policies are Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss, all with SignAndEncrypt. A failed policy, pin or user check fails the connection. A native contract for this example uses `"principal":"username:plant-reader"`. The client certificate identifies the application independently of the user. [OPC UA GetEndpoints](https://reference.opcfoundation.org/specs/OPC-10000-4/5.5.4)

## Resume polling after a PLC restart

Keep a `RecoveringClient` in the gateway driver. Each `session().await` reuses a healthy client or attempts one fresh pinned connection. The handshake runs on a blocking worker. On a fresh connection, the library verifies the server again and obtains the new namespace mapping and effective read limit. The host sets the interval between attempts. Dropping a wait leaves the pending attempt available for the next call.

```rust
use opcua_kit::{ConnectionConfig, ConnectionOptions, RecoveringClient, UserIdentity, SecurityPolicy};

fn driver<'a>(config: ConnectionConfig<'a>, password: &'a str) -> RecoveringClient<'a> {
    RecoveringClient::new(config, ConnectionOptions {
        user_identity: UserIdentity::Username { username: "plant-reader", password },
        security_policy: SecurityPolicy::Aes256Sha256RsaPss,
    })
}
```

```rust
use opcua_kit::{NodeId, RecoveringClient, Sample, SessionState};

async fn poll(
    driver: &mut RecoveringClient<'_>, node: &NodeId,
) -> Result<(u64, SessionState, Sample<u64>), Box<dyn std::error::Error>> {
    let session = driver.session().await?;
    let sample = session.client.read_scalar(node).await?;
    Ok((session.generation, session.state, sample))
}
```

Record a failed poll when it happens. A new generation starts at the first successful acquisition and increments at each replacement. Compare it with the generation of the last *successful reading*, since an operation on a newly returned session can fail too. Recreate any subscriptions on the new session. At shutdown call `driver.disconnect().await`. [OPC UA connection recovery](https://reference.opcfoundation.org/specs/OPC-10000-4/6.7)

## Query a historian for a missing interval

Run `cargo add time@0.3` in your application directory for the UTC window bounds.

Use `read_history` when the selected variable has a raw historian. Supply a forward UTC window on 100 ns boundaries and a total sample limit from 1 to 4096. The client follows continuation points for up to 64 pages, requests both timestamps, and keeps page and sample statuses. A service failure or exhausted local budget returns an error with no partial series. Present source timestamps must fall within the requested window and stay in chronological order across pages, including their 10 ps increments. A server-only timestamp stays explicitly server-only. The server determines what it retained. An empty result gives the application no observations for that interval.

```rust
use opcua_kit::{Client, HistoricalRead, HistoryError, NodeId};
use time::OffsetDateTime;

async fn backfill(
    client: &Client, node: &NodeId, start: OffsetDateTime, end: OffsetDateTime,
) -> Result<HistoricalRead<u64>, HistoryError> {
    client.read_history(node, start, end, 4096).await
}
```

History samples carry the server’s raw values and clocks. When units or sensor configuration can change, keep dated metadata alongside the series. [OPC UA raw history](https://reference.opcfoundation.org/specs/OPC-10000-11/6.5.3)

## Read part of an array

`read_array::<T>` retains OPC UA row-major dimensions and elements for Boolean and fixed-width numeric types. For example, `client.read_array_range::<f64>(&node, &[0..=2, 4..=7]).await?` sends the range `0:2,4:7` for a matrix. Each result retains its status and independent clocks. The client limits each projection to 65,536 elements and 16 dimensions. SDK response decoding precedes those application limits.
