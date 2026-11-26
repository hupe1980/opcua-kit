use opcua_kit::{
    Client, ConnectionConfig, ConnectionOptions, HistoryError, NodeId, SecurityPolicy,
    UserIdentity, discover_endpoints,
};
use std::{error::Error, fs, path::PathBuf, time::Duration};
use time::OffsetDateTime;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().expect("configured URL");
    let directory = PathBuf::from(args.next().expect("PKI fixture"));
    let timeout = Duration::from_secs(3);
    let server = fs::read(directory.join("server.der"))?;
    let certificate = fs::read(directory.join("client.der"))?;
    let key = fs::read(directory.join("client-key.der"))?;
    let config = ConnectionConfig {
        endpoint: &endpoint,
        server_application_uri: "urn:fixture:server",
        server_certificate_der: &server,
        client_application_uri: "urn:fixture:client",
        client_certificate_der: &certificate,
        client_private_key_der: &key,
        timeout,
    };
    let options = |policy, password| ConnectionOptions {
        security_policy: policy,
        user_identity: UserIdentity::Username {
            username: "read-fixture",
            password,
        },
    };
    assert!(
        Client::connect_with(
            config,
            options(SecurityPolicy::Aes128Sha256RsaOaep, "wrong-fixture")
        )
        .is_err()
    );
    for policy in [
        SecurityPolicy::Aes128Sha256RsaOaep,
        SecurityPolicy::Aes256Sha256RsaPss,
    ] {
        let client = Client::connect_with(config, options(policy, "local-restart-fixture"))
            .unwrap_or_else(|e| panic!("named connection with {policy:?}: {e}"));
        let node = |name: &str| NodeId::new("urn:protocol:meter", format!("s={name}")).unwrap();
        let matrix = client.read_array::<u32>(&node("Matrix")).await?;
        assert_eq!(matrix.status, 0x400);
        let matrix = matrix.value.unwrap();
        assert_eq!(matrix.dimensions, [2, 2]);
        assert_eq!(matrix.values, [0, 2, 6, u32::MAX]);
        assert!(client.read_array::<u64>(&node("Matrix")).await.is_err());
        let sub = client
            .read_array_range::<u32>(&node("Line"), &[1..=2])
            .await?
            .value
            .unwrap();
        assert_eq!(sub.dimensions, [2]);
        assert_eq!(sub.values, [3, 7]);
        let missing = client.read_array::<u32>(&node("absent")).await?;
        assert_eq!(missing.status, 0x8034_0000);
        assert!(missing.value.is_none());
        let start = OffsetDateTime::from_unix_timestamp(1_609_459_200)?;
        let end = start + time::Duration::seconds(3);
        let history = node("Archived");
        let actual = client.read_history::<u64>(&history, start, end, 8).await?;
        assert_eq!(actual.page_statuses.len(), 3);
        assert_eq!(actual.page_statuses, [0, 0x400, 0x400]);
        assert_eq!(actual.samples.len(), 3);
        for (i, (status, value)) in [
            (0, Some(u64::MAX)),
            (0x400, Some((1u64 << 53) + 1)),
            (0x4090_0400, None),
        ]
        .into_iter()
        .enumerate()
        {
            let sample = &actual.samples[i];
            assert_eq!((sample.status, sample.value), (status, value));
            let source = sample.source_timestamp.unwrap();
            assert_eq!(
                source.base_unix_nanos,
                (1_609_459_200 + i as i128) * 1_000_000_000
            );
            if i == 0 {
                assert_eq!(source.ten_picoseconds, Some(100));
                assert!(sample.server_timestamp.is_none());
            } else {
                assert_eq!(source.ten_picoseconds, None);
                let server = sample.server_timestamp.unwrap();
                assert_eq!(server.base_unix_nanos, source.base_unix_nanos + 1_000_000);
                assert_eq!(server.ten_picoseconds, Some(700));
            }
        }
        // 019-protocol-client/SR-002. Record a complete ordered history or fail and release its cursor.
        for limit in [1, 2] {
            assert!(matches!(
                client
                    .read_history::<u64>(&history, start, end, limit)
                    .await,
                Err(HistoryError::Limit)
            ));
        }
        for malformed in ["Outside", "Backwards"] {
            assert!(matches!(
                client
                    .read_history::<u64>(&node(malformed), start, end, 4)
                    .await,
                Err(HistoryError::InvalidTimestamp)
            ));
        }
        let empty = client
            .read_history::<u64>(&history, end, end + time::Duration::seconds(1), 4)
            .await?;
        assert!(empty.samples.is_empty());
        assert_eq!(empty.page_statuses, [0]);
        assert!(matches!(
            client
                .read_history::<u64>(&node("Denied"), start, end, 4)
                .await,
            Err(HistoryError::Status(0x801f_0000))
        ));
        assert!(
            client
                .read_history::<i64>(&history, start, end, 4)
                .await
                .is_err()
        );
        client.disconnect().await;
    }
    let endpoints = discover_endpoints(&endpoint, timeout).expect("credential-free discovery");
    for policy in [
        SecurityPolicy::Aes128Sha256RsaOaep,
        SecurityPolicy::Aes256Sha256RsaPss,
    ] {
        assert!(
            endpoints
                .iter()
                .any(|e| e.security_policy_uri == policy.uri()
                    && e.security_mode == 3
                    && e.application_uri == "urn:fixture:server"
                    && e.user_tokens.iter().any(|t| t.kind == 1)
                    && e.user_tokens.iter().all(|t| t.kind != 0))
        );
    }
    println!("Discovery, named AES128/AES256, matrix shape and raw paged history passed.");
    Ok(())
}
