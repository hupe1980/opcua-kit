//! A downstream Rust process exercising bounded retransmission on dedicated pinned sessions.
use opcua_kit::{
    ConnectionConfig, ConnectionOptions, EventError, EventField, Events, NodeId, Sample, Scalar,
    SequencedDataChanges, SubscriptionError,
};
use std::{error::Error, fs, path::PathBuf, time::Duration};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap();
    let dir = PathBuf::from(args.next().unwrap());
    let config = ConnectionConfig {
        endpoint: &endpoint,
        server_application_uri: "urn:fixture:server",
        server_certificate_der: &fs::read(dir.join("server.der"))?,
        client_application_uri: "urn:fixture:client",
        client_certificate_der: &fs::read(dir.join("client.der"))?,
        client_private_key_der: &fs::read(dir.join("client-key.der"))?,
        timeout: Duration::from_secs(3),
    };
    let options = ConnectionOptions::default();
    let nodes = [
        NodeId::new("urn:republish", "s=A")?,
        NodeId::new("urn:republish", "s=B")?,
    ];
    let interval = Duration::from_millis(50);
    for run in 0..3 {
        let mut data = SequencedDataChanges::connect(config, options, &nodes, interval).await?;
        assert_eq!(data.items().len(), 2);
        if run == 0 {
            let mut got = Vec::new();
            while got.last() != Some(&3u32) {
                let n = data.next(Duration::from_secs(6)).await?;
                assert_eq!(n.republished, n.sequence != 3);
                let value = Sample::<u64>::from_raw(&n.value.value)?;
                assert_eq!(value.value, Some([42, 97][n.value.index]));
                assert_eq!(value.status, 0);
                assert!(value.source_timestamp.is_some());
                if got.last() != Some(&n.sequence) {
                    got.push(n.sequence);
                }
            }
            assert_eq!(got, [1, 2, 3]);
            tokio::time::sleep(interval * 3).await; // permit acknowledgements to reach the independent server
        } else {
            assert!(matches!(
                data.next(Duration::from_secs(6)).await,
                Err(EventError::SequenceGap {
                    expected: 1,
                    actual: 3
                })
            ));
            assert!(matches!(
                data.next(interval).await,
                Err(EventError::Subscription(SubscriptionError::Ended))
            ));
        }
        data.disconnect().await;
    }
    let notifier = NodeId::new("http://opcfoundation.org/UA/", "i=2253")?;
    let mut events = Events::connect(
        config,
        options,
        &notifier,
        &[EventField::base("Severity")?],
        interval,
    )
    .await?;
    println!("TEST events");
    for seq in 1..=3 {
        let n = events.next_with_sequence(Duration::from_secs(6)).await?;
        assert_eq!(n.sequence, seq);
        assert_eq!(n.republished, seq < 3);
        assert_eq!(u16::from_variant(&n.value[0])?, Some(702));
    }
    tokio::time::sleep(interval * 3).await;
    events.disconnect().await;
    Ok(())
}
