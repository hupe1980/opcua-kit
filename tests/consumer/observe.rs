// External application using an encrypted event stream across a certificate replacement.
use std::{error::Error, fs, io, path::PathBuf, time::Duration};

use opcua_kit::{
    BrowseName, CertificateRollover, Client, ConnectionConfig, ConnectionOptions, EventError,
    EventField, Events, NodeId, ReadAttribute, ReadOperand, RecoveringClient, SessionState,
    SubscriptionError, client::ua,
};
use time::OffsetDateTime;
use uuid::Uuid;

fn wait_for(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    assert_eq!(line.trim(), expected);
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap();
    let dir = PathBuf::from(args.next().unwrap());
    let client_der = fs::read(dir.join("client.der"))?;
    let key = fs::read(dir.join("client-key.der"))?;
    let original = fs::read(dir.join("server.der"))?;
    let successor = fs::read(dir.join("successor.der"))?;
    let config = ConnectionConfig {
        endpoint: &endpoint,
        server_application_uri: "urn:fixture:server",
        server_certificate_der: &original,
        client_application_uri: "urn:fixture:client",
        client_certificate_der: &client_der,
        client_private_key_der: &key,
        timeout: Duration::from_secs(3),
    };
    let options = ConnectionOptions::default();
    let rollover = CertificateRollover {
        replacement_der: &successor,
        original_valid_until: OffsetDateTime::now_utc() + time::Duration::hours(1),
    };
    let retired = CertificateRollover {
        original_valid_until: OffsetDateTime::UNIX_EPOCH,
        ..rollover
    };
    let wrong_uri = fs::read(dir.join("wrong-uri.der"))?;
    assert!(
        Client::connect_with_rollover(
            config,
            options,
            CertificateRollover {
                replacement_der: &wrong_uri,
                ..rollover
            }
        )
        .is_err()
    );
    assert!(Client::connect_with_rollover(config, options, retired).is_err());
    let mut owner = RecoveringClient::new_with_rollover(config, options, rollover);
    let first = owner.session().await?;
    assert_eq!(first.generation, 1);
    let client = first.client;
    let buffer = NodeId::new("urn:example:observe", "s=Buffer")?;
    if args.next().as_deref() == Some("events") {
        observe(client, config, options).await?;
        return Ok(());
    }

    println!("TEST rotate");
    wait_for("disconnected")?;
    assert!(client.read_scalar::<Vec<u8>>(&buffer).await.is_err());
    println!("TEST gap");
    wait_for("unlisted")?;
    assert!(owner.session().await.is_err());
    println!("TEST rejected");
    wait_for("replacement")?;
    let fresh = owner.session().await?;
    assert_eq!(
        (fresh.generation, fresh.state),
        (2, SessionState::Reconnected)
    );
    assert_eq!(
        fresh.client.read_scalar::<Vec<u8>>(&buffer).await?.value,
        Some(vec![2])
    );
    owner.disconnect().await;
    let next = Client::connect_with_rollover(config, options, retired)?;
    next.disconnect().await;
    println!("TEST done");
    Ok(())
}

async fn observe(
    client: &Client,
    config: ConnectionConfig<'_>,
    options: ConnectionOptions<'_>,
) -> Result<(), Box<dyn Error>> {
    let node = |id: &str| NodeId::new("urn:example:observe", format!("s={id}"));
    let buffer = node("Buffer")?;
    assert_eq!(
        client
            .read_scalar::<Vec<u8>>(&buffer)
            .await?
            .value
            .as_deref(),
        Some(&[0, 255, 42][..])
    );
    assert_eq!(
        client
            .read_scalar::<Vec<u8>>(&node("EmptyBuffer")?)
            .await?
            .value,
        Some(Vec::new())
    );
    assert!(client.read_scalar::<String>(&buffer).await.is_err());
    let id = Uuid::parse_str("12345678-90ab-cdef-8888-1234567890ab")?;
    assert_eq!(
        client.read_scalar::<Uuid>(&node("Job")?).await?.value,
        Some(id)
    );
    let now = client
        .read_scalar::<OffsetDateTime>(&node("Started")?)
        .await?
        .value
        .unwrap();
    assert_eq!(now.unix_timestamp_nanos(), 1_609_459_200_123_456_000);
    let attrs = [
        ReadAttribute::DisplayName,
        ReadAttribute::AccessLevel,
        ReadAttribute::Historizing,
    ];
    let data = client
        .read_attributes(&attrs.map(|a| ReadOperand::new(&buffer, a)))
        .await?;
    assert_eq!(
        data[0]
            .value()
            .unwrap()
            .as_scalar::<ua::LocalizedText>()
            .unwrap()
            .text()
            .as_str(),
        Some("Buffer")
    );
    assert_eq!(
        data[1]
            .value()
            .unwrap()
            .as_scalar::<ua::Byte>()
            .unwrap()
            .value()
            & 1,
        1
    );
    assert!(
        !data[2]
            .value()
            .unwrap()
            .as_scalar::<ua::Boolean>()
            .unwrap()
            .value()
    );

    let notifier = NodeId::new("http://opcfoundation.org/UA/", "i=2253")?;
    let interval = Duration::from_millis(50);
    assert!(matches!(
        Events::connect(config, options, &notifier, &[], interval).await,
        Err(EventError::InvalidSelection)
    ));
    let fields = [
        EventField::base("Severity")?,
        EventField::base("Message")?,
        EventField::base("EventId")?,
        EventField::base("Severity")?,
        EventField {
            type_definition: NodeId::new("http://opcfoundation.org/UA/", "i=2915")?,
            path: ["ActiveState", "Id"]
                .map(|name| BrowseName::new("http://opcfoundation.org/UA/", name))
                .into_iter()
                .collect::<Result<_, _>>()?,
        },
    ];
    let mut events = Events::connect(config, options, &notifier, &fields, interval).await?;
    assert!(matches!(
        events.next(interval).await,
        Err(EventError::Subscription(SubscriptionError::Timeout))
    ));
    println!("TEST events");
    let event = events.next(Duration::from_secs(6)).await?;
    assert_eq!(event.len(), fields.len());
    assert_eq!(event[0].as_scalar::<ua::UInt16>().unwrap().value(), 702);
    assert_eq!(
        event[1]
            .as_scalar::<ua::LocalizedText>()
            .unwrap()
            .text()
            .as_str(),
        Some("fan stopped")
    );
    assert!(
        !event[2]
            .as_scalar::<ua::ByteString>()
            .unwrap()
            .as_bytes()
            .unwrap()
            .is_empty()
    );
    assert_eq!(event[3], event[0]);
    assert!(event[4].is_empty(), "BaseEventType has no ActiveState/Id");
    println!("TEST alarm");
    let alarm = events.next(Duration::from_secs(6)).await?;
    assert_eq!(alarm.len(), fields.len());
    assert_eq!(alarm[0].as_scalar::<ua::UInt16>().unwrap().value(), 904);
    assert!(alarm[4].as_scalar::<ua::Boolean>().unwrap().value());
    println!("TEST overflow");
    assert!(matches!(
        events.next(Duration::from_secs(6)).await,
        Err(EventError::ServerOverflow)
    ));
    assert!(matches!(
        events.next(interval).await,
        Err(EventError::Subscription(SubscriptionError::Ended))
    ));
    events.disconnect().await;
    println!("TEST disconnected");
    wait_for("next")?;
    // Sixty publishing cycles last a minute, far longer than the peer's cleanup deadline.
    let mut dropped =
        Events::connect(config, options, &notifier, &fields, Duration::from_secs(1)).await?;
    assert!(matches!(
        dropped.next(interval).await,
        Err(EventError::Subscription(SubscriptionError::Timeout))
    ));
    drop(dropped);
    println!("TEST dropped");
    tokio::task::spawn_blocking(|| wait_for("clean")).await??;
    Ok(())
}
