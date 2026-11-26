// Exercise Part 9 method identities and branch EventIds against a separate encrypted peer.
use std::{env, error::Error, fs, path::PathBuf, time::Duration};

use opcua_kit::{
    BrowseName, Client, ConditionComment, ConditionError, ConnectionConfig, ConnectionOptions,
    Control, EventField, Events, NodeId, SecurityPolicy, UserIdentity, client::ua,
};

const UA: &str = "http://opcfoundation.org/UA/";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let endpoint = args.next().unwrap();
    let dir = PathBuf::from(args.next().unwrap());
    let server = fs::read(dir.join("server.der"))?;
    let cert = fs::read(dir.join("client.der"))?;
    let key = fs::read(dir.join("client-key.der"))?;
    let config = ConnectionConfig {
        endpoint: &endpoint,
        server_application_uri: "urn:fixture:server",
        server_certificate_der: &server,
        client_application_uri: "urn:fixture:client",
        client_certificate_der: &cert,
        client_private_key_der: &key,
        timeout: Duration::from_secs(3),
    };
    let options = ConnectionOptions {
        security_policy: SecurityPolicy::Aes256Sha256RsaPss,
        user_identity: UserIdentity::Username {
            username: "read-fixture",
            password: "local-restart-fixture",
        },
    };
    let notifier = NodeId::new(UA, "i=2253")?;
    let fields = [
        EventField::base("EventType")?,
        EventField::base("EventId")?,
        EventField::condition_id(),
        EventField {
            type_definition: NodeId::new(UA, "i=2782")?,
            path: vec![BrowseName::new(UA, "BranchId")?],
        },
    ];
    let mut events =
        Events::connect(config, options, &notifier, &fields, Duration::from_secs(1)).await?;
    let client = Client::connect_with(config, options)?;
    let control = Control::new(&client);
    assert!(matches!(
        events.next(Duration::from_millis(100)).await,
        Err(opcua_kit::EventError::Subscription(
            opcua_kit::SubscriptionError::Timeout
        ))
    ));
    // A pending Publish may wait ten publishing intervals for its keepalive. Refresh
    // needs to dispatch immediately on that same session to initiate retained events.
    let refreshed =
        tokio::time::timeout(Duration::from_secs(3), events.refresh_conditions()).await??;
    assert_eq!(refreshed.status, 0);
    assert!(refreshed.outputs.is_empty());
    let wait = Duration::from_secs(6);
    let event_type = |event: &[ua::Variant]| {
        event[0]
            .as_scalar::<ua::NodeId>()
            .unwrap()
            .as_ns0()
            .unwrap()
    };
    assert_eq!(event_type(&events.next(wait).await?), 2787);
    let alarm = events.next(wait).await?;
    assert_eq!(event_type(&alarm), 2915);
    let condition = events.stable_node(alarm[2].as_scalar::<ua::NodeId>().unwrap())?;
    assert_eq!(
        condition,
        NodeId::new("urn:conditions:fixture", "s=MotorAlarm")?
    );
    let branch = events.stable_node(alarm[3].as_scalar::<ua::NodeId>().unwrap())?;
    assert_eq!(
        branch,
        NodeId::new("urn:conditions:fixture", "s=OlderBranch")?
    );
    let first_id = alarm[1]
        .as_scalar::<ua::ByteString>()
        .unwrap()
        .as_bytes()
        .unwrap();
    assert_eq!(event_type(&events.next(wait).await?), 2788);

    assert!(matches!(
        control.acknowledge_condition(&condition, &[], None).await,
        Err(ConditionError::InvalidEventId)
    ));
    assert!(matches!(
        control
            .acknowledge_condition(
                &condition,
                first_id,
                Some(ConditionComment {
                    locale: "en",
                    text: "bad\0comment"
                })
            )
            .await,
        Err(ConditionError::InvalidComment)
    ));
    assert!(matches!(
        control
            .confirm_condition(&NodeId::new(UA, "i=2881")?, first_id, None)
            .await,
        Err(ConditionError::InvalidCondition)
    ));
    let ack = control
        .acknowledge_condition(
            &condition,
            first_id,
            Some(ConditionComment {
                locale: "en-US",
                text: "operator reviewed",
            }),
        )
        .await?;
    assert_eq!(ack.status, 0);
    let changed = events.next(wait).await?;
    assert_eq!(event_type(&changed), 2915);
    let current_id = changed[1]
        .as_scalar::<ua::ByteString>()
        .unwrap()
        .as_bytes()
        .unwrap();
    assert_ne!(first_id, current_id);
    let stale = control
        .confirm_condition(
            &condition,
            first_id,
            Some(ConditionComment {
                locale: "en-US",
                text: "",
            }),
        )
        .await?;
    assert_eq!(stale.status, 0x809a_0000);
    let confirmed = control
        .confirm_condition(&condition, current_id, None)
        .await?;
    assert_eq!(confirmed.status, 0);
    assert!(confirmed.outputs.is_empty());
    assert_eq!(event_type(&events.next(wait).await?), 2915);
    let new_occurrence = events.next(wait).await?;
    let new_id = new_occurrence[1]
        .as_scalar::<ua::ByteString>()
        .unwrap()
        .as_bytes()
        .unwrap();
    assert_ne!(new_id, current_id);
    let result = control
        .acknowledge_condition(
            &condition,
            new_id,
            Some(ConditionComment {
                locale: "en-US",
                text: "new occurrence",
            }),
        )
        .await;
    assert!(matches!(
        result,
        Err(ConditionError::Call(
            opcua_kit::ControlError::Indeterminate(_)
        ))
    ));
    assert_eq!(event_type(&events.next(wait).await?), 2915);
    events.disconnect().await;
    client.disconnect().await;
    Ok(())
}
