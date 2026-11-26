// Public API test driver for the separately restarted independent asyncua peer.
use std::{
    error::Error,
    fs,
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    pin::pin,
    task::Poll,
    time::Duration,
};

use opcua_kit::{
    ConnectionConfig, ConnectionOptions, NodeId, SecurityPolicy, UserIdentity,
    client::{RecoveringClient, RecoveryError, SessionState},
};

fn wait_for(command: &str) -> Result<(), Box<dyn Error>> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    assert_eq!(line.trim(), command);
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().expect("endpoint");
    let directory = PathBuf::from(args.next().expect("fixture path"));
    let server_certificate_der = fs::read(directory.join("server.der"))?;
    let client_certificate_der = fs::read(directory.join("client.der"))?;
    let client_private_key_der = fs::read(directory.join("client-key.der"))?;
    let config = ConnectionConfig {
        endpoint: &endpoint,
        server_application_uri: "urn:fixture:server",
        server_certificate_der: &server_certificate_der,
        client_application_uri: "urn:fixture:client",
        client_certificate_der: &client_certificate_der,
        client_private_key_der: &client_private_key_der,
        timeout: Duration::from_secs(2),
    };
    let options = ConnectionOptions {
        security_policy: SecurityPolicy::Aes256Sha256RsaPss,
        user_identity: UserIdentity::Username {
            username: "read-fixture",
            password: "local-restart-fixture",
        },
    };
    let mut owner = RecoveringClient::new(config, options);
    let signal = NodeId::new("urn:recovery:meter", "s=Counter")?;
    // Poll then cancel an acquisition. The next awaiter should reuse that pending handshake.
    {
        let mut attempt = pin!(owner.session());
        poll_fn(|cx| {
            assert!(attempt.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    let first = owner.session().await?;
    assert_eq!((first.generation, first.state), (1, SessionState::Initial));
    let initial = first
        .client
        .read_scalars::<u64>(&[signal.clone(), signal.clone()])
        .await?;
    for item in initial {
        assert_eq!(item?.value, Some(111));
    }
    let same = owner.session().await?;
    assert_eq!((same.generation, same.state), (1, SessionState::Continuing));
    let clock = NodeId::new("http://opcfoundation.org/UA/", "i=2257")?;
    let mut group = same
        .client
        .subscribe_many(&[clock], Duration::from_millis(100))
        .await?;
    assert_eq!(group.next(Duration::from_secs(3)).await?.index, 0);
    println!("TEST initial");
    wait_for("disconnected")?;
    assert!(same.client.read_scalar::<u64>(&signal).await.is_err());
    assert!(matches!(
        group.next(Duration::from_secs(2)).await,
        Err(opcua_kit::SubscriptionError::Ended | opcua_kit::SubscriptionError::Session(_))
    ));
    assert!(matches!(
        group.next(Duration::from_secs(1)).await,
        Err(opcua_kit::SubscriptionError::Ended)
    ));
    drop(group);
    println!("TEST gap");
    wait_for("wrong-pin")?;
    assert!(matches!(
        owner.session().await,
        Err(RecoveryError::Connect(_))
    ));
    println!("TEST rejected");
    wait_for("restarted")?;
    let fresh = owner.session().await?;
    assert_eq!(
        (fresh.generation, fresh.state),
        (2, SessionState::Reconnected)
    );
    let resumed = fresh
        .client
        .read_scalars::<u64>(&[signal.clone(), signal])
        .await?;
    for item in resumed {
        assert_eq!(item?.value, Some(222));
    }
    assert_eq!(owner.session().await?.state, SessionState::Continuing);
    owner.disconnect().await;
    println!("TEST recovered");
    Ok(())
}
