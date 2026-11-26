//! A Rust application using the opt-in control capability with a pinned memory-only server.
use opcua_kit::{
    Client, ConnectionConfig, ConnectionOptions, Control, ControlError, NodeId, ReadError, Scalar,
    SecurityPolicy, UserIdentity,
};
use std::{env, error::Error, fs, path::PathBuf, time::Duration};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let endpoint = args.next().unwrap();
    let directory = PathBuf::from(args.next().unwrap());
    let server = fs::read(directory.join("server.der"))?;
    let cert = fs::read(directory.join("client.der"))?;
    let key = fs::read(directory.join("client-key.der"))?;
    let connect = || {
        Client::connect_with(
            ConnectionConfig {
                endpoint: &endpoint,
                server_application_uri: "urn:fixture:server",
                server_certificate_der: &server,
                client_application_uri: "urn:fixture:client",
                client_certificate_der: &cert,
                client_private_key_der: &key,
                timeout: Duration::from_secs(3),
            },
            ConnectionOptions {
                security_policy: SecurityPolicy::Aes256Sha256RsaPss,
                user_identity: UserIdentity::Username {
                    username: "read-fixture",
                    password: "local-restart-fixture",
                },
            },
        )
    };
    let node = |name: &str| NodeId::new("urn:control:fixture", format!("s={name}")).unwrap();
    let value = node("Writable");
    let object = node("Memory");
    let method = node("Echo");
    let client = connect()?;
    let control = Control::new(&client);
    assert!(matches!(
        control
            .write_scalar(&NodeId::new("urn:absent", "s=X")?, 1u64)
            .await,
        Err(ControlError::Preflight(ReadError::UnknownNamespace { .. }))
    ));
    let exact = (1u64 << 57) + 3;
    assert_eq!(control.write_scalar(&value, exact).await?, 0);
    assert_eq!(client.read_scalar::<u64>(&value).await?.value, Some(exact));
    assert_ne!(control.write_scalar(&value, true).await? >> 31, 0);
    assert_ne!(
        control.write_scalar(&node("ReadOnly"), exact).await? >> 31,
        0
    );
    let arg = exact.into_variant()?;
    let reply = control
        .call_method(&object, &method, std::slice::from_ref(&arg))
        .await?;
    assert_eq!(reply.status, 0);
    assert_eq!(reply.outputs.len(), 1);
    assert_eq!(u64::from_variant(&reply.outputs[0])?.unwrap(), exact);
    let text = String::from("line 2");
    let mixed = control
        .call_method(
            &object,
            &node("Mixed"),
            &[
                text.clone().into_variant()?,
                true.into_variant()?,
                exact.into_variant()?,
            ],
        )
        .await?;
    assert_eq!(mixed.status, 0);
    assert_eq!(mixed.outputs.len(), 3);
    assert_eq!(u64::from_variant(&mixed.outputs[0])?, Some(exact));
    assert_eq!(bool::from_variant(&mixed.outputs[1])?, Some(true));
    assert_eq!(String::from_variant(&mixed.outputs[2])?, Some(text));
    let bad = false.into_variant()?;
    let rejected = control.call_method(&object, &method, &[bad]).await?;
    assert_eq!(rejected.status, 0x80AB_0000); // Bad_InvalidArgument
    assert_eq!(rejected.input_statuses, [0x8074_0000]); // Bad_TypeMismatch
    assert!(rejected.outputs.is_empty());
    assert!(matches!(
        control.call_method(&object, &method, &vec![arg; 65]).await,
        Err(ControlError::InputLimit)
    ));
    assert!(matches!(
        control.write_scalar(&value, "x".repeat(128 * 1024)).await,
        Err(ControlError::InputLimit)
    ));
    assert!(matches!(
        control.call_method(&object, &node("Excess"), &[]).await,
        Err(ControlError::InvalidResponse)
    ));
    assert!(matches!(
        control.write_scalar(&value, 9u64).await,
        Err(ControlError::Preflight(ReadError::SessionInterrupted))
    ));
    client.disconnect().await;

    let client = connect()?;
    let control = Control::new(&client);
    // Warm the mapping before the cancellation test. The fixture counts executions independently.
    assert_eq!(client.read_scalar::<u64>(&value).await?.value, Some(exact));
    let slow = node("Slow");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            control.call_method(&object, &slow, &[])
        )
        .await
        .is_err()
    );
    assert!(matches!(
        control.call_method(&object, &slow, &[]).await,
        Err(ControlError::Preflight(ReadError::SessionInterrupted))
    ));
    client.disconnect().await;

    let client = connect()?;
    let control = Control::new(&client);
    let late = node("Late");
    assert!(matches!(
        control.call_method(&object, &late, &[]).await,
        Err(ControlError::Indeterminate(_))
    ));
    assert!(matches!(
        control.call_method(&object, &late, &[]).await,
        Err(ControlError::Preflight(ReadError::SessionInterrupted))
    ));
    client.disconnect().await;
    Ok(())
}
