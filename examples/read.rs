//! Read one or more UInt64 variables through a pinned native OPC UA session.
use opcua_kit::{Client, ConnectionConfig, NodeId};
use std::{env, error::Error, fs, time::Duration};

const USAGE: &str = "cargo run --example read -- ENDPOINT SERVER_URI SERVER.der CLIENT_URI CLIENT.der CLIENT_KEY.der NAMESPACE_URI NODE_ID [NODE_ID ...]";

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if matches!(args.as_slice(), [arg] if arg == "-h" || arg == "--help") {
        println!("Read UInt64 variables from an OPC UA server.\n\nUsage: {USAGE}");
        return Ok(());
    }
    let [
        endpoint,
        server_uri,
        server_cert,
        client_uri,
        client_cert,
        key,
        namespace,
        ids @ ..,
    ] = args.as_slice()
    else {
        return Err(format!("usage: {USAGE}").into());
    };
    if ids.is_empty() || ids.len() > opcua_kit::MAX_READ_NODES {
        return Err("supply 1 to 1024 node identifiers".into());
    }
    let nodes = ids
        .iter()
        .map(|id| NodeId::new(namespace, id))
        .collect::<Result<Vec<_>, _>>()?;
    let client = Client::connect(ConnectionConfig {
        endpoint,
        server_application_uri: server_uri,
        server_certificate_der: &fs::read(server_cert)?,
        client_application_uri: client_uri,
        client_certificate_der: &fs::read(client_cert)?,
        client_private_key_der: &fs::read(key)?,
        timeout: Duration::from_secs(5),
    })?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let result = client.read_scalars::<u64>(&nodes).await;
            client.disconnect().await;
            let mut unavailable = 0;
            for (node, item) in nodes.iter().zip(result?) {
                let id = node.identifier().escape_debug();
                match item {
                    Ok(opcua_kit::Sample {
                        status: 0,
                        value: Some(value),
                        ..
                    }) => println!("{id} {value}"),
                    Ok(sample) => {
                        eprintln!("{id} unavailable (0x{:08X})", sample.status);
                        unavailable += 1;
                    }
                    Err(error) => {
                        eprintln!("{id} {error}");
                        unavailable += 1;
                    }
                }
            }
            if unavailable != 0 {
                return Err(format!("{unavailable} variable(s) unavailable").into());
            }
            Ok(())
        })
}
