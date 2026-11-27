//! Serve a host-owned UInt64 counter on loopback. Supply certificates to enable an encrypted listener.
//! Enter a new integer on stdin to update the value. EOF shuts down the server.
use opcua_kit::server::{SecureServerConfig, SecurityPolicy, Server};
use std::{
    error::Error,
    io::{self, BufRead},
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

fn main() -> Result<(), Box<dyn Error>> {
    let port = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "4840".into())
        .parse::<NonZeroU16>()?;
    let args: Vec<String> = std::env::args().skip(2).collect();
    let (host, runner) = match args.as_slice() {
        [] => Server::loopback(port, "urn:example:line")?,
        [uri, cert, key, client_uri, client_cert, policy @ ..] => Server::secure_with_policy(
            SecureServerConfig {
                bind: ([127, 0, 0, 1], port.get()).into(),
                application_uri: uri,
                certificate_der: &std::fs::read(cert)?,
                private_key_der: &std::fs::read(key)?,
                trusted_client_uri: client_uri,
                trusted_client_certificate_der: &std::fs::read(client_cert)?,
            },
            "urn:example:line",
            match policy {
                [] => SecurityPolicy::Basic256Sha256,
                [p] => [
                    SecurityPolicy::Basic256Sha256,
                    SecurityPolicy::Aes128Sha256RsaOaep,
                    SecurityPolicy::Aes256Sha256RsaPss,
                ]
                .into_iter()
                .find(|policy| policy.uri().rsplit('#').next() == Some(p.as_str()))
                .ok_or("unknown security policy")?,
                _ => return Err("expected at most one security policy".into()),
            },
        )?,
        _ => {
            return Err(
                "expected PORT [SERVER_URI SERVER.der SERVER_KEY.der CLIENT_URI CLIENT.der [POLICY]]".into(),
            );
        }
    };
    let counter = host.add_variable("PartsProduced", 0_u64)?;
    let stop = Arc::new(AtomicBool::new(false));
    let input_closed = Arc::clone(&stop);
    thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            match line.trim().parse() {
                Ok(n) => {
                    if let Err(error) = counter.set(n) {
                        eprintln!("update failed: {error}");
                    }
                }
                Err(error) => eprintln!("expected a UInt64: {error}"),
            }
        }
        input_closed.store(true, Ordering::Release);
    });
    eprintln!("Serving PartsProduced on opc.tcp://127.0.0.1:{port} while stdin is open");
    runner.run_until(|| stop.load(Ordering::Acquire))?;
    Ok(())
}
