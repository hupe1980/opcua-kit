//! List the endpoints advertised at one OPC TCP address.
use opcua_kit::discover_endpoints;
use std::{env, error::Error, time::Duration};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let url = args
        .next()
        .filter(|_| args.next().is_none())
        .ok_or("usage: discover opc.tcp://HOST:PORT")?;
    for endpoint in discover_endpoints(&url, Duration::from_secs(5))? {
        println!(
            "{}\t{}\t{}",
            endpoint.endpoint_url.escape_default(),
            endpoint.application_uri.escape_default(),
            endpoint.security_policy_uri.escape_default()
        );
    }
    Ok(())
}
