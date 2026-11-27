use std::io::{self, Write};
use std::path::Path;

use super::{Capture, Result, native, read_document};
use opcua_kit::commissioning::parse_contract;
use tempfile::NamedTempFile;

fn destination(args: &Capture) -> Result<Option<NamedTempFile>> {
    let Some(path) = &args.output else {
        return Ok(None);
    };
    if let Ok(existing) = path.canonicalize() {
        if !existing.is_file() {
            return Err("output must be a regular file".into());
        }
        for source in [
            Some(&args.connection.contract),
            Some(&args.connection.credentials.server_cert),
            Some(&args.connection.credentials.client_cert),
            Some(&args.connection.credentials.client_key),
            args.connection.credentials.password_file.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if source.canonicalize().is_ok_and(|input| input == existing) {
                return Err(
                    "choose an output distinct from the contract and credential files".into(),
                );
            }
        }
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(Some(NamedTempFile::new_in(parent).map_err(|e| {
        format!("prepare snapshot destination: {e}")
    })?))
}

pub fn run(args: Capture) -> Result<u8> {
    let contract = parse_contract(&read_document(&args.connection.contract)?)?;
    contract.validate_capture_nodes()?;
    if args.preflight {
        native::preflight(&args.connection, &contract)?;
        writeln!(
            io::stdout().lock(),
            "Offline capture preparation passed. Run capture without --preflight to test the endpoint."
        )?;
        return Ok(0);
    }
    let dest = destination(&args)?;
    let snapshot = native::snapshot(args.connection, contract)?;
    let json = serde_json::to_string(&snapshot)?;
    let write = super::json_line(&json).ok_or("snapshot output exceeds 4 MiB")?;
    if let Some(mut tmp) = dest {
        write(&mut tmp)?;
        tmp.as_file().sync_all()?;
        tmp.persist(args.output.expect("destination was requested"))?;
    } else {
        write(&mut io::stdout().lock())?;
    }
    Ok(0)
}
