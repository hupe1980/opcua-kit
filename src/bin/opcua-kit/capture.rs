use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{Capture, Connection, Result, read_document};
#[cfg(feature = "cems")]
use opcua_kit::commissioning::meter::parse_meter_reading;
use opcua_kit::commissioning::{Contract, MAX_DOCUMENT_BYTES, parse_contract, parse_snapshot};
use tempfile::{NamedTempFile, tempfile};

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
            args.connection.server_cert.as_ref(),
            args.connection.client_cert.as_ref(),
            args.connection.client_key.as_ref(),
            args.connection.session.password_file.as_ref(),
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

const PREFLIGHT_ACK: &[u8] = b"preflight ok\n";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Snapshot,
    Preflight,
    #[cfg(feature = "cems")]
    MeterRead,
}

// The embedded helper and the launcher share these local preparation and meter-read codes.
// Keep operator diagnostics independent of Python, uv and credential file bytes.
fn worker_failure(operation: Operation, status: ExitStatus) -> &'static str {
    match (operation, status.code()) {
        (_, Some(64)) => {
            "invalid endpoint. Provide an opc.tcp URL with an explicit TCP port and no credentials. For --insecure-loopback use a literal loopback IP."
        }
        (_, Some(65)) => {
            "invalid live contract. Select 1 to 1024 application signals and the anonymous principal. Exclude standard session bootstrap nodes."
        }
        (_, Some(66)) => {
            "check the security mode. Supply the three credential files for secure capture, or use --insecure-loopback alone."
        }
        (_, Some(67)) => {
            "cannot load a credential file. Check that each input is a regular file up to 64 KiB and certificates use PEM or DER."
        }
        (_, Some(68)) => {
            "certificate expired or is not yet valid. Check the field laptop clock and both certificates."
        }
        (_, Some(69)) => {
            "certificate identity mismatch. Check the pinned server's host SAN, contract application URI and each certificate's application URI."
        }
        (_, Some(70)) => {
            "unsuitable certificate profile. Check RSA key size, KeyUsage and ExtendedKeyUsage for the server and client roles."
        }
        (_, Some(71)) => {
            "cannot load client private key. Supply a readable, unencrypted PEM or DER key."
        }
        (_, Some(72)) => {
            "client private key does not match the client certificate. Select the corresponding key."
        }
        (_, Some(73)) => {
            "local capture preparation failed. Check the runtime, endpoint, contract and credential configuration."
        }
        #[cfg(feature = "cems")]
        (Operation::MeterRead, Some(74)) => {
            "meter metadata could not be verified. Check the approved NodeId, scalar type and Wh unit with capture and check."
        }
        #[cfg(feature = "cems")]
        (Operation::MeterRead, Some(75)) => {
            "invalid meter Value or timestamp. Check the register wire type and clock precision."
        }
        #[cfg(feature = "cems")]
        (Operation::MeterRead, Some(76)) => {
            "meter read failed. Check the endpoint, server pin, user permissions and timeout."
        }
        #[cfg(feature = "cems")]
        (Operation::MeterRead, _) => {
            "meter runtime failed. Check uv, Python 3.13 and the asyncua dependency cache."
        }
        _ => {
            "offline capture runtime failed. Prepare Python 3.13 and asyncua on this laptop with: uv run --no-config --isolated --no-project --python 3.13 --with asyncua==2.1.0 python -I -c 'import asyncua'"
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod worker_group {
    use super::*;
    use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
    use signal_hook::{
        consts::{SIGINT, SIGTERM},
        flag,
    };
    use std::os::unix::process::CommandExt;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    pub(super) fn prepare(command: &mut Command) -> io::Result<Arc<AtomicBool>> {
        let cancelled = Arc::new(AtomicBool::new(false));
        for signal in [SIGINT, SIGTERM] {
            flag::register(signal, Arc::clone(&cancelled))?;
        }
        command.process_group(0);
        Ok(cancelled)
    }

    fn exited(child: &Child) -> io::Result<Option<bool>> {
        // Keep the group leader waitable until cleanup, so its PID and group
        // cannot be recycled while a descendant still holds the output pipe.
        let flags = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
        Ok(waitid(WaitId::Pid(Pid::from_child(child)), flags)?
            .map(|status| status.exit_status() == Some(0)))
    }

    pub(super) fn finished(child: &Child, cancelled: &AtomicBool) -> Result<Option<bool>> {
        if cancelled.load(Ordering::Relaxed) {
            return Err("collection interrupted".into());
        }
        Ok(exited(child)?)
    }

    pub(super) fn stop(child: &Child) -> io::Result<()> {
        match kill_process_group(Pid::from_child(child), Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            // Darwin reports EPERM when the exited leader is the group's
            // only member. A live same-user worker remains signalable.
            #[cfg(target_os = "macos")]
            Err(rustix::io::Errno::PERM) if exited(child)?.is_some() => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

fn runtime_output(
    child: &mut Child,
    limit: usize,
    deadline: Instant,
    mut finished: impl FnMut(&mut Child) -> Result<Option<bool>>,
) -> Result<Vec<u8>> {
    let stdout = child.stdout.take().expect("runtime stdout was piped");
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .and_then(|size| {
                if size > limit {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "capture runtime output exceeds the allowed size",
                    ))
                } else {
                    Ok(bytes)
                }
            });
        let _ = tx.send(result);
    })?;

    let mut output = None;
    loop {
        if let Ok(result) = rx.try_recv() {
            // Refuse oversized output even when the writer is still running.
            output = Some(result?);
        }
        if let Some(success) = finished(child)? {
            if !success {
                return Ok(Vec::new());
            }
            // A descendant could retain the pipe after uv exits. Allow the
            // reader to drain the final bytes without waiting for it indefinitely.
            let grace = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(1));
            let bytes = match output {
                Some(bytes) => bytes,
                None => rx
                    .recv_timeout(grace)
                    .map_err(|_| "capture runtime output did not close after exit")??,
            };
            return Ok(bytes);
        }
        if Instant::now() >= deadline {
            return Err("capture timed out during runtime setup or collection".into());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}

fn run_collector(args: &Connection, contract: &Contract, operation: Operation) -> Result<Vec<u8>> {
    let mut input = tempfile()?;
    serde_json::to_writer(&mut input, contract)?;
    input.rewind()?;
    let diagnostics = if operation == Operation::Snapshot {
        Some(tempfile()?)
    } else {
        None
    };
    let mut command = Command::new("uv");
    command.arg("run");
    if operation == Operation::Preflight {
        command.args(["--offline", "--no-build"]);
    }
    command
        .args([
            "--quiet",
            "--no-config",
            "--isolated",
            "--no-project",
            "--python",
            "3.13",
            "--with",
            "asyncua==2.1.0",
            "python",
            "-I",
            "-c",
            include_str!("capture.py"),
            "--endpoint",
        ])
        .arg(&args.endpoint)
        .arg("--timeout")
        .arg(args.timeout.to_string())
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(match &diagnostics {
            Some(file) => Stdio::from(file.try_clone()?),
            None => Stdio::null(),
        });
    for (option, path) in [
        ("--server-cert", &args.server_cert),
        ("--client-cert", &args.client_cert),
        ("--client-key", &args.client_key),
    ] {
        if let Some(path) = path {
            if !path.metadata().is_ok_and(|m| m.is_file()) {
                return Err(format!("{option} requires a readable regular file").into());
            }
            command.arg(option).arg(path);
        }
    }
    if args.insecure_loopback {
        command.arg("--insecure-loopback");
    }
    match operation {
        Operation::Snapshot => {}
        Operation::Preflight => {
            command.arg("--preflight");
        }
        #[cfg(feature = "cems")]
        Operation::MeterRead => {
            command.arg("--meter-read");
        }
    }
    // The wire deadline starts after provisioning. Cap the whole invocation too.
    let deadline = Instant::now() + Duration::from_secs(args.timeout + 60);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let cancelled = if operation != Operation::Snapshot {
        Some(worker_group::prepare(&mut command)?)
    } else {
        None
    };
    let mut child = command
        .spawn()
        .map_err(|e| format!("start capture runtime: {e}. Install uv and check PATH."))?;
    let limit = if operation == Operation::Preflight {
        PREFLIGHT_ACK.len()
    } else {
        MAX_DOCUMENT_BYTES
    };
    let output = runtime_output(&mut child, limit, deadline, |child| {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(flag) = &cancelled {
            return worker_group::finished(child, flag);
        }
        Ok(child.try_wait()?.map(|status| status.success()))
    });
    // One-shot meter reads and rehearsals finish all their work before publishing.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if operation != Operation::Snapshot
        && let Err(error) = worker_group::stop(&child)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    if output.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let output = output?;
    if !status.success() {
        let Some(mut diagnostics) = diagnostics else {
            return Err(worker_failure(operation, status).into());
        };
        let size = diagnostics.metadata()?.len();
        diagnostics.seek(SeekFrom::Start(size.saturating_sub(4096)))?;
        let mut tail = Vec::new();
        diagnostics.take(4096).read_to_end(&mut tail)?;
        let tail = String::from_utf8_lossy(&tail);
        let message = tail
            .lines()
            .rev()
            .find(|s| s.starts_with("capture: "))
            .unwrap_or(
                "capture runtime failed. Check uv, Python 3.13 and the asyncua dependency cache.",
            );
        return Err(message.into());
    }
    Ok(output)
}

pub fn run(args: Capture) -> Result<u8> {
    let contract = parse_contract(&read_document(&args.connection.contract)?)?;
    let dest = destination(&args)?;
    if args.preflight {
        let bytes = run_collector(&args.connection, &contract, Operation::Preflight)?;
        if bytes != PREFLIGHT_ACK {
            return Err("invalid capture preflight response".into());
        }
        writeln!(
            io::stdout().lock(),
            "Offline capture preparation passed. Run capture without --preflight to test the endpoint."
        )?;
        return Ok(0);
    }
    let bytes = if let Some(uri) = &args.client_uri {
        let snapshot = super::native::snapshot(&args.connection, uri, &contract)?;
        let json = serde_json::to_string(&snapshot)?;
        let mut bytes = Vec::with_capacity(json.len() + 1);
        super::json_line(&json).ok_or("snapshot output exceeds 4 MiB")?(&mut bytes)?;
        bytes
    } else {
        let bytes = run_collector(&args.connection, &contract, Operation::Snapshot)?;
        let snapshot =
            parse_snapshot(&bytes).map_err(|e| format!("invalid collector snapshot: {e}"))?;
        contract.validate_capture(&snapshot)?;
        bytes
    };
    if let Some(mut tmp) = dest {
        tmp.write_all(&bytes)?;
        tmp.as_file().sync_all()?;
        tmp.persist(args.output.as_ref().expect("destination was requested"))?;
    } else {
        io::stdout().lock().write_all(&bytes)?;
    }
    Ok(0)
}

#[cfg(feature = "cems")]
pub fn read_meter(args: &Connection, contract: &Contract) -> Result<u8> {
    let bytes = run_collector(args, contract, Operation::MeterRead)?;
    // Worker bytes can contain unapproved process data. Publish only the
    // contract-validated typed record and keep parser details out of diagnostics.
    let reading = parse_meter_reading(contract, &bytes)
        .map_err(|_| "collector returned invalid or out-of-scope meter evidence")?;
    super::write_compact_line(&reading, None)?;
    Ok(0)
}
