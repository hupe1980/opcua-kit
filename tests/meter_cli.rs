#![cfg(all(feature = "cli", feature = "cems"))]

use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::tempdir;

const BIN: &str = env!("CARGO_BIN_EXE_opcua-kit");
const START: &str = "2026-10-25T02:45:00+02:00";
const END: &str = "2026-10-25T02:00:00+01:00";

fn fixture(dir: &Path) -> Value {
    let node = json!({"namespace":"urn:plant","id":"s=K1"});
    let ty = json!({"namespace":"http://opcfoundation.org/UA/","id":"i=9"});
    let units =
        json!({"namespaceUri":"http://www.opcfoundation.org/UA/units/un/cefact","unitId":5720146});
    let contract = json!({
        "schemaVersion":1,"device":"incomer","applicationUri":"urn:plant:server","principal":"anonymous",
        "signals":[{"name":"Import","node":node,"dataType":ty,"valueRank":-1,"engineeringUnits":units}]
    });
    fs::write(dir.join("contract.json"), contract.to_string()).unwrap();
    fs::write(
        dir.join("window.json"),
        json!({
            "meter":{"device":"incomer","applicationUri":"urn:plant:server","node":node},
            "start":START,"end":END,"tolerance_wh":1,"closed":[{"at":START,"wh":100}]
        })
        .to_string(),
    )
    .unwrap();
    json!({
        "schemaVersion":1,"device":"incomer","applicationUri":"urn:plant:server","principal":"anonymous",
        "name":"Import","node":node,"dataType":ty,"valueRank":-1,"engineeringUnits":units,
        "sourceAt":START,"serverAt":null,"receivedAt":END,"status":0,"value":982
    })
}

fn trace(dir: &Path, source: &str) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.current_dir(dir).args([
        "meter",
        "trace",
        "--contract",
        "contract.json",
        "--window",
        "window.json",
        "--readings",
        source,
    ]);
    cmd
}

fn piped(dir: &Path, bytes: &[u8]) -> Output {
    let mut child = trace(dir, "-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

fn exit(out: &Output, expected: i32) {
    assert_eq!(
        out.status.code(),
        Some(expected),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    if expected == 1 {
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.is_empty() && out.stderr.len() < 2048);
    }
}

// 006-meter-pilot/SR-002 006-meter-pilot/SR-003
#[test]
fn project_register_and_independent_closes_through_file_or_pipe() {
    let temp = tempdir().unwrap();
    let dir = temp.path();
    let mut reading = fixture(dir);
    let first = reading.to_string();
    reading["sourceAt"] = json!(END);
    reading["value"] = json!(1082);
    let last = reading.to_string();
    let records = format!("{last}\n{first}\n");
    fs::write(dir.join("meter.ndjson"), &records).unwrap();
    let saved = trace(dir, "meter.ndjson").output().unwrap();
    let stream = piped(dir, records.as_bytes());
    for result in [&saved, &stream] {
        exit(result, 0);
        assert_eq!(result.stdout.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(result.stdout.last(), Some(&b'\n'));
    }
    assert_eq!(stream.stdout, saved.stdout);
    assert!(!String::from_utf8_lossy(&stream.stderr).contains("First exclusion"));
    let output: Value = serde_json::from_slice(&stream.stdout).unwrap();
    assert_eq!(output.as_object().unwrap().len(), 5);
    assert_eq!(output["register"][0]["wh"], 982);
    assert_eq!(output["register"][1]["wh"], 1082);
    assert_eq!(output["closed"][0]["wh"], 100);

    // A failed boundary reading is kept in the evidence file. Omitting its point
    // from the projected trace leaves the missing boundary for cemsd to report.
    reading["status"] = json!(0x8034_0000_u32);
    reading.as_object_mut().unwrap().remove("value");
    let gap = piped(dir, format!("{first}\n{reading}\n").as_bytes());
    exit(&gap, 0);
    let output: Value = serde_json::from_slice(&gap.stdout).unwrap();
    assert_eq!(output["register"].as_array().unwrap().len(), 1);
    assert_eq!(output["closed"][0]["wh"], 100);
    let diagnostic = String::from_utf8_lossy(&gap.stderr);
    assert!(diagnostic.contains("1 excluded by status"));
    assert!(diagnostic.contains("First exclusion at readings line 2 (source 2026-10-25T01:00:00Z): OPC UA status 0x80340000."));
}

// 006-meter-pilot/SR-002 006-meter-pilot/SR-003
#[test]
fn invalid_or_oversized_batch_is_rejected_before_trace_publication() {
    let temp = tempdir().unwrap();
    let dir = temp.path();
    let mut reading = fixture(dir);
    let first = reading.to_string();
    reading["device"] = json!("other-plant");
    exit(&piped(dir, format!("{first}\n{reading}\n").as_bytes()), 1);
    exit(&piped(dir, format!("{first}\n{{").as_bytes()), 1);
    let oversized = vec![b' '; opcua_kit::commissioning::MAX_DOCUMENT_BYTES + 1];
    exit(&piped(dir, &oversized), 1);
    fs::write(dir.join("too-big"), oversized).unwrap();
    exit(&trace(dir, "too-big").output().unwrap(), 1);
    let mut window: Value =
        serde_json::from_slice(&fs::read(dir.join("window.json")).unwrap()).unwrap();
    window["meter"]["node"]["id"] = json!("s=AnotherMeter");
    fs::write(dir.join("window.json"), window.to_string()).unwrap();
    exit(&piped(dir, first.as_bytes()), 1);
    fs::write(dir.join("window.json"), b"{}").unwrap();
    exit(&piped(dir, first.as_bytes()), 1);
}

#[test]
fn exported_meter_example_replays_and_preserves_existing_edits() {
    let dir = tempdir().unwrap();
    let export = || {
        Command::new(BIN)
            .current_dir(dir.path())
            .args(["meter", "example", "--export", "pilot"])
            .output()
            .unwrap()
    };
    exit(&export(), 0);
    let pilot = dir.path().join("pilot");
    let out = trace(&pilot, "readings.ndjson").output().unwrap();
    exit(&out, 0);
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!result["register"].as_array().unwrap().is_empty());
    assert!(!result["closed"].as_array().unwrap().is_empty());
    fs::write(pilot.join("contract.json"), "operator review").unwrap();
    exit(&export(), 1);
    assert_eq!(
        fs::read(pilot.join("contract.json")).unwrap(),
        b"operator review"
    );
}

// 007-float-meter/SR-002
#[test]
fn float_example_counts_precision_and_rejects_conflicting_payloads() {
    let root = tempdir().unwrap();
    let export = Command::new(BIN)
        .current_dir(root.path())
        .args([
            "meter",
            "example",
            "--register-type",
            "float",
            "--export",
            "shift",
        ])
        .output()
        .unwrap();
    exit(&export, 0);
    let dir = root.path().join("shift");
    let readings = fs::read_to_string(dir.join("readings.ndjson")).unwrap();
    let out = piped(&dir, readings.as_bytes());
    exit(&out, 0);
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("1 excluded for invalid or insufficiently precise whole Wh")
    );
    let output: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        output["register"].as_array().unwrap().len(),
        readings.lines().count() - 1
    );
    let mut conflict: Value = serde_json::from_str(readings.lines().nth(1).unwrap()).unwrap();
    conflict["valueBits"] = json!(f32::NAN.to_bits());
    exit(
        &piped(&dir, format!("{readings}{conflict}\n").as_bytes()),
        1,
    );
}

// 008-double-meter/SR-001 008-double-meter/SR-002
#[test]
fn double_example_preserves_large_odd_wh_and_refuses_malformed_hex() {
    let root = tempdir().unwrap();
    let export = Command::new(BIN)
        .current_dir(root.path())
        .args([
            "meter",
            "example",
            "--register-type",
            "double",
            "--export",
            "shift",
        ])
        .output()
        .unwrap();
    exit(&export, 0);
    let dir = root.path().join("shift");
    let out = trace(&dir, "readings.ndjson").output().unwrap();
    exit(&out, 0);
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("1 excluded for invalid or insufficiently precise whole Wh")
    );
    let trace: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(trace["register"][0]["wh"], 4_001_000_001u64);

    let records = fs::read_to_string(dir.join("readings.ndjson")).unwrap();
    let mut negative: Value = serde_json::from_str(records.lines().next().unwrap()).unwrap();
    negative["valueBits"] = json!("bff0000000000000");
    let out = piped(&dir, negative.to_string().as_bytes());
    exit(&out, 0);
    let projected: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(projected["register"], json!([]));
    assert_eq!(projected["closed"], trace["closed"]);
    let diagnostic = String::from_utf8_lossy(&out.stderr);
    assert!(diagnostic.contains("1 excluded for invalid or insufficiently precise whole Wh"));
    assert!(diagnostic.contains(
        "First exclusion at readings line 1 (source 2026-10-25T00:45:00Z): negative cumulative Wh."
    ));

    let mut malformed: Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
    malformed["valueBits"] = json!(42);
    exit(
        &piped(&dir, format!("{records}{malformed}\n").as_bytes()),
        1,
    );
}

// 009-safe-export/SR-002
#[test]
fn trace_output_preserves_counts_and_rejects_invalid_evidence() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    let mut reading = fixture(dir);
    let first = reading.to_string();
    reading["status"] = json!(0x8034_0000u32);
    reading["sourceAt"] = json!(END);
    reading.as_object_mut().unwrap().remove("value");
    let records = format!("{first}\n{reading}\n");
    fs::write(dir.join("input.ndjson"), &records).unwrap();
    let expected = piped(dir, records.as_bytes());
    exit(&expected, 0);
    assert!(String::from_utf8_lossy(&expected.stderr).contains("1 excluded by status"));

    let save = |name| {
        trace(dir, "input.ndjson")
            .args(["--output", name])
            .output()
            .unwrap()
    };
    let saved = save("trace.json");
    exit(&saved, 0);
    assert!(saved.stdout.is_empty());
    assert_eq!(saved.stderr, expected.stderr);
    assert_eq!(fs::read(dir.join("trace.json")).unwrap(), expected.stdout);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.join("trace.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
    for name in ["input.ndjson", "contract.json", "window.json"] {
        let path = dir.join(name);
        let before = fs::read(&path).unwrap();
        exit(&save(name), 1);
        assert_eq!(fs::read(path).unwrap(), before);
    }
    fs::write(
        dir.join("input.ndjson"),
        format!("{records}{{\"PRIVATE-READING\":1}}\n"),
    )
    .unwrap();
    let refused = save("invalid.json");
    exit(&refused, 1);
    let error = String::from_utf8(refused.stderr).unwrap();
    assert!(!error.contains("PRIVATE-READING") && !error.contains("Meter trace:"));
    assert!(!dir.join("invalid.json").exists());
    assert_eq!(fs::read_dir(dir).unwrap().count(), 4);
}

// 009-safe-export/SR-001
#[cfg(unix)]
#[test]
fn trace_output_preserves_link_entries() {
    use std::os::unix::fs::symlink;
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    let reading = fixture(dir);
    fs::write(dir.join("input.ndjson"), reading.to_string()).unwrap();
    fs::write(dir.join("existing"), b"operator copy").unwrap();
    fs::create_dir(dir.join("folder")).unwrap();
    for target in ["existing", "folder", "absent"] {
        let link = dir.join("alias");
        symlink(target, &link).unwrap();
        let refused = trace(dir, "input.ndjson")
            .args(["--output", "alias"])
            .output()
            .unwrap();
        exit(&refused, 1);
        assert_eq!(fs::read_link(&link).unwrap(), Path::new(target));
        fs::remove_file(&link).unwrap();
    }
    assert_eq!(fs::read(dir.join("existing")).unwrap(), b"operator copy");
    assert!(dir.join("folder").is_dir());
    assert!(!dir.join("absent").exists());
}

// 009-safe-export/SR-001 009-safe-export/SR-002
#[test]
fn competing_trace_outputs_publish_exactly_one_complete_result() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    let mut reading = fixture(dir);
    let mut contenders = Vec::new();
    for value in [101, 202] {
        reading["value"] = json!(value);
        let batch = reading.to_string();
        let expected = piped(dir, batch.as_bytes());
        exit(&expected, 0);
        let child = trace(dir, "-")
            .args(["--output", "shared.json"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        contenders.push((child, batch, expected.stdout));
    }
    // Both processes receive EOF only after they have started.
    for (child, batch, _) in &mut contenders {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(batch.as_bytes())
            .unwrap();
    }
    let mut winners = 0;
    for (child, _, expected) in contenders {
        let result = child.wait_with_output().unwrap();
        if result.status.success() {
            winners += 1;
            assert!(result.stdout.is_empty());
            assert_eq!(fs::read(dir.join("shared.json")).unwrap(), expected);
        } else {
            exit(&result, 1);
            assert!(!String::from_utf8_lossy(&result.stderr).contains("Meter trace:"));
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(fs::read_dir(dir).unwrap().count(), 3);
}

// 009-safe-export/SR-002
#[cfg(unix)]
#[test]
fn disconnected_logger_preserves_save_and_collision_exit_codes() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    fs::write(dir.join("input.ndjson"), fixture(dir).to_string()).unwrap();
    for expected in [0, 1] {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(reader);
        let out = trace(dir, "input.ndjson")
            .args(["--output", "trace.json"])
            .stderr(Stdio::from(OwnedFd::from(writer)))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(expected));
        assert!(out.stdout.is_empty());
    }
    let saved = fs::read(dir.join("trace.json")).unwrap();
    assert_eq!(saved, trace(dir, "input.ndjson").output().unwrap().stdout);
}
