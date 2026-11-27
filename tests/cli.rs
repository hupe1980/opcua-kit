#![cfg(feature = "cli")]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};
use tempfile::tempdir;

const BIN: &str = env!("CARGO_BIN_EXE_opcua-kit");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/commissioning");

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn inspection(dir: &Path, snapshot: &str) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.current_dir(dir).args([
        "check",
        "--contract",
        "contract.json",
        "--snapshot",
        snapshot,
    ]);
    cmd
}

fn inspect_pipe(dir: &Path, bytes: &[u8]) -> Output {
    pipe(inspection(dir, "-").arg("--json"), bytes)
}

fn pipe(command: &mut Command, bytes: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

fn exit(result: &Output, code: i32) {
    assert_eq!(
        result.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn meter_command_follows_cems_feature() {
    let dir = tempdir().unwrap();
    let help = run(dir.path(), &["meter", "--help"]);
    if cfg!(feature = "cems") {
        exit(&help, 0);
        assert!(String::from_utf8_lossy(&help.stdout).contains("opcua-kit meter"));
    } else {
        exit(&help, 1);
        assert!(String::from_utf8_lossy(&help.stderr).contains("unrecognized subcommand"));
    }
}

#[test]
fn native_capture_selection_and_scope_fail_before_connecting() {
    let dir = tempdir().unwrap();
    let dir = dir.path();
    let help = run(dir, &["capture", "--help"]);
    exit(&help, 0);
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("--client-uri")
    );

    let base = [
        "capture",
        "--client-uri",
        "urn:site:client",
        "--contract",
        "reviewed.json",
        "--endpoint",
        "opc.tcp://127.0.0.1:4840",
    ];
    let secure = [
        "--server-cert",
        "pin.der",
        "--client-cert",
        "client.der",
        "--client-key",
        "key.der",
    ];
    let rejected = run(dir, &[base.as_slice(), &["--insecure-loopback"]].concat());
    exit(&rejected, 1);
    assert!(rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("--insecure-loopback"));

    let mut doc: Value =
        serde_json::from_slice(include_bytes!("../fixtures/commissioning/contract.json")).unwrap();
    doc["principal"] = json!("operator");
    fs::write(dir.join("reviewed.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
    fs::write(dir.join("saved.json"), b"previous evidence").unwrap();
    let result = run(
        dir,
        &[base.as_slice(), &secure, &["--output", "saved.json"]].concat(),
    );
    exit(&result, 1);
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("anonymous")
    );
    assert_eq!(
        fs::read(dir.join("saved.json")).unwrap(),
        b"previous evidence"
    );
}

// 012-native-client/SR-001 012-native-client/SR-002
#[test]
fn native_read_help_and_local_errors_do_not_require_a_peer() {
    let dir = tempdir().unwrap();
    for (command, subject) in [("read", "UInt64"), ("describe", "DataType")] {
        let help = run(dir.path(), &[command, "--help"]);
        exit(&help, 0);
        let help = String::from_utf8(help.stdout).unwrap();
        assert_eq!(help.contains("--units"), command == "describe");
        for term in [
            subject,
            "--server-cert",
            "--client-key",
            "--server-uri",
            "--namespace",
            "--id",
        ] {
            assert!(help.contains(term), "{term} missing from {command} --help");
        }
    }
    let invoke = |command: &str, identifier: &str| {
        run(
            dir.path(),
            &[
                command,
                "--endpoint",
                "opc.tcp://127.0.0.1:4840",
                "--server-uri",
                "urn:server",
                "--client-uri",
                "urn:client",
                "--server-cert",
                "server.der",
                "--client-cert",
                "client.der",
                "--client-key",
                "client-key.der",
                "--namespace",
                "urn:meter",
                "--id",
                identifier,
            ],
        )
    };
    fs::write(dir.path().join("server.der"), vec![0; 64 * 1024 + 1]).unwrap();
    for command in ["read", "describe"] {
        let bad_id = invoke(command, "ns=2;i=1");
        exit(&bad_id, 1);
        assert!(bad_id.stdout.is_empty());
        assert!(String::from_utf8_lossy(&bad_id.stderr).contains("identifier"));

        let too_large = invoke(command, "i=1");
        exit(&too_large, 1);
        assert!(too_large.stdout.is_empty());
        assert!(String::from_utf8_lossy(&too_large.stderr).contains("--server-cert"));
    }
}

// 016-native-meter-reading: native credentials never fall back to another adapter.
#[cfg(feature = "cems")]
#[test]
fn native_meter_requires_pinned_credentials_and_validates_the_contract_first() {
    let dir = tempdir().unwrap();
    let help = run(dir.path(), &["meter", "read", "--help"]);
    exit(&help, 0);
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--client-uri") && help.contains("DER"));
    let base = [
        "meter",
        "read",
        "--endpoint",
        "opc.tcp://127.0.0.1:4840",
        "--client-uri",
        "urn:client",
        "--contract",
        "contract.json",
    ];
    let mut plain = base.to_vec();
    plain.push("--insecure-loopback");
    let refused = run(dir.path(), &plain);
    exit(&refused, 1);
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--insecure-loopback"));
    let mut pinned = base.to_vec();
    pinned.extend([
        "--server-cert",
        "missing.der",
        "--client-cert",
        "client.der",
        "--client-key",
        "key.der",
    ]);
    let contract = dir.path().join("contract.json");
    fs::write(
        &contract,
        include_bytes!("../fixtures/commissioning/contract.json"),
    )
    .unwrap();
    let invalid = run(dir.path(), &pinned);
    exit(&invalid, 1);
    assert!(invalid.stdout.is_empty());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("meter contract"));
    fs::write(&contract, include_bytes!("../fixtures/meter/contract.json")).unwrap();
    let credential = run(dir.path(), &pinned);
    exit(&credential, 1);
    assert!(credential.stdout.is_empty());
    assert!(String::from_utf8_lossy(&credential.stderr).contains("--server-cert"));
}

fn check(dir: &Path, before: &str, after: &str) -> Output {
    run(
        dir,
        &[
            "check",
            "--contract",
            "contract.json",
            "--before",
            before,
            "--after",
            after,
            "--json",
        ],
    )
}

fn export(dir: &Path) {
    exit(&run(dir, &["demo", "--export", "case"]), 0);
}

fn author(dir: &Path, action: &str, flag: &str, source: &str) -> Command {
    let mut command = Command::new(BIN);
    command
        .current_dir(dir)
        .args(["contract", action, flag, source]);
    command
}

// 004-contract-authoring/SR-001 004-contract-authoring/SR-003
#[test]
fn draft_is_reviewable_deterministic_and_reusable_by_check() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    for file in ["before.json", "after.json"] {
        fs::copy(Path::new(FIXTURES).join(file), dir.join(file)).unwrap();
    }
    let snapshot = fs::read(dir.join("before.json")).unwrap();
    let draft = author(dir, "draft", "--snapshot", "before.json")
        .output()
        .unwrap();
    exit(&draft, 0);
    assert!(draft.stderr.is_empty());
    let mut reordered: Value = serde_json::from_slice(&snapshot).unwrap();
    reordered["signals"].as_array_mut().unwrap().reverse();
    let replay = pipe(
        &mut author(dir, "draft", "--snapshot", "-"),
        &serde_json::to_vec(&reordered).unwrap(),
    );
    exit(&replay, 0);
    assert_eq!(draft.stdout, replay.stdout);
    let contract: Value = serde_json::from_slice(&draft.stdout).unwrap();
    let expected: Value =
        serde_json::from_slice(&fs::read(Path::new(FIXTURES).join("contract.json")).unwrap())
            .unwrap();
    assert_eq!(contract, expected);

    fs::write(dir.join("contract.json"), &draft.stdout).unwrap();
    let file = author(dir, "validate", "--contract", "contract.json")
        .output()
        .unwrap();
    let piped = pipe(
        &mut author(dir, "validate", "--contract", "-"),
        &draft.stdout,
    );
    for result in [file, piped] {
        exit(&result, 0);
        assert_eq!(result.stdout, b"Valid contract (3 signals)\n");
        assert!(result.stderr.is_empty());
    }
    exit(&inspection(dir, "before.json").output().unwrap(), 0);
    exit(&inspection(dir, "after.json").output().unwrap(), 2);

    let incomplete = author(dir, "draft", "--snapshot", "after.json")
        .output()
        .unwrap();
    exit(&incomplete, 1);
    assert!(incomplete.stdout.is_empty());
    assert!(
        String::from_utf8(incomplete.stderr)
            .unwrap()
            .contains("0x80340000")
    );
}

// 009-safe-export/SR-001 009-safe-export/SR-002
#[test]
fn draft_output_refuses_input_aliases_and_reports_destination_errors() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    let snapshot = fs::read(Path::new(FIXTURES).join("before.json")).unwrap();
    fs::write(dir.join("snapshot.json"), &snapshot).unwrap();
    fs::hard_link(dir.join("snapshot.json"), dir.join("alias.json")).unwrap();
    fs::write(dir.join("review.json"), "KEEP-REVIEW-PRIVATE").unwrap();

    let save = |name| {
        author(dir, "draft", "--snapshot", "snapshot.json")
            .args(["--output", name])
            .output()
            .unwrap()
    };
    for name in [
        "snapshot.json",
        "alias.json",
        "review.json",
        ".",
        "absent/contract.json",
        "-",
    ] {
        let out = save(name);
        exit(&out, 1);
        assert!(out.stdout.is_empty());
        let message = String::from_utf8(out.stderr).unwrap();
        assert!(!message.is_empty() && message.len() < 2048);
        assert!(!message.contains("KEEP-REVIEW-PRIVATE"));
        if name == "-" {
            assert!(
                message.contains("stdout") && message.contains("--output"),
                "{message}"
            );
        }
    }
    assert_eq!(fs::read(dir.join("snapshot.json")).unwrap(), snapshot);
    assert_eq!(fs::read(dir.join("alias.json")).unwrap(), snapshot);
    assert_eq!(
        fs::read(dir.join("review.json")).unwrap(),
        b"KEEP-REVIEW-PRIVATE"
    );
    assert!(!dir.join("absent").exists());
    assert!(!dir.join("-").exists());
    let literal = save("./-");
    exit(&literal, 0);
    assert!(literal.stdout.is_empty());
    let expected = author(dir, "draft", "--snapshot", "snapshot.json")
        .output()
        .unwrap();
    exit(&expected, 0);
    assert_eq!(fs::read(dir.join("-")).unwrap(), expected.stdout);
}

// 004-contract-authoring/SR-002 004-contract-authoring/SR-003
#[test]
fn authoring_rejects_invalid_inputs_without_partial_output() {
    let dir = Path::new(FIXTURES);
    let tmp = tempdir().unwrap();
    for (action, flag, fixture) in [
        ("draft", "--snapshot", "before.json"),
        ("validate", "--contract", "contract.json"),
    ] {
        let mut padded = fs::read(dir.join(fixture)).unwrap();
        let limit = opcua_kit::commissioning::MAX_DOCUMENT_BYTES;
        for (size, expected_exit) in [(limit, 0), (limit + 1, 1)] {
            padded.resize(size, b' ');
            fs::write(tmp.path().join("input.json"), &padded).unwrap();
            let file = author(tmp.path(), action, flag, "input.json")
                .output()
                .unwrap();
            let stream = pipe(&mut author(tmp.path(), action, flag, "-"), &padded);
            exit(&file, expected_exit);
            exit(&stream, expected_exit);
            assert_eq!(file.stdout, stream.stdout);
            if expected_exit == 1 {
                assert!(file.stdout.is_empty());
            }
        }
        for bytes in [b"".as_slice(), br#"{"bad\u001b":0}"#, b"{}{}"] {
            let out = pipe(&mut author(dir, action, flag, "-"), bytes);
            exit(&out, 1);
            assert!(out.stdout.is_empty());
            assert!(!out.stderr.is_empty() && out.stderr.len() < 2048);
            assert!(!out.stderr.contains(&27));
        }
        let out = author(dir, action, flag, ".").output().unwrap();
        exit(&out, 1);
        assert!(out.stdout.is_empty());
    }
}

// 004-contract-authoring/SR-001
#[test]
fn draft_reports_raw_status_for_invalid_typed_metadata() {
    let dir = Path::new(FIXTURES);
    let mut snapshot: Value =
        serde_json::from_slice(&fs::read(dir.join("before.json")).unwrap()).unwrap();
    let signal = snapshot["signals"][0].clone();
    for (field, value, status) in [
        (
            "dataType",
            Some(json!({"namespace": "urn:test", "id": "i=invalid"})),
            0x400u32,
        ),
        ("valueRank", Some(json!(-4)), 0x400),
        (
            "engineeringUnits",
            Some(json!({"namespaceUri": "urn:test\n", "unitId": 1})),
            0x400,
        ),
        ("dataType", None, 0x400),
        ("valueRank", Some(json!(-1)), 0x80340400),
    ] {
        let mut evidence = json!({"status": status});
        if let Some(value) = value {
            evidence["value"] = value;
        }
        snapshot["signals"][0] = signal.clone();
        snapshot["signals"][0][field] = evidence;
        let out = pipe(
            &mut author(dir, "draft", "--snapshot", "-"),
            &serde_json::to_vec(&snapshot).unwrap(),
        );
        exit(&out, 1);
        assert!(out.stdout.is_empty());
        let diagnostic = String::from_utf8(out.stderr).unwrap();
        assert!(
            diagnostic.contains(&format!("signals[0].{field}")),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains(&format!("0x{status:08X}")),
            "{diagnostic}"
        );
    }
}

// 004-contract-authoring/SR-003: A readable draft must fit the input limit including its newline.
#[test]
fn draft_at_input_limit_falls_back_to_compact_valid_json() {
    use opcua_kit::commissioning::MAX_DOCUMENT_BYTES;

    let dir = Path::new(FIXTURES);
    let mut snapshot: Value =
        serde_json::from_slice(&fs::read(dir.join("before.json")).unwrap()).unwrap();
    snapshot["device"] = json!("");
    let padding = MAX_DOCUMENT_BYTES - serde_json::to_vec(&snapshot).unwrap().len();
    snapshot["device"] = json!("x".repeat(padding));
    let input = serde_json::to_vec(&snapshot).unwrap();
    assert_eq!(input.len(), MAX_DOCUMENT_BYTES);
    let draft = pipe(&mut author(dir, "draft", "--snapshot", "-"), &input);
    exit(&draft, 0);
    assert!(draft.stdout.len() <= MAX_DOCUMENT_BYTES);
    assert_eq!(draft.stdout.last(), Some(&b'\n'));
    assert!(!draft.stdout[..draft.stdout.len() - 1].contains(&b'\n'));
    let validated = pipe(
        &mut author(dir, "validate", "--contract", "-"),
        &draft.stdout,
    );
    exit(&validated, 0);
    assert_eq!(validated.stdout, b"Valid contract (3 signals)\n");
}

// 009-safe-export/SR-002
// 004-contract-authoring/SR-003: Bidi marks stay visible to reviewers without changing identity.
#[test]
fn draft_escapes_review_controls_and_enforces_the_escaped_size() {
    use opcua_kit::commissioning::MAX_DOCUMENT_BYTES;

    let dir = Path::new(FIXTURES);
    let mut source: Value =
        serde_json::from_slice(&fs::read(dir.join("before.json")).unwrap()).unwrap();
    let mut expected: Value =
        serde_json::from_slice(&fs::read(dir.join("contract.json")).unwrap()).unwrap();
    let label = "設備\u{202e}\u{2066}\u{061c}";
    expected["device"] = json!(label);
    source["device"] = json!(label);
    let draft = pipe(
        &mut author(dir, "draft", "--snapshot", "-"),
        &serde_json::to_vec(&source).unwrap(),
    );
    exit(&draft, 0);
    let text = std::str::from_utf8(&draft.stdout).unwrap();
    assert!(text.contains(r"設備\u202e\u2066\u061c"));
    assert_eq!(
        serde_json::from_slice::<Value>(&draft.stdout).unwrap(),
        expected
    );

    // Without the escapes, pretty JSON plus its newline would fit exactly.
    let padding = MAX_DOCUMENT_BYTES - serde_json::to_vec_pretty(&expected).unwrap().len() - 1;
    expected["device"] = json!(format!("{label}{}", "a".repeat(padding)));
    source["device"] = expected["device"].clone();
    let input = serde_json::to_vec(&source).unwrap();
    assert!(input.len() <= MAX_DOCUMENT_BYTES);
    let compact = pipe(&mut author(dir, "draft", "--snapshot", "-"), &input);
    exit(&compact, 0);
    assert!(compact.stdout.len() <= MAX_DOCUMENT_BYTES);
    assert_eq!(compact.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&compact.stdout).unwrap(),
        expected
    );

    let tmp = tempdir().unwrap();
    let exported = pipe(
        author(tmp.path(), "draft", "--snapshot", "-").args(["--output", "compact.json"]),
        &input,
    );
    exit(&exported, 0);
    assert!(exported.stdout.is_empty() && exported.stderr.is_empty());
    assert_eq!(
        fs::read(tmp.path().join("compact.json")).unwrap(),
        compact.stdout
    );

    source["device"] = json!("\u{202e}".repeat(MAX_DOCUMENT_BYTES / 6 + 1));
    let oversized = serde_json::to_vec(&source).unwrap();
    for out in [
        pipe(&mut author(dir, "draft", "--snapshot", "-"), &oversized),
        pipe(
            author(tmp.path(), "draft", "--snapshot", "-").args(["--output", "oversized.json"]),
            &oversized,
        ),
    ] {
        exit(&out, 1);
        assert!(out.stdout.is_empty());
        assert!(
            String::from_utf8(out.stderr)
                .unwrap()
                .contains("draft contract exceeds 4 MiB")
        );
    }
    assert!(!tmp.path().join("oversized.json").exists());
}

// 004-contract-authoring/SR-002
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn authoring_refuses_terminal_stdin_with_the_relevant_option() {
    for (action, flag) in [("draft", "--snapshot"), ("validate", "--contract")] {
        let tty = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/ptmx")
            .unwrap();
        let out = author(Path::new(FIXTURES), action, flag, "-")
            .stdin(tty)
            .output()
            .unwrap();
        exit(&out, 1);
        assert!(out.stdout.is_empty());
        let diagnostic = String::from_utf8(out.stderr).unwrap();
        assert!(diagnostic.contains(&format!("{flag} FILE")));
    }
}

// 003-first-inspection/SR-001 003-first-inspection/SR-002
#[test]
fn first_inspection_distinguishes_absent_baseline_from_missing_evidence() {
    let tmp = tempdir().unwrap();
    exit(
        &run(
            tmp.path(),
            &["demo", "--scenario", "units", "--export", "case"],
        ),
        0,
    );
    let dir = tmp.path().join("case");
    let mut partial: Value =
        serde_json::from_slice(&fs::read(dir.join("before.json")).unwrap()).unwrap();
    partial["signals"] = json!([]);
    fs::write(dir.join("empty.json"), partial.to_string()).unwrap();
    for (name, code, counts) in [
        (
            "before.json",
            0,
            json!({"matched":2,"mismatch":0,"unverified":0}),
        ),
        (
            "after.json",
            2,
            json!({"matched":1,"mismatch":1,"unverified":0}),
        ),
        (
            "empty.json",
            3,
            json!({"matched":0,"mismatch":0,"unverified":2}),
        ),
    ] {
        let file = inspection(&dir, name).arg("--json").output().unwrap();
        let pipe = inspect_pipe(&dir, &fs::read(dir.join(name)).unwrap());
        exit(&file, code);
        exit(&pipe, code);
        assert_eq!(pipe.stdout, file.stdout);
        assert!(pipe.stderr.is_empty() && file.stderr.is_empty());
        let report: Value = serde_json::from_slice(&pipe.stdout).unwrap();
        assert_eq!(report["schemaVersion"], 2);
        assert_eq!(report["baselineProvided"], false);
        assert_eq!(report["counts"], counts);
        for f in report["findings"].as_array().unwrap() {
            assert_eq!(f.get("before"), Some(&Value::Null));
            assert_eq!(f.get("beforeOutcome"), Some(&Value::Null));
            if code != 3 {
                assert_eq!(f["after"]["status"], 0);
            }
        }
    }
    let text = inspection(&dir, "before.json").output().unwrap();
    exit(&text, 0);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("First inspection"));
    assert!(!text.contains("RESOLVED"));

    let partial = check(&dir, "empty.json", "before.json");
    exit(&partial, 0);
    let report: Value = serde_json::from_slice(&partial.stdout).unwrap();
    assert_eq!(report["baselineProvided"], true);
    for f in report["findings"].as_array().unwrap() {
        assert_eq!(f.get("before"), Some(&Value::Null));
        assert_eq!(f["beforeOutcome"], "unverified");
    }
}

// 003-first-inspection/SR-002 003-first-inspection/SR-003
#[test]
fn snapshot_input_has_the_same_bounds_and_validation_in_pipes_and_files() {
    use opcua_kit::commissioning::MAX_DOCUMENT_BYTES;

    let tmp = tempdir().unwrap();
    export(tmp.path());
    let dir = tmp.path().join("case");
    let mut bytes = fs::read(dir.join("before.json")).unwrap();
    bytes.resize(MAX_DOCUMENT_BYTES, b' ');
    fs::write(dir.join("limit.json"), &bytes).unwrap();
    let exact = inspection(&dir, "limit.json")
        .arg("--json")
        .output()
        .unwrap();
    exit(&exact, 0);
    let streamed = inspect_pipe(&dir, &bytes);
    exit(&streamed, 0);
    assert_eq!(exact.stdout, streamed.stdout);
    bytes.push(b' ');
    let scope = fs::read_to_string(dir.join("before.json"))
        .unwrap()
        .replace("anonymous", "different");
    let mut trailing = fs::read(dir.join("before.json")).unwrap();
    trailing.extend_from_slice(b"{}");
    for invalid in [
        Vec::new(),
        b"{".to_vec(),
        br#"{"\u001b[31m":0}"#.to_vec(),
        scope.into_bytes(),
        trailing,
        bytes,
    ] {
        fs::write(dir.join("invalid.json"), &invalid).unwrap();
        for out in [
            inspect_pipe(&dir, &invalid),
            inspection(&dir, "invalid.json")
                .arg("--json")
                .output()
                .unwrap(),
        ] {
            exit(&out, 1);
            assert!(out.stdout.is_empty());
            assert!(!out.stderr.is_empty() && out.stderr.len() < 2048);
            assert!(!out.stderr.contains(&27));
        }
    }
    let unknown_flag = format!("--{}", "界".repeat(4_000));
    let out = run(&dir, &["check", &unknown_flag]);
    exit(&out, 1);
    assert!(out.stdout.is_empty() && out.stderr.len() < 1200);
    assert!(String::from_utf8(out.stderr).unwrap().contains("--help"));
    let out = inspection(&dir, &"a".repeat(10_000)).output().unwrap();
    exit(&out, 1);
    assert!(out.stdout.is_empty() && out.stderr.len() < 2048);
    assert!(String::from_utf8(out.stderr).unwrap().contains("…: "));
}

// 003-first-inspection/SR-003: Use an actual pseudo-terminal without invoking a shell.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn snapshot_dash_rejects_interactive_input_with_a_pipe_hint() {
    let dir = Path::new(FIXTURES);
    let terminal = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/ptmx")
        .unwrap();
    let out = inspection(dir, "-").stdin(terminal).output().unwrap();
    exit(&out, 1);
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("pipe a snapshot")
    );
}

// 003-first-inspection/SR-003
#[test]
fn only_the_current_snapshot_treats_a_literal_dash_as_stdin() {
    let tmp = tempdir().unwrap();
    export(tmp.path());
    let dir = tmp.path().join("case");
    fs::copy(dir.join("contract.json"), dir.join("-")).unwrap();
    exit(
        &run(
            &dir,
            &["check", "--contract", "-", "--after", "before.json"],
        ),
        0,
    );
    fs::copy(dir.join("before.json"), dir.join("-")).unwrap();
    exit(
        &run(
            &dir,
            &[
                "check",
                "--contract",
                "contract.json",
                "--before",
                "-",
                "--snapshot",
                "./-",
            ],
        ),
        0,
    );
    let help = run(&dir, &["check", "--help"]);
    exit(&help, 0);
    let help = String::from_utf8(help.stdout).unwrap();
    for option in ["--snapshot", "--before", "--after", "First inspection"] {
        assert!(help.contains(option));
    }
}

#[test]
fn installed_demo_and_editable_case_share_the_library_decision() {
    let tmp = tempdir().unwrap();
    export(tmp.path());
    let dir = tmp.path().join("case");
    let demo = run(tmp.path(), &["demo", "--json"]);
    let mixed = check(&dir, "before.json", "after.json");
    exit(&demo, 2);
    assert!(mixed.stderr.is_empty());
    assert_eq!(demo.stdout, mixed.stdout);
    let report: Value = serde_json::from_slice(&mixed.stdout).unwrap();
    assert_eq!(
        report["counts"],
        json!({"matched":1,"mismatch":1,"unverified":1})
    );
    assert_eq!(report["complete"], false);
    let before = fs::read(dir.join("before.json")).unwrap();
    let after = fs::read(dir.join("after.json")).unwrap();
    let contract = fs::read(dir.join("contract.json")).unwrap();
    use opcua_kit::commissioning::{compare, parse_contract, parse_snapshot};
    let library = compare(
        &parse_contract(&contract).unwrap(),
        &parse_snapshot(&before).unwrap(),
        &parse_snapshot(&after).unwrap(),
    )
    .unwrap();
    assert_eq!(serde_json::to_value(library).unwrap(), report);

    let resolved = check(&dir, "after.json", "before.json");
    exit(&resolved, 0);
    let report: Value = serde_json::from_slice(&resolved.stdout).unwrap();
    let temp = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "SupplyTemp")
        .unwrap();
    assert_eq!(temp["beforeOutcome"], "mismatch");
    assert_eq!(temp["outcome"], "matched");
    let mut partial: Value = serde_json::from_slice(&before).unwrap();
    partial["signals"].as_array_mut().unwrap().pop();
    fs::write(dir.join("partial.json"), partial.to_string()).unwrap();
    exit(&check(&dir, "before.json", "partial.json"), 3);

    let text = run(tmp.path(), &["demo"]);
    let text = String::from_utf8(text.stdout).unwrap();
    for term in ["Double", "String", "BadNodeIdUnknown", "0x80340000"] {
        assert!(text.contains(term));
    }
    fs::write(dir.join("contract.json"), "operator edits").unwrap();
    exit(&run(tmp.path(), &["demo", "--export", "case"]), 1);
    assert_eq!(
        fs::read(dir.join("contract.json")).unwrap(),
        b"operator edits"
    );
}

// SR-003 SR-004
#[test]
fn invalid_input_has_bounded_safe_diagnostics_and_no_stdout() {
    let tmp = tempdir().unwrap();
    export(tmp.path());
    let dir = tmp.path().join("case");
    for bytes in [
        vec![b' '; 4 * 1024 * 1024 + 1],
        br#"{"\u001b[31m":0}"#.to_vec(),
    ] {
        fs::write(dir.join("broken.json"), bytes).unwrap();
        let out = check(&dir, "before.json", "broken.json");
        exit(&out, 1);
        assert!(out.stdout.is_empty() && !out.stderr.is_empty());
        assert!(!out.stderr.contains(&27) && out.stderr.len() < 2048);
    }
    let out = run(&dir, &["--bad\x1b[31m"]);
    exit(&out, 1);
    assert!(out.stdout.is_empty() && !out.stderr.contains(&27));
    exit(&run(&dir, &["--help"]), 0);
}

#[test]
fn offline_preflight_rejects_output_and_preserves_inputs() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    let contract = include_bytes!("../fixtures/commissioning/contract.json");
    fs::write(dir.join("contract.json"), contract).unwrap();
    fs::write(dir.join("saved.json"), b"prior evidence").unwrap();
    for output in ["saved.json", "new.json"] {
        let result = Command::new(BIN)
            .current_dir(dir)
            .env("PATH", "")
            .args([
                "capture",
                "--preflight",
                "--contract",
                "contract.json",
                "--endpoint",
                "opc.tcp://127.0.0.1:4840",
                "--server-cert",
                "pin.der",
                "--client-cert",
                "client.der",
                "--client-key",
                "key.der",
                "--output",
                output,
            ])
            .output()
            .unwrap();
        exit(&result, 1);
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("--output"));
    }
    assert_eq!(fs::read(dir.join("saved.json")).unwrap(), b"prior evidence");
    assert_eq!(fs::read(dir.join("contract.json")).unwrap(), contract);
    assert!(!dir.join("new.json").exists());
}

// 002-engineering-units/SR-004: Replay the exact unit finding, including unusable Good evidence.
#[test]
fn unit_scenario_explains_drift_repair_and_incomplete_identity() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();
    exit(
        &run(dir, &["demo", "--scenario", "units", "--export", "case"]),
        0,
    );
    let case = dir.join("case");
    let demo = run(dir, &["demo", "--scenario", "units", "--json"]);
    exit(&demo, 2);
    let replay = check(&case, "before.json", "after.json");
    exit(&replay, 2);
    assert_eq!(demo.stdout, replay.stdout);
    let report: Value = serde_json::from_slice(&demo.stdout).unwrap();
    assert_eq!(
        report["counts"],
        json!({"matched":1,"mismatch":1,"unverified":0})
    );
    let text = run(dir, &["demo", "--scenario", "units"]);
    exit(&text, 2);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("SupplyTemp.EngineeringUnits  expected °C (CEL), observed °F (FAH)"));
    let human = |after| {
        run(
            &case,
            &[
                "check",
                "--contract",
                "contract.json",
                "--before",
                "after.json",
                "--after",
                after,
            ],
        )
    };
    let repaired = human("before.json");
    exit(&repaired, 0);
    assert!(
        String::from_utf8(repaired.stdout)
            .unwrap()
            .contains("RESOLVED    SupplyTemp.EngineeringUnits")
    );
    let mut unknown: Value =
        serde_json::from_slice(&fs::read(case.join("before.json")).unwrap()).unwrap();
    unknown["signals"][0]["engineeringUnits"]["value"]["unitId"] = json!(-1);
    fs::write(case.join("unknown.json"), unknown.to_string()).unwrap();
    let result = human("unknown.json");
    exit(&result, 3);
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains(
        "UNVERIFIED  SupplyTemp.EngineeringUnits  server supplied no usable unit identity"
    ));
    assert!(!text.contains("MISMATCH"));
    // A custom authority can contain bidi marks. Diagnostics render them visibly.
    unknown["signals"][0]["engineeringUnits"]["value"] =
        json!({"namespaceUri":"urn:custom\u{202e}site","unitId":23});
    fs::write(case.join("unknown.json"), unknown.to_string()).unwrap();
    let result = human("unknown.json");
    exit(&result, 2);
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains(r"urn:custom\u{202e}site (unitId 23)"));
}
