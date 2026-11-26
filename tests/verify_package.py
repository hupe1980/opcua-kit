"""Exercise the default Rust library and opt-in CLI from the extracted Cargo package."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def cargo(*args):
    return subprocess.run(
        ["cargo", *args], text=True, check=True, stdout=subprocess.PIPE
    ).stdout


def verify_library_consumer(
    root, source, rust_version, name, *, offline_feature=None, wrapper_override=None
):
    consumer = root / name
    (consumer / "src").mkdir(parents=True)
    manifest = consumer / "Cargo.toml"
    features = (
        f', default-features = false, features = ["{offline_feature}"]'
        if offline_feature
        else ""
    )
    time_dep = 'time = "0.3"' if offline_feature == "cems" else ""
    content = f"""[package]
name = "consumer-{name}"
version = "0.0.0"
edition = "2024"
rust-version = "{rust_version}"

[dependencies]
opcua-kit = {{ path = {json.dumps(str(source), ensure_ascii=False)}{features} }}
{time_dep}
"""
    if wrapper_override:
        content += f"\n[patch.crates-io]\nopen62541 = {{ path = {json.dumps(str(wrapper_override))} }}\n"
    manifest.write_text(content)
    source_file = {
        None: "default.rs",
        "commissioning": "commissioning.rs",
        "cems": "meter.rs",
    }[offline_feature]
    (consumer / "src/main.rs").write_bytes(
        (source / "tests/consumer" / source_file).read_bytes()
    )
    (consumer / "Cargo.lock").write_bytes((source / "Cargo.lock").read_bytes())
    args = ["--manifest-path", str(manifest)]
    graph = json.loads(cargo("metadata", "--format-version=1", *args))
    names = {p["id"]: p["name"] for p in graph["packages"]}
    for node in graph["resolve"]["nodes"]:
        package = names[node["id"]]
        assert package not in {"chrono", "chrono-tz", "clap", "signal-hook"}, (
            name,
            package,
        )
        if package == "opcua-kit":
            expected = (
                {"commissioning", offline_feature}
                if offline_feature
                else {"client", "default"}
            )
            assert set(node["features"]) == expected, node
        if package == "time":
            assert "local-offset" not in node["features"], node
    assert ("open62541" in names.values()) == (offline_feature is None)
    if offline_feature == "commissioning":
        assert "time" not in names.values()
    if offline_feature is None:
        wrapper = next(p for p in graph["packages"] if p["name"] == "open62541")
        if (source / "vendor/open62541/Cargo.toml").is_file() or wrapper_override:
            assert wrapper["source"] is None and "pastey" in names.values()
            assert "paste" not in names.values()
        else:
            assert wrapper["source"].startswith("registry+")
    fixture = "meter" if offline_feature == "cems" else "commissioning"
    run_args = [str(source / "fixtures" / fixture)] if offline_feature else []
    cargo("run", "--locked", *args, "--", *run_args)
    print(f"Verified {name} Rust consumer.")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--allow-dirty", action="store_true", help="package edits in this checkout"
)
parser.add_argument(
    "--cemsd", type=Path, help="also run the installed trace through this EMS consumer"
)
options = parser.parse_args()
cemsd = options.cemsd.resolve(strict=True) if options.cemsd else None
package_args = ["--locked"]
if options.allow_dirty:
    package_args.append("--allow-dirty")
cargo("package", *package_args)
files = cargo("package", *package_args, "--list").splitlines()
assert "fixtures/units/contract.json" in files
assert {"CHANGELOG.md", "CONTRIBUTING.md"} <= set(files)
assert "contrib/open62541-pastey.patch" in files
assert "site/content/client.md" in files
assert "site/content/services.md" in files
assert {
    "examples/uadp.rs",
    "examples/local_server.rs",
    "src/pubsub.rs",
    "src/server.rs",
} <= set(files)
assert "src/bin/opcua-kit/capture.py" in files
assert "site/content/authoring.md" in files
assert "site/content/meter.md" in files
assert "fixtures/meter/readings.ndjson" in files
assert not any(f.startswith(("concepts/", "specs/", ".specify/")) for f in files)
meta = json.loads(cargo("metadata", "--format-version=1", "--no-deps"))
crate = next(p for p in meta["packages"] if p["name"] == "opcua-kit")
source = Path(meta["target_directory"], "package", "opcua-kit-" + crate["version"])

with tempfile.TemporaryDirectory() as scratch:
    root = Path(scratch)
    checkout = Path(crate["manifest_path"]).parent
    verify_library_consumer(root, source, crate["rust_version"], "archive")
    for feature in ("commissioning", "cems"):
        verify_library_consumer(
            root,
            source,
            crate["rust_version"],
            f"archive-{feature}",
            offline_feature=feature,
        )
    # Verify optional roles against the normalized archive and its actual registry backend.
    for feature, example in (("server", "local_server"), ("pubsub", "uadp")):
        cargo(
            "build",
            "--locked",
            "--manifest-path",
            str(source / "Cargo.toml"),
            "--no-default-features",
            "--features",
            feature,
            "--example",
            example,
        )
    cargo(
        "check",
        "--locked",
        "--manifest-path",
        str(source / "Cargo.toml"),
        "--features",
        "control",
    )
    # The normalized registry archive omits the versioned path dependency.
    wrapper = checkout / "vendor/open62541"
    if (wrapper / "Cargo.toml").is_file():
        verify_library_consumer(root, checkout, crate["rust_version"], "checkout")
        verify_library_consumer(
            root,
            source,
            crate["rust_version"],
            "archive-patched",
            wrapper_override=wrapper,
        )
    cargo(
        "install",
        "--locked",
        "--features",
        "cli,cems",
        "--path",
        str(source),
        "--root",
        str(root / "kit"),
    )
    binary = root / "kit/bin/opcua-kit"

    def invoke(code, *args, stdin=None):
        r = subprocess.run(
            [binary, *args],
            cwd=root,
            input=stdin,
            capture_output=True,
            check=False,
            timeout=10,
        )
        assert r.returncode == code, (r.returncode, r.stderr)
        return r.stdout

    # 009-safe-export/SR-001 009-safe-export/SR-002
    def save_trace(filename, args, source, stdin=None):
        expected = invoke(0, *args, source, stdin=stdin)
        assert invoke(0, *args, source, "--output", filename, stdin=stdin) == b""
        path = root / filename
        assert path.read_bytes() == expected
        return path

    # 006-meter-pilot/SR-002 006-meter-pilot/SR-003
    invoke(0, "meter", "example", "--export", "shift")
    trace = (
        "meter",
        "trace",
        "--contract",
        "shift/contract.json",
        "--window",
        "shift/window.json",
        "--readings",
    )
    readings = (root / "shift/readings.ndjson").read_bytes()
    saved_good = save_trace("trace.json", trace, "shift/readings.ndjson")
    good_trace = saved_good.read_bytes()
    assert good_trace == invoke(0, *trace, "-", stdin=readings)
    assert invoke(1, *trace, "shift/readings.ndjson", "--output", "-") == b""
    assert not (root / "-").exists()
    assert invoke(0, *trace, "shift/readings.ndjson", "--output", "./-") == b""
    assert (root / "-").read_bytes() == good_trace
    (root / "-").unlink()
    records = [json.loads(line) for line in readings.splitlines()]
    assert [p["wh"] for p in json.loads(good_trace)["register"]] == [
        r["value"] for r in records
    ]
    # Substitute an unusable read at the boundary shared by two quarters.
    shared = records[-2]
    shared["status"] = 0x80340000
    del shared["value"]
    batch = "\n".join(map(json.dumps, records)).encode()
    saved_gap = save_trace("gap.json", trace, "-", stdin=batch)
    gap_trace = saved_gap.read_bytes()
    assert invoke(1, *trace, "-", "--output", "trace.json", stdin=batch) == b""
    assert saved_good.read_bytes() == good_trace
    assert invoke(1, *trace, "-", "--output", "invalid.json", stdin=b"invalid") == b""
    assert not (root / "invalid.json").exists()
    assert len(json.loads(gap_trace)["register"]) == len(records) - 1
    # Interior readings remain available to the consumer's decrease detector.
    reset_records = [json.loads(line) for line in readings.splitlines()]
    reset_records[1]["value"] = reset_records[0]["value"] - 1
    reset = "\n".join(map(json.dumps, reset_records)).encode()
    saved_reset = save_trace("reset.json", trace, "-", stdin=reset)
    # 007-float-meter/SR-002 008-double-meter/SR-002. Both floating-point
    # fixtures add a fractional interior sample that cannot supply whole Wh.
    cases = [
        (saved_good, 0, ["within_tolerance"] * 2),
        (saved_gap, 1, ["missing_boundary"] * 2),
        (saved_reset, 1, ["register_decreased", "within_tolerance"]),
    ]
    for dtype, offset, coarse_word in [
        ("float", 0, 0x4B800000),
        ("double", 4_000_000_001, "4340000000000000"),
    ]:
        invoke(0, "meter", "example", "--register-type", dtype, "--export", dtype)
        args = (
            "meter",
            "trace",
            "--contract",
            f"{dtype}/contract.json",
            "--window",
            f"{dtype}/window.json",
            "--readings",
        )
        sample = save_trace(f"{dtype}-trace.json", args, f"{dtype}/readings.ndjson")
        expected = json.loads(good_trace)
        for point in expected["register"]:
            point["wh"] += offset
        assert json.loads(sample.read_bytes()) == expected
        rows = [
            json.loads(line)
            for line in (root / dtype / "readings.ndjson").read_bytes().splitlines()
        ]
        shared_at = json.loads((root / dtype / "window.json").read_bytes())["closed"][
            1
        ]["at"]
        shared_row = next(row for row in rows if row["sourceAt"] == shared_at)
        shared_row["valueBits"] = coarse_word
        batch = "\n".join(map(json.dumps, rows)).encode()
        gap = save_trace(f"{dtype}-gap.json", args, "-", stdin=batch)
        expected_gap = json.loads(gap_trace)
        for point in expected_gap["register"]:
            point["wh"] += offset
        assert json.loads(gap.read_bytes()) == expected_gap
        cases.extend(
            [(sample, 0, ["within_tolerance"] * 2), (gap, 1, ["missing_boundary"] * 2)]
        )

    if cemsd and os.name == "posix":
        # The shell creates the consumer report only if the right side of &&
        # runs. Keep all paths in positional arguments, outside shell source.
        chain = subprocess.run(
            [
                "sh",
                "-c",
                (
                    '"$1" meter trace --contract shift/contract.json --window shift/window.json '
                    '--readings - --output rejected.json && "$2" reconcile rejected.json > downstream.json'
                ),
                "handoff",
                str(binary),
                str(cemsd),
            ],
            cwd=root,
            input=b"invalid",
            capture_output=True,
            check=False,
            timeout=10,
        )
        assert chain.returncode == 1 and chain.stdout == b""
        assert not (root / "rejected.json").exists()
        assert not (root / "downstream.json").exists()

    if cemsd:
        for trace_file, expected, states in cases:
            actual = subprocess.run(
                [cemsd, "reconcile", trace_file],
                cwd=root,
                capture_output=True,
                check=False,
                timeout=10,
            )
            assert actual.returncode == expected, actual.stderr
            report = json.loads(actual.stdout)
            assert [i["status"] for i in report["intervals"]] == states
            if expected == 0:
                assert [i["difference_wh"] for i in report["intervals"]] == [0, 1]
        print(
            "Real cemsd confirmed integer, Float and Double quarters, missing quality and precision boundaries, and an interior counter decrease."
        )

    invoke(0, "demo", "--scenario", "units", "--export", "visit")
    # 005-capture-preflight/SR-001 005-capture-preflight/SR-003
    prepare = (
        "capture",
        "--preflight",
        "--contract",
        "visit/contract.json",
        "--endpoint",
        "opc.tcp://127.0.0.1:4840",
        "--insecure-loopback",
    )
    ready = invoke(0, *prepare)
    assert b"offline" in ready.lower() and b"endpoint" in ready.lower()
    assert invoke(1, *prepare, "--output", "unused.json") == b""
    assert not (root / "unused.json").exists()
    # 004-contract-authoring/SR-001 004-contract-authoring/SR-003
    draft_args = ("contract", "draft", "--snapshot")
    validate_args = ("contract", "validate", "--contract")
    reference = (root / "visit/before.json").read_bytes()
    draft = invoke(0, *draft_args, "visit/before.json")
    assert draft == invoke(0, *draft_args, "-", stdin=reference)
    assert invoke(1, *draft_args, "visit/before.json", "--output", "-") == b""
    assert not (root / "-").exists()
    assert invoke(0, *draft_args, "visit/before.json", "--output", "./-") == b""
    assert (root / "-").read_bytes() == draft
    assert draft.endswith(b"\n")
    assert json.loads(draft) == json.loads((root / "visit/contract.json").read_bytes())
    assert invoke(0, *draft_args, "visit/before.json", "--output", "draft.json") == b""
    assert (root / "draft.json").read_bytes() == draft
    summary = invoke(0, *validate_args, "draft.json")
    assert b"1 signal" in summary and summary == invoke(
        0, *validate_args, "-", stdin=draft
    )
    author_check = ("check", "--contract", "draft.json", "--snapshot")
    invoke(0, *author_check, "visit/before.json")
    assert b"SupplyTemp.EngineeringUnits" in invoke(
        2, *author_check, "visit/after.json"
    )
    edited = json.loads(draft)
    edited["signals"][0]["valueRank"] = -1
    edited_bytes = json.dumps(edited).encode()
    (root / "draft.json").write_bytes(edited_bytes)
    assert invoke(1, *draft_args, "-", "--output", "draft.json", stdin=reference) == b""
    assert (root / "draft.json").read_bytes() == edited_bytes
    invoke(0, *validate_args, "draft.json")
    assert b"UNVERIFIED" in invoke(3, *author_check, "visit/before.json")
    incomplete = json.loads(reference)
    incomplete["signals"][0]["dataType"] = {"status": 0x80340000}
    assert (
        invoke(
            1,
            *draft_args,
            "-",
            "--output",
            "unusable.json",
            stdin=json.dumps(incomplete).encode(),
        )
        == b""
    )
    assert not (root / "unusable.json").exists()
    assert invoke(1, *draft_args, "-", stdin=json.dumps(incomplete).encode()) == b""
    assert invoke(1, *validate_args, "-", stdin=b"{}") == b""
    check = ("check", "--contract", "visit/contract.json")
    after = (root / "visit/after.json").read_bytes()
    assert b"First inspection" in invoke(0, *check, "--snapshot", "visit/before.json")
    empty = json.loads(after)
    empty["signals"] = []
    (root / "visit/empty.json").write_text(json.dumps(empty))
    for code, name, decision in (
        (0, "before", "matched"),
        (2, "after", "mismatch"),
        (3, "empty", "unverified"),
    ):
        path = f"visit/{name}.json"
        raw = (root / path).read_bytes()
        current = invoke(code, *check, "--snapshot", path, "--json")
        assert invoke(code, *check, "--snapshot", "-", "--json", stdin=raw) == current
        report = json.loads(current)
        assert report["schemaVersion"] == 2 and report["baselineProvided"] is False
        assert report["decision"] == decision and report["complete"] == (code != 3)
        observed_rows = json.loads(raw)["signals"]
        row = observed_rows[0] if observed_rows else {}
        fields = {"DataType": "dataType", "EngineeringUnits": "engineeringUnits"}
        assert [f["attribute"] for f in report["findings"]] == list(fields)
        for finding in report["findings"]:
            assert finding["name"] == "SupplyTemp"
            assert finding["beforeOutcome"] is None and finding["before"] is None
            assert finding["after"] == row.get(fields[finding["attribute"]])
    mismatch = invoke(2, *check, "--snapshot", "visit/after.json")
    assert b"SupplyTemp.EngineeringUnits" in mismatch
    assert "expected °C (CEL), observed °F (FAH)" in mismatch.decode()
    repaired = invoke(
        0, *check, "--before", "visit/after.json", "--after", "visit/before.json"
    )
    assert b"RESOLVED" in repaired
    assert invoke(1, *check, "--snapshot", "-", "--json", stdin=after + b"{}") == b""
    print(
        "Packaged CLI verified outside checkout for local preflight, exits 0/1/2/3, file/pipe parity, absent history and repair."
    )
