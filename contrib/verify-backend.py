"""Verify the checked-in Rust wrapper against the published open62541 0.12.1 archive."""

import argparse
import hashlib
import io
import tarfile
from pathlib import Path
from urllib.request import urlopen

NAME = "open62541-0.12.1"
SHA256 = "981cb8f3d1861debcdad0e95b0ce212a5e5e8104adb6b5c49ceea95fe76d6dd7"
ROOT = Path(__file__).resolve().parents[1] / "vendor/open62541"

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("archive", nargs="?", type=Path, help="use a cached .crate archive")
args = parser.parse_args()
if args.archive:
    data = args.archive.read_bytes()
else:
    with urlopen(
        f"https://static.crates.io/crates/open62541/{NAME}.crate", timeout=30
    ) as response:
        data = response.read(1024 * 1024)
if hashlib.sha256(data).hexdigest() != SHA256:
    raise SystemExit("Backend crate checksum mismatch")

expected = set()
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
    for entry in archive:
        path = Path(entry.name).relative_to(NAME)
        if not entry.isfile() or path.parts[0] not in {
            "src",
            "LICENSES",
            "Cargo.toml",
            "README.md",
            "CHANGELOG.md",
        }:
            continue
        original = archive.extractfile(entry).read()
        if path.name == "Cargo.toml":
            old = b'[dependencies.paste]\nversion = "1.0.14"'
            new = b'[dependencies.paste]\npackage = "pastey"\nversion = "0.2.3"'
            if original.count(old) != 1:
                raise SystemExit("Expected upstream manifest dependency is missing")
            original = original.replace(old, new)
        if (ROOT / path).read_bytes() != original:
            raise SystemExit(f"Backend differs from reviewed release at {path}")
        expected.add(path)

actual = {p.relative_to(ROOT) for p in ROOT.rglob("*") if p.is_file()}
if actual != expected:
    raise SystemExit(f"Unexpected backend files: {sorted(actual ^ expected)}")
print(
    f"Verified {len(expected)} backend files against {NAME} and the reviewed manifest change."
)
