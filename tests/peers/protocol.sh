#!/usr/bin/env bash
# Build an external consumer and exercise its encrypted service requests.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
suite=${1:-protocol}
features="[]"
extra_deps=""
case "$suite" in
  republish) binary=${OPCUA_KIT_REPUBLISH_BIN:-} ;;
  protocol) binary=${OPCUA_KIT_PROTOCOL_BIN:-} ;;
  observe) binary=${OPCUA_KIT_OBSERVE_BIN:-}; extra_deps='uuid = { version = "1", default-features = false }' ;;
  conditions) binary=${OPCUA_KIT_CONDITIONS_BIN:-}; features='["control"]' ;;
  control) binary=${OPCUA_KIT_CONTROL_BIN:-}; features='["control"]' ;;
  recovery) binary=${OPCUA_KIT_RECOVERY_BIN:-} ;;
  *) exit 2 ;;
esac
if [[ -z "$binary" ]]; then
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' EXIT
  mkdir -p "$scratch/consumer/src"
  ln -s "$root" "$scratch/kit"
  cp "tests/consumer/$suite.rs" "$scratch/consumer/src/main.rs"
  cp Cargo.lock "$scratch/consumer/Cargo.lock"
  cat > "$scratch/consumer/Cargo.toml" <<TOML
[package]
name = "opcua-kit-$suite-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
opcua-kit = {path = "../kit", features = $features}
time = "0.3"
$extra_deps
tokio = {version = "1", features = ["rt", "macros"]}
TOML
  build_dir=$(cargo metadata --format-version=1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
  cargo build --manifest-path "$scratch/consumer/Cargo.toml" --target-dir "$build_dir"
  binary="$build_dir/debug/opcua-kit-$suite-consumer"
fi
uv run --isolated --no-project --python 3.13 --with asyncua==2.1.0 python "$root/tests/peers/$suite.py" "$binary"
