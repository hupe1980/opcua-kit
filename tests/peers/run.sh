#!/usr/bin/env bash
# Run the public client and CLI against independent node-opcua and asyncua servers.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
if [[ -n "${OPCUA_KIT_BIN:-}" ]]; then
  OPCUA_KIT_BIN=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$OPCUA_KIT_BIN")
  export OPCUA_KIT_BIN
fi
cd "$root"
target_dir=$(cargo metadata --format-version=1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
if [[ -z "${OPCUA_KIT_BIN:-}" ]]; then
  # Isolate the executable from concurrent builds using different Cargo features.
  cargo install --locked --debug --path . --features cli,cems --bin opcua-kit \
    --target-dir "$target_dir" --root "$temp/cli"
  export OPCUA_KIT_BIN="$temp/cli/bin/opcua-kit"
fi
if [[ -z "${OPCUA_KIT_NATIVE_PEER_BIN:-}" || -z "${OPCUA_KIT_NATIVE_COMMISSIONING_BIN:-}" ]]; then
  mkdir -p "$temp/consumer/src"
  ln -s "$root" "$temp/kit"
  cp tests/consumer/native.rs "$temp/consumer/src/main.rs"
  cp tests/consumer/navigation.rs "$temp/consumer/src/navigation.rs"
  cp Cargo.lock "$temp/consumer/Cargo.lock"
  cat > "$temp/consumer/Cargo.toml" <<'TOML'
[package]
name = "opcua-kit-peer-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[features]
commissioning = ["opcua-kit/cems", "dep:serde_json", "dep:time"]

[dependencies]
opcua-kit = { path = "../kit", features = ["client"] }
serde_json = { version = "1", optional = true }
time = { version = "0.3", optional = true }
tokio = { version = "1", features = ["rt", "macros", "time"] }
TOML
  if [[ -z "${OPCUA_KIT_NATIVE_PEER_BIN:-}" ]]; then
    cargo build --manifest-path "$temp/consumer/Cargo.toml" --target-dir "$target_dir"
    cp "$target_dir/debug/opcua-kit-peer-consumer" "$temp/default-consumer"
    export OPCUA_KIT_NATIVE_PEER_BIN="$temp/default-consumer"
  fi
  if [[ -z "${OPCUA_KIT_NATIVE_COMMISSIONING_BIN:-}" ]]; then
    cargo build --manifest-path "$temp/consumer/Cargo.toml" --target-dir "$target_dir" --features commissioning
    cp "$target_dir/debug/opcua-kit-peer-consumer" "$temp/commissioning-consumer"
    export OPCUA_KIT_NATIVE_COMMISSIONING_BIN="$temp/commissioning-consumer"
  fi
fi
npm install --prefix "$temp" --ignore-scripts --no-audit --no-fund --save-exact node-opcua@2.187.34 >/dev/null
export NODE_PATH="$temp/node_modules"
peer_python=(uv run --isolated --no-project --python 3.13 --with asyncua==2.1.0 python)
"${peer_python[@]}" "$root/tests/capture_peer.py" -v
"${peer_python[@]}" "$root/tests/peers/field_commands.py" "$OPCUA_KIT_BIN"
