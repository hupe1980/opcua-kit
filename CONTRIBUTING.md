# Contributing

Use Rust 1.88 or newer. The library and installed CLI run entirely in Rust. Interoperability tests use independent Node.js and Python OPC UA stacks.

## Check a change

Run `just` in the checkout to list development commands. Use `just check` for the Rust checks below, `just docs` for the API reference and `just site` to build and validate the website.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

The feature matrix matters for library consumers. Run `cargo +1.88.0 test --locked --all-features` for minimum-version compatibility and `cargo test --locked --no-default-features --features commissioning` for a Rust-only offline build. To check embedded targets, install `thumbv7em-none-eabihf` with rustup and run `cargo check --locked --lib --no-default-features --features pubsub --target thumbv7em-none-eabihf`.

For website edits, run `zola check --skip-external-links` and `zola build` from `site/` with Zola 0.23.6. [Site development](site/README.md)

## Test against independent peers

The peer suites use loopback servers, ephemeral certificates, Node/npm, Python and uv. Choose the suite that exercises your change.

| Command | Coverage |
| --- | --- |
| `tests/peers/run.sh` | Encrypted client reads, metadata-only snapshots, operation limits, meter reads and CLI capture |
| `bash tests/peers/recovery.sh` | Restart with a new namespace order and read limit |
| `bash tests/peers/protocol.sh` | Discovery, array ranges and paged history |
| `bash tests/peers/protocol.sh observe` | Event delivery and server certificate rollover |
| `bash tests/peers/protocol.sh control` | Writes and method calls |
| `bash tests/peers/protocol.sh conditions` | Alarm refresh, acknowledgement and confirmation |
| `bash tests/peers/protocol.sh republish` | Recovery of retained notifications |

For server and UADP changes, build both examples with `cargo build --locked --no-default-features --features server,pubsub --example local_server --example uadp`. The CI workflow contains the independent loopback, encrypted server, UDP and CLI peer commands. [CI workflow](.github/workflows/ci.yml)

## Verify the packaged crate

Run `python3 tests/verify_package.py --allow-dirty` to build downstream applications from the Cargo archive, install its CLI and exercise the packaged fixtures. The verifier uses the `openssl` command to generate short-lived certificate fixtures and runs the installed CLI with an empty PATH.

For an energy-meter change, run `cargo run --locked --no-default-features --features cems --example project_meter`. To include the downstream EMS consumer, build `cemsd` in its workspace, pass `--cemsd /absolute/path/to/cemsd` to the package verifier and set `OPCUA_KIT_CEMSD_BIN` to that path when running `tests/peers/run.sh`.

## Update UA Binary service definitions

The compiled service structures and status codes come from the OPC Foundation UA-Nodeset schema. The generator verifies the three input files against the pinned revision before writing Rust source. To regenerate, run `python3 tools/generate-ua.py /path/to/UA-Nodeset/Schema`. Normal builds use the checked-in Rust source. [Schema source](https://github.com/OPCFoundation/UA-Nodeset/tree/ed0b821f6a6f1f0c440c442ed95a9146ae8b7f8d/Schema)
