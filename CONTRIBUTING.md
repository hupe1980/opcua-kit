# Contributing

Use Rust 1.88 or newer. Native client and server builds also need a C toolchain, CMake, Python 3 and libclang.

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

## Verify the packaged SDK

Warm the capture runtime using the [capture guide](site/content/capture.md) or run the peer suite first. Run `python3 tests/verify_package.py --allow-dirty` to build downstream applications from the Cargo archive, install its CLI and exercise the packaged fixtures. CI runs the same suite from a clean checkout.

For an energy-meter change, run `cargo run --locked --no-default-features --features cems --example project_meter`. To include the downstream EMS consumer, build `cemsd` in its workspace, pass `--cemsd /absolute/path/to/cemsd` to the package verifier and set `OPCUA_KIT_CEMSD_BIN` to that path when running `tests/peers/run.sh`.

## Build an application workspace with the maintained macro dependency

Path and Git dependencies on this development checkout pick up our reviewed open62541 0.12.1 wrapper automatically. Its published Rust source and MPL license are preserved. A one-line dependency substitution in the wrapper manifest uses the maintained pastey macro implementation. Run `cargo audit --deny warnings` and `python3 contrib/verify-backend.py` in the checkout. [Provenance](vendor/README.md)

Cargo removes the local dependency path when creating a registry archive. The normalized archive resolves the published open62541 wrapper, which still depends on paste. An application using that archive can apply the included patch to keep its strict audit clean. Cargo applies this override from the application workspace root. [Advisory](https://rustsec.org/advisories/RUSTSEC-2024-0436.html) · [Patch](contrib/open62541-pastey.patch) · [Cargo path and version rules](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations)

Save the [wrapper patch](contrib/open62541-pastey.patch) as `open62541-pastey.patch` in the application workspace. From that workspace, prepare the backend source and apply the patch.

```sh
git clone https://github.com/HMIProject/open62541.git vendor/open62541
git -C vendor/open62541 checkout --detach 99091a4b80dd6c5bfec5d969286cc6a20d8cb091
git -C vendor/open62541 apply - < open62541-pastey.patch
```

Add the override to the root Cargo.toml. Cargo still uses the same open62541 native implementation and encryption features.

```toml
[patch.crates-io]
open62541 = { path = "vendor/open62541" }
```

Run `cargo update -p open62541`, review the lockfile, then run the application's tests and `cargo audit --deny warnings`. Store the patched source reproducibly with the application. Reevaluate the override when updating the wrapper. The standard crates.io dependency retains the upstream advisory until a corrected release is available.

## Release a version

Set the package version in Cargo.toml, update Cargo.lock and commit the release. Push a tag matching the version, such as `v0.1.0`. The [release workflow](.github/workflows/release.yml) runs CI on the tagged commit, publishes the crate and verifies the revision in the registry archive. Rerunning the workflow for the same tag can resume after publication.

Configure crates.io trusted publishing for `hupe1980/opcua-kit`, workflow `release.yml` and environment `crates-io`. Stable tags also build and test the CLI formula before updating `hupe1980/homebrew-tap`. In the `homebrew` environment, configure `HOMEBREW_APP_ID` and `HOMEBREW_APP_PRIVATE_KEY` for a GitHub App installed on the tap with Contents write permission. Prerelease tags publish only to crates.io.
