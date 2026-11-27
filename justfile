# List the available recipes.
default:
    @just --list

# Build the library with its Rust discovery and PubSub features.
build:
    cargo build --locked

# Format the Rust workspace.
fmt:
    cargo fmt --all

# Check Rust formatting without changing files.
fmt-check:
    cargo fmt --all --check

# Lint all targets and features.
lint:
    cargo clippy --locked --all-targets --all-features -- -D warnings

# Run the Rust tests and doctests with all features enabled.
test:
    cargo test --locked --all-features

# Run the Rust checks before submitting a change.
check: fmt-check lint test

# Generate the Rust API reference for all features.
docs:
    cargo doc --locked --all-features --no-deps

# Build the documentation site and verify its links and metadata.
[working-directory: 'site']
site:
    zola check --skip-external-links
    zola build
    python3 check_output.py

# Preview the documentation site with live reload.
[working-directory: 'site']
site-serve:
    zola serve
