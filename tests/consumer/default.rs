//! Downstream consumer of the Rust-only default crate.
use opcua_kit::{DiscoveryError, discover_endpoints, pubsub};
use std::time::Duration;

fn main() {
    assert!(matches!(
        discover_endpoints("http://localhost", Duration::from_secs(1)),
        Err(DiscoveryError::InvalidEndpoint)
    ));
    assert_eq!(pubsub::MAX_FIELDS, 64);
}
