#![forbid(unsafe_code)]
#![cfg_attr(
    not(any(feature = "discovery", feature = "commissioning", feature = "server")),
    no_std
)]
//! Embed OPC UA protocol services in a Rust application.
//!
//! The default build implements UA TCP endpoint discovery and UADP key frames in Rust.
//! Both can be embedded without third-party dependencies. Discovery lists the policies an endpoint advertises.
//! Before connecting, provision the approved server certificate and application URI.
//!
//! ```no_run
//! # #[cfg(feature = "discovery")]
//! # fn run() -> Result<(), opcua_kit::DiscoveryError> {
//! use std::time::Duration;
//! let endpoints = opcua_kit::discover_endpoints("opc.tcp://localhost:4840", Duration::from_secs(5))?;
//! for endpoint in endpoints { println!("{}", endpoint.security_policy_uri); }
//! # Ok(()) }
//! ```
//!
//! The optional `client` and `server` features provide Rust implementations of sessions,
//! reads, subscriptions and serving host-owned variables. `control` adds writes and calls.
//! `commissioning` and `cems` support offline signal checks and meter processing.
//! Enable only `pubsub` for the standalone `no_std` codec with an allocator.
//! With all features disabled, the crate provides a dependency-free `no_std` status classifier.

#[cfg(any(feature = "client", feature = "commissioning"))]
mod identity;
#[cfg(any(feature = "client", feature = "commissioning"))]
pub use identity::{NodeId, NodeIdError};

#[cfg(any(feature = "client", feature = "commissioning"))]
mod unit;
#[cfg(any(feature = "client", feature = "commissioning"))]
pub use unit::EngineeringUnit;

#[cfg(all(feature = "client", feature = "cems"))]
pub use client::MeterReadError;
#[cfg(all(feature = "client", feature = "commissioning"))]
pub use client::SnapshotReadError;

#[cfg(feature = "control")]
pub use client::{CallOutcome, ConditionComment, ConditionError, Control, ControlError};

#[cfg(feature = "client")]
pub use certificate::certificate_application_uri;

#[cfg(feature = "client")]
pub use client::{
    ArrayValue, BrowseEntry, BrowseError, BrowseName, CertificateRollover, Client, ConnectError,
    ConnectionConfig, ConnectionOptions, DataChange, DataChanges, EngineeringUnitEvidence,
    EventError, EventField, Events, FixedScalar, HistoricalRead, HistoryError, MAX_MONITORED_NODES,
    MAX_READ_NODES, MonitoredDataChanges, MonitoredNode, PublishError, ReadAttribute, ReadError,
    ReadOperand, RecoveredSession, RecoveringClient, RecoveryError, Sample, SampleTimestamp,
    Scalar, SecurityPolicy, Sequenced, SequencedDataChanges, SessionState, SubscriptionError,
    TimestampError, UnitStage, UserIdentity, VariableDefinition,
};

#[cfg(feature = "discovery")]
pub mod discovery;
#[cfg(feature = "discovery")]
pub use discovery::{DiscoveryError, EndpointInfo, EndpointToken, discover_endpoints};

#[cfg(feature = "client")]
pub mod client;

#[cfg(any(feature = "client", feature = "server"))]
mod secure_channel;
#[cfg(any(feature = "client", feature = "server"))]
pub mod ua;

#[cfg(feature = "commissioning")]
pub mod commissioning;

#[cfg(any(feature = "server", feature = "client"))]
mod certificate;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "pubsub")]
extern crate alloc;
#[cfg(feature = "pubsub")]
pub mod pubsub;

/// Client interpretation of the severity field of an OPC UA StatusCode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    /// The operation succeeded.
    Good,
    /// The result may be unsuitable for some uses.
    Uncertain,
    /// The operation failed or the severity uses the reserved encoding.
    Bad,
}

/// Classifies the two severity bits, independently of the subcode and flags.
///
/// ```
/// use opcua_kit::{status_severity, Severity};
///
/// assert_eq!(status_severity(0x0000_0000), Severity::Good);
/// assert_eq!(status_severity(0x4000_0000), Severity::Uncertain);
/// assert_eq!(status_severity(0x8000_0000), Severity::Bad);
/// assert_eq!(status_severity(0xFFFF_FFFF), Severity::Bad);
/// ```
pub const fn status_severity(status_code: u32) -> Severity {
    match status_code >> 30 {
        0 => Severity::Good,
        1 => Severity::Uncertain,
        _ => Severity::Bad,
    }
}
