#![cfg_attr(
    not(any(feature = "client", feature = "commissioning", feature = "server")),
    no_std
)]
//! Embed OPC UA protocol services in a Rust application.
//!
//! The default `client` feature uses open62541 for UA Binary over OPC TCP. It provides
//! endpoint discovery, pinned sessions, browsing, typed reads, grouped data changes, event streams,
//! raw historical reads and reconnect handling. The application owns credentials and scheduling.
//!
//! ```
//! # #[cfg(feature = "client")]
//! # async fn example(client: &opcua_kit::Client) -> Result<(), Box<dyn std::error::Error>> {
//! use opcua_kit::{NodeId, Sample};
//!
//! let node = NodeId::new("urn:factory:line-1", "s=PartsProduced")?;
//! let sample: Sample<u64> = client.read_scalar(&node).await?;
//! if let (0, Some(count)) = (sample.status, sample.value) {
//!     println!("parts produced = {count}");
//! }
//! # Ok(()) }
//! ```
//!
//! Enable `control` for explicit Write and Call, `server` for host-owned variables,
//! and `pubsub` for a standalone UADP key-frame codec.
//! Enable `commissioning` to inspect signal metadata and assess a reviewed contract.
//! Enable `cems` for energy-meter collection and interval reconciliation.
//! Both commissioning and meter processing can run offline with default features disabled.
//! The standalone `pubsub` feature supports `no_std` targets with an allocator.
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
pub use client::{
    ArrayValue, BrowseEntry, BrowseError, BrowseName, CertificateRollover, Client, ConnectError,
    ConnectionConfig, ConnectionOptions, DataChange, DataChanges, EndpointInfo, EndpointToken,
    EngineeringUnitEvidence, EventError, EventField, Events, FixedScalar, HistoricalRead,
    HistoryError, MAX_MONITORED_NODES, MAX_READ_NODES, MonitoredDataChanges, MonitoredNode,
    PublishError, ReadAttribute, ReadError, ReadOperand, RecoveredSession, RecoveringClient,
    RecoveryError, Sample, SampleTimestamp, Scalar, SecurityPolicy, Sequenced,
    SequencedDataChanges, SessionState, SubscriptionError, TimestampError, UnitStage, UserIdentity,
    VariableDefinition, discover_endpoints,
};

#[cfg(feature = "client")]
pub mod client;

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
