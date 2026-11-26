//! Compare the declared metadata consumed by a gateway against scoped OPC UA observations.
//!
//! Parse a contract and a snapshot, then call [`assess`] to check the device on
//! its first visit. When you have an earlier snapshot, [`compare`] also
//! computes baseline outcomes. Both entry points validate device, server,
//! principal and signal identity, and derive their decision from current
//! evidence. Parsing and evaluation are independent of I/O.
//! To author a contract from an existing snapshot, use [`draft_contract`]
//! and review the resulting requirements against the gateway configuration.
//!
//! Each signal requires a DataType. Add `valueRank` to check its dimensionality,
//! or `engineeringUnits` to check its unit by namespace URI and signed numeric
//! identifier. For example, a signal can require
//! `"engineeringUnits": {"namespaceUri":"http://www.opcfoundation.org/UA/units/un/cefact","unitId":4408652}`
//! for degrees Celsius. Reports retain the raw evidence when a server returns an
//! unidentified unit. Look for [`Outcome::Unverified`] in that case.
//!
//! ```
//! use opcua_kit::commissioning::{assess, compare, parse_contract, parse_snapshot, Outcome};
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let contract = parse_contract(include_bytes!("../../fixtures/commissioning/contract.json"))?;
//! let before = parse_snapshot(include_bytes!("../../fixtures/commissioning/before.json"))?;
//! let inspection = assess(&contract, &before)?;
//! assert_eq!(inspection.exit_code(), 0);
//! assert!(!inspection.baseline_provided);
//! assert!(inspection.findings.iter().all(|f| f.before_outcome.is_none()));
//!
//! let after = parse_snapshot(include_bytes!("../../fixtures/commissioning/after.json"))?;
//! let report = compare(&contract, &before, &after)?;
//! assert!(report.baseline_provided);
//! assert_eq!(report.decision, Outcome::Mismatch);
//! assert_eq!(report.counts.unverified, 1);
//! # Ok(()) }
//! # example().unwrap();
//! ```
//!
//! ```
//! use opcua_kit::commissioning::{compare, parse_contract, parse_snapshot, Error, Report};
//!
//! fn check(requirements: &[u8], baseline: &[u8], current: &[u8]) -> Result<Report, Error> {
//!     let contract = parse_contract(requirements)?;
//!     let before = parse_snapshot(baseline)?;
//!     let after = parse_snapshot(current)?;
//!     compare(&contract, &before, &after)
//! }
//! ```

mod draft;
#[cfg(feature = "cems")]
pub mod meter;
mod report;

use std::{collections::BTreeSet, fmt, io};

use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};

use crate::{Severity, status_severity};

pub use crate::NodeId;
pub use draft::draft_contract;
pub use report::{Attribute, AttributeValue, Counts, Finding, Outcome, Report, assess, compare};
use {SignalObservation as Observed, SignalRequirement as Expected};

/// Maximum encoded size of a contract or snapshot, in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of signal definitions or observations per document.
pub const MAX_SIGNALS: usize = 1024;

/// Invalid commissioning document or incompatible observation scope.
#[derive(Clone, Debug)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn at(self, path: &str) -> Self {
        Self(format!("{path}: {self}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<crate::NodeIdError> for Error {
    fn from(error: crate::NodeIdError) -> Self {
        Self::new(error.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document<T> {
    schema_version: u32,
    device: String,
    application_uri: String,
    principal: String,
    signals: Vec<T>,
}

/// Metadata a client requires from one named OPC UA node.
/// Pass requirements to [`Contract::new`] for validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignalRequirement {
    /// Name used to correlate the signal with a commissioning observation.
    pub name: String,
    /// Node to inspect in the server's address space.
    pub node: NodeId,
    /// Required DataType attribute.
    pub data_type: NodeId,
    /// Optional OPC UA ValueRank, such as -1 for a scalar.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub value_rank: Option<i32>,
    /// Optional unit identity required by the application.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub engineering_units: Option<Unit>,
}

impl SignalRequirement {
    /// Require the named node to have the given DataType.
    pub fn new(name: impl Into<String>, node: NodeId, data_type: NodeId) -> Self {
        Self {
            name: name.into(),
            node,
            data_type,
            value_rank: None,
            engineering_units: None,
        }
    }
}

/// The same programmatic unit identity used by the native client.
pub use crate::EngineeringUnit as Unit;

impl Unit {
    fn validate(&self) -> Result<(), Error> {
        if self.namespace_uri.chars().any(char::is_control) {
            return Err(Error::new("namespaceUri contains control characters"));
        }
        Ok(())
    }
}

/// Numeric operation status and the associated metadata when readable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
pub struct Evidence<T> {
    /// Full raw OPC UA StatusCode, including its subcode and flags.
    pub status: u32,
    /// Observed metadata when supplied with Good severity. An omitted value is unverified.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub value: Option<T>,
}

// A missing optional member and an explicitly null member have different meanings.
// Deserialize a present member as T to retain that distinction.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Attribute results for one named node. Missing attributes were not observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignalObservation {
    /// Name under which the application commissioned this signal.
    pub name: String,
    /// Node that supplied the observed attributes.
    pub node: NodeId,
    /// DataType read result, including the raw operation status.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub data_type: Option<Evidence<NodeId>>,
    /// ValueRank read result.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub value_rank: Option<Evidence<i32>>,
    /// EngineeringUnits read result.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub engineering_units: Option<Evidence<Unit>>,
}

impl SignalObservation {
    /// Start an observation with no attribute results.
    pub fn new(name: impl Into<String>, node: NodeId) -> Self {
        Self {
            name: name.into(),
            node,
            data_type: None,
            value_rank: None,
            engineering_units: None,
        }
    }
}

/// Validated, versioned requirements for one device, server and principal.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct Contract(Document<SignalRequirement>);

impl Contract {
    /// Build a version 1 contract in memory using the same rules as [`parse_contract`].
    ///
    /// ```
    /// use opcua_kit::commissioning::{Contract, NodeId, SignalRequirement};
    /// # fn example() -> Result<(), opcua_kit::commissioning::Error> {
    /// let node = NodeId::new("urn:plant:line-1", "s=PartsProduced")?;
    /// let uint64 = NodeId::new("http://opcfoundation.org/UA/", "i=9")?;
    /// let mut counter = SignalRequirement::new("PartsProduced", node, uint64);
    /// counter.value_rank = Some(-1);
    /// let contract = Contract::new("line-1", "urn:plant:server", "anonymous", vec![counter])?;
    /// assert_eq!(contract.signals()[0].node.identifier(), "s=PartsProduced");
    /// # Ok(()) }
    /// # example().unwrap();
    /// ```
    pub fn new(
        device: impl Into<String>,
        application_uri: impl Into<String>,
        principal: impl Into<String>,
        signals: Vec<SignalRequirement>,
    ) -> Result<Self, Error> {
        validate_contract(Document::new(device, application_uri, principal, signals)?)
    }

    /// Device identifier chosen by the application.
    pub fn device(&self) -> &str {
        &self.0.device
    }

    /// Expected server ApplicationUri.
    pub fn application_uri(&self) -> &str {
        &self.0.application_uri
    }

    /// Principal under which the attributes are to be read.
    pub fn principal(&self) -> &str {
        &self.0.principal
    }

    /// Validated signal requirements in declaration order, with canonical node identifiers.
    pub fn signals(&self) -> &[SignalRequirement] {
        &self.0.signals
    }

    /// Number of distinct signals required by this contract.
    pub fn signal_count(&self) -> usize {
        self.0.signals.len()
    }
}

/// Validated, versioned observations for one device, server and principal.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct Snapshot(Document<SignalObservation>);

impl Snapshot {
    /// Build a version 1 snapshot in memory using the same rules as [`parse_snapshot`].
    pub fn new(
        device: impl Into<String>,
        application_uri: impl Into<String>,
        principal: impl Into<String>,
        signals: Vec<SignalObservation>,
    ) -> Result<Self, Error> {
        validate_snapshot(Document::new(device, application_uri, principal, signals)?)
    }

    /// Device identifier associated with the observations.
    pub fn device(&self) -> &str {
        &self.0.device
    }

    /// ApplicationUri of the observed server.
    pub fn application_uri(&self) -> &str {
        &self.0.application_uri
    }

    /// Principal under which the attributes were observed.
    pub fn principal(&self) -> &str {
        &self.0.principal
    }

    /// Validated observations in declaration order, with canonical node identifiers.
    pub fn signals(&self) -> &[SignalObservation] {
        &self.0.signals
    }
}

// Native capture owns at most one uncharged candidate row while it grows the snapshot.
// The empty envelope includes both brackets. Each subsequent row adds one comma.
#[cfg(feature = "client")]
pub(crate) struct SnapshotCollector {
    document: Document<SignalObservation>,
    budget: ByteBudget,
}

#[cfg(feature = "client")]
impl SnapshotCollector {
    pub(crate) fn new(contract: &Contract) -> Result<Self, Error> {
        let document = Document {
            schema_version: 1,
            device: contract.device().to_owned(),
            application_uri: contract.application_uri().to_owned(),
            principal: contract.principal().to_owned(),
            signals: Vec::with_capacity(contract.signal_count()),
        };
        let mut budget = ByteBudget(MAX_DOCUMENT_BYTES - 1);
        serde_json::to_writer(&mut budget, &document).map_err(|e| Error::new(e.to_string()))?;
        Ok(Self { document, budget })
    }

    pub(crate) fn push(&mut self, row: SignalObservation) -> Result<(), Error> {
        use io::Write;
        if !self.document.signals.is_empty() {
            self.budget
                .write_all(b",")
                .map_err(|e| Error::new(e.to_string()))?;
        }
        serde_json::to_writer(&mut self.budget, &row).map_err(|e| Error::new(e.to_string()))?;
        self.document.signals.push(row);
        Ok(())
    }

    pub(crate) fn finish(self, contract: &Contract) -> Result<Snapshot, Error> {
        let snapshot = validate_snapshot(self.document)?;
        contract.validate_capture(&snapshot)?;
        Ok(snapshot)
    }
}

// Count exact compact JSON bytes, including escapes, without allocating a wire document.
struct ByteBudget(usize);

impl io::Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("document exceeds 4 MiB"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<T: Serialize> Document<T> {
    fn new(
        device: impl Into<String>,
        application_uri: impl Into<String>,
        principal: impl Into<String>,
        signals: Vec<T>,
    ) -> Result<Self, Error> {
        let doc = Self {
            schema_version: 1,
            device: device.into(),
            application_uri: application_uri.into(),
            principal: principal.into(),
            signals,
        };
        validate_header(&doc)?;
        serde_json::to_writer(ByteBudget(MAX_DOCUMENT_BYTES), &doc)
            .map_err(|error| Error::new(error.to_string()))?;
        Ok(doc)
    }
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<Document<T>, Error> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::new("document exceeds 4 MiB"));
    }
    let doc: Document<T> = serde_json::from_slice(bytes).map_err(|error| {
        // serde can quote fields from untrusted JSON. Keep diagnostics single-line
        // and bounded even for unknown field names.
        let message: String = error
            .to_string()
            .chars()
            .take(180)
            .flat_map(char::escape_debug)
            .collect();
        Error::new(format!(
            "invalid JSON at line {}, column {}: {message}",
            error.line(),
            error.column()
        ))
    })?;
    validate_header(&doc)?;
    Ok(doc)
}

fn validate_header<T>(doc: &Document<T>) -> Result<(), Error> {
    if doc.schema_version != 1 {
        return Err(Error::new("unsupported schemaVersion (expected 1)"));
    }
    for (path, value) in [
        ("device", &doc.device),
        ("applicationUri", &doc.application_uri),
        ("principal", &doc.principal),
    ] {
        validate_label(value).map_err(|e| e.at(path))?;
    }
    if doc.signals.len() > MAX_SIGNALS {
        return Err(Error::new("signals exceeds 1024 entries"));
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), Error> {
    if label.trim().is_empty() || label.chars().any(char::is_control) {
        return Err(Error::new(
            "expected nonempty text without control characters",
        ));
    }
    Ok(())
}

fn validate_rank(rank: i32) -> Result<(), Error> {
    if rank < -3 {
        return Err(Error::new("ValueRank must be -3 or greater"));
    }
    Ok(())
}

fn unique<'a>(items: impl Iterator<Item = (&'a str, &'a NodeId)>) -> Result<(), Error> {
    let mut names = BTreeSet::new();
    let mut nodes = BTreeSet::new();
    for (i, (name, node)) in items.enumerate() {
        if !names.insert(name) {
            return Err(Error::new(format!(
                "signals[{i}].name duplicates another signal name"
            )));
        }
        if !nodes.insert(node) {
            return Err(Error::new(format!(
                "signals[{i}].node duplicates another node identity"
            )));
        }
    }
    Ok(())
}

/// Parse a contract from UTF-8 JSON, normalizing typed IDs and checking all bounds.
pub fn parse_contract(bytes: &[u8]) -> Result<Contract, Error> {
    validate_contract(parse(bytes)?)
}

fn validate_contract(doc: Document<SignalRequirement>) -> Result<Contract, Error> {
    if doc.signals.is_empty() {
        return Err(Error::new("contract must specify at least one signal"));
    }
    for (i, s) in doc.signals.iter().enumerate() {
        validate_label(&s.name).map_err(|e| e.at(&format!("signals[{i}].name")))?;
        if let Some(rank) = s.value_rank {
            validate_rank(rank).map_err(|e| e.at(&format!("signals[{i}].valueRank")))?;
        }
        if let Some(unit) = &s.engineering_units {
            let path = format!("signals[{i}].engineeringUnits");
            unit.validate().map_err(|e| e.at(&path))?;
            if !unit.is_identified() {
                return Err(
                    Error::new("expected nonempty namespaceUri and unitId other than -1").at(&path),
                );
            }
        }
    }
    unique(doc.signals.iter().map(|s| (s.name.as_str(), &s.node)))?;
    Ok(Contract(doc))
}

fn validate_observation<T>(
    evidence: &Evidence<T>,
    validate: impl FnOnce(&T) -> Result<(), Error>,
) -> Result<(), Error> {
    let good = status_severity(evidence.status) == Severity::Good;
    let result = match (good, evidence.value.as_ref()) {
        (true, Some(value)) => validate(value),
        (_, None) => Ok(()),
        (false, Some(_)) => Err(Error::new("non-Good status requires omitting the value")),
    };
    result.map_err(|e| Error::new(format!("{e} (status 0x{:08X})", evidence.status)))
}

// Decode the DataType identifier after its surrounding evidence so an invalid
// identifier can be reported with the operand index and the original status.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireObservation {
    name: String,
    node: NodeId,
    #[serde(default, deserialize_with = "present")]
    data_type: Option<Evidence<crate::identity::WireNode>>,
    #[serde(default, deserialize_with = "present")]
    value_rank: Option<Evidence<i32>>,
    #[serde(default, deserialize_with = "present")]
    engineering_units: Option<Evidence<Unit>>,
}

impl WireObservation {
    fn into_observation(self, index: usize) -> Result<SignalObservation, Error> {
        let data_type = self
            .data_type
            .map(|evidence| -> Result<_, Error> {
                let value = evidence
                    .value
                    .map(NodeId::try_from)
                    .transpose()
                    .map_err(|err| {
                        Error::new(format!(
                            "signals[{index}].dataType: {err} (status 0x{:08X})",
                            evidence.status
                        ))
                    })?;
                Ok(Evidence {
                    status: evidence.status,
                    value,
                })
            })
            .transpose()?;
        Ok(SignalObservation {
            name: self.name,
            node: self.node,
            data_type,
            value_rank: self.value_rank,
            engineering_units: self.engineering_units,
        })
    }
}

/// Parse snapshot JSON, verifying the status/value invariants of each observation.
pub fn parse_snapshot(bytes: &[u8]) -> Result<Snapshot, Error> {
    let doc: Document<WireObservation> = parse(bytes)?;
    let signals = doc
        .signals
        .into_iter()
        .enumerate()
        .map(|(index, row)| row.into_observation(index))
        .collect::<Result<_, _>>()?;
    validate_snapshot(Document {
        schema_version: doc.schema_version,
        device: doc.device,
        application_uri: doc.application_uri,
        principal: doc.principal,
        signals,
    })
}

fn validate_snapshot(doc: Document<SignalObservation>) -> Result<Snapshot, Error> {
    for (i, s) in doc.signals.iter().enumerate() {
        validate_label(&s.name).map_err(|e| e.at(&format!("signals[{i}].name")))?;
        if let Some(evidence) = &s.data_type {
            validate_observation(evidence, |_| Ok(()))
                .map_err(|e| e.at(&format!("signals[{i}].dataType")))?;
        }
        if let Some(evidence) = &s.value_rank {
            validate_observation(evidence, |n| validate_rank(*n))
                .map_err(|e| e.at(&format!("signals[{i}].valueRank")))?;
        }
        if let Some(evidence) = &s.engineering_units {
            validate_observation(evidence, |unit| unit.validate())
                .map_err(|e| e.at(&format!("signals[{i}].engineeringUnits")))?;
        }
    }
    unique(doc.signals.iter().map(|s| (s.name.as_str(), &s.node)))?;
    Ok(Snapshot(doc))
}
