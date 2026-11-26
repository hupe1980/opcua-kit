use std::collections::BTreeMap;

use serde::Serialize;

use super::{Contract, Error, Evidence, Expected, NodeId, Observed, Snapshot, Unit};

/// Result of a required check, also used for the overall decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// The current observation satisfies the expectation.
    Matched,
    /// The current observation contradicts the expectation.
    Mismatch,
    /// The current observation is missing, has non-Good status or lacks unit identity.
    Unverified,
}

/// OPC UA attribute or property evaluated by a commissioning check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Attribute {
    /// Declared DataType NodeId.
    DataType,
    /// Declared ValueRank integer.
    ValueRank,
    /// EngineeringUnits property of the signal.
    EngineeringUnits,
}

/// Expected or observed metadata in a finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AttributeValue {
    /// Namespace-qualified DataType identity.
    DataType(NodeId),
    /// Exact OPC UA ValueRank.
    ValueRank(i32),
    /// Namespace-qualified identity in an EngineeringUnits property.
    EngineeringUnits(Unit),
}

/// Comparison of one named signal's required attribute.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Contract's signal name.
    pub name: String,
    /// Stable namespace-qualified signal identifier.
    pub node: NodeId,
    /// Attribute the operator required.
    pub attribute: Attribute,
    /// Requirement taken from the contract.
    pub expected: AttributeValue,
    /// Baseline evidence, if captured.
    pub before: Option<Evidence<AttributeValue>>,
    /// Current evidence, if captured.
    pub after: Option<Evidence<AttributeValue>>,
    /// Decision for this attribute in the supplied baseline. A first inspection
    /// has no baseline decision. Missing evidence in a supplied baseline yields
    /// `Some(Outcome::Unverified)`.
    pub before_outcome: Option<Outcome>,
    /// Decision for this attribute against the current observation.
    pub outcome: Outcome,
}

/// Number of required attributes in each outcome.
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct Counts {
    /// Current observations that satisfy the contract.
    pub matched: usize,
    /// Confirmed current differences.
    pub mismatch: usize,
    /// Current observations with insufficient evidence.
    pub unverified: usize,
}

/// A self-contained decision for one logical device, server and principal.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Report format version (2). Contracts and snapshots use format 1.
    pub schema_version: u32,
    /// Whether the caller supplied an earlier snapshot for comparison.
    pub baseline_provided: bool,
    /// Logical device label.
    pub device: String,
    /// Expected server application identity.
    pub application_uri: String,
    /// Principal used for the supplied observations.
    pub principal: String,
    /// Overall decision, with confirmed mismatches taking precedence.
    pub decision: Outcome,
    /// True when every required current attribute could be evaluated.
    pub complete: bool,
    /// Number of required attributes by outcome.
    pub counts: Counts,
    /// Sorted by signal name, then DataType, ValueRank and EngineeringUnits.
    pub findings: Vec<Finding>,
}

impl Report {
    /// CLI-compatible exit status. Invalid input is a separate [`Error`].
    pub fn exit_code(&self) -> u8 {
        match self.decision {
            Outcome::Matched => 0,
            Outcome::Mismatch => 2,
            Outcome::Unverified => 3,
        }
    }
}

fn index<'a>(
    contract: &Contract,
    definitions: &BTreeMap<&str, &Expected>,
    snapshot: &'a Snapshot,
) -> Result<BTreeMap<&'a str, &'a Observed>, Error> {
    let c = &contract.0;
    let s = &snapshot.0;
    for (field, expected, observed) in [
        ("device", &c.device, &s.device),
        ("applicationUri", &c.application_uri, &s.application_uri),
        ("principal", &c.principal, &s.principal),
    ] {
        if expected != observed {
            return Err(Error::new(format!("{field} differs from the contract")));
        }
    }
    let mut index = BTreeMap::new();
    for (i, row) in s.signals.iter().enumerate() {
        let definition = definitions
            .get(row.name.as_str())
            .ok_or_else(|| Error::new(format!("signals[{i}].name is absent from the contract")))?;
        if definition.node != row.node {
            return Err(Error::new(format!(
                "signals[{i}].node differs from the contract mapping"
            )));
        }
        index.insert(row.name.as_str(), row);
    }
    Ok(index)
}

impl<T: Clone> Evidence<T> {
    fn mapped(&self, f: impl FnOnce(T) -> AttributeValue) -> Evidence<AttributeValue> {
        Evidence {
            status: self.status,
            value: self.value.clone().map(f),
        }
    }
}

fn evidence(row: Option<&&Observed>, attribute: Attribute) -> Option<Evidence<AttributeValue>> {
    let signal = row?;
    match attribute {
        Attribute::DataType => signal
            .data_type
            .as_ref()
            .map(|e| e.mapped(AttributeValue::DataType)),
        Attribute::ValueRank => signal
            .value_rank
            .as_ref()
            .map(|e| e.mapped(AttributeValue::ValueRank)),
        Attribute::EngineeringUnits => signal
            .engineering_units
            .as_ref()
            .map(|e| e.mapped(AttributeValue::EngineeringUnits)),
    }
}

/// Assess the current snapshot against the contract at the first inspection.
/// Missing observations yield unverified findings. The report contains current
/// evidence and leaves all baseline evidence and baseline outcomes empty.
pub fn assess(contract: &Contract, snapshot: &Snapshot) -> Result<Report, Error> {
    evaluate(contract, None, snapshot)
}

/// Compare two validated snapshots against the contract. Missing observations are
/// valid partial evidence. Snapshot rows with an unknown name or a changed NodeId
/// are invalid. Only current evidence determines the gate decision.
pub fn compare(contract: &Contract, before: &Snapshot, after: &Snapshot) -> Result<Report, Error> {
    evaluate(contract, Some(before), after)
}

fn evaluate(
    contract: &Contract,
    baseline: Option<&Snapshot>,
    snapshot: &Snapshot,
) -> Result<Report, Error> {
    let definitions: BTreeMap<_, _> = contract
        .0
        .signals
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();
    let before = baseline
        .map(|s| index(contract, &definitions, s))
        .transpose()
        .map_err(|e| e.at("before"))?;
    let after = index(contract, &definitions, snapshot).map_err(|e| e.at("snapshot"))?;
    let mut counts = Counts::default();
    let mut findings = Vec::new();
    for (name, signal) in definitions {
        let prior_row = before.as_ref().and_then(|rows| rows.get(name));
        let current_row = after.get(name);
        let datatype = (
            Attribute::DataType,
            AttributeValue::DataType(signal.data_type.clone()),
        );
        let rank = signal
            .value_rank
            .map(|v| (Attribute::ValueRank, AttributeValue::ValueRank(v)));
        let units = signal.engineering_units.clone().map(|unit| {
            (
                Attribute::EngineeringUnits,
                AttributeValue::EngineeringUnits(unit),
            )
        });
        for (attribute, expected) in std::iter::once(datatype).chain(rank).chain(units) {
            let previous = evidence(prior_row, attribute);
            let current = evidence(current_row, attribute);
            let classify = |e: &Option<Evidence<AttributeValue>>| match e
                .as_ref()
                .and_then(|r| r.value.as_ref())
            {
                Some(AttributeValue::EngineeringUnits(unit)) if !unit.is_identified() => {
                    Outcome::Unverified
                }
                Some(value) if *value == expected => Outcome::Matched,
                Some(_) => Outcome::Mismatch,
                None => Outcome::Unverified,
            };
            let outcome = classify(&current);
            let before_outcome = baseline.map(|_| classify(&previous));
            match outcome {
                Outcome::Matched => counts.matched += 1,
                Outcome::Mismatch => counts.mismatch += 1,
                Outcome::Unverified => counts.unverified += 1,
            }
            findings.push(Finding {
                name: name.to_owned(),
                node: signal.node.clone(),
                attribute,
                expected,
                before: previous,
                before_outcome,
                after: current,
                outcome,
            });
        }
    }
    let decision = if counts.mismatch > 0 {
        Outcome::Mismatch
    } else if counts.unverified > 0 {
        Outcome::Unverified
    } else {
        Outcome::Matched
    };
    Ok(Report {
        schema_version: 2,
        baseline_provided: baseline.is_some(),
        device: contract.0.device.clone(),
        application_uri: contract.0.application_uri.clone(),
        principal: contract.0.principal.clone(),
        complete: counts.unverified == 0,
        counts,
        decision,
        findings,
    })
}

impl Contract {
    /// Check that the collector accounted for every signal under the requested identities.
    /// A row without evidence records an unresolved namespace. When a node
    /// resolves, each requested attribute needs a result, including non-Good statuses.
    ///
    /// Use this before publishing a new capture. Offline [`compare`] also accepts
    /// partial snapshots so previously collected evidence can still be assessed.
    pub fn validate_capture(&self, snapshot: &Snapshot) -> Result<(), Error> {
        let definitions = self
            .0
            .signals
            .iter()
            .map(|s| (s.name.as_str(), s))
            .collect();
        let observed = index(self, &definitions, snapshot)?;
        if observed.len() != self.0.signals.len() {
            return Err(Error::new(
                "capture is missing one or more requested signals",
            ));
        }
        for (i, expected) in self.0.signals.iter().enumerate() {
            let signal = observed[expected.name.as_str()];
            if signal.data_type.is_none()
                && signal.value_rank.is_none()
                && signal.engineering_units.is_none()
            {
                continue;
            }
            if signal.data_type.is_none() {
                return Err(Error::new(format!(
                    "capture is missing DataType for contract signals[{i}]"
                )));
            }
            if signal.value_rank.is_some() != expected.value_rank.is_some() {
                return Err(Error::new(format!(
                    "capture ValueRank coverage differs from contract signals[{i}]"
                )));
            }
            if signal.engineering_units.is_some() != expected.engineering_units.is_some() {
                return Err(Error::new(format!(
                    "capture EngineeringUnits coverage differs from contract signals[{i}]"
                )));
            }
        }
        Ok(())
    }
}
