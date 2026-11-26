use super::{Contract, Document, Error, Evidence, Expected, Observed, Snapshot};

impl<T> Evidence<T> {
    // An observation may carry an original Good status and still lack a value.
    fn draft_value(&self) -> Result<&T, Error> {
        self.value.as_ref().ok_or_else(|| {
            Error::new(format!(
                "cannot draft from unavailable evidence (status 0x{:08X})",
                self.status
            ))
        })
    }
}

fn draft_signal(index: usize, row: &Observed) -> Result<Expected, Error> {
    let data_type = row
        .data_type
        .as_ref()
        .ok_or_else(|| Error::new("required observation is missing"))
        .and_then(Evidence::draft_value)
        .map_err(|e| e.at(&format!("signals[{index}].dataType")))?;
    let value_rank = row
        .value_rank
        .as_ref()
        .map(Evidence::draft_value)
        .transpose()
        .map_err(|e| e.at(&format!("signals[{index}].valueRank")))?;
    let engineering_units = row
        .engineering_units
        .as_ref()
        .map(|evidence| {
            let unit = evidence.draft_value()?;
            if !unit.is_identified() {
                return Err(Error::new(format!(
                    "unit identity is unavailable (status 0x{:08X})",
                    evidence.status
                )));
            }
            Ok(unit.clone())
        })
        .transpose()
        .map_err(|e| e.at(&format!("signals[{index}].engineeringUnits")))?;
    Ok(Expected {
        name: row.name.clone(),
        node: row.node.clone(),
        data_type: data_type.clone(),
        value_rank: value_rank.copied(),
        engineering_units,
    })
}

/// Draft editable requirements from a trusted snapshot of a known-good configuration.
///
/// Every observed signal must supply a Good DataType value. Observed ValueRank and
/// EngineeringUnits must also supply Good values, and any observed unit must have a usable
/// identity. An empty source or one unusable observation fails the entire draft.
/// The result preserves the device, server and principal and sorts signals by name.
///
/// Review the signal list and optional attributes against the gateway's actual
/// requirements before approving the draft. Attributes absent from the source
/// are omitted. A passing check against that same snapshot is expected.
///
/// ```
/// use opcua_kit::commissioning::{assess, draft_contract, parse_contract, parse_snapshot};
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let snapshot = parse_snapshot(include_bytes!("../../fixtures/units/before.json"))?;
/// let draft = draft_contract(&snapshot)?;
/// assert_eq!(draft.signal_count(), 1);
/// let editable = serde_json::to_vec(&draft)?;
/// let reviewed = parse_contract(&editable)?;
/// assert_eq!(assess(&reviewed, &snapshot)?.exit_code(), 0);
/// # Ok(()) }
/// # example().unwrap();
/// ```
pub fn draft_contract(snapshot: &Snapshot) -> Result<Contract, Error> {
    let source = &snapshot.0;
    if source.signals.is_empty() {
        return Err(Error::new("cannot draft a contract from an empty snapshot"));
    }
    let mut signals = Vec::with_capacity(source.signals.len());
    for (index, row) in source.signals.iter().enumerate() {
        signals.push(draft_signal(index, row)?);
    }
    signals.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    Ok(Contract(Document {
        schema_version: source.schema_version,
        device: source.device.clone(),
        application_uri: source.application_uri.clone(),
        principal: source.principal.clone(),
        signals,
    }))
}
