use super::sample::Quality;
use super::{Client, DataValue, EngineeringUnit, Namespaces, ReadError, ReadSession, Sample, ua};
use crate::NodeId;

pub(super) const MAX_REFERENCES: usize = 256;
pub(super) const MAX_PAGES: usize = 256;
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const HAS_PROPERTY: u32 = 46;
const EU_INFORMATION: u32 = 887;

/// Operation that supplied the decisive status and clocks for a unit lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitStage {
    /// Lookup failed at Browse or completed without a standard EngineeringUnits property.
    Browse,
    /// The property's declared DataType was unavailable.
    DataType,
    /// The property's declared ValueRank was unavailable.
    ValueRank,
    /// The verified property's Value was read.
    Value,
}

/// Unit evidence from a single signal, with the original operation status.
#[derive(Debug)]
pub struct EngineeringUnitEvidence {
    /// The operation whose result appears in the sample.
    pub stage: UnitStage,
    /// Stable local property node, once the complete lookup found exactly one.
    pub property: Option<NodeId>,
    /// Original status and clocks; a Good Browse with no value means no matching property.
    pub sample: Sample<EngineeringUnit>,
}

fn decode_unit(v: &ua::Variant) -> Result<Option<EngineeringUnit>, ReadError> {
    let ua::Variant::ExtensionObject(object) = v else {
        return Err(ReadError::InvalidUnitProperty);
    };
    let eu = object
        .inner_as::<ua::EUInformation>()
        .ok_or(ReadError::InvalidUnitProperty)?;
    unit_from_fields(eu.namespace_uri.as_ref().as_bytes(), eu.unit_id).map(Some)
}

fn unit_from_fields(bytes: &[u8], unit_id: i32) -> Result<EngineeringUnit, ReadError> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(ReadError::InvalidUnitProperty);
    }
    let namespace = std::str::from_utf8(bytes).map_err(|_| ReadError::InvalidUnitProperty)?;
    if namespace.chars().any(char::is_control) {
        return Err(ReadError::InvalidUnitProperty);
    }
    Ok(EngineeringUnit {
        namespace_uri: namespace.to_owned(),
        unit_id,
    })
}

// Borrow the sole result so bounds are checked before copying reference names and IDs.
pub(super) enum Page {
    First(ua::BrowseResponse),
    Next(ua::BrowseNextResponse),
}

impl Page {
    pub(super) fn checked<'a>(
        &'a self,
        session: &mut ReadSession,
    ) -> Result<(&'a ua::BrowseResult, Option<ua::ContinuationPoint>), ReadError> {
        self.result()
            .and_then(|result| Ok((result, continuation(result)?)))
            .inspect_err(|_| {
                // An invalid page may own a token that cannot safely be released. An
                // explicit disconnect releases remaining resources on the old session.
                session.interrupted = true;
            })
    }

    fn result(&self) -> Result<&ua::BrowseResult, ReadError> {
        let results = match self {
            Self::First(r) => &r.results,
            Self::Next(r) => &r.results,
        };
        match results.as_deref() {
            Some([r]) => Ok(r),
            _ => Err(ReadError::InvalidUnitReference),
        }
    }
}

pub(super) fn references(
    result: &ua::BrowseResult,
) -> Result<&[ua::ReferenceDescription], ReadError> {
    let entries = result.references.as_deref().unwrap_or_default();
    if entries.len() > MAX_REFERENCES {
        return Err(ReadError::InvalidUnitReference);
    }
    Ok(entries)
}

fn continuation(result: &ua::BrowseResult) -> Result<Option<ua::ContinuationPoint>, ReadError> {
    let point = &result.continuation_point;
    if point.len() > MAX_TOKEN_BYTES {
        return Err(ReadError::InvalidUnitReference);
    }
    Ok((!point.is_null_or_empty()).then(|| point.clone()))
}

pub(super) fn local_target(
    namespaces: &Namespaces,
    target: &ua::ExpandedNodeId,
) -> Result<NodeId, ReadError> {
    if target.server_index != 0 {
        return Err(ReadError::InvalidUnitReference);
    }
    let uri = &target.namespace_uri;
    if uri.as_ref().is_empty() {
        namespaces.stable_node(&target.node_id)
    } else {
        let uri = uri
            .value()
            .as_deref()
            .filter(|uri| namespaces.by_uri.contains_key(*uri))
            .ok_or(ReadError::InvalidUnitReference)?;
        Namespaces::node_in(uri, &target.node_id)
    }
    .map_err(|_| ReadError::InvalidUnitReference)
}

fn local_property(
    namespaces: &Namespaces,
    target: &ua::ExpandedNodeId,
    signal: &NodeId,
) -> Result<NodeId, ReadError> {
    let node = local_target(namespaces, target)?;
    if &node == signal {
        return Err(ReadError::InvalidUnitReference);
    }
    Ok(node)
}

#[derive(Default)]
struct Selection {
    found: Option<NodeId>,
    visited: usize,
    pages: usize,
}

impl Selection {
    fn inspect(
        &mut self,
        entries: &[ua::ReferenceDescription],
        namespaces: &Namespaces,
        signal: &NodeId,
    ) -> Result<(), ReadError> {
        if self.pages == MAX_PAGES || entries.len() > MAX_REFERENCES - self.visited {
            return Err(ReadError::InvalidUnitReference);
        }
        self.pages += 1;
        self.visited += entries.len();
        for entry in entries {
            if !entry.is_forward || entry.reference_type_id != ua::NodeId::new(0, HAS_PROPERTY) {
                return Err(ReadError::InvalidUnitReference);
            }
            if entry.browse_name.namespace_index != 0
                || entry.browse_name.name.as_ref() != "EngineeringUnits"
            {
                continue;
            }
            if self.found.is_some() || entry.node_class != ua::NodeClass::Variable {
                return Err(ReadError::InvalidUnitReference);
            }
            self.found = Some(local_property(namespaces, &entry.node_id, signal)?);
        }
        Ok(())
    }
}

fn gate(
    raw: &DataValue,
    stage: UnitStage,
    quality: Quality,
) -> Result<Option<Sample<EngineeringUnit>>, ReadError> {
    let result = Sample::decode_with(raw, quality, |value| {
        let matches = match stage {
            UnitStage::DataType => {
                matches!(value, ua::Variant::NodeId(id) if **id == ua::NodeId::new(0,EU_INFORMATION))
            }
            UnitStage::ValueRank => matches!(value, ua::Variant::Int32(-1)),
            _ => false,
        };
        if !matches {
            return Err(ReadError::InvalidUnitProperty);
        }
        Ok(Some(()))
    })?;
    Ok(result.value.is_none().then_some(Sample {
        status: result.status,
        value: None,
        source_timestamp: result.source_timestamp,
        server_timestamp: result.server_timestamp,
    }))
}

impl ReadSession {
    fn confirm_unit_release(
        &mut self,
        results: usize,
        diagnostics: usize,
    ) -> Result<(), ReadError> {
        if results != 0 || diagnostics != 0 {
            self.interrupted = true;
            return Err(ReadError::InvalidUnitReference);
        }
        Ok(())
    }
}

impl Client {
    pub(super) async fn next_browse_page(
        &self,
        session: &mut ReadSession,
        point: ua::ContinuationPoint,
        release: bool,
    ) -> Result<ua::BrowseNextResponse, ReadError> {
        let request = ua::BrowseNextRequest {
            release_continuation_points: release,
            continuation_points: Some(vec![point]),
            ..Default::default()
        };
        let response = self.guarded(session, self.inner.request(request)).await?;
        if release {
            session.confirm_unit_release(
                response.results.as_ref().map_or(0, Vec::len),
                response.diagnostic_infos.as_ref().map_or(0, Vec::len),
            )?;
        }
        Ok(response)
    }

    async fn unit_target(
        &self,
        session: &mut ReadSession,
        namespaces: &Namespaces,
        signal: &NodeId,
        quality: Quality,
    ) -> Result<(u32, Option<NodeId>), ReadError> {
        let description = ua::BrowseDescription {
            node_id: namespaces.wire_node(signal, 0)?,
            browse_direction: ua::BrowseDirection::Forward,
            reference_type_id: ua::NodeId::new(0, HAS_PROPERTY),
            include_subtypes: false,
            result_mask: 0x0f,
            node_class_mask: 0,
        };
        let request = ua::BrowseRequest {
            requested_max_references_per_node: MAX_REFERENCES as u32,
            nodes_to_browse: Some(vec![description]),
            ..Default::default()
        };
        let mut page = Page::First(self.guarded(session, self.inner.request(request)).await?);
        let mut selection = Selection::default();
        loop {
            let (result, point) = page.checked(session)?;
            let status = result.status_code.bits();
            if !quality.accepts(status) {
                if let Some(point) = point {
                    self.next_browse_page(session, point, true).await?;
                }
                return Ok((status, None));
            }
            let inspected = references(result)
                .and_then(|entries| selection.inspect(entries, namespaces, signal));
            let Some(point) = point else {
                inspected?;
                return Ok((status, selection.found));
            };
            if inspected.is_err() || selection.pages == MAX_PAGES {
                self.next_browse_page(session, point, true).await?;
                return Err(ReadError::InvalidUnitReference);
            }
            page = Page::Next(self.next_browse_page(session, point, false).await?);
        }
    }

    /// Resolve the standard EngineeringUnits property and verify its declared type and rank
    /// before reading its value. The signal's process Value is never requested.
    /// Lookup visits at most 256 forward HasProperty references and 256 pages.
    /// A malformed response envelope or an unusable continuation token (over
    /// 64 KiB) retires the session. Disconnect to release its remaining resources.
    ///
    /// ```
    /// # async fn inspect(client: &opcua_kit::Client, node: &opcua_kit::NodeId) -> Result<(), opcua_kit::ReadError> {
    /// let evidence = client.read_engineering_units(node).await?;
    /// if let Some(unit) = evidence.sample.value.filter(|unit| unit.is_identified()) {
    ///     println!("{} {}", unit.namespace_uri, unit.unit_id);
    /// }
    /// # Ok(()) }
    /// ```
    pub async fn read_engineering_units(
        &self,
        signal: &NodeId,
    ) -> Result<EngineeringUnitEvidence, ReadError> {
        let (mut session, metadata) = self.read_session().await?;
        self.units_locked(
            &mut session,
            &metadata.namespaces,
            signal,
            Quality::GoodSeverity,
            |_| true,
        )
        .await
    }

    pub(super) async fn units_locked(
        &self,
        session: &mut ReadSession,
        namespaces: &Namespaces,
        signal: &NodeId,
        quality: Quality,
        allow_property: impl FnOnce(&NodeId) -> bool,
    ) -> Result<EngineeringUnitEvidence, ReadError> {
        let (status, property) = self
            .unit_target(session, namespaces, signal, quality)
            .await?;
        let Some(property) = property else {
            return Ok(EngineeringUnitEvidence {
                stage: UnitStage::Browse,
                property: None,
                sample: Sample {
                    status,
                    value: None,
                    source_timestamp: None,
                    server_timestamp: None,
                },
            });
        };
        if !allow_property(&property) {
            return Err(ReadError::UnitAliasesSignal);
        }
        let wire = namespaces.wire_node(&property, 0)?;
        for (stage, attribute) in [
            (UnitStage::DataType, ua::AttributeId::DataType),
            (UnitStage::ValueRank, ua::AttributeId::ValueRank),
        ] {
            let raw = self.one_attribute(session, wire.clone(), attribute).await?;
            if let Some(sample) = gate(&raw, stage, quality)? {
                return Ok(EngineeringUnitEvidence {
                    stage,
                    property: Some(property),
                    sample,
                });
            }
        }
        let raw = self
            .one_attribute(session, wire, ua::AttributeId::Value)
            .await?;
        Ok(EngineeringUnitEvidence {
            stage: UnitStage::Value,
            property: Some(property),
            sample: Sample::decode_with(&raw, quality, decode_unit)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "cems")]
    #[test]
    fn meter_unit_pages_and_declarations_require_unqualified_good() {
        let flagged = ua::StatusCode::GoodClamped;
        assert!(Quality::GoodSeverity.accepts(flagged.bits()));
        assert!(!Quality::ExactGood.accepts(flagged.bits()));
        let data_type = ua::Variant::from(ua::NodeId::from(EU_INFORMATION));
        let rank = ua::Variant::Int32(-1);
        for (stage, declaration) in [
            (UnitStage::DataType, data_type),
            (UnitStage::ValueRank, rank),
        ] {
            let raw = ua::DataValue {
                status: Some(flagged),
                ..ua::DataValue::value_only(declaration)
            };
            assert!(gate(&raw, stage, Quality::GoodSeverity).unwrap().is_none());
            let unavailable = gate(&raw, stage, Quality::ExactGood).unwrap().unwrap();
            assert_eq!(unavailable.status, flagged.bits());
            assert!(unavailable.value.is_none());
        }
    }

    #[test]
    fn only_an_empty_release_envelope_keeps_the_session_usable() {
        let mut clean = ReadSession::default();
        assert!(clean.confirm_unit_release(0, 0).is_ok());
        assert!(!clean.interrupted);
        for (results, diagnostics) in [(1, 0), (0, 1), (1, 1)] {
            let mut session = ReadSession::default();
            assert!(matches!(
                session.confirm_unit_release(results, diagnostics),
                Err(ReadError::InvalidUnitReference)
            ));
            assert!(session.interrupted);
        }
    }

    #[test]
    fn property_identity_resolves_local_indexes_and_explicit_namespaces() {
        let table = ["http://opcfoundation.org/UA/", "urn:signal", "urn:property"]
            .map(|s| ua::Variant::String(s.into()));
        let ns = crate::client::namespace_map(&table).unwrap();
        let signal = NodeId::new("urn:signal", "s=x").unwrap();
        let explicit = |uri: &str, server: u32| ua::ExpandedNodeId {
            node_id: ua::NodeId::new(0, "x"),
            namespace_uri: uri.into(),
            server_index: server,
        };
        let expected = NodeId::new("urn:property", "s=x").unwrap();
        let zero = ua::ExpandedNodeId {
            node_id: ua::NodeId::null(),
            namespace_uri: "urn:property".into(),
            server_index: 0,
        };
        assert_eq!(
            local_property(&ns, &zero, &signal).unwrap(),
            NodeId::new("urn:property", "i=0").unwrap()
        );
        assert_eq!(
            local_property(&ns, &explicit("urn:property", 0), &signal).unwrap(),
            expected
        );
        assert_eq!(
            local_property(&ns, &ua::NodeId::new(2, "x").into(), &signal).unwrap(),
            expected
        );
        for target in [
            explicit("urn:property", 2),
            explicit("urn:absent", 0),
            explicit("urn:signal", 0),
            ua::NodeId::new(1, "x").into(),
            ua::ExpandedNodeId::null(),
            ua::NodeId::new(9, 1u32).into(),
        ] {
            assert!(matches!(
                local_property(&ns, &target, &signal),
                Err(ReadError::InvalidUnitReference)
            ));
        }
    }

    #[test]
    fn declaration_gates_require_exact_scalar_type_and_preserve_unavailable_clocks() {
        let valid = ua::DataValue {
            status: Some(ua::StatusCode::GoodClamped),
            ..ua::DataValue::value_only(ua::Variant::from(ua::NodeId::from(887u32)))
        };
        assert!(
            gate(&valid, UnitStage::DataType, Quality::GoodSeverity)
                .unwrap()
                .is_none()
        );
        let rank = ua::DataValue::value_only(ua::Variant::Int32(-1));
        assert!(
            gate(&rank, UnitStage::ValueRank, Quality::GoodSeverity)
                .unwrap()
                .is_none()
        );
        for (value, stage) in [
            (
                ua::Variant::from(ua::NodeId::new(2, 887u32)),
                UnitStage::DataType,
            ),
            (ua::Variant::Int32(0), UnitStage::ValueRank),
            (ua::Variant::from(vec![-1i32]), UnitStage::ValueRank),
        ] {
            assert!(matches!(
                gate(
                    &ua::DataValue::value_only(value),
                    stage,
                    Quality::GoodSeverity
                ),
                Err(ReadError::InvalidUnitProperty)
            ));
        }
        let missing = gate(
            &ua::DataValue::default(),
            UnitStage::DataType,
            Quality::GoodSeverity,
        )
        .unwrap()
        .unwrap();
        assert_eq!(missing.status, 0);
        assert!(missing.value.is_none());
        let raw = ua::DataValue {
            status: Some(ua::StatusCode::UncertainLastUsableValue),
            source_timestamp: Some(ua::DateTime::from_unix_timestamp_nanos(100).unwrap()),
            source_picoseconds: Some(3),
            ..ua::DataValue::value_only(ua::Variant::Int32(-1))
        };
        let unavailable = gate(&raw, UnitStage::ValueRank, Quality::GoodSeverity)
            .unwrap()
            .unwrap();
        assert_eq!(
            unavailable.status,
            ua::StatusCode::UncertainLastUsableValue.bits()
        );
        assert_eq!(
            unavailable.source_timestamp.unwrap().ten_picoseconds,
            Some(3)
        );
        assert!(unavailable.value.is_none());
    }

    #[test]
    fn actual_eu_structure_keeps_signed_identity_and_ignores_localized_labels() {
        let eu = ua::EUInformation {
            namespace_uri: "urn:Vendor".into(),
            unit_id: i32::MIN,
            display_name: ua::LocalizedText::new("de-DE", "nicht maßgeblich"),
            ..Default::default()
        };
        let unit = decode_unit(&ua::Variant::ExtensionObject(ua::ExtensionObject::new(eu)))
            .unwrap()
            .unwrap();
        assert_eq!(
            (unit.namespace_uri.as_str(), unit.unit_id),
            ("urn:Vendor", i32::MIN)
        );
        assert!(unit.is_identified());
        assert!(!unit_from_fields(b"urn:vendor", -1).unwrap().is_identified());
        assert!(!unit_from_fields(b"", 42).unwrap().is_identified());
        assert!(matches!(
            decode_unit(&ua::Variant::Int32(42)),
            Err(ReadError::InvalidUnitProperty)
        ));
        assert!(unit_from_fields(&[255], 0).is_err());
        assert!(unit_from_fields(b"urn:site\n", 0).is_err());
        let mut namespace = vec![b'a'; 4 * 1024 * 1024];
        assert!(unit_from_fields(&namespace, i32::MAX).is_ok());
        namespace.push(b'a');
        assert!(unit_from_fields(&namespace, 1).is_err());
    }

    #[test]
    fn continuation_representation_and_page_budget_are_checked_before_cloning() {
        let mut result = ua::BrowseResult::default();
        assert!(continuation(&result).unwrap().is_none());
        for size in [0, 1, MAX_TOKEN_BYTES, MAX_TOKEN_BYTES + 1] {
            result.continuation_point = vec![1; size].into();
            match size {
                0 => assert!(continuation(&result).unwrap().is_none()),
                1 | MAX_TOKEN_BYTES => assert!(continuation(&result).unwrap().is_some()),
                _ => assert!(matches!(
                    continuation(&result),
                    Err(ReadError::InvalidUnitReference)
                )),
            }
        }
        // A terminal page with zero references is consumable even at the reference ceiling.
        assert!(references(&result).unwrap().is_empty());
        let mut session = ReadSession::default();
        let page = Page::First(ua::BrowseResponse::default());
        assert!(matches!(
            page.checked(&mut session),
            Err(ReadError::InvalidUnitReference)
        ));
        assert!(session.interrupted);
    }

    #[test]
    fn bounded_pages_preserve_a_candidate_until_the_sequence_is_complete() {
        let ns = crate::client::namespace_map(
            &["http://opcfoundation.org/UA/", "urn:site"].map(|s| ua::Variant::String(s.into())),
        )
        .unwrap();
        let signal = NodeId::new("urn:site", "i=10").unwrap();
        let entry = |qualified_name: ua::QualifiedName| ua::ReferenceDescription {
            is_forward: true,
            reference_type_id: ua::NodeId::new(0, HAS_PROPERTY),
            node_class: ua::NodeClass::Variable,
            browse_name: qualified_name,
            node_id: ua::NodeId::new(1, 11u32).into(),
            ..Default::default()
        };
        let unrelated = entry(ua::QualifiedName::new(1, "EngineeringUnits"));
        let matched = entry(ua::QualifiedName::new(0, "EngineeringUnits"));
        let mut complete = Selection::default();
        complete
            .inspect(&vec![unrelated.clone(); 255], &ns, &signal)
            .unwrap();
        assert!(complete.found.is_none());
        complete
            .inspect(std::slice::from_ref(&matched), &ns, &signal)
            .unwrap();
        complete.inspect(&[], &ns, &signal).unwrap();
        assert_eq!(
            complete.found,
            Some(NodeId::new("urn:site", "i=11").unwrap())
        );
        assert!(complete.inspect(&[unrelated], &ns, &signal).is_err());
        let mut ambiguous = Selection::default();
        ambiguous
            .inspect(std::slice::from_ref(&matched), &ns, &signal)
            .unwrap();
        assert!(ambiguous.inspect(&[matched], &ns, &signal).is_err());
        let mut empty = Selection::default();
        for _ in 0..MAX_PAGES {
            empty.inspect(&[], &ns, &signal).unwrap();
        }
        assert!(empty.inspect(&[], &ns, &signal).is_err());
    }
}
