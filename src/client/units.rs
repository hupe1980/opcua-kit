use open62541::DataType;

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
    let eu = v
        .as_scalar::<ua::EUInformation>()
        .or_else(|| {
            v.as_scalar::<ua::ExtensionObject>()?
                .decoded_content::<ua::EUInformation>()
        })
        .ok_or(ReadError::InvalidUnitProperty)?;
    // SAFETY: the decoded scalar owns these fields for the duration of this immutable borrow.
    // The SDK exposes the localized labels but no getter for namespaceUri or the signed raw unitId.
    let fields = unsafe { eu.as_ref() };
    let text = ua::String::raw_ref(&fields.namespaceUri);
    unit_from_fields(text.as_bytes().unwrap_or_default(), fields.unitId).map(Some)
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

// Both services return the same BrowseResult layout. These borrowed views keep
// the SDK from deep-copying arbitrary labels and node IDs before our size checks.
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
        // SAFETY: each SDK response owns its decoded array. Borrow the sole result for
        // the lifetime of the response; positive length means the pointer is initialized.
        let (count, ptr) = unsafe {
            match self {
                Self::First(r) => {
                    let fields = r.as_ref();
                    (fields.resultsSize, fields.results)
                }
                Self::Next(r) => {
                    let fields = r.as_ref();
                    (fields.resultsSize, fields.results)
                }
            }
        };
        if count != 1 || ptr.is_null() {
            return Err(ReadError::InvalidUnitReference);
        }
        // SAFETY: the decoder returned exactly one element in this owned response.
        Ok(ua::BrowseResult::raw_ref(unsafe { &*ptr }))
    }
}

pub(super) fn references(
    result: &ua::BrowseResult,
) -> Result<&[ua::ReferenceDescription], ReadError> {
    // SAFETY: the SDK decoder owns this array. Only borrow within the result's lifetime.
    // Positive lengths have live elements; never dereference the zero-length sentinel.
    let raw = unsafe { result.as_ref() };
    if raw.referencesSize == 0 {
        return Ok(&[]);
    }
    if raw.referencesSize > MAX_REFERENCES || raw.references.is_null() {
        return Err(ReadError::InvalidUnitReference);
    }
    // DataType guarantees transparent representation over the corresponding UA data type.
    Ok(unsafe {
        std::slice::from_raw_parts(
            raw.references.cast::<ua::ReferenceDescription>(),
            raw.referencesSize,
        )
    })
}

fn continuation(result: &ua::BrowseResult) -> Result<Option<ua::ContinuationPoint>, ReadError> {
    // SAFETY: borrow this SDK-owned byte string only to check its representation.
    let token = ua::ByteString::raw_ref(&unsafe { result.as_ref() }.continuationPoint);
    // Part 6 §5.1.11 treats null and empty ByteStrings alike. The SDK's
    // continuation_point() assumes any non-null token is nonempty.
    let bytes = token.as_bytes().unwrap_or_default();
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(ReadError::InvalidUnitReference);
    }
    Ok(result.continuation_point())
}

pub(super) fn local_target(
    namespaces: &Namespaces,
    target: &ua::ExpandedNodeId,
) -> Result<NodeId, ReadError> {
    if target.server_index() != 0 {
        return Err(ReadError::InvalidUnitReference);
    }
    let uri = target.namespace_uri();
    if uri.is_null() || uri.is_empty() {
        namespaces.stable_node(target.node_id())
    } else {
        let uri = uri
            .as_str()
            .filter(|uri| namespaces.by_uri.contains_key(*uri))
            .ok_or(ReadError::InvalidUnitReference)?;
        Namespaces::node_in(uri, target.node_id())
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
            if !entry.is_forward() || entry.reference_type_id().as_ns0() != Some(HAS_PROPERTY) {
                return Err(ReadError::InvalidUnitReference);
            }
            if entry.browse_name().as_ns0().and_then(ua::String::as_str) != Some("EngineeringUnits")
            {
                continue;
            }
            if self.found.is_some() || entry.node_class() != &ua::NodeClass::VARIABLE {
                return Err(ReadError::InvalidUnitReference);
            }
            self.found = Some(local_property(namespaces, entry.node_id(), signal)?);
        }
        Ok(())
    }
}

fn gate(
    raw: &DataValue<ua::Variant>,
    stage: UnitStage,
    quality: Quality,
) -> Result<Option<Sample<EngineeringUnit>>, ReadError> {
    let result = Sample::decode_with(raw, quality, |value| {
        let matches = match stage {
            UnitStage::DataType => {
                value.as_scalar::<ua::NodeId>().and_then(ua::NodeId::as_ns0) == Some(EU_INFORMATION)
            }
            UnitStage::ValueRank => value
                .as_scalar::<ua::Int32>()
                .is_some_and(|rank| rank.value() == -1),
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
        let request = ua::BrowseNextRequest::init()
            .with_release_continuation_points(release)
            .with_continuation_points(&[point]);
        let response = self
            .guarded(session, self.inner.service_request(request))
            .await?;
        if release {
            // Part 4 §5.9.3.2 requires empty arrays when releasing points. Inspect the
            // counts only. SAFETY: this temporary borrow does not take ownership of any field.
            let envelope = unsafe { response.as_ref() };
            session.confirm_unit_release(envelope.resultsSize, envelope.diagnosticInfosSize)?;
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
        let mask = ua::BrowseResultMask::REFERENCETYPEINFO
            | ua::BrowseResultMask::BROWSENAME
            | ua::BrowseResultMask::NODECLASS;
        let description = ua::BrowseDescription::init()
            .with_node_id(&namespaces.wire_node(signal, 0)?)
            .with_browse_direction(&ua::BrowseDirection::FORWARD)
            .with_reference_type_id(&ua::NodeId::ns0(HAS_PROPERTY))
            .with_include_subtypes(false)
            .with_result_mask(&mask);
        let request = ua::BrowseRequest::init()
            .with_requested_max_references_per_node(MAX_REFERENCES as u32)
            .with_nodes_to_browse(&[description]);
        let mut page = Page::First(
            self.guarded(session, self.inner.service_request(request))
                .await?,
        );
        let mut selection = Selection::default();
        loop {
            let (result, point) = page.checked(session)?;
            let status = result.status_code().into_raw();
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
            return Err(ReadError::InvalidUnitReference);
        }
        let wire = namespaces.wire_node(&property, 0)?;
        for (stage, attribute) in [
            (UnitStage::DataType, ua::AttributeId::DATATYPE),
            (UnitStage::ValueRank, ua::AttributeId::VALUERANK),
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
            .one_attribute(session, wire, ua::AttributeId::VALUE)
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
        let flagged = ua::StatusCode::GOODCLAMPED;
        assert!(Quality::GoodSeverity.accepts(flagged.clone().into_raw()));
        assert!(!Quality::ExactGood.accepts(flagged.clone().into_raw()));
        let data_type = ua::Variant::scalar(ua::NodeId::ns0(EU_INFORMATION));
        let rank = ua::Variant::scalar(ua::Int32::new(-1));
        for (stage, declaration) in [
            (UnitStage::DataType, data_type),
            (UnitStage::ValueRank, rank),
        ] {
            let raw = ua::DataValue::new(declaration).with_status(&flagged).cast();
            assert!(gate(&raw, stage, Quality::GoodSeverity).unwrap().is_none());
            let unavailable = gate(&raw, stage, Quality::ExactGood).unwrap().unwrap();
            assert_eq!(unavailable.status, flagged.clone().into_raw());
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
            .map(|s| ua::String::new(s).unwrap());
        let ns = crate::client::namespace_map(&table).unwrap();
        let signal = NodeId::new("urn:signal", "s=x").unwrap();
        let explicit = |uri: &str, server: u32| {
            ua::ExpandedNodeId::new(
                ua::NodeId::string(0, "x"),
                ua::String::new(uri).unwrap(),
                server,
            )
        };
        let expected = NodeId::new("urn:property", "s=x").unwrap();
        let zero = ua::ExpandedNodeId::new(
            ua::NodeId::ns0(0),
            ua::String::new("urn:property").unwrap(),
            0,
        );
        assert_eq!(
            local_property(&ns, &zero, &signal).unwrap(),
            NodeId::new("urn:property", "i=0").unwrap()
        );
        assert_eq!(
            local_property(&ns, &explicit("urn:property", 0), &signal).unwrap(),
            expected
        );
        assert_eq!(
            local_property(&ns, &ua::NodeId::string(2, "x").into(), &signal).unwrap(),
            expected
        );
        for target in [
            explicit("urn:property", 2),
            explicit("urn:absent", 0),
            explicit("urn:signal", 0),
            ua::NodeId::string(1, "x").into(),
            ua::ExpandedNodeId::numeric(0, 0),
            ua::ExpandedNodeId::numeric(9, 1),
        ] {
            assert!(matches!(
                local_property(&ns, &target, &signal),
                Err(ReadError::InvalidUnitReference)
            ));
        }
    }

    #[test]
    fn declaration_gates_require_exact_scalar_type_and_preserve_unavailable_clocks() {
        let valid = ua::DataValue::new(ua::Variant::scalar(ua::NodeId::ns0(887)))
            .with_status(&ua::StatusCode::GOODCLAMPED)
            .cast();
        assert!(
            gate(&valid, UnitStage::DataType, Quality::GoodSeverity)
                .unwrap()
                .is_none()
        );
        let rank = ua::DataValue::new(ua::Variant::scalar(ua::Int32::new(-1))).cast();
        assert!(
            gate(&rank, UnitStage::ValueRank, Quality::GoodSeverity)
                .unwrap()
                .is_none()
        );
        for (value, stage) in [
            (
                ua::Variant::scalar(ua::NodeId::numeric(2, 887)),
                UnitStage::DataType,
            ),
            (ua::Variant::scalar(ua::Int32::new(0)), UnitStage::ValueRank),
            (
                ua::Variant::array(ua::Array::from_slice(&[ua::Int32::new(-1)])),
                UnitStage::ValueRank,
            ),
        ] {
            assert!(matches!(
                gate(
                    &ua::DataValue::new(value).cast(),
                    stage,
                    Quality::GoodSeverity
                ),
                Err(ReadError::InvalidUnitProperty)
            ));
        }
        let missing = gate(
            &ua::DataValue::init().cast(),
            UnitStage::DataType,
            Quality::GoodSeverity,
        )
        .unwrap()
        .unwrap();
        assert_eq!(missing.status, 0);
        assert!(missing.value.is_none());
        let raw = ua::DataValue::new(ua::Variant::scalar(ua::Int32::new(-1)))
            .with_status(&ua::StatusCode::UNCERTAINLASTUSABLEVALUE)
            .with_source_timestamp(&ua::DateTime::try_from_unix_timestamp_nanos(100).unwrap())
            .with_source_picoseconds(3)
            .cast();
        let unavailable = gate(&raw, UnitStage::ValueRank, Quality::GoodSeverity)
            .unwrap()
            .unwrap();
        assert_eq!(
            unavailable.status,
            ua::StatusCode::UNCERTAINLASTUSABLEVALUE.into_raw()
        );
        assert_eq!(
            unavailable.source_timestamp.unwrap().ten_picoseconds,
            Some(3)
        );
        assert!(unavailable.value.is_none());
    }

    #[test]
    fn actual_eu_structure_keeps_signed_identity_and_ignores_localized_labels() {
        let mut eu = ua::EUInformation::init();
        // SAFETY: own the initialized SDK value and use the SDK's ownership-transfer
        // operations for both strings. All fields are released by its ordinary drop.
        let fields = unsafe { eu.as_mut() };
        ua::String::new("urn:Vendor")
            .unwrap()
            .move_into_raw(&mut fields.namespaceUri);
        ua::LocalizedText::new("de-DE", "nicht maßgeblich")
            .unwrap()
            .move_into_raw(&mut fields.displayName);
        fields.unitId = i32::MIN;
        let unit = decode_unit(&ua::Variant::scalar(eu)).unwrap().unwrap();
        assert_eq!(
            (unit.namespace_uri.as_str(), unit.unit_id),
            ("urn:Vendor", i32::MIN)
        );
        assert!(unit.is_identified());
        assert!(!unit_from_fields(b"urn:vendor", -1).unwrap().is_identified());
        assert!(!unit_from_fields(b"", 42).unwrap().is_identified());
        assert!(matches!(
            decode_unit(&ua::Variant::scalar(ua::Int32::new(42))),
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
        let mut result = ua::BrowseResult::init();
        assert!(continuation(&result).unwrap().is_none());
        for size in [0, 1, MAX_TOKEN_BYTES, MAX_TOKEN_BYTES + 1] {
            // SAFETY: the test owns this initialized field; moving replaces the old token.
            ua::ByteString::new(&vec![1; size])
                .move_into_raw(&mut unsafe { result.as_mut() }.continuationPoint);
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
        let page = Page::First(ua::BrowseResponse::init());
        assert!(matches!(
            page.checked(&mut session),
            Err(ReadError::InvalidUnitReference)
        ));
        assert!(session.interrupted);
    }

    #[test]
    fn bounded_pages_preserve_a_candidate_until_the_sequence_is_complete() {
        let ns = crate::client::namespace_map(
            &["http://opcfoundation.org/UA/", "urn:site"].map(|s| ua::String::new(s).unwrap()),
        )
        .unwrap();
        let signal = NodeId::new("urn:site", "i=10").unwrap();
        let entry = |qualified_name: ua::QualifiedName| {
            let mut reference = ua::ReferenceDescription::init();
            // SAFETY: the test owns the initialized SDK structure and transfers ownership of
            // each field through DataType; the SDK is responsible for its resulting allocations.
            let fields = unsafe { reference.as_mut() };
            fields.isForward = true;
            ua::NodeId::ns0(HAS_PROPERTY).move_into_raw(&mut fields.referenceTypeId);
            ua::NodeClass::VARIABLE.move_into_raw(&mut fields.nodeClass);
            qualified_name.move_into_raw(&mut fields.browseName);
            ua::ExpandedNodeId::numeric(1, 11).move_into_raw(&mut fields.nodeId);
            reference
        };
        let unrelated = entry(ua::QualifiedName::new(1, "EngineeringUnits"));
        let matched = entry(ua::QualifiedName::ns0("EngineeringUnits"));
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
