use super::{Host, UA_NAMESPACE};
use crate::ua::*;

const ROOT: u32 = 84;
const OBJECTS: u32 = 85;
const SERVER: u32 = 2253;
const SERVER_ARRAY: u32 = 2254;
const NAMESPACES: u32 = 2255;
const CAPABILITIES: u32 = 2268;
const LIMITS: u32 = 11704;
const MAX_READ: u32 = 11705;
const SERVER_STATUS: u32 = 2256;
const START_TIME: u32 = 2257;
const CURRENT_TIME: u32 = 2258;
const STATE: u32 = 2259;
const ORGANIZES: u32 = 35;
const HAS_PROPERTY: u32 = 46;
const HAS_COMPONENT: u32 = 47;

struct Node {
    id: NodeId,
    name: QualifiedName,
    class: NodeClass,
    parent: Option<(u32, u32)>,
    data_type: u32,
    type_definition: u32,
}

const STANDARD: &[u32] = &[
    ROOT,
    OBJECTS,
    SERVER,
    SERVER_ARRAY,
    NAMESPACES,
    CAPABILITIES,
    LIMITS,
    MAX_READ,
    SERVER_STATUS,
    START_TIME,
    CURRENT_TIME,
    STATE,
];

impl Host {
    fn node(&self, id: &NodeId) -> Result<Node, StatusCode> {
        let (name, parent, class, data_type, type_definition) =
            match (&id.namespace, &id.identifier) {
                (2, Identifier::String(name)) => {
                    let vars = self.variables.read().unwrap_or_else(|e| e.into_inner());
                    let (ty, _) = vars
                        .get(name.as_ref())
                        .ok_or(StatusCode::BadNodeIdUnknown)?;
                    (
                        name.as_ref(),
                        Some((OBJECTS, ORGANIZES)),
                        NodeClass::Variable,
                        *ty,
                        63,
                    )
                }
                (0, Identifier::Numeric(num)) => match *num {
                    ROOT => ("Root", None, NodeClass::Object, 0, 61),
                    OBJECTS => ("Objects", Some((ROOT, ORGANIZES)), NodeClass::Object, 0, 61),
                    SERVER => (
                        "Server",
                        Some((OBJECTS, ORGANIZES)),
                        NodeClass::Object,
                        0,
                        2004,
                    ),
                    SERVER_ARRAY => (
                        "ServerArray",
                        Some((SERVER, HAS_PROPERTY)),
                        NodeClass::Variable,
                        12,
                        68,
                    ),
                    NAMESPACES => (
                        "NamespaceArray",
                        Some((SERVER, HAS_PROPERTY)),
                        NodeClass::Variable,
                        12,
                        68,
                    ),
                    CAPABILITIES => (
                        "ServerCapabilities",
                        Some((SERVER, HAS_COMPONENT)),
                        NodeClass::Object,
                        0,
                        2013,
                    ),
                    LIMITS => (
                        "OperationLimits",
                        Some((CAPABILITIES, HAS_COMPONENT)),
                        NodeClass::Object,
                        0,
                        11564,
                    ),
                    MAX_READ => (
                        "MaxNodesPerRead",
                        Some((LIMITS, HAS_PROPERTY)),
                        NodeClass::Variable,
                        7,
                        68,
                    ),
                    SERVER_STATUS => (
                        "ServerStatus",
                        Some((SERVER, HAS_COMPONENT)),
                        NodeClass::Variable,
                        862,
                        2138,
                    ),
                    START_TIME => (
                        "StartTime",
                        Some((SERVER_STATUS, HAS_COMPONENT)),
                        NodeClass::Variable,
                        13,
                        63,
                    ),
                    CURRENT_TIME => (
                        "CurrentTime",
                        Some((SERVER_STATUS, HAS_COMPONENT)),
                        NodeClass::Variable,
                        13,
                        63,
                    ),
                    STATE => (
                        "State",
                        Some((SERVER_STATUS, HAS_COMPONENT)),
                        NodeClass::Variable,
                        852,
                        63,
                    ),
                    _ => return Err(StatusCode::BadNodeIdUnknown),
                },
                _ => return Err(StatusCode::BadNodeIdUnknown),
            };
        Ok(Node {
            id: id.clone(),
            name: QualifiedName::new(id.namespace, name),
            class,
            data_type,
            parent,
            type_definition,
        })
    }

    pub(super) fn read(
        &self,
        item: ReadValueId,
        timestamps: TimestampsToReturn,
    ) -> Result<DataValue, StatusCode> {
        let node = self.node(&item.node_id)?;
        if !item.data_encoding.is_null() {
            return Err(StatusCode::BadDataEncodingUnsupported);
        }
        let array = matches!(
            node.id.identifier,
            Identifier::Numeric(SERVER_ARRAY | NAMESPACES)
        );
        let variable = node.class == NodeClass::Variable;
        let mut value = match item.attribute_id {
            1 => DataValue::value_only(node.id),
            2 => DataValue::value_only(node.class as i32),
            3 => DataValue::value_only(node.name),
            4 => DataValue::value_only(LocalizedText::new("", node.name.name.as_ref())),
            5 => DataValue::value_only(LocalizedText::null()),
            6 | 7 => DataValue::value_only(0_u32),
            12 if !variable => DataValue::value_only(0_u8),
            13 if variable => match &node.id.identifier {
                Identifier::String(name) => {
                    let vars = self.variables.read().unwrap_or_else(|e| e.into_inner());
                    let sample = &vars
                        .get(name.as_ref())
                        .ok_or(StatusCode::BadNodeIdUnknown)?
                        .1;
                    sample.read().unwrap_or_else(|e| e.into_inner()).clone()
                }
                Identifier::Numeric(SERVER_ARRAY) => {
                    DataValue::value_only(vec![self.application_uri.clone()])
                }
                Identifier::Numeric(NAMESPACES) => DataValue::value_only(vec![
                    UA_NAMESPACE.into(),
                    self.application_uri.clone(),
                    self.namespace.clone(),
                ]),
                Identifier::Numeric(MAX_READ) => DataValue::value_only(1024_u32),
                Identifier::Numeric(SERVER_STATUS) => {
                    DataValue::value_only(ExtensionObject::new(ServerStatusDataType {
                        start_time: self.started,
                        current_time: DateTime::now(),
                        state: ServerState::Running,
                        build_info: BuildInfo {
                            product_uri: "urn:opcua-kit".into(),
                            manufacturer_name: UAString::null(),
                            product_name: "opcua-kit".into(),
                            software_version: env!("CARGO_PKG_VERSION").into(),
                            build_number: UAString::null(),
                            build_date: DateTime::default(),
                        },
                        seconds_till_shutdown: 0,
                        shutdown_reason: LocalizedText::null(),
                    }))
                }
                Identifier::Numeric(START_TIME) => DataValue::value_only(self.started),
                Identifier::Numeric(CURRENT_TIME) => DataValue::value_only(DateTime::now()),
                Identifier::Numeric(STATE) => DataValue::value_only(0_i32),
                _ => return Err(StatusCode::BadNotReadable),
            },
            14 if variable => DataValue::value_only(NodeId::new(0, node.data_type)),
            15 if variable => DataValue::value_only(if array { 1_i32 } else { -1 }),
            16 if variable && array => DataValue::value_only(vec![0_u32]),
            16 if variable => {
                DataValue::value_only(Variant::NullArray(VariantScalarTypeId::UInt32))
            }
            17 | 18 if variable => DataValue::value_only(1_u8),
            19 if variable => DataValue::value_only(0_f64),
            20 if variable => DataValue::value_only(false),
            _ => return Err(StatusCode::BadAttributeIdInvalid),
        };
        if !item.index_range.is_empty() {
            let sample = value.value.take().ok_or(StatusCode::BadIndexRangeNoData)?;
            value.value = Some(slice_value(sample, item.index_range.as_ref())?);
        }
        let now = DateTime::now();
        value.source_timestamp = (item.attribute_id == 13
            && matches!(
                timestamps,
                TimestampsToReturn::Both | TimestampsToReturn::Source
            ))
        .then_some(value.source_timestamp.unwrap_or(now));
        value.server_timestamp = matches!(
            timestamps,
            TimestampsToReturn::Both | TimestampsToReturn::Server
        )
        .then_some(now);
        value.source_picoseconds = None;
        value.server_picoseconds = None;
        Ok(value)
    }

    pub(super) fn references(
        &self,
        browse: &BrowseDescription,
        after: Option<&NodeId>,
        size: usize,
    ) -> Result<Vec<ReferenceDescription>, StatusCode> {
        use std::ops::Bound::{Excluded, Unbounded};
        let origin = self.node(&browse.node_id)?;
        let mut refs = Vec::new();
        if after.is_none_or(|node| node.namespace == 0) {
            if browse.browse_direction != BrowseDirection::Forward
                && let Some((parent, rel)) = origin.parent
                && let Some(reference) = self
                    .node(&NodeId::new(0, parent))?
                    .reference(browse, rel, false)
            {
                refs.push(reference);
            }
            if browse.browse_direction != BrowseDirection::Inverse {
                for id in STANDARD {
                    let child = self.node(&NodeId::new(0, *id))?;
                    if let Some((parent, rel)) = child.parent
                        && origin.id == NodeId::new(0, parent)
                        && let Some(reference) = child.reference(browse, rel, true)
                    {
                        refs.push(reference);
                    }
                }
            }
            refs.sort_by_key(|r| match r.node_id.node_id.identifier {
                Identifier::Numeric(n) => n,
                _ => 0,
            });
            if let Some(NodeId {
                identifier: Identifier::Numeric(min),
                ..
            }) = after
            {
                refs.retain(
                    |r| matches!(r.node_id.node_id.identifier,Identifier::Numeric(n) if n>*min),
                );
            }
        }
        if origin.id == NodeId::new(0, OBJECTS)
            && browse.browse_direction != BrowseDirection::Inverse
            && (browse.node_class_mask == 0
                || browse.node_class_mask & NodeClass::Variable as u32 != 0)
            && reference_matches(
                &browse.reference_type_id,
                browse.include_subtypes,
                ORGANIZES,
            )
        {
            let start = match after {
                Some(NodeId {
                    namespace: 2,
                    identifier: Identifier::String(key),
                }) => Excluded(key.as_ref()),
                _ => Unbounded,
            };
            let vars = self.variables.read().unwrap_or_else(|e| e.into_inner());
            for (name, (ty, _)) in vars
                .range::<str, _>((start, Unbounded))
                .take((size + 1).saturating_sub(refs.len()))
            {
                let child = Node {
                    id: NodeId::new(2, name.as_str()),
                    name: QualifiedName::new(2, name.as_str()),
                    class: NodeClass::Variable,
                    parent: Some((OBJECTS, ORGANIZES)),
                    data_type: *ty,
                    type_definition: 63,
                };
                if let Some(reference) = child.reference(browse, ORGANIZES, true) {
                    refs.push(reference);
                }
            }
        }
        refs.truncate(size + 1);
        Ok(refs)
    }

    pub(super) fn translate(&self, path: BrowsePath) -> Result<Vec<BrowsePathTarget>, StatusCode> {
        let mut origin = self.node(&path.starting_node)?;
        let parts = path.relative_path.elements.unwrap_or_default();
        if parts.is_empty() {
            return Err(StatusCode::BadNothingToDo);
        }
        for part in parts {
            let (candidate, rel) = if part.is_inverse {
                let (parent, rel) = origin.parent.ok_or(StatusCode::BadNoMatch)?;
                (self.node(&NodeId::new(0, parent))?, rel)
            } else {
                let child = match part.target_name.namespace_index {
                    0 => STANDARD
                        .iter()
                        .filter_map(|id| self.node(&NodeId::new(0, *id)).ok())
                        .find(|node| node.name == part.target_name),
                    2 => self
                        .node(&NodeId::new(2, part.target_name.name.as_ref()))
                        .ok(),
                    _ => None,
                }
                .ok_or(StatusCode::BadNoMatch)?;
                let (parent, rel) = child.parent.ok_or(StatusCode::BadNoMatch)?;
                if NodeId::new(0, parent) != origin.id {
                    return Err(StatusCode::BadNoMatch);
                }
                (child, rel)
            };
            if candidate.name != part.target_name
                || !reference_matches(&part.reference_type_id, part.include_subtypes, rel)
            {
                return Err(StatusCode::BadNoMatch);
            }
            origin = candidate;
        }
        let node = origin.id;
        Ok(vec![BrowsePathTarget {
            target_id: node.into(),
            remaining_path_index: u32::MAX,
        }])
    }
}

impl Node {
    fn reference(
        self,
        browse: &BrowseDescription,
        relation: u32,
        forward: bool,
    ) -> Option<ReferenceDescription> {
        if !reference_matches(&browse.reference_type_id, browse.include_subtypes, relation)
            || browse.node_class_mask != 0 && browse.node_class_mask & self.class as u32 == 0
        {
            return None;
        }
        let mask = browse.result_mask;
        Some(ReferenceDescription {
            reference_type_id: if mask & 1 != 0 {
                NodeId::new(0, relation)
            } else {
                NodeId::null()
            },
            is_forward: mask & 2 != 0 && forward,
            node_id: self.id.into(),
            display_name: if mask & 16 != 0 {
                LocalizedText::new("", self.name.name.as_ref())
            } else {
                LocalizedText::null()
            },
            browse_name: if mask & 8 != 0 {
                self.name
            } else {
                QualifiedName::default()
            },
            node_class: if mask & 4 != 0 {
                self.class
            } else {
                NodeClass::Unspecified
            },
            type_definition: if mask & 32 != 0 {
                NodeId::new(0, self.type_definition).into()
            } else {
                ExpandedNodeId::null()
            },
        })
    }
}

fn reference_matches(filter: &NodeId, subtypes: bool, relation: u32) -> bool {
    if filter.is_null() || filter == &NodeId::new(0, relation) {
        return true;
    }
    if !subtypes || filter.namespace != 0 {
        return false;
    }
    match filter.identifier {
        Identifier::Numeric(31 | 33) => true,
        Identifier::Numeric(34 | 44) => matches!(relation, HAS_PROPERTY | HAS_COMPONENT),
        _ => false,
    }
}

fn slice_value(value: Variant, range: &str) -> Result<Variant, StatusCode> {
    let parse = |s: &str| {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(StatusCode::BadIndexRangeInvalid);
        }
        s.parse::<u32>()
            .map(|n| n as usize)
            .map_err(|_| StatusCode::BadIndexRangeInvalid)
    };
    let (first, last) = if let Some((low, high)) = range.split_once(':') {
        let low = parse(low)?;
        let high = parse(high)?;
        if low >= high {
            return Err(StatusCode::BadIndexRangeInvalid);
        }
        (low, high)
    } else {
        let index = parse(range)?;
        (index, index)
    };
    match value {
        Variant::String(text) => {
            let slice: String = text
                .as_ref()
                .chars()
                .skip(first)
                .take(last.saturating_sub(first).saturating_add(1))
                .collect();
            if slice.is_empty() {
                return Err(StatusCode::BadIndexRangeNoData);
            }
            Ok(Variant::from(slice))
        }
        Variant::ByteString(bytes) => {
            let data = bytes.as_ref();
            if first >= data.len() {
                return Err(StatusCode::BadIndexRangeNoData);
            }
            Ok(Variant::ByteString(ByteString::from(
                &data[first..=last.min(data.len() - 1)],
            )))
        }
        Variant::Array(mut array) => {
            if first >= array.values.len() {
                return Err(StatusCode::BadIndexRangeNoData);
            }
            array.values = array
                .values
                .drain(first..=last.min(array.values.len() - 1))
                .collect();
            Ok(Variant::Array(array))
        }
        _ => Err(StatusCode::BadIndexRangeNoData),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_ranges_count_unicode_characters_and_clip_the_upper_bound() {
        assert_eq!(
            slice_value("UA🌐".into(), "1:70").unwrap(),
            Variant::from("A🌐")
        );
        assert_eq!(
            slice_value("UA🌐".into(), "3"),
            Err(StatusCode::BadIndexRangeNoData)
        );
        assert_eq!(
            slice_value("UA🌐".into(), "0:0"),
            Err(StatusCode::BadIndexRangeInvalid)
        );
    }
}
