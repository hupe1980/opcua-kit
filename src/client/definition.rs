use base64::{Engine, engine::general_purpose::STANDARD};
use uuid::Uuid;

use super::sample::Quality;
use super::{Client, DataValue, Namespaces, ReadError, ReadMetadata, ReadSession, Sample, ua};
use crate::NodeId;

/// A standard node attribute selectable through the OPC UA Read service.
/// Nodes that do not support a selected attribute return its per-operand status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReadAttribute {
    NodeId,
    NodeClass,
    BrowseName,
    DisplayName,
    Description,
    WriteMask,
    UserWriteMask,
    IsAbstract,
    Symmetric,
    InverseName,
    ContainsNoLoops,
    EventNotifier,
    ArrayDimensions,
    AccessLevel,
    UserAccessLevel,
    MinimumSamplingInterval,
    Historizing,
    Executable,
    UserExecutable,
    DataTypeDefinition,
    RolePermissions,
    UserRolePermissions,
    AccessRestrictions,
    AccessLevelEx,

    /// The process value.
    Value,
    /// The declared DataType node.
    DataType,
    /// The declared dimensionality, such as -1 for a scalar.
    ValueRank,
}

impl ReadAttribute {
    pub(super) fn wire(self) -> ua::AttributeId {
        match self {
            Self::NodeId => ua::AttributeId::NODEID,
            Self::NodeClass => ua::AttributeId::NODECLASS,
            Self::BrowseName => ua::AttributeId::BROWSENAME,
            Self::DisplayName => ua::AttributeId::DISPLAYNAME,
            Self::Description => ua::AttributeId::DESCRIPTION,
            Self::WriteMask => ua::AttributeId::WRITEMASK,
            Self::UserWriteMask => ua::AttributeId::USERWRITEMASK,
            Self::IsAbstract => ua::AttributeId::ISABSTRACT,
            Self::Symmetric => ua::AttributeId::SYMMETRIC,
            Self::InverseName => ua::AttributeId::INVERSENAME,
            Self::ContainsNoLoops => ua::AttributeId::CONTAINSNOLOOPS,
            Self::EventNotifier => ua::AttributeId::EVENTNOTIFIER,
            Self::ArrayDimensions => ua::AttributeId::ARRAYDIMENSIONS,
            Self::AccessLevel => ua::AttributeId::ACCESSLEVEL,
            Self::UserAccessLevel => ua::AttributeId::USERACCESSLEVEL,
            Self::MinimumSamplingInterval => ua::AttributeId::MINIMUMSAMPLINGINTERVAL,
            Self::Historizing => ua::AttributeId::HISTORIZING,
            Self::Executable => ua::AttributeId::EXECUTABLE,
            Self::UserExecutable => ua::AttributeId::USEREXECUTABLE,
            Self::DataTypeDefinition => ua::AttributeId::DATATYPEDEFINITION,
            Self::RolePermissions => ua::AttributeId::ROLEPERMISSIONS,
            Self::UserRolePermissions => ua::AttributeId::USERROLEPERMISSIONS,
            Self::AccessRestrictions => ua::AttributeId::ACCESSRESTRICTIONS,
            Self::AccessLevelEx => ua::AttributeId::ACCESSLEVELEX,

            Self::Value => ua::AttributeId::VALUE,
            Self::DataType => ua::AttributeId::DATATYPE,
            Self::ValueRank => ua::AttributeId::VALUERANK,
        }
    }
}

/// A URI-qualified node and the attribute to read from it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOperand<'a> {
    /// Stable node identity supplied by the application.
    pub node: &'a NodeId,
    /// Attribute requested at this position in the batch.
    pub attribute: ReadAttribute,
}

impl<'a> ReadOperand<'a> {
    /// Select an attribute of a node for [`Client::read_attributes`].
    pub const fn new(node: &'a NodeId, attribute: ReadAttribute) -> Self {
        Self { node, attribute }
    }

    pub(super) fn value(node: &'a NodeId) -> Self {
        Self::new(node, ReadAttribute::Value)
    }
}

/// Two independent attribute results. Each sample preserves its status and clocks.
#[derive(Debug)]
pub struct VariableDefinition {
    /// Declared DataType, translated into a stable namespace URI.
    pub data_type: Result<Sample<NodeId>, ReadError>,
    /// OPC UA ValueRank as a signed integer (-3 or greater).
    pub value_rank: Result<Sample<i32>, ReadError>,
}

impl Namespaces {
    pub(super) fn stable_node(&self, wire: &ua::NodeId) -> Result<NodeId, ReadError> {
        let namespace = self
            .by_index
            .get(usize::from(wire.namespace_index()))
            .ok_or(ReadError::InvalidDataType)?;
        Self::node_in(namespace, wire)
    }

    pub(super) fn node_in(namespace: &str, wire: &ua::NodeId) -> Result<NodeId, ReadError> {
        let id = if let Some((_, n)) = wire.as_numeric() {
            format!("i={n}")
        } else if let Some((_, text)) = wire.as_string() {
            // Four UTF-8 bytes per character bounds the copy before NodeId::new checks the text.
            let text = text
                .as_str()
                .filter(|text| text.len() <= 4 * 4096)
                .ok_or(ReadError::InvalidDataType)?;
            format!("s={text}")
        } else if let Some((_, guid)) = wire.as_guid() {
            let uuid = Uuid::from_fields(guid.data1(), guid.data2(), guid.data3(), &guid.data4());
            format!("g={uuid}")
        } else if let Some((_, bytes)) = wire.as_byte_string() {
            let bytes = bytes
                .as_bytes()
                .filter(|bytes| bytes.len() <= 4096)
                .ok_or(ReadError::InvalidDataType)?;
            format!("b={}", STANDARD.encode(bytes))
        } else {
            return Err(ReadError::InvalidDataType);
        };
        NodeId::new(namespace, id).map_err(|_| ReadError::InvalidDataType)
    }
}

pub(super) fn decode_data_type(
    namespaces: &Namespaces,
    raw: &DataValue<ua::Variant>,
    quality: Quality,
) -> Result<Sample<NodeId>, ReadError> {
    Sample::decode_with(raw, quality, |v| {
        let wire = v
            .as_scalar::<ua::NodeId>()
            .ok_or(ReadError::ScalarTypeMismatch { expected: "NodeId" })?;
        namespaces.stable_node(wire).map(Some)
    })
}

impl VariableDefinition {
    fn decode(
        namespaces: &Namespaces,
        data_type: &DataValue<ua::Variant>,
        value_rank: &DataValue<ua::Variant>,
        quality: Quality,
    ) -> Self {
        let data_type = decode_data_type(namespaces, data_type, quality);
        let value_rank = Sample::<i32>::from_raw_with(value_rank, quality).and_then(|rank| {
            if rank.value.is_some_and(|n| n < -3) {
                Err(ReadError::InvalidValueRank)
            } else {
                Ok(rank)
            }
        });
        Self {
            data_type,
            value_rank,
        }
    }
}

impl Client {
    /// Read any combination of standard node attributes in caller order.
    /// Each operand counts toward the logical and per-request limits. NodeId
    /// values in these raw results carry the server's session-local indices.
    pub async fn read_attributes(
        &self,
        operands: &[ReadOperand<'_>],
    ) -> Result<Vec<DataValue<ua::Variant>>, ReadError> {
        self.read_batch(operands.iter().copied(), std::convert::identity)
            .await
    }

    /// Read only DataType and ValueRank. A malformed attribute affects its own
    /// field. Service and session failures apply to the whole definition.
    ///
    /// ```
    /// # async fn inspect(client: &opcua_kit::Client, node: &opcua_kit::NodeId) -> Result<(), opcua_kit::ReadError> {
    /// let definition = client.read_definition(node).await?;
    /// let data_type = definition.data_type?;
    /// let value_rank = definition.value_rank?;
    /// if let (Some(id), Some(rank)) = (data_type.value, value_rank.value) {
    ///     println!("{} {} has rank {rank}", id.namespace(), id.identifier());
    /// }
    /// # Ok(()) }
    /// ```
    pub async fn read_definition(&self, node: &NodeId) -> Result<VariableDefinition, ReadError> {
        let (mut session, metadata) = self.read_session().await?;
        self.definition_locked(&mut session, metadata, node, Quality::GoodSeverity)
            .await
    }

    pub(super) async fn definition_locked(
        &self,
        session: &mut ReadSession,
        metadata: &ReadMetadata,
        node: &NodeId,
        quality: Quality,
    ) -> Result<VariableDefinition, ReadError> {
        let response = self
            .read_locked(
                session,
                metadata,
                [
                    ReadOperand::new(node, ReadAttribute::DataType),
                    ReadOperand::new(node, ReadAttribute::ValueRank),
                ]
                .into_iter(),
                std::convert::identity,
            )
            .await?;
        let [data_type, value_rank] = response.as_slice() else {
            return Err(ReadError::InvalidServerMetadata);
        };
        Ok(VariableDefinition::decode(
            &metadata.namespaces,
            data_type,
            value_rank,
            quality,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use open62541::DataType;

    fn namespaces() -> Namespaces {
        let entries = [
            "http://opcfoundation.org/UA/",
            "urn:site:signals",
            "urn:site:datatypes",
        ]
        .map(|s| ua::String::new(s).unwrap());
        crate::client::namespace_map(&entries).unwrap()
    }

    #[test]
    fn declared_node_ids_use_the_session_uri_and_preserve_all_four_identifier_forms() {
        let ns = namespaces();
        for (wire, expected) in [
            (ua::NodeId::numeric(2, u32::MAX), "i=4294967295"),
            (
                ua::NodeId::string(2, "Rate;ns=3;温度%2F"),
                "s=Rate;ns=3;温度%2F",
            ),
            (
                ua::NodeId::guid(
                    2,
                    ua::Guid::new(0x12345678, 0x90ab, 0xcdef, [1, 2, 3, 4, 5, 6, 7, 8]),
                ),
                "g=12345678-90ab-cdef-0102-030405060708",
            ),
            (ua::NodeId::byte_string(2, &[0xfb, 0xff, 0]), "b=+/8A"),
        ] {
            let stable = ns.stable_node(&wire).unwrap();
            assert_eq!(stable.namespace(), "urn:site:datatypes");
            assert_eq!(stable.identifier(), expected);
        }
        for invalid in [
            ua::NodeId::ns0(0),
            ua::NodeId::numeric(3, 1),
            ua::NodeId::string(2, "x\ny"),
            ua::NodeId::string(2, &"x".repeat(4097)),
            ua::NodeId::byte_string(2, &[1; 4097]),
        ] {
            assert!(matches!(
                ns.stable_node(&invalid),
                Err(ReadError::InvalidDataType)
            ));
        }
    }

    #[test]
    fn definition_preserves_independent_status_clocks_and_malformed_results() {
        let ns = namespaces();
        let at = ua::DateTime::try_from_unix_timestamp_nanos(100).unwrap();
        let data = ua::DataValue::new(ua::Variant::scalar(ua::NodeId::ns0(9)))
            .with_source_timestamp(&at)
            .with_source_picoseconds(5)
            .with_status(&ua::StatusCode::GOODCLAMPED)
            .cast();
        let rank = ua::DataValue::new(ua::Variant::scalar(ua::Int32::new(-3))).cast();
        let valid = VariableDefinition::decode(&ns, &data, &rank, Quality::GoodSeverity);
        let ty = valid.data_type.unwrap();
        assert_eq!(
            ty.value.unwrap().namespace(),
            "http://opcfoundation.org/UA/"
        );
        assert_eq!(ty.status, ua::StatusCode::GOODCLAMPED.into_raw());
        assert_eq!(ty.source_timestamp.unwrap().ten_picoseconds, Some(5));
        assert_eq!(valid.value_rank.unwrap().value, Some(-3));

        let wrong_type = ua::DataValue::new(ua::Variant::scalar(ua::Int32::new(9))).cast();
        let partial = VariableDefinition::decode(&ns, &wrong_type, &rank, Quality::GoodSeverity);
        assert!(matches!(
            partial.data_type,
            Err(ReadError::ScalarTypeMismatch { expected: "NodeId" })
        ));
        assert_eq!(partial.value_rank.unwrap().value, Some(-3));
        let invalid_rank = ua::DataValue::new(ua::Variant::scalar(ua::Int32::new(-4))).cast();
        let partial = VariableDefinition::decode(&ns, &data, &invalid_rank, Quality::GoodSeverity);
        assert_eq!(
            partial.data_type.unwrap().value.unwrap().identifier(),
            "i=9"
        );
        assert!(matches!(
            partial.value_rank,
            Err(ReadError::InvalidValueRank)
        ));
        let bad = ua::DataValue::init()
            .with_status(&ua::StatusCode::BADATTRIBUTEIDINVALID)
            .cast();
        let missing = VariableDefinition::decode(
            &ns,
            &bad,
            &ua::DataValue::init().cast(),
            Quality::GoodSeverity,
        );
        let missing_type = missing.data_type.unwrap();
        assert_eq!(
            missing_type.status,
            ua::StatusCode::BADATTRIBUTEIDINVALID.into_raw()
        );
        assert!(missing_type.value.is_none());
        assert!(missing.value_rank.unwrap().value.is_none());
    }

    #[test]
    fn rank_accepts_all_standard_categories_and_rejects_arrays_and_unsigned_integers() {
        let ns = namespaces();
        let type_array = ua::DataValue::new(ua::Variant::array(ua::Array::from_slice(&[
            ua::NodeId::ns0(9),
        ])))
        .cast();
        for n in [-3, -2, -1, 0, 1, 2, i32::MAX] {
            let raw = ua::DataValue::new(ua::Variant::scalar(ua::Int32::new(n))).cast();
            let result = VariableDefinition::decode(&ns, &type_array, &raw, Quality::GoodSeverity);
            assert!(matches!(
                result.data_type,
                Err(ReadError::ScalarTypeMismatch { expected: "NodeId" })
            ));
            assert_eq!(result.value_rank.unwrap().value, Some(n));
        }
        for wrong in [
            ua::Variant::scalar(ua::UInt32::new(1)),
            ua::Variant::array(ua::Array::from_slice(&[ua::Int32::new(-1)])),
        ] {
            let result = VariableDefinition::decode(
                &ns,
                &type_array,
                &ua::DataValue::new(wrong).cast(),
                Quality::GoodSeverity,
            );
            assert!(matches!(
                result.value_rank,
                Err(ReadError::ScalarTypeMismatch { expected: "Int32" })
            ));
        }
    }
}
