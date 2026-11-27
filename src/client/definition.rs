use base64::{Engine, engine::general_purpose::STANDARD};

use super::sample::Quality;
use super::{Client, DataValue, Namespaces, ReadError, ReadMetadata, ReadSession, Sample, ua};
use crate::NodeId;

pub use crate::ua::AttributeId as ReadAttribute;

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
            .get(usize::from(wire.namespace))
            .ok_or(ReadError::InvalidDataType)?;
        Self::node_in(namespace, wire)
    }

    pub(super) fn node_in(namespace: &str, wire: &ua::NodeId) -> Result<NodeId, ReadError> {
        let id = match &wire.identifier {
            ua::Identifier::Numeric(n) => format!("i={n}"),
            ua::Identifier::String(text) => {
                let text = text
                    .value()
                    .as_deref()
                    .filter(|text| text.len() <= 4 * 4096)
                    .ok_or(ReadError::InvalidDataType)?;
                format!("s={text}")
            }
            ua::Identifier::Guid(id) => format!("g={id}"),
            ua::Identifier::ByteString(bytes) => {
                let data = bytes
                    .value
                    .as_deref()
                    .filter(|bytes| bytes.len() <= 4096)
                    .ok_or(ReadError::InvalidDataType)?;
                format!("b={}", STANDARD.encode(data))
            }
        };
        NodeId::new(namespace, id).map_err(|_| ReadError::InvalidDataType)
    }
}

pub(super) fn decode_data_type(
    namespaces: &Namespaces,
    raw: &DataValue,
    quality: Quality,
) -> Result<Sample<NodeId>, ReadError> {
    Sample::decode_with(raw, quality, |v| {
        let ua::Variant::NodeId(wire) = v else {
            return Err(ReadError::ScalarTypeMismatch { expected: "NodeId" });
        };
        namespaces.stable_node(wire).map(Some)
    })
}

impl VariableDefinition {
    fn decode(
        namespaces: &Namespaces,
        data_type: &DataValue,
        value_rank: &DataValue,
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
    ) -> Result<Vec<DataValue>, ReadError> {
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

    fn namespaces() -> Namespaces {
        let entries = [
            "http://opcfoundation.org/UA/",
            "urn:site:signals",
            "urn:site:datatypes",
        ]
        .map(|s| ua::Variant::String(s.into()));
        crate::client::namespace_map(&entries).unwrap()
    }

    #[test]
    fn declared_node_ids_use_the_session_uri_and_preserve_all_four_identifier_forms() {
        let ns = namespaces();
        for (wire, expected) in [
            (ua::NodeId::new(2, u32::MAX), "i=4294967295"),
            (
                ua::NodeId::new(2, "Rate;ns=3;温度%2F"),
                "s=Rate;ns=3;温度%2F",
            ),
            (
                ua::NodeId::new(
                    2,
                    "12345678-90ab-cdef-0102-030405060708"
                        .parse::<ua::Guid>()
                        .unwrap(),
                ),
                "g=12345678-90ab-cdef-0102-030405060708",
            ),
            (
                ua::NodeId::new(2, ua::ByteString::from(vec![0xfb, 0xff, 0])),
                "b=+/8A",
            ),
        ] {
            let stable = ns.stable_node(&wire).unwrap();
            assert_eq!(stable.namespace(), "urn:site:datatypes");
            assert_eq!(stable.identifier(), expected);
        }
        for invalid in [
            ua::NodeId::from(0u32),
            ua::NodeId::new(3, 1u32),
            ua::NodeId::new(2, "x\ny"),
            ua::NodeId::new(2, "x".repeat(4097)),
            ua::NodeId::new(2, ua::ByteString::from(vec![1; 4097])),
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
        let at = ua::DateTime::from_unix_timestamp_nanos(100).unwrap();
        let data = ua::DataValue {
            source_timestamp: Some(at),
            source_picoseconds: Some(5),
            status: Some(ua::StatusCode::GoodClamped),
            ..ua::DataValue::value_only(ua::Variant::from(ua::NodeId::from(9u32)))
        };
        let rank = ua::DataValue::value_only(ua::Variant::Int32(-3));
        let valid = VariableDefinition::decode(&ns, &data, &rank, Quality::GoodSeverity);
        let ty = valid.data_type.unwrap();
        assert_eq!(
            ty.value.unwrap().namespace(),
            "http://opcfoundation.org/UA/"
        );
        assert_eq!(ty.status, ua::StatusCode::GoodClamped.bits());
        assert_eq!(ty.source_timestamp.unwrap().ten_picoseconds, Some(5));
        assert_eq!(valid.value_rank.unwrap().value, Some(-3));

        let wrong_type = ua::DataValue::value_only(ua::Variant::Int32(9));
        let partial = VariableDefinition::decode(&ns, &wrong_type, &rank, Quality::GoodSeverity);
        assert!(matches!(
            partial.data_type,
            Err(ReadError::ScalarTypeMismatch { expected: "NodeId" })
        ));
        assert_eq!(partial.value_rank.unwrap().value, Some(-3));
        let invalid_rank = ua::DataValue::value_only(ua::Variant::Int32(-4));
        let partial = VariableDefinition::decode(&ns, &data, &invalid_rank, Quality::GoodSeverity);
        assert_eq!(
            partial.data_type.unwrap().value.unwrap().identifier(),
            "i=9"
        );
        assert!(matches!(
            partial.value_rank,
            Err(ReadError::InvalidValueRank)
        ));
        let bad = ua::DataValue {
            status: Some(ua::StatusCode::BadAttributeIdInvalid),
            ..ua::DataValue::default()
        };
        let missing =
            VariableDefinition::decode(&ns, &bad, &ua::DataValue::default(), Quality::GoodSeverity);
        let missing_type = missing.data_type.unwrap();
        assert_eq!(
            missing_type.status,
            ua::StatusCode::BadAttributeIdInvalid.bits()
        );
        assert!(missing_type.value.is_none());
        assert!(missing.value_rank.unwrap().value.is_none());
    }

    #[test]
    fn rank_accepts_all_standard_categories_and_rejects_arrays_and_unsigned_integers() {
        let ns = namespaces();
        let type_array = ua::DataValue::value_only(ua::Variant::from(vec![ua::NodeId::from(9u32)]));
        for n in [-3, -2, -1, 0, 1, 2, i32::MAX] {
            let raw = ua::DataValue::value_only(ua::Variant::Int32(n));
            let result = VariableDefinition::decode(&ns, &type_array, &raw, Quality::GoodSeverity);
            assert!(matches!(
                result.data_type,
                Err(ReadError::ScalarTypeMismatch { expected: "NodeId" })
            ));
            assert_eq!(result.value_rank.unwrap().value, Some(n));
        }
        for wrong in [ua::Variant::UInt32(1), ua::Variant::from(vec![-1i32])] {
            let result = VariableDefinition::decode(
                &ns,
                &type_array,
                &ua::DataValue::value_only(wrong),
                Quality::GoodSeverity,
            );
            assert!(matches!(
                result.value_rank,
                Err(ReadError::ScalarTypeMismatch { expected: "Int32" })
            ));
        }
    }
}
