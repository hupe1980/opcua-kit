//! Typed fixed-width OPC UA arrays and matrices.
use super::ua;
use super::{
    Client, ReadError, Sample,
    sample::{FixedScalar, Quality},
};
use crate::NodeId;

/// Values in OPC UA row-major order. A missing dimensions field on the wire is
/// represented by one dimension equal to the number of elements.
#[derive(Clone, Debug, PartialEq)]
pub struct ArrayValue<T> {
    /// Extents from outermost to innermost dimension.
    pub dimensions: Vec<u32>,
    /// Elements in the same order as the wire.
    pub values: Vec<T>,
}

fn decode<T: FixedScalar>(value: &ua::Variant) -> Result<Option<ArrayValue<T>>, ReadError> {
    if let ua::Variant::NullArray(kind) = value {
        return if *kind == T::TYPE {
            Ok(None)
        } else {
            Err(ReadError::ArrayTypeMismatch)
        };
    }
    let ua::Variant::Array(array) = value else {
        return Err(ReadError::ArrayTypeMismatch);
    };
    if array.value_type != T::TYPE {
        return Err(ReadError::ArrayTypeMismatch);
    }
    let elements = &array.values;
    let dims = array.dimensions.as_deref().unwrap_or_default();
    if elements.len() > 65536 || dims.len() > 16 {
        return Err(ReadError::InvalidArray);
    }
    if !dims.is_empty()
        && dims
            .iter()
            .try_fold(1usize, |n, &d| n.checked_mul(d as usize))
            != Some(elements.len())
    {
        return Err(ReadError::InvalidArray);
    }
    Ok(Some(ArrayValue {
        dimensions: if dims.is_empty() {
            vec![elements.len() as u32]
        } else {
            dims.to_vec()
        },
        values: elements
            .iter()
            .map(|v| T::decode(v)?.ok_or(ReadError::ArrayTypeMismatch))
            .collect::<Result<_, _>>()?,
    }))
}

impl Client {
    /// Read a numeric or Boolean array, preserving status, both clocks, and matrix dimensions.
    /// Accepts at most 65,536 elements and 16 dimensions after response decoding.
    pub async fn read_array<T: FixedScalar>(
        &self,
        node: &NodeId,
    ) -> Result<Sample<ArrayValue<T>>, ReadError> {
        let raw = self.read(node).await?;
        Sample::decode_with(&raw, Quality::GoodSeverity, decode::<T>)
    }
    /// Read a rectangular section using OPC UA NumericRange. Each inclusive range
    /// selects one dimension; at most 65,536 elements and 16 dimensions are requested.
    pub async fn read_array_range<T: FixedScalar>(
        &self,
        node: &NodeId,
        ranges: &[std::ops::RangeInclusive<u32>],
    ) -> Result<Sample<ArrayValue<T>>, ReadError> {
        let range = range_text(ranges)?;
        let (mut session, metadata) = self.read_session().await?;
        let operand = ua::ReadValueId {
            node_id: metadata.namespaces.wire_node(node, 0)?,
            attribute_id: ua::AttributeId::Value as u32,
            index_range: range.into(),
            ..Default::default()
        };
        let request = ua::ReadRequest {
            timestamps_to_return: ua::TimestampsToReturn::Both,
            nodes_to_read: Some(vec![operand]),
            ..Default::default()
        };
        let response = self
            .guarded(&mut session, self.inner.request(request))
            .await?;
        let Some([value]) = response.results.as_deref() else {
            session.interrupted = true;
            return Err(ReadError::InvalidServerMetadata);
        };
        let sample = super::sample::decode_borrowed(value, decode::<T>)?;
        if let Some(a) = &sample.value
            && (a.dimensions.len() != ranges.len()
                || a.dimensions.iter().zip(ranges).any(|(&size, r)| {
                    u64::from(size) > u64::from(*r.end()) - u64::from(*r.start()) + 1
                }))
        {
            return Err(ReadError::InvalidArray);
        }
        Ok(sample)
    }
}

fn range_text(ranges: &[std::ops::RangeInclusive<u32>]) -> Result<String, ReadError> {
    if ranges.is_empty() || ranges.len() > 16 {
        return Err(ReadError::InvalidArray);
    }
    let mut count = 1u64;
    let mut fields = Vec::with_capacity(ranges.len());
    for range in ranges {
        let (&start, &end) = (range.start(), range.end());
        if start > end {
            return Err(ReadError::InvalidArray);
        }
        count *= u64::from(end) - u64::from(start) + 1;
        if count > 65536 {
            return Err(ReadError::InvalidArray);
        }
        fields.push(if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        });
    }
    Ok(fields.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_ranges_are_bounded_before_service_io() {
        assert_eq!(range_text(&[42..=42, 1..=3]).unwrap(), "42,1:3");
        assert!(range_text(std::slice::from_ref(&(0..=65535))).is_ok());
        assert!(range_text(std::slice::from_ref(&(0..=65536))).is_err());
        assert!(range_text(std::slice::from_ref(&(0..=u32::MAX))).is_err());
        assert!(range_text(&[0..=255, 0..=256]).is_err());
        assert!(range_text(&vec![0..=0; 17]).is_err());
        assert!(range_text(&[]).is_err());
    }
    #[test]
    fn array_decoder_checks_type_before_copy_and_preserves_dimensions() {
        let make = |dimensions| {
            ua::Variant::Array(Box::new(ua::Array {
                value_type: ua::VariantScalarTypeId::UInt32,
                values: vec![12u32.into(), 45u32.into()],
                dimensions,
            }))
        };
        assert!(decode::<i32>(&make(None)).is_err());
        assert_eq!(decode::<u32>(&make(None)).unwrap().unwrap().dimensions, [2]);
        let matrix = decode::<u32>(&make(Some(vec![1, 2]))).unwrap().unwrap();
        assert_eq!(matrix.dimensions, [1, 2]);
        assert_eq!(matrix.values, [12, 45]);
        assert!(decode::<u32>(&make(Some(vec![2, 2]))).is_err());
    }
}
