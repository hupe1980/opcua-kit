//! Typed fixed-width OPC UA arrays and matrices.
use super::{
    Client, ReadError, Sample,
    sample::{FixedScalar, Quality},
};
use crate::NodeId;
use open62541::{DataType, ua};

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
    // SAFETY: the SDK owns the decoded Variant and arrays throughout this borrow.
    let raw = unsafe { value.as_ref() };
    if value.is_scalar() || raw.type_ != T::Wire::data_type() {
        return Err(ReadError::ArrayTypeMismatch);
    }
    // A null array and an empty array are distinct OPC UA values.
    if raw.arrayLength == 0 && raw.data.is_null() && raw.arrayDimensionsSize == 0 {
        return Ok(None);
    }
    let elements =
        unsafe { super::wire::slice(raw.data.cast::<T::Wire>(), raw.arrayLength, 65536) }
            .ok_or(ReadError::InvalidArray)?;
    let dims = unsafe { super::wire::slice(raw.arrayDimensions, raw.arrayDimensionsSize, 16) }
        .ok_or(ReadError::InvalidArray)?;
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
        values: elements.iter().map(T::element).collect(),
    }))
}

impl Client {
    /// Read a numeric or Boolean array, preserving status, both clocks, and matrix dimensions.
    /// Accepts at most 65,536 elements and 16 dimensions after SDK response decoding.
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
        let mut operand = ua::ReadValueId::init()
            .with_node_id(&metadata.namespaces.wire_node(node, 0)?)
            .with_attribute_id(&ua::AttributeId::VALUE);
        // SAFETY: operand owns the UA string until the request takes a deep copy.
        ua::String::new(&range)
            .expect("numeric range is ASCII")
            .move_into_raw(&mut unsafe { operand.as_mut() }.indexRange);
        let req = ua::ReadRequest::init()
            .with_timestamps_to_return(&ua::TimestampsToReturn::BOTH)
            .with_nodes_to_read(&[operand]);
        let response = self
            .guarded(&mut session, self.inner.service_request(req))
            .await?;
        let raw = unsafe { response.as_ref() };
        let [v] = unsafe { super::wire::slice(raw.results, raw.resultsSize, 1) }
            .ok_or(ReadError::InvalidServerMetadata)?
        else {
            return Err(ReadError::InvalidServerMetadata);
        };
        let sample = super::sample::decode_borrowed(ua::DataValue::raw_ref(v), decode::<T>)?;
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
        let mut v = ua::Variant::array(ua::Array::from_slice(&[
            ua::UInt32::new(12),
            ua::UInt32::new(45),
        ]));
        assert!(decode::<i32>(&v).is_err());
        assert_eq!(decode::<u32>(&v).unwrap().unwrap().dimensions, [2]);
        // SAFETY: assign temporary, live borrowed dimensions; restore before dropping the owner.
        let mut dims = [1, 2];
        unsafe {
            let r = v.as_mut();
            r.arrayDimensionsSize = 2;
            r.arrayDimensions = dims.as_mut_ptr();
        }
        let matrix = decode::<u32>(&v);
        unsafe {
            *v.as_mut().arrayDimensions = 2;
        }
        let invalid = decode::<u32>(&v);
        unsafe {
            let r = v.as_mut();
            r.arrayDimensionsSize = 0;
            r.arrayDimensions = std::ptr::null_mut();
        }
        assert_eq!(matrix.unwrap().unwrap().dimensions, [1, 2]);
        assert!(invalid.is_err());
        let empty = ua::Variant::array(ua::Array::<ua::UInt16>::new(0));
        assert!(decode::<u32>(&empty).is_err());
    }
}
