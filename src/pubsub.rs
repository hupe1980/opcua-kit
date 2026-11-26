//! A bounded OPC UA Part 14 UADP wire profile for host-owned transports.
//!
//! One unsigned NetworkMessage carries one Variant key frame, the UInt16 PublisherId,
//! WriterGroupId, DataSetWriterId and DataSetMessage sequence number. Match these
//! identifiers and an agreed field layout at the receiver. They identify a stream
//! but do not authenticate its sender. The host supplies transport security, sequence
//! tracking and metadata. No I/O occurs in the codec.
use alloc::vec::Vec;
use core::{error::Error, fmt, num::NonZeroU16};

/// Maximum scalar fields per frame. Each encoded field takes at most nine bytes.
pub const MAX_FIELDS: usize = 64;
const HEADER_BYTES: usize = 15;

/// Built-in scalar Variant types supported by this profile.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Field {
    Boolean(bool),
    SByte(i8),
    Byte(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Float(f32),
    Double(f64),
}

/// Unauthenticated routing information carried in a NetworkMessage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataSetId {
    /// PublisherId shared by the publisher’s writer groups.
    pub publisher: NonZeroU16,
    /// WriterGroupId within the publisher.
    pub writer_group: NonZeroU16,
    /// DataSetWriterId assigned to this dataset writer.
    pub writer: NonZeroU16,
}

/// Complete key frame. Field order follows the publisher's configured dataset.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyFrame {
    /// Routing identifiers to match against the subscriber configuration.
    pub id: DataSetId,
    /// DataSetMessage sequence, incremented modulo 65536 by the publisher.
    pub sequence: u16,
    /// One to [`MAX_FIELDS`] scalar values in the agreed field order.
    pub fields: Vec<Field>,
}

/// Invalid wire data or a UADP profile outside the supported subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Unsupported,
    FieldCount,
    NullId,
    Length,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "unsupported UADP header, field encoding or Variant type",
            Self::FieldCount => "expected 1 to 64 UADP key-frame fields",
            Self::NullId => "publisher, writer group and dataset writer IDs must be nonzero",
            Self::Length => "invalid UADP message length",
        })
    }
}
impl Error for FrameError {}

impl KeyFrame {
    /// Encode header and fields as a single UADP NetworkMessage.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if !(1..=MAX_FIELDS).contains(&self.fields.len()) {
            return Err(FrameError::FieldCount);
        }
        let mut out = Vec::with_capacity(HEADER_BYTES + self.fields.len() * 9);
        out.extend([0xf1, 0x01]); // Version 1, UInt16 publisher, group and payload headers.
        out.extend(self.id.publisher.get().to_le_bytes());
        out.push(1); // Group contains only WriterGroupId.
        out.extend(self.id.writer_group.get().to_le_bytes());
        out.push(1); // Exactly one DataSetMessage.
        out.extend(self.id.writer.get().to_le_bytes());
        out.push(9); // Valid Variant key frame with sequence number.
        out.extend(self.sequence.to_le_bytes());
        out.extend((self.fields.len() as u16).to_le_bytes());
        for &field in &self.fields {
            field.encode_into(&mut out);
        }
        Ok(out)
    }

    /// Decode a complete datagram. Unsupported flags, signed messages, unknown
    /// types, truncated fields and trailing data fail as a whole.
    pub fn decode(mut input: &[u8]) -> Result<Self, FrameError> {
        if input.len() > HEADER_BYTES + MAX_FIELDS * 9 {
            return Err(FrameError::Length);
        }
        if take::<2>(&mut input)? != [0xf1, 0x01] {
            return Err(FrameError::Unsupported);
        }
        let publisher =
            NonZeroU16::new(u16::from_le_bytes(take(&mut input)?)).ok_or(FrameError::NullId)?;
        expect_byte(&mut input, 1)?;
        let writer_group =
            NonZeroU16::new(u16::from_le_bytes(take(&mut input)?)).ok_or(FrameError::NullId)?;
        expect_byte(&mut input, 1)?;
        let writer =
            NonZeroU16::new(u16::from_le_bytes(take(&mut input)?)).ok_or(FrameError::NullId)?;
        expect_byte(&mut input, 9)?;
        let sequence = u16::from_le_bytes(take(&mut input)?);
        let count = usize::from(u16::from_le_bytes(take(&mut input)?));
        if !(1..=MAX_FIELDS).contains(&count) {
            return Err(FrameError::FieldCount);
        }
        let fields = (0..count)
            .map(|_| Field::decode_from(&mut input))
            .collect::<Result<_, _>>()?;
        if !input.is_empty() {
            return Err(FrameError::Length);
        }
        Ok(Self {
            id: DataSetId {
                publisher,
                writer_group,
                writer,
            },
            sequence,
            fields,
        })
    }
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], FrameError> {
    let (value, rest) = input.split_first_chunk::<N>().ok_or(FrameError::Length)?;
    *input = rest;
    Ok(*value)
}

fn expect_byte(input: &mut &[u8], byte: u8) -> Result<(), FrameError> {
    if take::<1>(input)? == [byte] {
        Ok(())
    } else {
        Err(FrameError::Unsupported)
    }
}

impl Field {
    fn encode_into(self, out: &mut Vec<u8>) {
        fn append<const N: usize>(out: &mut Vec<u8>, kind: u8, bytes: [u8; N]) {
            out.push(kind);
            out.extend(bytes);
        }
        match self {
            Self::Boolean(v) => append(out, 1, [u8::from(v)]),
            Self::SByte(v) => append(out, 2, v.to_le_bytes()),
            Self::Byte(v) => append(out, 3, [v]),
            Self::Int16(v) => append(out, 4, v.to_le_bytes()),
            Self::UInt16(v) => append(out, 5, v.to_le_bytes()),
            Self::Int32(v) => append(out, 6, v.to_le_bytes()),
            Self::UInt32(v) => append(out, 7, v.to_le_bytes()),
            Self::Int64(v) => append(out, 8, v.to_le_bytes()),
            Self::UInt64(v) => append(out, 9, v.to_le_bytes()),
            Self::Float(v) => append(out, 10, v.to_le_bytes()),
            Self::Double(v) => append(out, 11, v.to_le_bytes()),
        }
    }

    fn decode_from(input: &mut &[u8]) -> Result<Self, FrameError> {
        Ok(match take::<1>(input)?[0] {
            1 => Self::Boolean(take::<1>(input)?[0] != 0),
            2 => Self::SByte(i8::from_le_bytes(take(input)?)),
            3 => Self::Byte(take::<1>(input)?[0]),
            4 => Self::Int16(i16::from_le_bytes(take(input)?)),
            5 => Self::UInt16(u16::from_le_bytes(take(input)?)),
            6 => Self::Int32(i32::from_le_bytes(take(input)?)),
            7 => Self::UInt32(u32::from_le_bytes(take(input)?)),
            8 => Self::Int64(i64::from_le_bytes(take(input)?)),
            9 => Self::UInt64(u64::from_le_bytes(take(input)?)),
            10 => Self::Float(f32::from_le_bytes(take(input)?)),
            11 => Self::Double(f64::from_le_bytes(take(input)?)),
            _ => return Err(FrameError::Unsupported),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn frame() -> KeyFrame {
        KeyFrame {
            id: DataSetId {
                publisher: NonZeroU16::new(0x1234).unwrap(),
                writer_group: NonZeroU16::new(9).unwrap(),
                writer: NonZeroU16::new(2).unwrap(),
            },
            sequence: 65535,
            fields: vec![
                Field::Boolean(true),
                Field::SByte(-128),
                Field::Byte(255),
                Field::Int16(i16::MIN),
                Field::UInt16(u16::MAX),
                Field::Int32(i32::MIN),
                Field::UInt32(u32::MAX),
                Field::Int64(i64::MIN),
                Field::UInt64(u64::MAX),
                Field::Float(f32::from_bits(1)),
                Field::Double(f64::from_bits(1)),
            ],
        }
    }

    #[test]
    fn preserves_numeric_fields_and_rejects_incomplete_or_wrong_profile() {
        let frame = frame();
        let bytes = frame.encode().unwrap();
        assert_eq!(KeyFrame::decode(&bytes), Ok(frame));
        for i in 0..bytes.len() {
            assert!(KeyFrame::decode(&bytes[..i]).is_err());
        }
        let mut damaged = bytes.clone();
        damaged.push(0);
        assert_eq!(KeyFrame::decode(&damaged), Err(FrameError::Length));
        for (index, value) in [(0, 0xf2), (1, 0x11), (4, 2), (7, 2), (10, 2), (15, 0x80)] {
            let mut damaged = bytes.clone();
            damaged[index] = value;
            assert_eq!(KeyFrame::decode(&damaged), Err(FrameError::Unsupported));
        }
        for range in [2..4, 5..7, 8..10] {
            let mut damaged = bytes.clone();
            damaged[range].fill(0);
            assert_eq!(KeyFrame::decode(&damaged), Err(FrameError::NullId));
        }
    }

    #[test]
    fn bounds_fields_and_bytes_before_allocating() {
        let mut frame = frame();
        frame.fields = vec![Field::UInt64(7); MAX_FIELDS];
        let mut data = frame.encode().unwrap();
        assert_eq!(data.len(), HEADER_BYTES + MAX_FIELDS * 9);
        assert_eq!(KeyFrame::decode(&data), Ok(frame.clone()));
        data.push(9);
        assert_eq!(KeyFrame::decode(&data), Err(FrameError::Length));
        data.pop();
        data[13..15].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(KeyFrame::decode(&data), Err(FrameError::FieldCount));
        frame.fields.push(Field::Boolean(false));
        assert_eq!(frame.encode(), Err(FrameError::FieldCount));
        frame.fields.clear();
        assert_eq!(frame.encode(), Err(FrameError::FieldCount));
    }
}
