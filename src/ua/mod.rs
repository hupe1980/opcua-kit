//! UA Binary values and service structures for the protocol roles provided by this crate.
//!
//! Use a session to translate numeric namespace indexes before persisting node identifiers.
//! Use the typed read API for application values or inspect raw Variants for heterogeneous batches.
//! A raw DateTime preserves the original signed ticks. A nullable UAString preserves
//! the distinction between missing text and an explicitly empty string.
//!
//! ```
//! use opcua_kit::ua::{BinaryDecodable, BinaryEncodable, ContextOwned, NodeId};
//!
//! let context = ContextOwned::default();
//! let wire_id = NodeId::new(2, "Temperature");
//! let mut bytes = Vec::new();
//! wire_id.encode(&mut bytes, &context.context())?;
//! let received = NodeId::decode(&mut bytes.as_slice(), &context.context())?;
//! assert_eq!(received, wire_id);
//! # Ok::<(), opcua_kit::ua::StatusCode>(())
//! ```

mod binary;
pub(crate) use binary::BoundedBuffer;
pub use binary::{BinaryDecodable, BinaryEncodable, Context, ContextOwned, DecodingOptions};
mod scalar;
pub use scalar::*;
mod value;
pub use value::*;

/// Binary service or structure identifier in the standard namespace.
pub trait MessageInfo {
    fn type_id(&self) -> ObjectId;
}

macro_rules! ua_enum {
    ($name:ident { $first:ident = $one:expr, $($member:ident = $number:expr,)* }) => {
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        #[repr(i32)]
        pub enum $name {
            #[default]
            $first = $one,
            $($member = $number,)*
        }
        impl BinaryEncodable for $name {
            fn encode<W: std::io::Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
                (*self as i32).encode(w, c)
            }
        }
        impl BinaryDecodable for $name {
            fn decode<R: std::io::Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
                match i32::decode(r, c)? {
                    $one => Ok(Self::$first),
                    $($number => Ok(Self::$member),)*
                    _ => Err(StatusCode::BadDecodingError),
                }
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }
    };
}
macro_rules! ua_struct {
    ($name:ident { $($field:ident : $ty:ty,)* }) => {
        #[derive(Clone, Debug, Default, PartialEq)]
        pub struct $name { $(pub $field: $ty,)* }
        impl BinaryEncodable for $name {
            fn encode<W: std::io::Write + ?Sized>(&self,w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
                $(self.$field.encode(w, c)?;)*
                Ok(())
            }
        }
        impl BinaryDecodable for $name {
            fn decode<R: std::io::Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
                Ok(Self { $($field: <$ty>::decode(r, c)?,)* })
            }
        }
    };
}
macro_rules! object_ids {
    ($($id:ident = $n:expr,)*) => {
        #[allow(non_camel_case_types)]
        #[repr(u32)]
        #[derive(Copy,Clone,Debug,PartialEq,Eq)]
        pub enum ObjectId { $($id=$n,)* }
        impl TryFrom<u32> for ObjectId {
            type Error = StatusCode;
            fn try_from(id: u32) -> Result<Self, StatusCode> {
                match id {
                    $($n => Ok(Self::$id),)*
                    _ => Err(StatusCode::BadServiceUnsupported),
                }
            }
        }
    };
}
macro_rules! message {
    ($name:ident, $id:ident) => {
        impl MessageInfo for $name {
            fn type_id(&self) -> ObjectId {
                ObjectId::$id
            }
        }
    };
}
mod generated;
use generated::decode_extension;
pub use generated::*;

/// Opaque server-issued cursor for BrowseNext and HistoryRead.
pub type ContinuationPoint = ByteString;

impl ResponseHeader {
    pub fn new_good(request_handle: u32) -> Self {
        Self::new_service_result(request_handle, StatusCode::Good)
    }
    pub fn new_service_result(request_handle: u32, service_result: StatusCode) -> Self {
        Self {
            timestamp: DateTime::now(),
            request_handle,
            service_result,
            ..Default::default()
        }
    }
}
