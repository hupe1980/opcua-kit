//! Built-in values, field masks and structured extension payloads from OPC UA Part 6.
use super::*;
use std::{
    any::Any,
    fmt,
    io::{Read, Write},
    sync::Arc,
};

/// A Rust type with one built-in scalar representation on the wire.
pub trait VariantType {
    /// Built-in type identifier used when declaring a variable or array element.
    fn variant_type_id() -> VariantScalarTypeId;
}

/// A homogeneous array in row-major order. Products of matrix dimensions must match the value count.
#[derive(Clone, Debug, PartialEq)]
pub struct Array {
    /// Built-in type carried by every element. Use Variant for heterogeneous arrays.
    pub value_type: VariantScalarTypeId,
    pub values: Vec<Variant>,
    /// Present for matrices with at least two nonzero dimensions.
    pub dimensions: Option<Vec<u32>>,
}

// The wire IDs and payload types are defined together so scalar and array codecs agree.
macro_rules! builtins {
    ($( $id:literal $kind:ident $ty:ty => $payload:ty ),+ $(,)?) => {
        /// Part 6 built-in IDs used in the Variant encoding mask.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum VariantScalarTypeId {
            $( $kind = $id, )+
            XmlElement = 16, Variant = 24,
            Reserved26 = 26, Reserved27 = 27, Reserved28 = 28, Reserved29 = 29, Reserved30 = 30, Reserved31 = 31,
        }

        /// A tagged OPC UA value. Arrays carry their element type even when empty.
        #[derive(Clone, Debug, PartialEq, Default)]
        pub enum Variant {
            #[default]
            Empty,
            $( $kind($payload), )+
            XmlElement(UAString),
            Array(Box<Array>),
            /// A typed array with a wire length of −1.
            NullArray(VariantScalarTypeId),
            /// A future built-in type in the reserved range 26–31, received as a ByteString.
            Reserved(VariantScalarTypeId, ByteString),
        }

        impl TryFrom<u8> for VariantScalarTypeId {
            type Error = StatusCode;
            fn try_from(id: u8) -> Result<Self, Self::Error> {
                match id {
                    $( $id => Ok(Self::$kind), )+
                    16 => Ok(Self::XmlElement),
                    24 => Ok(Self::Variant),
                    26 => Ok(Self::Reserved26),
                    27 => Ok(Self::Reserved27),
                    28 => Ok(Self::Reserved28),
                    29 => Ok(Self::Reserved29),
                    30 => Ok(Self::Reserved30),
                    31 => Ok(Self::Reserved31),
                    _ => Err(StatusCode::BadDecodingError),
                }
            }
        }

        impl Variant {
            /// Built-in ID for a non-null scalar. Arrays carry the element ID in their array value.
            pub fn scalar_type_id(&self) -> Option<VariantScalarTypeId> {
                match self {
                    $( Self::$kind(_) => Some(VariantScalarTypeId::$kind), )+
                    Self::XmlElement(_) => Some(VariantScalarTypeId::XmlElement),
                    Self::Reserved(kind, _) => Some(*kind),
                    Self::Empty | Self::Array(_) | Self::NullArray(_) => None,
                }
            }

            fn decode_element<R: Read+?Sized>(t: VariantScalarTypeId, r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
                match t {
                    $( VariantScalarTypeId::$kind => Ok(Self::$kind(<$payload>::decode(r, c)?)), )+
                    VariantScalarTypeId::XmlElement => Ok(Self::XmlElement(UAString::decode(r, c)?)),
                    VariantScalarTypeId::Variant => Self::decode(r, c),
                    _ => Ok(Self::Reserved(t, ByteString::decode(r, c)?)),
                }
            }

            fn encode_element<W: Write+?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
                match self {
                    $( Self::$kind(v) => v.encode(w, c), )+
                    Self::XmlElement(v) => v.encode(w, c),
                    _ => Err(StatusCode::BadEncodingError),
                }
            }
        }
        $(
            impl From<$ty> for Variant {
                fn from(v: $ty) -> Self { Self::$kind(v.into()) }
            }
            impl VariantType for $ty {
                fn variant_type_id() -> VariantScalarTypeId { VariantScalarTypeId::$kind }
            }
        )+
    }
}

builtins! {
    1 Boolean bool => bool, 2 SByte i8 => i8, 3 Byte u8 => u8, 4 Int16 i16 => i16,
    5 UInt16 u16 => u16, 6 Int32 i32 => i32, 7 UInt32 u32 => u32, 8 Int64 i64 => i64,
    9 UInt64 u64 => u64, 10 Float f32 => f32, 11 Double f64 => f64, 12 String UAString => UAString,
    13 DateTime DateTime => Box<DateTime>, 14 Guid Guid => Box<Guid>, 15 ByteString ByteString => ByteString,
    17 NodeId NodeId => Box<NodeId>, 18 ExpandedNodeId ExpandedNodeId => Box<ExpandedNodeId>,
    19 StatusCode StatusCode => StatusCode, 20 QualifiedName QualifiedName => Box<QualifiedName>,
    21 LocalizedText LocalizedText => Box<LocalizedText>, 22 ExtensionObject ExtensionObject => ExtensionObject,
    23 DataValue DataValue => Box<DataValue>, 25 DiagnosticInfo DiagnosticInfo => Box<DiagnosticInfo>,
}

impl From<String> for Variant {
    fn from(v: String) -> Self {
        Self::String(v.into())
    }
}
impl From<&str> for Variant {
    fn from(v: &str) -> Self {
        Self::String(v.into())
    }
}
impl VariantType for String {
    fn variant_type_id() -> VariantScalarTypeId {
        VariantScalarTypeId::String
    }
}
impl VariantType for &str {
    fn variant_type_id() -> VariantScalarTypeId {
        VariantScalarTypeId::String
    }
}
impl VariantType for Variant {
    fn variant_type_id() -> VariantScalarTypeId {
        VariantScalarTypeId::Variant
    }
}
impl<T: Into<Variant> + VariantType> From<Vec<T>> for Variant {
    fn from(items: Vec<T>) -> Self {
        Self::Array(Box::new(Array {
            value_type: T::variant_type_id(),
            values: items.into_iter().map(Into::into).collect(),
            dimensions: None,
        }))
    }
}

fn dimensions_match(dims: &[u32], count: usize) -> bool {
    dims.len() >= 2
        && dims.iter().all(|&d| d > 0 && d <= i32::MAX as u32)
        && dims
            .iter()
            .try_fold(1usize, |n, &d| n.checked_mul(d as usize))
            == Some(count)
}

impl BinaryEncodable for Variant {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        let c = &c.nested()?;
        match self {
            Self::Empty => 0u8.encode(w, c),
            Self::Reserved(_, _) => Err(StatusCode::BadEncodingError),
            Self::NullArray(kind) => {
                if *kind as u8 > 25 {
                    return Err(StatusCode::BadEncodingError);
                }
                (0x80 | *kind as u8).encode(w, c)?;
                (-1i32).encode(w, c)
            }
            Self::Array(a) => {
                if a.value_type as u8 > 25
                    || a.dimensions
                        .as_ref()
                        .is_some_and(|d| !dimensions_match(d, a.values.len()))
                {
                    return Err(StatusCode::BadEncodingError);
                }
                if a.values.len() > c.max_array_length {
                    return Err(StatusCode::BadEncodingLimitsExceeded);
                }
                let len = i32::try_from(a.values.len())
                    .map_err(|_| StatusCode::BadEncodingLimitsExceeded)?;
                let mask = if a.dimensions.is_some() { 0xc0 } else { 0x80 };
                (mask | a.value_type as u8).encode(w, c)?;
                len.encode(w, c)?;
                for value in &a.values {
                    if a.value_type == VariantScalarTypeId::Variant {
                        value.encode(w, c)?;
                    } else if value.scalar_type_id() == Some(a.value_type) {
                        value.encode_element(w, c)?;
                    } else {
                        return Err(StatusCode::BadEncodingError);
                    }
                }
                if a.dimensions.is_some() {
                    a.dimensions.encode(w, c)?;
                }
                Ok(())
            }
            value => {
                let kind = value.scalar_type_id().ok_or(StatusCode::BadEncodingError)?;
                (kind as u8).encode(w, c)?;
                value.encode_element(w, c)
            }
        }
    }
}

impl BinaryDecodable for Variant {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        let c = &c.nested()?;
        let mask = u8::decode(r, c)?;
        if mask == 0 {
            return Ok(Self::Empty);
        }
        let kind = VariantScalarTypeId::try_from(mask & 0x3f)?;
        if mask & 0x80 == 0 {
            if mask & 0x40 != 0 || kind == VariantScalarTypeId::Variant {
                return Err(StatusCode::BadDecodingError);
            }
            return Self::decode_element(kind, r, c);
        }
        let count = i32::decode(r, c)?;
        if count == -1 && mask & 0x40 == 0 {
            return Ok(Self::NullArray(kind));
        }
        let count = usize::try_from(count).map_err(|_| StatusCode::BadDecodingError)?;
        if count > c.max_array_length {
            return Err(StatusCode::BadEncodingLimitsExceeded);
        }
        c.charge::<Array>(1)?;
        let values = super::binary::decode_array(count, c, || Self::decode_element(kind, r, c))?;
        let dimensions = if mask & 0x40 != 0 {
            let dims = Option::<Vec<u32>>::decode(r, c)?.ok_or(StatusCode::BadDecodingError)?;
            if !dimensions_match(&dims, count) {
                return Err(StatusCode::BadDecodingError);
            }
            Some(dims)
        } else {
            None
        };
        Ok(Self::Array(Box::new(Array {
            value_type: kind,
            values,
            dimensions,
        })))
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
/// A value with independent source and server clocks, quality, and 10-picosecond increments.
pub struct DataValue {
    pub value: Option<Variant>,
    pub status: Option<StatusCode>,
    pub source_timestamp: Option<DateTime>,
    pub source_picoseconds: Option<u16>,
    pub server_timestamp: Option<DateTime>,
    pub server_picoseconds: Option<u16>,
}

impl DataValue {
    /// The effective status. An absent status field carries Good severity.
    pub fn status(&self) -> StatusCode {
        self.status.unwrap_or_default()
    }

    pub fn set_timestamps(
        &mut self,
        selection: TimestampsToReturn,
        source: DateTime,
        server: DateTime,
    ) {
        let has_source = matches!(
            selection,
            TimestampsToReturn::Source | TimestampsToReturn::Both
        );
        let has_server = matches!(
            selection,
            TimestampsToReturn::Server | TimestampsToReturn::Both
        );
        if !has_source || self.source_timestamp != Some(source) {
            self.source_picoseconds = None;
        }
        if !has_server || self.server_timestamp != Some(server) {
            self.server_picoseconds = None;
        }
        self.source_timestamp = has_source.then_some(source);
        self.server_timestamp = has_server.then_some(server);
    }
    pub fn null() -> Self {
        Self::default()
    }
    pub fn value_only<V: Into<Variant>>(value: V) -> Self {
        Self {
            value: Some(value.into()),
            ..Self::default()
        }
    }
    pub fn new_now<V: Into<Variant>>(value: V) -> Self {
        let now = DateTime::now();
        Self {
            source_timestamp: Some(now),
            server_timestamp: Some(now),
            ..Self::value_only(value)
        }
    }
}
macro_rules! data_from {
    ($($ty:ty),+) => {$(impl From<$ty> for DataValue {
        fn from(v:$ty)->Self {Self::value_only(v)}
    })+};
}
data_from!(
    Variant, bool, i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, String, UAString, ByteString
);

macro_rules! masked_structure {
    ($name:ident,$allowed:literal, $( $bit:literal $field:ident : $ty:ty ),+ $(,)?)=>{
        impl BinaryEncodable for $name {
            fn encode<W:Write+?Sized>(&self,w:&mut W,c:&Context<'_>)->Result<(),StatusCode>{
                let c=&c.nested()?;
                let mask=0u8 $(| if self.$field.is_some() {$bit} else {0})+;
                mask.encode(w,c)?;
                $(if let Some(value)=&self.$field {value.encode(w,c)?;})+
                Ok(())
            }
        }
        impl BinaryDecodable for $name {
            fn decode<R:Read+?Sized>(r:&mut R,c:&Context<'_>)->Result<Self,StatusCode>{
                let c=&c.nested()?;
                let mask=u8::decode(r,c)?;
                if mask & !$allowed !=0{return Err(StatusCode::BadDecodingError);}
                Ok(Self{$($field: if mask & $bit !=0 {Some(<$ty>::decode(r,c)?)}else{None}),+})
            }
        }
    }
}
masked_structure!(DataValue,0x3f,1 value:Variant,2 status:StatusCode,4 source_timestamp:DateTime,
    16 source_picoseconds:u16,8 server_timestamp:DateTime,32 server_picoseconds:u16);

/// Indexes refer to the string table carried in the ResponseHeader.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct DiagnosticInfo {
    pub symbolic_id: Option<i32>,
    pub namespace_uri: Option<i32>,
    pub locale: Option<i32>,
    pub localized_text: Option<i32>,
    pub additional_info: Option<UAString>,
    pub inner_status_code: Option<StatusCode>,
    pub inner_diagnostic_info: Option<Box<DiagnosticInfo>>,
}
masked_structure!(DiagnosticInfo,0x7f,1 symbolic_id:i32,2 namespace_uri:i32,8 locale:i32,
    4 localized_text:i32,16 additional_info:UAString,32 inner_status_code:StatusCode,
    64 inner_diagnostic_info:Box<DiagnosticInfo>);

trait ExtensionValue: fmt::Debug + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn equivalent(&self, other: &dyn ExtensionValue) -> bool;
    fn encode_body(&self, w: &mut dyn Write, c: &Context<'_>) -> Result<(), StatusCode>;
}
impl<T> ExtensionValue for T
where
    T: BinaryEncodable + fmt::Debug + PartialEq + Send + Sync + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn equivalent(&self, other: &dyn ExtensionValue) -> bool {
        other.as_any().downcast_ref::<T>() == Some(self)
    }
    fn encode_body(&self, w: &mut dyn Write, c: &Context<'_>) -> Result<(), StatusCode> {
        self.encode(w, c)
    }
}

#[derive(Clone, Debug)]
enum ExtensionBody {
    None,
    Known(Arc<dyn ExtensionValue>),
    Opaque { xml: bool, bytes: ByteString },
}

/// An encoded structure identified by its DataTypeEncoding NodeId. Unknown structures retain their original bytes.
#[derive(Clone, Debug)]
pub struct ExtensionObject {
    type_id: NodeId,
    body: ExtensionBody,
}
impl PartialEq for ExtensionObject {
    fn eq(&self, other: &Self) -> bool {
        self.type_id == other.type_id
            && match (&self.body, &other.body) {
                (ExtensionBody::None, ExtensionBody::None) => true,
                (ExtensionBody::Known(a), ExtensionBody::Known(b)) => a.equivalent(b.as_ref()),
                (
                    ExtensionBody::Opaque { xml: a, bytes: av },
                    ExtensionBody::Opaque { xml: b, bytes: bv },
                ) => a == b && av == bv,
                _ => false,
            }
    }
}
impl Default for ExtensionObject {
    fn default() -> Self {
        Self {
            type_id: NodeId::default(),
            body: ExtensionBody::None,
        }
    }
}
impl ExtensionObject {
    pub fn new<T>(value: T) -> Self
    where
        T: MessageInfo + BinaryEncodable + fmt::Debug + PartialEq + Send + Sync + 'static,
    {
        Self {
            type_id: NodeId::from(MessageInfo::type_id(&value) as u32),
            body: ExtensionBody::Known(Arc::new(value)),
        }
    }
    pub(super) fn decode_known<T>(bytes: &mut &[u8], c: &Context<'_>) -> Result<Self, StatusCode>
    where
        T: MessageInfo
            + BinaryEncodable
            + BinaryDecodable
            + fmt::Debug
            + PartialEq
            + Send
            + Sync
            + 'static,
    {
        // The type-erased Arc stores the decoded structure and its strong/weak counters.
        c.charge::<T>(1)?;
        c.charge::<usize>(2)?;
        Ok(Self::new(T::decode(bytes, c)?))
    }

    pub fn from_message<T>(value: T) -> Self
    where
        T: MessageInfo + BinaryEncodable + fmt::Debug + PartialEq + Send + Sync + 'static,
    {
        Self::new(value)
    }
    pub fn null() -> Self {
        Self::default()
    }
    pub fn is_null(&self) -> bool {
        self.type_id.is_null() && matches!(self.body, ExtensionBody::None)
    }
    /// Wrap host-encoded UA Binary for a vendor-defined DataTypeEncoding.
    pub fn from_binary(encoding_id: NodeId, bytes: ByteString) -> Self {
        Self {
            type_id: encoding_id,
            body: ExtensionBody::Opaque { xml: false, bytes },
        }
    }

    pub fn encoding_id(&self) -> &NodeId {
        &self.type_id
    }
    pub fn inner_as<T: 'static>(&self) -> Option<&T> {
        let ExtensionBody::Known(value) = &self.body else {
            return None;
        };
        value.as_any().downcast_ref()
    }
    /// Return the wire body of an unrecognized type and whether it uses XML encoding.
    pub fn opaque_body(&self) -> Option<(&ByteString, bool)> {
        let ExtensionBody::Opaque { xml, bytes } = &self.body else {
            return None;
        };
        Some((bytes, *xml))
    }
}

impl BinaryEncodable for ExtensionObject {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        self.type_id.encode(w, c)?;
        match &self.body {
            ExtensionBody::None => 0u8.encode(w, c),
            ExtensionBody::Known(value) => {
                let c = &c.nested()?;
                let mut body = super::binary::BoundedBuffer::new(
                    c.max_byte_string_length.min(i32::MAX as usize),
                );
                value.encode_body(&mut body, c)?;
                1u8.encode(w, c)?;
                super::binary::write_bytes(Some(&body.into_vec()), w, c)
            }
            ExtensionBody::Opaque { xml, bytes } => {
                (if *xml { 2u8 } else { 1u8 }).encode(w, c)?;
                bytes.encode(w, c)
            }
        }
    }
}
impl BinaryDecodable for ExtensionObject {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        let type_id = NodeId::decode(r, c)?;
        let tag = u8::decode(r, c)?;
        if tag == 0 {
            return Ok(Self {
                type_id,
                body: ExtensionBody::None,
            });
        }
        if tag != 1 && tag != 2 {
            return Err(StatusCode::BadDecodingError);
        }
        let bytes = ByteString::decode(r, c)?;
        if tag == 1
            && type_id.namespace == 0
            && let Identifier::Numeric(id) = type_id.identifier
            && let Some(body) = bytes.value.as_deref()
            && let Some(value) = super::decode_extension(id, body, &c.nested()?)?
        {
            return Ok(value);
        }
        Ok(Self {
            type_id,
            body: ExtensionBody::Opaque {
                xml: tag == 2,
                bytes,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_arrays_share_the_message_budget_and_fresh_messages_reset_it() {
        let input = Variant::from(vec![Variant::from(vec![1u8, 2]), Variant::from(vec![3u8])]);
        let mut encoded = Vec::new();
        let config = ContextOwned::default();
        input.encode(&mut encoded, &config.context()).unwrap();
        // Three Array boxes, two outer Variant entries and three inner entries.
        let required = 3 * size_of::<Array>() + 5 * size_of::<Variant>();
        let config = ContextOwned(DecodingOptions {
            max_allocation_bytes: required,
            ..Default::default()
        });
        let msg = config.context();
        assert_eq!(
            Variant::decode(&mut encoded.as_slice(), &msg).unwrap(),
            input
        );
        assert_eq!(
            Variant::decode(&mut encoded.as_slice(), &msg),
            Err(StatusCode::BadEncodingLimitsExceeded)
        );
        assert_eq!(
            Variant::decode(&mut encoded.as_slice(), &config.context()).unwrap(),
            input
        );
        let tight = ContextOwned(DecodingOptions {
            max_allocation_bytes: required - 1,
            ..Default::default()
        });
        assert_eq!(
            Variant::decode(&mut encoded.as_slice(), &tight.context()),
            Err(StatusCode::BadEncodingLimitsExceeded)
        );
    }

    #[test]
    fn extension_body_and_decoded_fields_both_consume_the_budget() {
        let info = EUInformation {
            namespace_uri: "urn:fixture".into(),
            ..Default::default()
        };
        let config = ContextOwned::default();
        let mut body = Vec::new();
        info.encode(&mut body, &config.context()).unwrap();
        let limit =
            body.len() + size_of::<EUInformation>() + 2 * size_of::<usize>() + "urn:fixture".len();
        let object = ExtensionObject::new(info);
        let mut encoded = Vec::new();
        object.encode(&mut encoded, &config.context()).unwrap();
        let config = ContextOwned(DecodingOptions {
            max_allocation_bytes: limit,
            ..Default::default()
        });
        assert_eq!(
            ExtensionObject::decode(&mut encoded.as_slice(), &config.context()).unwrap(),
            object
        );
        let tight = ContextOwned(DecodingOptions {
            max_allocation_bytes: limit - 1,
            ..Default::default()
        });
        assert_eq!(
            ExtensionObject::decode(&mut encoded.as_slice(), &tight.context()),
            Err(StatusCode::BadEncodingLimitsExceeded)
        );
    }

    #[test]
    fn timestamp_selection_preserves_absent_and_observed_picoseconds() {
        let now = DateTime::now();
        let mut value = DataValue {
            source_timestamp: Some(now),
            source_picoseconds: Some(17),
            ..Default::default()
        };
        value.set_timestamps(TimestampsToReturn::Both, now, now);
        assert_eq!(value.source_picoseconds, Some(17));
        assert_eq!(value.server_picoseconds, None);
        value.set_timestamps(TimestampsToReturn::Server, now, now);
        assert_eq!(value.source_timestamp, None);
        assert_eq!(value.source_picoseconds, None);
    }

    #[test]
    fn typed_nulls_and_variant_arrays_preserve_their_wire_types() {
        let c = ContextOwned::default();
        for bytes in [
            &[0x87, 255, 255, 255, 255][..],
            &[0x98, 2, 0, 0, 0, 0, 1, 1],
            &[0x87, 0, 0, 0, 0],
        ] {
            let v = Variant::decode(&mut &*bytes, &c.context()).unwrap();
            let mut roundtrip = Vec::new();
            v.encode(&mut roundtrip, &c.context()).unwrap();
            assert_eq!(roundtrip, bytes);
        }
        let future = Variant::decode(&mut &[28, 1, 0, 0, 0, 9][..], &c.context()).unwrap();
        assert!(matches!(
            future,
            Variant::Reserved(VariantScalarTypeId::Reserved28, _)
        ));
        assert!(future.encode(&mut Vec::new(), &c.context()).is_err());
    }

    #[test]
    fn unknown_extension_preserves_namespace_id_and_payload() {
        let c = ContextOwned::default();
        let object =
            ExtensionObject::from_binary(NodeId::new(3, "ValveEncoding"), vec![0, 1, 255].into());
        let mut encoded = Vec::new();
        object.encode(&mut encoded, &c.context()).unwrap();
        let decoded = ExtensionObject::decode(&mut encoded.as_slice(), &c.context()).unwrap();
        assert_eq!(decoded, object);
        assert_eq!(decoded.encoding_id(), &NodeId::new(3, "ValveEncoding"));
        let (bytes, xml) = decoded.opaque_body().unwrap();
        assert_eq!(bytes.as_ref(), [0, 1, 255]);
        assert!(!xml);
    }

    #[test]
    fn inconsistent_matrices_and_excessive_nesting_are_rejected() {
        let c = ContextOwned::default();
        let bytes = [0xc3, 1, 0, 0, 0, 1, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(
            Variant::decode(&mut &bytes[..], &c.context()),
            Err(StatusCode::BadDecodingError)
        );
        let nested = [0x40; 100];
        assert_eq!(
            DiagnosticInfo::decode(&mut &nested[..], &c.context()),
            Err(StatusCode::BadEncodingLimitsExceeded)
        );
    }
}
