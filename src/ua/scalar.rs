use super::{BinaryDecodable, BinaryEncodable, Context, ObjectId, binary};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fmt,
    io::{Read, Write},
    str::FromStr,
};

/// Full 32-bit OPC UA status, including quality and information bits.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Hash)]
pub struct StatusCode(pub(super) u32);
impl StatusCode {
    pub fn bits(self) -> u32 {
        self.0
    }
    pub fn is_good(self) -> bool {
        self.0 >> 30 == 0
    }
    pub fn is_bad(self) -> bool {
        self.0 >> 31 != 0
    }
}
impl From<u32> for StatusCode {
    fn from(n: u32) -> Self {
        Self(n)
    }
}
impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:08X})", self.0),
            None => write!(f, "0x{:08X}", self.0),
        }
    }
}
impl std::error::Error for StatusCode {}
impl From<std::io::Error> for StatusCode {
    fn from(_: std::io::Error) -> Self {
        Self::BadDecodingError
    }
}

macro_rules! wrapped {
    ($ty:ident, $base:ty) => {
        impl BinaryEncodable for $ty {
            fn encode<W: Write + ?Sized>(
                &self,
                w: &mut W,
                c: &Context<'_>,
            ) -> Result<(), StatusCode> {
                self.0.encode(w, c)
            }
        }
        impl BinaryDecodable for $ty {
            fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
                Ok(Self(<$base>::decode(r, c)?))
            }
        }
    };
}
wrapped!(StatusCode, u32);

/// Number of 100 ns ticks since 1601-01-01 UTC, as transmitted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DateTime(i64);
wrapped!(DateTime, i64);
impl From<i64> for DateTime {
    fn from(ticks: i64) -> Self {
        Self(ticks)
    }
}
impl DateTime {
    pub fn null() -> Self {
        Self::default()
    }
    /// 100 ns intervals between the UA epoch in 1601 and the Unix epoch.
    const UNIX_EPOCH_TICKS: i128 = 116_444_736_000_000_000;

    /// Construct a wire DateTime when the instant fits exactly on a 100 ns tick.
    pub fn from_unix_timestamp_nanos(nanos: i128) -> Option<Self> {
        if nanos % 100 != 0 {
            return None;
        }
        i64::try_from(nanos / 100 + Self::UNIX_EPOCH_TICKS)
            .ok()
            .map(Self)
    }

    /// Exact timestamp in Unix nanoseconds, including values outside the application calendar.
    pub fn unix_timestamp_nanos(self) -> i128 {
        (i128::from(self.0) - Self::UNIX_EPOCH_TICKS) * 100
    }

    pub fn ticks(self) -> i64 {
        self.0
    }
    pub fn endtimes() -> Self {
        Self(i64::MAX)
    }
    pub fn now() -> Self {
        let ns = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        Self((ns / 100 + Self::UNIX_EPOCH_TICKS) as i64)
    }
}

/// A nullable OPC UA UTF-8 string. Use `value` to distinguish absent and empty text.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct UAString(Option<String>);
impl UAString {
    pub fn null() -> Self {
        Self(None)
    }
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }
    pub fn value(&self) -> &Option<String> {
        &self.0
    }
    pub fn is_null(&self) -> bool {
        self.0.is_none()
    }
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}
impl AsRef<str> for UAString {
    fn as_ref(&self) -> &str {
        self.0.as_deref().unwrap_or_default()
    }
}
impl From<String> for UAString {
    fn from(s: String) -> Self {
        Self(Some(s))
    }
}
impl From<&str> for UAString {
    fn from(s: &str) -> Self {
        s.to_owned().into()
    }
}
impl fmt::Display for UAString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}
impl BinaryEncodable for UAString {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        binary::write_bytes(self.0.as_deref().map(str::as_bytes), w, c)
    }
}
impl BinaryDecodable for UAString {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        Ok(Self(
            binary::read_bytes(r, c, c.max_string_length)?
                .map(String::from_utf8)
                .transpose()
                .map_err(|_| StatusCode::BadDecodingError)?,
        ))
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
/// Nullable opaque bytes. An empty byte string has a present, zero-length value.
pub struct ByteString {
    pub value: Option<Vec<u8>>,
}
impl ByteString {
    pub fn null() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
    pub fn is_null_or_empty(&self) -> bool {
        self.is_empty()
    }
}
impl AsRef<[u8]> for ByteString {
    fn as_ref(&self) -> &[u8] {
        self.value.as_deref().unwrap_or_default()
    }
}
impl From<Vec<u8>> for ByteString {
    fn from(v: Vec<u8>) -> Self {
        Self { value: Some(v) }
    }
}
impl From<&[u8]> for ByteString {
    fn from(v: &[u8]) -> Self {
        v.to_vec().into()
    }
}
impl BinaryEncodable for ByteString {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        binary::write_bytes(self.value.as_deref(), w, c)
    }
}
impl BinaryDecodable for ByteString {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        Ok(Self {
            value: binary::read_bytes(r, c, c.max_byte_string_length)?,
        })
    }
}
/// A UUID encoded with UA Binary field byte order.
pub type Guid = uuid::Uuid;
impl BinaryEncodable for Guid {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, _: &Context<'_>) -> Result<(), StatusCode> {
        w.write_all(&self.to_bytes_le())
            .map_err(|_| StatusCode::BadEncodingError)
    }
}
impl BinaryDecodable for Guid {
    fn decode<R: Read + ?Sized>(r: &mut R, _: &Context<'_>) -> Result<Self, StatusCode> {
        let mut bytes = [0; 16];
        r.read_exact(&mut bytes)?;
        Ok(Self::from_bytes_le(bytes))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Identifier {
    Numeric(u32),
    String(UAString),
    Guid(Guid),
    ByteString(ByteString),
}
impl From<u32> for Identifier {
    fn from(n: u32) -> Self {
        Self::Numeric(n)
    }
}
impl From<String> for Identifier {
    fn from(s: String) -> Self {
        Self::String(s.into())
    }
}
impl From<&str> for Identifier {
    fn from(s: &str) -> Self {
        Self::String(s.into())
    }
}
impl From<Guid> for Identifier {
    fn from(v: Guid) -> Self {
        Self::Guid(v)
    }
}
impl From<ByteString> for Identifier {
    fn from(v: ByteString) -> Self {
        Self::ByteString(v)
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
/// A session-local namespace index and a numeric, string, UUID or opaque identifier.
pub struct NodeId {
    pub namespace: u16,
    pub identifier: Identifier,
}
impl NodeId {
    pub fn new(namespace: u16, id: impl Into<Identifier>) -> Self {
        Self {
            namespace,
            identifier: id.into(),
        }
    }
    pub fn null() -> Self {
        Self::new(0, 0)
    }
    pub fn is_null(&self) -> bool {
        self.namespace == 0 && self.identifier == Identifier::Numeric(0)
    }
    pub fn as_u32(&self) -> Option<u32> {
        match self.identifier {
            Identifier::Numeric(n) => Some(n),
            _ => None,
        }
    }
    pub fn as_object_id(&self) -> Result<ObjectId, StatusCode> {
        match self {
            Self {
                namespace: 0,
                identifier: Identifier::Numeric(n),
            } => (*n).try_into(),
            _ => Err(StatusCode::BadServiceUnsupported),
        }
    }
    fn write_tagged<W: Write + ?Sized>(
        &self,
        w: &mut W,
        c: &Context<'_>,
        flags: u8,
    ) -> Result<(), StatusCode> {
        match &self.identifier {
            Identifier::Numeric(n) if self.namespace == 0 && *n <= 255 => {
                flags.encode(w, c)?;
                (*n as u8).encode(w, c)
            }
            Identifier::Numeric(n) if self.namespace <= 255 && *n <= 65535 => {
                (flags | 1).encode(w, c)?;
                (self.namespace as u8).encode(w, c)?;
                (*n as u16).encode(w, c)
            }
            id => {
                let tag = match id {
                    Identifier::Numeric(_) => 2,
                    Identifier::String(_) => 3,
                    Identifier::Guid(_) => 4,
                    Identifier::ByteString(_) => 5,
                };
                (flags | tag).encode(w, c)?;
                self.namespace.encode(w, c)?;
                match id {
                    Identifier::Numeric(n) => n.encode(w, c),
                    Identifier::String(s) => s.encode(w, c),
                    Identifier::Guid(id) => id.encode(w, c),
                    Identifier::ByteString(bytes) => bytes.encode(w, c),
                }
            }
        }
    }
    fn read_tagged<R: Read + ?Sized>(
        r: &mut R,
        c: &Context<'_>,
        tag: u8,
    ) -> Result<Self, StatusCode> {
        match tag {
            0 => Ok(Self::new(0, u32::from(u8::decode(r, c)?))),
            1 => Ok(Self::new(
                u16::from(u8::decode(r, c)?),
                u32::from(u16::decode(r, c)?),
            )),
            2..=5 => {
                let namespace = u16::decode(r, c)?;
                let identifier = match tag {
                    2 => Identifier::Numeric(u32::decode(r, c)?),
                    3 => Identifier::String(UAString::decode(r, c)?),
                    4 => Identifier::Guid(Guid::decode(r, c)?),
                    _ => Identifier::ByteString(ByteString::decode(r, c)?),
                };
                Ok(Self {
                    namespace,
                    identifier,
                })
            }
            _ => Err(StatusCode::BadDecodingError),
        }
    }
}
impl Default for NodeId {
    fn default() -> Self {
        Self::null()
    }
}
impl From<u32> for NodeId {
    fn from(n: u32) -> Self {
        Self::new(0, n)
    }
}
impl From<ObjectId> for NodeId {
    fn from(id: ObjectId) -> Self {
        Self::new(0, id as u32)
    }
}
impl FromStr for NodeId {
    type Err = StatusCode;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = StatusCode::BadNodeIdInvalid;
        let (ns, s) = if let Some(body) = s.strip_prefix("ns=") {
            let (ns, id) = body.split_once(';').ok_or(bad)?;
            (ns.parse().map_err(|_| bad)?, id)
        } else {
            (0, s)
        };
        let (kind, value) = s.split_once('=').ok_or(bad)?;
        let id = match kind {
            "i" => Identifier::Numeric(value.parse().map_err(|_| bad)?),
            "s" => value.into(),
            "g" => Identifier::Guid(value.parse().map_err(|_| bad)?),
            "b" => Identifier::ByteString(STANDARD.decode(value).map_err(|_| bad)?.into()),
            _ => return Err(bad),
        };
        Ok(Self::new(ns, id))
    }
}
impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.namespace != 0 {
            write!(f, "ns={};", self.namespace)?;
        }
        match &self.identifier {
            Identifier::Numeric(n) => write!(f, "i={n}"),
            Identifier::String(s) => write!(f, "s={s}"),
            Identifier::Guid(id) => write!(f, "g={id}"),
            Identifier::ByteString(bytes) => write!(f, "b={}", STANDARD.encode(bytes.as_ref())),
        }
    }
}
impl BinaryEncodable for NodeId {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        self.write_tagged(w, c, 0)
    }
}
impl BinaryDecodable for NodeId {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        let tag = u8::decode(r, c)?;
        Self::read_tagged(r, c, tag)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpandedNodeId {
    pub node_id: NodeId,
    pub namespace_uri: UAString,
    pub server_index: u32,
}
impl ExpandedNodeId {
    pub fn null() -> Self {
        Self::default()
    }
}
impl From<NodeId> for ExpandedNodeId {
    fn from(node_id: NodeId) -> Self {
        Self {
            node_id,
            ..Default::default()
        }
    }
}
impl BinaryEncodable for ExpandedNodeId {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        let uri = !self.namespace_uri.is_empty();
        let server = self.server_index != 0;
        self.node_id
            .write_tagged(w, c, (u8::from(uri) << 7) | (u8::from(server) << 6))?;
        if uri {
            self.namespace_uri.encode(w, c)?;
        }
        if server {
            self.server_index.encode(w, c)?;
        }
        Ok(())
    }
}
impl BinaryDecodable for ExpandedNodeId {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        let tag = u8::decode(r, c)?;
        let node_id = NodeId::read_tagged(r, c, tag & 63)?;
        let namespace_uri = if tag & 128 != 0 {
            UAString::decode(r, c)?
        } else {
            UAString::null()
        };
        let server_index = if tag & 64 != 0 { u32::decode(r, c)? } else { 0 };
        Ok(Self {
            node_id,
            namespace_uri,
            server_index,
        })
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QualifiedName {
    pub namespace_index: u16,
    pub name: UAString,
}
impl QualifiedName {
    pub fn null() -> Self {
        Self::default()
    }
    pub fn new(ns: u16, name: impl Into<UAString>) -> Self {
        Self {
            namespace_index: ns,
            name: name.into(),
        }
    }
    pub fn is_null(&self) -> bool {
        self.namespace_index == 0 && self.name.is_empty()
    }
}
impl BinaryEncodable for QualifiedName {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        self.namespace_index.encode(w, c)?;
        self.name.encode(w, c)
    }
}
impl BinaryDecodable for QualifiedName {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        Ok(Self::new(u16::decode(r, c)?, UAString::decode(r, c)?))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalizedText {
    pub locale: UAString,
    pub text: UAString,
}
impl From<&str> for LocalizedText {
    fn from(text: &str) -> Self {
        Self {
            locale: UAString::null(),
            text: text.into(),
        }
    }
}
impl LocalizedText {
    pub fn new(locale: &str, text: &str) -> Self {
        Self {
            locale: locale.into(),
            text: text.into(),
        }
    }
    pub fn null() -> Self {
        Self::default()
    }
}
impl BinaryEncodable for LocalizedText {
    fn encode<W: Write + ?Sized>(&self, w: &mut W, c: &Context<'_>) -> Result<(), StatusCode> {
        let mask = u8::from(!self.locale.is_null()) | (u8::from(!self.text.is_null()) << 1);
        mask.encode(w, c)?;
        if mask & 1 != 0 {
            self.locale.encode(w, c)?;
        }
        if mask & 2 != 0 {
            self.text.encode(w, c)?;
        }
        Ok(())
    }
}
impl BinaryDecodable for LocalizedText {
    fn decode<R: Read + ?Sized>(r: &mut R, c: &Context<'_>) -> Result<Self, StatusCode> {
        let mask = u8::decode(r, c)?;
        if mask > 3 {
            return Err(StatusCode::BadDecodingError);
        }
        Ok(Self {
            locale: if mask & 1 != 0 {
                UAString::decode(r, c)?
            } else {
                UAString::null()
            },
            text: if mask & 2 != 0 {
                UAString::decode(r, c)?
            } else {
                UAString::null()
            },
        })
    }
}
/// Attribute numbers from OPC UA Part 3, Table 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AttributeId {
    NodeId = 1,
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
    Value,
    DataType,
    ValueRank,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ua::ContextOwned;

    #[test]
    fn node_id_forms_use_part_six_layout_and_leave_the_next_field_unread() {
        let context = ContextOwned::default();
        let ctx = context.context();
        let cases = [
            ("i=255", vec![0, 255]),
            ("ns=1;i=512", vec![1, 1, 0, 2]),
            ("ns=256;i=1", vec![2, 0, 1, 1, 0, 0, 0]),
            ("ns=2;s=x;y", vec![3, 2, 0, 3, 0, 0, 0, b'x', b';', b'y']),
            ("ns=2;b=+/8A", vec![5, 2, 0, 3, 0, 0, 0, 251, 255, 0]),
            (
                "ns=3;g=12345678-90ab-cdef-0102-030405060708",
                vec![
                    4, 3, 0, 0x78, 0x56, 0x34, 0x12, 0xab, 0x90, 0xef, 0xcd, 1, 2, 3, 4, 5, 6, 7, 8,
                ],
            ),
        ];
        for (text, bytes) in cases {
            let node: NodeId = text.parse().unwrap();
            let mut body = Vec::new();
            node.encode(&mut body, &ctx).unwrap();
            assert_eq!(body, bytes);
            body.push(0xab);
            let mut input = body.as_slice();
            assert_eq!(NodeId::decode(&mut input, &ctx).unwrap().to_string(), text);
            assert_eq!(input, [0xab]);
        }
    }

    #[test]
    fn distinguishes_an_absent_comment_from_an_explicit_empty_translation() {
        let context = ContextOwned::default();
        let ctx = context.context();
        for (text, bytes) in [
            (LocalizedText::null(), vec![0]),
            (LocalizedText::new("", ""), vec![3, 0, 0, 0, 0, 0, 0, 0, 0]),
        ] {
            let mut out = Vec::new();
            text.encode(&mut out, &ctx).unwrap();
            assert_eq!(out, bytes);
            assert_eq!(
                LocalizedText::decode(&mut out.as_slice(), &ctx).unwrap(),
                text
            );
        }
        assert!(LocalizedText::decode(&mut [0x80].as_slice(), &ctx).is_err());
    }

    #[test]
    fn status_names_preserve_qualified_and_unknown_statuses() {
        assert_eq!(
            StatusCode::from(StatusCode::BadNodeIdUnknown.bits() | 0x480).name(),
            Some("BadNodeIdUnknown")
        );
        assert_eq!(StatusCode::from(0xafab0000).name(), None);
    }
}
