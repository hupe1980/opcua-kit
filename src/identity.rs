use base64::{Engine, engine::general_purpose::STANDARD};
use uuid::Uuid;

/// An invalid namespace URI or OPC UA identifier.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NodeIdError(&'static str);

impl std::fmt::Display for NodeIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for NodeIdError {}

#[cfg(feature = "commissioning")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireNode {
    namespace: String,
    id: String,
}

#[cfg(feature = "commissioning")]
impl TryFrom<WireNode> for NodeId {
    type Error = NodeIdError;
    fn try_from(raw: WireNode) -> Result<Self, Self::Error> {
        Self::new(raw.namespace, raw.id)
    }
}

/// A namespace URI and a typed OPC UA identifier. Namespace indexes are session-local.
///
/// Numeric identifiers use decimal, GUIDs use hyphenated hex, and opaque identifiers
/// use RFC 4648 standard Base64. String identifier contents are case-sensitive.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "commissioning",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "WireNode")
)]
pub struct NodeId {
    /// Case-sensitive namespace URI.
    namespace: String,
    /// Identifier prefixed with `i=`, `s=`, `g=`, or `b=`.
    id: String,
}

impl NodeId {
    /// Create a canonical node identity from a namespace URI and a typed OPC UA identifier.
    ///
    /// For example, `NodeId::new("urn:plant:line-1", "i=00042")` stores `i=42`.
    pub fn new(namespace: impl Into<String>, id: impl Into<String>) -> Result<Self, NodeIdError> {
        let mut node = Self {
            namespace: namespace.into(),
            id: id.into(),
        };
        node.normalize()?;
        Ok(node)
    }

    /// The case-sensitive namespace URI, stable across sessions.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The canonical identifier, including its OPC UA type prefix.
    pub fn identifier(&self) -> &str {
        &self.id
    }

    fn normalize(&mut self) -> Result<(), NodeIdError> {
        // Part 3 §8.2 permits up to 4096 characters for strings or 4096 bytes
        // for opaque identifiers. The four null representations only apply in ns=0.
        if self.namespace.trim().is_empty() || self.namespace.chars().any(char::is_control) {
            return Err(NodeIdError(
                "expected a nonempty namespace URI without controls",
            ));
        }
        let (kind, text) = self
            .id
            .split_once('=')
            .ok_or(NodeIdError("expected an i=, s=, g= or b= identifier"))?;
        let standard = self.namespace == "http://opcfoundation.org/UA/";
        let null = match kind {
            "i" => {
                if !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(NodeIdError("numeric identifier must be unsigned decimal"));
                }
                let number = text
                    .parse::<u32>()
                    .map_err(|_| NodeIdError("numeric identifier is outside UInt32"))?;
                self.id = format!("i={number}");
                number == 0
            }
            "s" => {
                if text.chars().count() > 4096 || text.chars().any(char::is_control) {
                    return Err(NodeIdError(
                        "string identifier exceeds 4096 characters or contains a control",
                    ));
                }
                text.is_empty()
            }
            "g" => {
                let guid =
                    Uuid::try_parse(text).map_err(|_| NodeIdError("invalid hyphenated GUID"))?;
                if text.len() != 36 {
                    return Err(NodeIdError("GUID must use its hyphenated representation"));
                }
                self.id = format!("g={guid}");
                guid.is_nil()
            }
            "b" => {
                if text.len() > 5464 {
                    return Err(NodeIdError("opaque identifier exceeds 4096 bytes"));
                }
                let bytes = STANDARD.decode(text).map_err(|_| {
                    NodeIdError("opaque identifier must use standard padded base64")
                })?;
                if bytes.len() > 4096 {
                    return Err(NodeIdError("opaque identifier exceeds 4096 bytes"));
                }
                bytes.is_empty()
            }
            _ => return Err(NodeIdError("expected an i=, s=, g= or b= identifier")),
        };
        if standard && null {
            return Err(NodeIdError(
                "null NodeId cannot identify a node or data type",
            ));
        }
        Ok(())
    }
}
