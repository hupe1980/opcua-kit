/// A programmatic OPC UA engineering unit, identified by its authority and signed ID.
///
/// Localized display names and descriptions do not participate in comparisons.
/// See [Part 8, EUInformation](https://reference.opcfoundation.org/specs/OPC-10000-8/5.6.4.3).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "commissioning",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct EngineeringUnit {
    /// Case-sensitive namespace URI for the organization defining the unit.
    pub namespace_uri: String,
    /// Identifier assigned by that organization. A server can report -1 for an unknown unit.
    pub unit_id: i32,
}

impl EngineeringUnit {
    /// Whether the server supplied both parts of a usable programmatic identity.
    pub fn is_identified(&self) -> bool {
        self.unit_id != -1
            && !self.namespace_uri.trim().is_empty()
            && !self.namespace_uri.chars().any(char::is_control)
    }

    #[cfg(feature = "cems")]
    /// Whether this is the UN/CEFACT watt-hour unit (common code WHR).
    pub fn is_watt_hour(&self) -> bool {
        self.namespace_uri == "http://www.opcfoundation.org/UA/units/un/cefact"
            && self.unit_id == 0x574852
    }
}
