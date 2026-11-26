use opcua_kit::commissioning::{Attribute, AttributeValue, Evidence, Outcome, Report, Unit};
use std::io::{self, Write};

pub fn unsafe_terminal_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

pub fn safe(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if unsafe_terminal_char(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

fn unit_text(unit: &Unit) -> String {
    if unit.namespace_uri == "http://www.opcfoundation.org/UA/units/un/cefact" {
        let bytes = unit.unit_id.to_be_bytes();
        let start = bytes.iter().position(|&byte| byte != 0).unwrap_or(4);
        let code = &bytes[start..];
        if (1..=3).contains(&code.len()) && code.iter().all(u8::is_ascii_alphanumeric) {
            return match code {
                b"CEL" => "°C (CEL)".into(),
                b"FAH" => "°F (FAH)".into(),
                _ => format!("UN/CEFACT {}", String::from_utf8_lossy(code)),
            };
        }
    }
    format!("{} (unitId {})", safe(&unit.namespace_uri), unit.unit_id)
}

fn unavailable(evidence: Option<&Evidence<AttributeValue>>) -> String {
    let Some(e) = evidence else {
        return "no observation".into();
    };
    if matches!(e.value, Some(AttributeValue::EngineeringUnits(_))) {
        return format!(
            "server supplied no usable unit identity (status 0x{:08X})",
            e.status
        );
    }
    if e.status >> 30 == 0 && e.value.is_none() {
        return format!("no metadata value returned (status 0x{:08X})", e.status);
    }
    match e.status & 0xffff_0000 {
        0x8034_0000 => format!("BadNodeIdUnknown (0x{:08X})", e.status),
        0x801f_0000 => format!("BadUserAccessDenied (0x{:08X})", e.status),
        0x806f_0000 => format!("BadNoMatch (0x{:08X})", e.status),
        _ => format!("status 0x{:08X}", e.status),
    }
}

fn value(v: &AttributeValue) -> String {
    match v {
        AttributeValue::EngineeringUnits(unit) => unit_text(unit),
        AttributeValue::ValueRank(-1) => "scalar (-1)".into(),
        AttributeValue::ValueRank(rank) => rank.to_string(),
        AttributeValue::DataType(id) => {
            const TYPES: [&str; 26] = [
                "",
                "Boolean",
                "SByte",
                "Byte",
                "Int16",
                "UInt16",
                "Int32",
                "UInt32",
                "Int64",
                "UInt64",
                "Float",
                "Double",
                "String",
                "DateTime",
                "Guid",
                "ByteString",
                "XmlElement",
                "NodeId",
                "ExpandedNodeId",
                "StatusCode",
                "QualifiedName",
                "LocalizedText",
                "Structure",
                "DataValue",
                "BaseDataType",
                "DiagnosticInfo",
            ];
            if id.namespace() == "http://opcfoundation.org/UA/"
                && let Some(label) = id
                    .identifier()
                    .strip_prefix("i=")
                    .and_then(|s| s.parse::<usize>().ok())
                    .and_then(|i| TYPES.get(i))
            {
                return (*label).into();
            }
            format!("{} {}", safe(id.namespace()), safe(id.identifier()))
        }
    }
}

pub fn report(mut out: impl Write, r: &Report) -> io::Result<()> {
    if !r.baseline_provided {
        writeln!(out, "First inspection")?;
    }
    writeln!(
        out,
        "{} · {} · {}",
        safe(&r.device),
        safe(&r.application_uri),
        safe(&r.principal)
    )?;
    writeln!(
        out,
        "{} mismatched, {} unverified, {} matched",
        r.counts.mismatch, r.counts.unverified, r.counts.matched
    )?;
    for group in [Outcome::Mismatch, Outcome::Unverified] {
        for f in r.findings.iter().filter(|f| f.outcome == group) {
            let name = safe(&f.name);
            if group == Outcome::Mismatch {
                let observed = f
                    .after
                    .as_ref()
                    .and_then(|e| e.value.as_ref())
                    .expect("a confirmed mismatch has an observed value");
                let action = match f.attribute {
                    Attribute::EngineeringUnits => "Verify the device unit and gateway scaling.",
                    _ => "Review the gateway mapping.",
                };
                writeln!(
                    out,
                    "MISMATCH    {name}.{:?}  expected {}, observed {}. {action}",
                    f.attribute,
                    value(&f.expected),
                    value(observed)
                )?;
            } else {
                let reason = unavailable(f.after.as_ref());
                let action = match f.after.as_ref().and_then(|e| e.value.as_ref()) {
                    Some(AttributeValue::EngineeringUnits(_)) => {
                        "Check the device’s EngineeringUnits configuration."
                    }
                    _ => "Check the mapping and account visibility.",
                };
                writeln!(
                    out,
                    "UNVERIFIED  {name}.{:?}  {reason}. {action}",
                    f.attribute
                )?;
            }
        }
    }
    for f in r
        .findings
        .iter()
        .filter(|f| f.before_outcome == Some(Outcome::Mismatch) && f.outcome == Outcome::Matched)
    {
        writeln!(
            out,
            "RESOLVED    {}.{:?}  now matches {}.",
            safe(&f.name),
            f.attribute,
            value(&f.expected)
        )?;
    }
    Ok(())
}
