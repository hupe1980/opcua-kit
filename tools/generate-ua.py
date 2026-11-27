"""Regenerate the Rust service layouts from a checkout of the pinned UA-Nodeset Schema directory."""

import csv
import hashlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REVISION = "ed0b821f6a6f1f0c440c442ed95a9146ae8b7f8d"
SCHEMA = Path(sys.argv[1])
for filename, checksum in {
    "NodeIds.csv": "beb46640d1ba5281eee470282fd31bff8f654f20a465948f0d237ecab6880a92",
    "Opc.Ua.Types.bsd": "a75e05f4c3865e32c8414fe08b3078bae6718e090fbc2134d44170335d1537f1",
    "StatusCode.csv": "69912ec2b15955d9264ea5bc5c511c90c524ec59c7fe55d70e952d35777503cc",
}.items():
    if hashlib.sha256((SCHEMA / filename).read_bytes()).hexdigest() != checksum:
        sys.exit(f"{filename} differs from UA-Nodeset {REVISION}")
OUTPUT = Path(__file__).resolve().parents[1] / "src/ua/generated.rs"
SERVICES = [
    "FindServers",
    "GetEndpoints",
    "OpenSecureChannel",
    "CloseSecureChannel",
    "CreateSession",
    "ActivateSession",
    "CloseSession",
    "Read",
    "Write",
    "Browse",
    "BrowseNext",
    "TranslateBrowsePathsToNodeIds",
    "Call",
    "HistoryRead",
    "CreateSubscription",
    "CreateMonitoredItems",
    "DeleteMonitoredItems",
    "DeleteSubscriptions",
    "Publish",
    "Republish",
    "ModifySubscription",
    "SetPublishingMode",
    "SetMonitoringMode",
    "ModifyMonitoredItems",
]
EXTENSIONS = [
    "AnonymousIdentityToken",
    "UserNameIdentityToken",
    "EUInformation",
    "ReadRawModifiedDetails",
    "HistoryData",
    "DataChangeNotification",
    "EventNotificationList",
    "StatusChangeNotification",
    "EventFilter",
    "EventFilterResult",
    "DataChangeFilter",
    "Argument",
    "BuildInfo",
    "ServerStatusDataType",
]
DENIED = [
    "AddNodes",
    "DeleteNodes",
    "AddReferences",
    "DeleteReferences",
    "HistoryUpdate",
]
BUILTINS = {
    "StatusCode",
    "ExtensionObject",
    "NodeId",
    "ExpandedNodeId",
    "LocalizedText",
    "QualifiedName",
    "DiagnosticInfo",
    "DataValue",
    "Variant",
    "Guid",
}
PRIMITIVES = {
    "Boolean": "bool",
    "SByte": "i8",
    "Byte": "u8",
    "Int16": "i16",
    "UInt16": "u16",
    "Int32": "i32",
    "UInt32": "u32",
    "Int64": "i64",
    "UInt64": "u64",
    "Float": "f32",
    "Double": "f64",
    "String": "UAString",
    "ByteString": "ByteString",
    "DateTime": "DateTime",
}
NS = "{http://opcfoundation.org/BinarySchema/}"
schema = {e.get("Name"): e for e in ET.parse(SCHEMA / "Opc.Ua.Types.bsd").getroot()}
ids = {
    name: int(number)
    for name, number, *_ in csv.reader((SCHEMA / "NodeIds.csv").open())
}
structures, enums = {}, {}


def snake(name):
    return re.sub(
        r"([a-z0-9])([A-Z])", r"\1_\2", re.sub(r"([A-Z])([A-Z][a-z])", r"\1_\2", name)
    ).lower()


def visit(name):
    if name in BUILTINS or name in PRIMITIVES or name in structures or name in enums:
        return
    e = schema[name]
    if e.tag == NS + "EnumeratedType":
        enums[name] = [
            (v.get("Name"), int(v.get("Value")))
            for v in e.findall(NS + "EnumeratedValue")
        ]
        return
    fields = structures[name] = []
    for f in e.findall(NS + "Field"):
        field = f.get("Name")
        if field.startswith("NoOf"):
            continue
        assert not f.get("SwitchField"), (name, field)
        t = f.get("TypeName").split(":")[1]
        visit(t)
        rust = PRIMITIVES.get(t, t)
        fields.append(
            (snake(field), f"Option<Vec<{rust}>>" if f.get("LengthField") else rust)
        )


for operation in SERVICES:
    for suffix in ("Request", "Response"):
        visit(operation + suffix)
for name in EXTENSIONS + ["ServiceFault"]:
    visit(name)

with OUTPUT.open("w") as out:

    def emit(line=""):
        print(line, file=out)

    emit(f"// Generated from OPC Foundation UA-Nodeset {REVISION}.")
    emit("// Regenerate with tools/generate-ua.py. See LICENSE-OPC-Foundation.")
    emit("use super::*;")
    for name, values in sorted(enums.items()):
        emit(f"ua_enum!({name} {{")
        for k, v in values:
            emit(f"    {k} = {v},")
        emit("});")
    for name, fields in sorted(structures.items()):
        emit(f"ua_struct!({name} {{")
        for field, t in fields:
            emit(f"    {field}: {t},")
        emit("});")
    objects = sorted(set(structures).union(n + "Request" for n in DENIED))
    emit("object_ids! {")
    for name in objects:
        key = name + "_Encoding_DefaultBinary"
        emit(f"    {key} = {ids[key]},")
    emit("}")
    for name in sorted(structures):
        emit(f"message!({name}, {name}_Encoding_DefaultBinary);")
    emit(
        "pub(super) fn decode_extension(id: u32, mut bytes: &[u8], ctx: &Context<'_>) -> Result<Option<ExtensionObject>, StatusCode> {"
    )
    emit("    let object = match id {")
    for name in sorted(EXTENSIONS):
        emit(
            f"        {ids[name + '_Encoding_DefaultBinary']} => ExtensionObject::decode_known::<{name}>(&mut bytes, ctx)?,"
        )
    emit("        _ => return Ok(None),\n    };")
    emit(
        "    if !bytes.is_empty() { return Err(StatusCode::BadDecodingError); }\n    Ok(Some(object))\n}"
    )
    emit("#[allow(non_upper_case_globals)]\nimpl StatusCode {")
    statuses = list(csv.reader((SCHEMA / "StatusCode.csv").open()))
    for name, code, description in statuses:
        emit(f"    /// {description}\n    pub const {name}: Self = Self({code});")
    emit("    /// Standard symbolic name, ignoring the information bits.")
    emit("    pub fn name(self) -> Option<&'static str> {")
    emit("        match self.bits() & 0xffff0000 {")
    for name, code, _ in statuses:
        if int(code, 16) & 0xFFFF == 0:
            emit(f'            {code} => Some("{name}"),')
    emit("            _ => None,\n        }\n    }")
    emit("}")

subprocess.run(["rustfmt", "--edition", "2024", str(OUTPUT)], check=True)
