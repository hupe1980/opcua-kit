"""Pinned asyncua backend. The Rust CLI validates and sends the contract on stdin."""

import argparse
import asyncio
import base64
import io
import ipaddress
import json
import logging
import os
import stat
import sys
import time
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from urllib.parse import urlsplit
from uuid import UUID

from asyncua import Client, ua
from asyncua.common.utils import ServiceError
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua.crypto.uacrypto import CertProperties, load_private_key
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from asyncua.ua.ua_binary import Primitives, nodeid_from_binary, struct_from_binary
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

MAX_BYTES = 4 * 1024 * 1024
BATCH_SIZE = 64
UA_NAMESPACE = "http://opcfoundation.org/UA/"
METER_UNITS = {
    "namespaceUri": "http://www.opcfoundation.org/UA/units/un/cefact",
    "unitId": int.from_bytes(b"WHR", "big"),
}
METER_TYPES = {
    "i=7": ua.VariantType.UInt32,
    "i=9": ua.VariantType.UInt64,
    "i=10": ua.VariantType.Float,
    "i=11": ua.VariantType.Double,
}


class PreflightExit(IntEnum):
    """Private process protocol shared with capture.rs."""

    ENDPOINT = 64
    CONTRACT = 65
    SECURITY_OPTIONS = 66
    CREDENTIAL_FILE = 67
    VALIDITY = 68
    IDENTITY = 69
    POLICY = 70
    PRIVATE_KEY = 71
    KEY_MISMATCH = 72
    PREPARATION = 73


class MeterExit(IntEnum):
    """Additional private refusal codes for the explicit meter reader."""

    METADATA = 74
    VALUE = 75
    SERVICE = 76


class CaptureError(Exception):
    """A diagnostic suitable for an operator, with no peer-supplied text."""

    def __init__(self, message, preflight_exit=PreflightExit.PREPARATION):
        super().__init__(message)
        self.preflight_exit = preflight_exit


def validate_endpoint(endpoint, insecure):
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in endpoint):
        raise CaptureError(
            "endpoint contains whitespace or control characters", PreflightExit.ENDPOINT
        )
    try:
        url = urlsplit(endpoint)
        port = url.port
        host = url.hostname
    except ValueError:
        raise CaptureError(
            "invalid endpoint host or port", PreflightExit.ENDPOINT
        ) from None
    if (
        url.scheme != "opc.tcp"
        or not host
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or "%" in host
        or "\\" in url.netloc
    ):
        raise CaptureError(
            "provide an opc.tcp endpoint without credentials, query or fragment",
            PreflightExit.ENDPOINT,
        )
    if not port:
        raise CaptureError(
            "specify the endpoint TCP port (usually 4840)", PreflightExit.ENDPOINT
        )
    if insecure:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise CaptureError(
                "--insecure-loopback requires a literal loopback IP address",
                PreflightExit.ENDPOINT,
            )
    return host


def read_pki_file(path):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CaptureError(
                "certificate and key inputs must be regular files",
                PreflightExit.CREDENTIAL_FILE,
            )
        data = stream.read(65537)
    if len(data) > 65536:
        raise CaptureError(
            "certificate or private key exceeds the 64 KiB limit",
            PreflightExit.CREDENTIAL_FILE,
        )
    return data


def load_application_certificate(path, role):
    try:
        data = read_pki_file(path)
        if data.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
    except (ValueError, OSError):
        raise CaptureError(
            f"cannot load {role} certificate as PEM or DER",
            PreflightExit.CREDENTIAL_FILE,
        ) from None

    now = datetime.now(UTC)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise CaptureError(
            f"{role} certificate expired or is not yet valid", PreflightExit.VALIDITY
        )
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        raise CaptureError(
            f"{role} certificate is missing a subject alternative name",
            PreflightExit.IDENTITY,
        ) from None
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1 or not uris[0]:
        raise CaptureError(
            f"{role} certificate must contain one application URI",
            PreflightExit.IDENTITY,
        )
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey) or not (
        2048 <= public_key.key_size <= 4096
    ):
        raise CaptureError(
            f"{role} certificate needs a 2048–4096-bit RSA key for Basic256Sha256",
            PreflightExit.POLICY,
        )
    return cert, san, uris[0]


def validate_pin(san, certificate_uri, host, application_uri):
    if certificate_uri != application_uri:
        raise CaptureError(
            "pinned server certificate application URI differs from the contract",
            PreflightExit.IDENTITY,
        )
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        hostname = host.encode("idna").decode("ascii").rstrip(".").lower()
        matches = any(
            name.rstrip(".").lower() == hostname
            for name in san.get_values_for_type(x509.DNSName)
        )
    else:
        matches = ip in san.get_values_for_type(x509.IPAddress)
    if not matches:
        raise CaptureError(
            "endpoint host differs from the pinned server certificate SAN",
            PreflightExit.IDENTITY,
        )


async def validate_certificate_usage(cert, description, role):
    flags = CertificateValidatorOptions
    peer = flags.PEER_SERVER if role == "server" else flags.PEER_CLIENT
    validator = CertificateValidator(flags.KEY_USAGE | flags.EXT_KEY_USAGE | peer)
    try:
        await validator(cert, description)
    except ServiceError as exc:
        raise CaptureError(
            f"{role} certificate key usage is unsuitable (0x{exc.code:08X}); check KeyUsage and ExtendedKeyUsage",
            PreflightExit.POLICY,
        ) from None


async def configure_security(client, args, host, application_uri):
    provided = [args.server_cert, args.client_cert, args.client_key]
    if args.insecure_loopback:
        if any(provided):
            raise CaptureError(
                "choose one security mode; certificate options conflict with --insecure-loopback",
                PreflightExit.SECURITY_OPTIONS,
            )
        return
    if not all(provided):
        raise CaptureError(
            "secure capture needs --server-cert, --client-cert and --client-key",
            PreflightExit.SECURITY_OPTIONS,
        )
    server_cert, san, uri = load_application_certificate(args.server_cert, "server")
    validate_pin(san, uri, host, application_uri)
    await validate_certificate_usage(
        server_cert,
        ua.ApplicationDescription(ApplicationType=ua.ApplicationType.Server),
        "server",
    )
    client_cert, _, client.application_uri = load_application_certificate(
        args.client_cert, "client"
    )
    await validate_certificate_usage(
        client_cert,
        ua.ApplicationDescription(ApplicationType=ua.ApplicationType.Client),
        "client",
    )
    pin = server_cert.public_bytes(serialization.Encoding.DER)

    async def verify_session(cert, description):
        if cert.public_bytes(serialization.Encoding.DER) != pin:
            raise CaptureError("server certificate differs from the approved pin")
        if description.ApplicationUri != application_uri:
            raise CaptureError(
                "secured endpoint application URI differs from the contract"
            )

        await validate_certificate_usage(cert, description, "server")

    try:
        key = read_pki_file(args.client_key)
        key_format = "pem" if key.lstrip().startswith(b"-----BEGIN") else "der"
        private_key = await load_private_key(key, extension=key_format)
    except (ValueError, TypeError, OSError, UnsupportedAlgorithm):
        raise CaptureError(
            "cannot load client key; supply an unencrypted PEM or DER private key",
            PreflightExit.PRIVATE_KEY,
        ) from None
    if private_key.public_key() != client_cert.public_key():
        raise CaptureError(
            "client private key does not match the client certificate",
            PreflightExit.KEY_MISMATCH,
        )
    client.certificate_validator = verify_session
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        client_cert.public_bytes(serialization.Encoding.DER),
        CertProperties(key, key_format),
        server_certificate=pin,
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )


def node_id(identifier, index):
    kind, body = identifier[:2], identifier[2:]
    if kind == "i=":
        return ua.NodeId(int(body), index, ua.NodeIdType.Numeric)
    if kind == "s=":
        return ua.NodeId(body, index, ua.NodeIdType.String)
    if kind == "g=":
        return ua.NodeId(UUID(body), index, ua.NodeIdType.Guid)
    if kind == "b=":
        return ua.NodeId(
            base64.b64decode(body, validate=True), index, ua.NodeIdType.ByteString
        )
    raise CaptureError("unknown NodeId identifier kind")


def qualified_id(node, namespaces):
    if not isinstance(node, ua.NodeId) or not (
        0 <= node.NamespaceIndex < len(namespaces)
    ):
        raise CaptureError("server returned an unresolved namespace index")
    kind = node.NodeIdType
    value = node.Identifier
    if kind in (ua.NodeIdType.String, ua.NodeIdType.ByteString) and len(value) > 4096:
        raise CaptureError(
            "server returned a node identifier above the OPC UA length limit"
        )
    if kind in (ua.NodeIdType.Numeric, ua.NodeIdType.TwoByte, ua.NodeIdType.FourByte):
        ident = f"i={value}"
    elif kind == ua.NodeIdType.String:
        if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
            raise CaptureError(
                "server returned a string NodeId with control characters"
            )
        ident = "s=" + value
    elif kind == ua.NodeIdType.Guid:
        ident = f"g={value}"
    elif kind == ua.NodeIdType.ByteString:
        ident = "b=" + base64.b64encode(value).decode("ascii")
    else:
        raise CaptureError("server returned an unsupported NodeId")
    return {"namespace": namespaces[node.NamespaceIndex], "id": ident}


async def bounded_results(requests, execute):
    offset, limit = 0, BATCH_SIZE
    while offset < len(requests):
        batch = requests[offset : offset + limit]
        try:
            results = await execute([item for _, item in batch])
        except ua.UaStatusCodeError as exc:
            if exc.code == ua.StatusCodes.BadTooManyOperations and len(batch) > 1:
                limit = max(1, len(batch) // 2)
                continue
            raise
        if len(results) != len(batch):
            raise CaptureError("server returned the wrong number of operation results")
        for item, result in zip(batch, results, strict=True):
            yield item, result
        offset += len(batch)


def attribute_evidence(result, attr, namespaces):
    raw = result.StatusCode.value
    evidence = {"status": raw}
    if raw >> 30 != 0 or result.Value is None:
        return evidence
    if result.Value.VariantType == ua.VariantType.Null and not result.Value.is_array:
        return evidence

    expected_type = {
        ua.AttributeIds.DataType: ua.VariantType.NodeId,
        ua.AttributeIds.ValueRank: ua.VariantType.Int32,
        ua.AttributeIds.Value: ua.VariantType.ExtensionObject,
    }[attr]
    if result.Value.VariantType != expected_type or result.Value.is_array:
        raise CaptureError(
            "server returned the wrong wire type for the requested attribute"
        )
    value = result.Value.Value
    if attr == ua.AttributeIds.DataType:
        if isinstance(value, ua.ExpandedNodeId):
            raise CaptureError("server returned an expanded DataType NodeId")
        evidence["value"] = qualified_id(value, namespaces)
    elif attr == ua.AttributeIds.ValueRank:
        if type(value) is not int or not -3 <= value <= 2**31 - 1:
            raise CaptureError("server returned an invalid ValueRank")
        evidence["value"] = value
    else:
        if not isinstance(value, ua.EUInformation):
            raise CaptureError("EngineeringUnits Value must contain EUInformation")
        evidence["value"] = {
            "namespaceUri": value.NamespaceUri or "",
            "unitId": value.UnitId,
        }
    return evidence


async def read_evidence(client, requests, attr, namespaces):
    async def read(nodes):
        return await client.read_attributes(nodes, attr)

    async for item, result in bounded_results(requests, read):
        yield item, attribute_evidence(result, attr, namespaces)


async def read_batches(client, requests, attr, field, namespaces):
    async for (row, _), evidence in read_evidence(client, requests, attr, namespaces):
        row[field] = evidence


def local_property_target(targets, namespaces, signal_ids):
    if len(targets) != 1 or targets[0].RemainingPathIndex != 0xFFFFFFFF:
        raise CaptureError(
            "EngineeringUnits must resolve to one fully matched property"
        )
    node = targets[0].TargetId
    if not isinstance(node, ua.NodeId) or getattr(node, "ServerIndex", 0):
        raise CaptureError(
            "EngineeringUnits target must be local to the approved server"
        )
    if getattr(node, "NamespaceUri", None) is not None:
        raise CaptureError("local EngineeringUnits target must use a namespace index")
    local = ua.NodeId(node.Identifier, node.NamespaceIndex, node.NodeIdType)
    if local.is_null() or local in signal_ids:
        raise CaptureError(
            "EngineeringUnits target is null or aliases a contracted signal"
        )
    qualified_id(local, namespaces)  # Validate the index and identifier bounds.
    return local


async def read_engineering_units(client, requests, namespaces, signal_ids):
    step = ua.RelativePathElement(
        ReferenceTypeId=ua.NodeId(ua.ObjectIds.HasProperty),
        IsInverse=False,
        IncludeSubtypes=False,
        TargetName=ua.QualifiedName("EngineeringUnits", 0),
    )
    path = ua.RelativePath([step])
    paths = [(row, ua.BrowsePath(node, path)) for row, node in requests]
    properties = []
    translate = client.uaclient.translate_browsepaths_to_nodeids
    async for (row, _), result in bounded_results(paths, translate):
        raw = result.StatusCode.value
        if raw >> 30 != 0:
            row["engineeringUnits"] = {"status": raw}
            continue
        target = local_property_target(result.Targets, namespaces, signal_ids)
        properties.append((row, client.get_node(target)))

    # Prove the property type and rank before issuing any Value reads.
    # Keep the first unavailable operation's raw status as evidence.
    for attr, expected in (
        (
            ua.AttributeIds.DataType,
            {"namespace": UA_NAMESPACE, "id": f"i={ua.ObjectIds.EUInformation}"},
        ),
        (ua.AttributeIds.ValueRank, -1),
    ):
        verified = []
        async for (row, node), evidence in read_evidence(
            client, properties, attr, namespaces
        ):
            if "value" not in evidence:
                row["engineeringUnits"] = evidence
            elif evidence["value"] != expected:
                raise CaptureError("EngineeringUnits must declare scalar EUInformation")
            else:
                verified.append((row, node))
        properties = verified
    # Namespace strings originate in separate responses and could otherwise
    # accumulate above the snapshot budget before the final serialization check.
    unit_bytes = 0
    async for (row, _), evidence in read_evidence(
        client, properties, ua.AttributeIds.Value, namespaces
    ):
        if "value" in evidence:
            unit_bytes += len(evidence["value"]["namespaceUri"].encode("utf-8"))
            if unit_bytes > MAX_BYTES:
                raise CaptureError(
                    "snapshot exceeds the 4 MiB limit; use a smaller signal list"
                )
        row["engineeringUnits"] = evidence


def validate_meter_contract(contract):
    signals = contract["signals"]
    if len(signals) == 1:
        signal = signals[0]
        dtype = signal["dataType"]
        if (
            dtype["namespace"] == UA_NAMESPACE
            and dtype["id"] in METER_TYPES
            and signal.get("valueRank") == -1
            and signal.get("engineeringUnits") == METER_UNITS
        ):
            return
    raise CaptureError(
        "meter contract must select one scalar UInt32, UInt64, Float or Double watt-hour register",
        MeterExit.METADATA,
    )


def format_meter_time(epoch, nanoseconds):
    seconds, nanos = divmod(nanoseconds, 1_000_000_000)
    stamp = epoch + timedelta(seconds=seconds)
    return f"{stamp.date().isoformat()}T{stamp:%H:%M:%S}.{nanos:09d}Z"


def meter_timestamp(data, has_time, has_picos):
    ticks = Primitives.Int64.unpack(data) if has_time else 0
    picos = Primitives.UInt16.unpack(data) if has_picos else 0
    if ticks == 0:
        # Part 6 table 27 ignores a picoseconds field when its timestamp is absent.
        return None
    # UA DateTime has 100 ns ticks, with optional increments of 10 ps.
    # The evidence format supports nanoseconds. Never truncate into a boundary.
    if ticks < 0 or picos >= 10000 or picos % 100:
        raise ValueError("timestamp not representable")
    return format_meter_time(
        datetime(1601, 1, 1, tzinfo=UTC), ticks * 100 + picos // 100
    )


def meter_result(data, expected_type):
    # asyncua's ordinary DataValue decoder floors wire DateTime to microseconds.
    # Use its binary primitives only for this one restricted ReadResponse. Part 6
    # table 27 places SourcePicoseconds BEFORE ServerTimestamp on the wire.
    if nodeid_from_binary(data) != ua.NodeId(
        ua.ObjectIds.ReadResponse_Encoding_DefaultBinary
    ):
        raise ValueError("unexpected response")
    struct_from_binary(ua.ResponseHeader, data).ServiceResult.check()
    if Primitives.Int32.unpack(data) != 1:
        raise ValueError("expected exactly one result")
    mask = Primitives.Byte.unpack(data)
    if mask & ~0x3F:
        raise ValueError("invalid DataValue mask")
    value = None
    if mask & 1:
        kind = Primitives.Byte.unpack(data)
        if kind == expected_type.value:
            # Decode the little-endian word directly to preserve signed zero and NaN payloads.
            primitive = (
                Primitives.UInt64
                if expected_type in (ua.VariantType.UInt64, ua.VariantType.Double)
                else Primitives.UInt32
            )
            value = primitive.unpack(data)
        elif kind != ua.VariantType.Null.value:
            raise ValueError("unexpected scalar or array type")
    status = Primitives.UInt32.unpack(data) if mask & 2 else 0
    source = meter_timestamp(data, mask & 4, mask & 16)
    server = meter_timestamp(data, mask & 8, mask & 32)
    # No DiagnosticInfos were requested. Reject unexpected trailing payload.
    if Primitives.Int32.unpack(data) not in (-1, 0) or len(data):
        raise ValueError("unexpected trailer")
    fields = {"status": status, "sourceAt": source, "serverAt": server}
    if status >> 30 == 0:
        if value is None:
            raise ValueError("Good reading has no register value")
        if expected_type == ua.VariantType.Double:
            # A JSON number cannot carry all 64-bit words through a binary64 reader.
            fields["valueBits"] = f"{value:016x}"
        elif expected_type == ua.VariantType.Float:
            fields["valueBits"] = value
        else:
            fields["value"] = value
    return fields


async def read_meter(client, node, signal, metadata, scope):
    for field in ("dataType", "valueRank", "engineeringUnits"):
        if metadata.get(field, {}).get("value") != signal[field]:
            raise CaptureError(
                "meter metadata unavailable or changed", MeterExit.METADATA
            )
    request = ua.ReadRequest()
    request.Parameters.TimestampsToReturn = ua.TimestampsToReturn.Both
    request.Parameters.NodesToRead = [
        ua.ReadValueId(NodeId=node.nodeid, AttributeId=ua.AttributeIds.Value)
    ]
    # Same session, security and request limits as asyncua's normal read.
    data = await client.uaclient.session._send_request(request)
    received_at = format_meter_time(datetime(1970, 1, 1, tzinfo=UTC), time.time_ns())
    try:
        fields = meter_result(data, METER_TYPES[signal["dataType"]["id"]])
    except ua.UaStatusCodeError:
        raise
    except (ValueError, OverflowError, ua.UaError):
        raise CaptureError(
            "invalid register DataValue or timestamp", MeterExit.VALUE
        ) from None
    return {**scope, **signal, "receivedAt": received_at, **fields}


async def observe(client, contract, *, meter_read=False):
    namespaces = await client.get_namespace_array()
    if (
        not isinstance(namespaces, list)
        or not 2 <= len(namespaces) <= 65536
        or not all(isinstance(uri, str) and uri for uri in namespaces)
        or namespaces[0] != UA_NAMESPACE
        or len(set(namespaces)) != len(namespaces)
    ):
        raise CaptureError("server namespace table is invalid or ambiguous")
    if namespaces[1] != contract["applicationUri"]:
        raise CaptureError("server application URI differs from the contract")
    indexes = {uri: index for index, uri in enumerate(namespaces)}
    rows, types, ranks, units = [], [], [], []
    signal_ids = set()
    for signal in contract["signals"]:
        identity = signal["node"]
        row = {"name": signal["name"], "node": identity}
        rows.append(row)
        if identity["namespace"] not in indexes:
            continue
        local = node_id(identity["id"], indexes[identity["namespace"]])
        signal_ids.add(local)
        node = client.get_node(local)
        if "engineeringUnits" in signal:
            units.append((row, local))
        types.append((row, node))
        if "valueRank" in signal:
            ranks.append((row, node))
    await read_batches(client, types, ua.AttributeIds.DataType, "dataType", namespaces)
    await read_batches(
        client, ranks, ua.AttributeIds.ValueRank, "valueRank", namespaces
    )
    if units:
        await read_engineering_units(client, units, namespaces, signal_ids)
    snapshot = {
        key: contract[key]
        for key in ("schemaVersion", "device", "principal", "applicationUri")
    }
    if meter_read:
        if not types:
            raise CaptureError("register namespace unavailable", MeterExit.METADATA)
        row, node = types[0]
        return await read_meter(client, node, contract["signals"][0], row, snapshot)
    return {**snapshot, "signals": rows}


async def run(args, contract):
    host = validate_endpoint(args.endpoint, args.insecure_loopback)
    if not 1 <= args.timeout <= 300:
        raise CaptureError("--timeout must be between 1 and 300 seconds")
    if contract["principal"] != "anonymous":
        raise CaptureError(
            "live capture supports the anonymous principal", PreflightExit.CONTRACT
        )
    if not 1 <= len(contract["signals"]) <= 1024:
        raise CaptureError(
            "contract must specify between 1 and 1024 signals", PreflightExit.CONTRACT
        )
    if args.meter_read:
        validate_meter_contract(contract)
    elif any(
        signal["node"]["namespace"] == UA_NAMESPACE
        and signal["node"]["id"] in {"i=2254", "i=2255", "i=11705"}
        for signal in contract["signals"]
    ):
        raise CaptureError(
            "contract selects a reserved session bootstrap node", PreflightExit.CONTRACT
        )
    async with asyncio.timeout(args.timeout):
        client = Client(
            args.endpoint,
            timeout=min(5, args.timeout),
            watchdog_intervall=args.timeout + 1,
        )
        client.server_uri = contract["applicationUri"]
        client.max_messagesize = MAX_BYTES
        client.max_chunkcount = 128
        await configure_security(client, args, host, contract["applicationUri"])
        if args.preflight:
            return None
        async with client:
            return await observe(client, contract, meter_read=args.meter_read)


def encode_snapshot(snapshot):
    # A long URI can be shared by many observations. Enforce the serialized cap
    # while encoding, before that URI has been expanded across the whole document.
    output = io.BytesIO()
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
    for chunk in encoder.iterencode(snapshot):
        data = chunk.encode("utf-8")
        if output.tell() + len(data) + 1 > MAX_BYTES:
            raise CaptureError(
                "snapshot exceeds the 4 MiB limit; use a smaller signal list"
            )
        output.write(data)
    output.write(b"\n")
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--server-cert")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--insecure-loopback", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--meter-read", action="store_true")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    # Third-party diagnostics may contain raw endpoint or peer-controlled strings.
    logging.disable(logging.CRITICAL)
    preflight_exit = PreflightExit.PREPARATION
    try:
        data = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise CaptureError(
                "contract exceeds the 4 MiB limit", PreflightExit.CONTRACT
            )
        report = asyncio.run(run(args, json.loads(data)))
        sys.stdout.buffer.write(
            b"preflight ok\n" if args.preflight else encode_snapshot(report)
        )
        return 0
    except CaptureError as exc:
        message = str(exc)
        preflight_exit = exc.preflight_exit
    except TimeoutError:
        message = "operation timed out; check connectivity and the capture deadline"
    except ua.UaStatusCodeError as exc:
        message = f"OPC UA request failed with status 0x{exc.code:08X}; verify endpoint policy and permissions"
    except Exception as exc:  # noqa: BLE001 - third-party errors can contain peer data or file paths.
        message = f"could not complete capture ({type(exc).__name__}); check connectivity, certificate pin and client key"
    if args.meter_read:
        return (
            MeterExit.SERVICE
            if preflight_exit == PreflightExit.PREPARATION
            else preflight_exit
        )
    if args.preflight:
        return preflight_exit
    print("capture: " + message, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
