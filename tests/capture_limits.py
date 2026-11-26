"""Small backend tests for bounds, operation scope and typed node identities."""

import asyncio
import io
import json
import struct
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from asyncua import ua
from asyncua.common.utils import Buffer
from asyncua.ua.ua_binary import nodeid_to_binary, struct_to_binary
from cryptography.hazmat.primitives import serialization

sys.dont_write_bytecode = True
from capture_peer import certificate

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/bin/opcua-kit"))
import capture


def contract():
    return {
        "schemaVersion": 1,
        "principal": "anonymous",
        "device": "unit",
        "applicationUri": "urn:test:server",
        "signals": [
            {
                "name": f"signal-{n}",
                "node": {"id": f"i={n + 1}", "namespace": "urn:test:nodes"},
                "dataType": {"id": "i=6", "namespace": capture.UA_NAMESPACE},
                "valueRank": -1,
            }
            for n in range(130)
        ],
    }


class UnitPeer:
    """Record service operands so a leaked Value read fails even if its value is discarded."""

    def __init__(self):
        self.uaclient = self
        self.translations = []
        self.reads = []
        self.statuses = {}
        self.targets = {}
        self.types = {}
        self.ranks = {}
        self.units = {}

    async def get_namespace_array(self):
        return [capture.UA_NAMESPACE, "urn:test:server", "urn:test:nodes"]

    def get_node(self, node):
        return node

    async def translate_browsepaths_to_nodeids(self, paths):
        self.translations.append(paths)
        if len(paths) > 10:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadTooManyOperations)
        results = []
        for path in paths:
            i = path.StartingNode.Identifier
            targets = self.targets.get(
                i, [ua.BrowsePathTarget(ua.NodeId(i + 1000, 2), 0xFFFFFFFF)]
            )
            results.append(
                ua.BrowsePathResult(
                    ua.StatusCode(self.statuses.get((i, "path"), 0)), targets
                )
            )
        return results

    async def read_attributes(self, nodes, attr):
        self.reads.append((attr, nodes))
        if len(nodes) > 17:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadTooManyOperations)
        values = []
        for node in nodes:
            i = node.Identifier
            if attr == ua.AttributeIds.Value:
                if i < 1000:
                    raise AssertionError("collector read a process Value")
                value = self.units.get(i, ua.EUInformation("urn:test:units", 12))
                variant = ua.Variant(value)
            elif attr == ua.AttributeIds.DataType:
                dtype = self.types.get(
                    i, ua.ObjectIds.EUInformation if i >= 1000 else 6
                )
                variant = ua.Variant(ua.NodeId(dtype))
            elif attr == ua.AttributeIds.ValueRank:
                variant = ua.Variant(self.ranks.get(i, -1), ua.VariantType.Int32)
            else:
                raise AssertionError("unexpected attribute")
            values.append(
                ua.DataValue(
                    variant, StatusCode=ua.StatusCode(self.statuses.get((i, attr), 0))
                )
            )
        return values


def meter_frame(value, *, count=1, trailer=b""):
    # Result bytes supplied independently of asyncua's lossy datetime decoder.
    return Buffer(
        nodeid_to_binary(ua.NodeId(ua.ObjectIds.ReadResponse_Encoding_DefaultBinary))
        + struct_to_binary(ua.ResponseHeader())
        + struct.pack("<i", count)
        + value
        + struct.pack("<i", 0)
        + trailer
    )


class MeterWire(unittest.IsolatedAsyncioTestCase):
    # 006-meter-pilot/SR-001 006-meter-pilot/SR-002
    def test_clocks_keep_ticks_and_picos_in_wire_order(self):
        # 100ns after 1970-01-01 00:00:00, plus 12 nanoseconds.
        epoch = 116444736000000000
        raw = struct.pack(
            "<BBQQHQH", 0x3D, 9, 2**64 - 1, epoch + 1, 1200, epoch + 10, 100
        )
        result = capture.meter_result(meter_frame(raw), ua.VariantType.UInt64)
        self.assertEqual(
            result,
            {
                "status": 0,
                "sourceAt": "1970-01-01T00:00:00.000000112Z",
                "serverAt": "1970-01-01T00:00:00.000001001Z",
                "value": 2**64 - 1,
            },
        )
        # A picoseconds field alone does not create a timestamp (Part 6, table 27).
        raw = struct.pack("<BBIHH", 0x31, 7, 42, 123, 456)
        absent = capture.meter_result(meter_frame(raw), ua.VariantType.UInt32)
        self.assertIsNone(absent["sourceAt"])
        self.assertIsNone(absent["serverAt"])
        for offset in (1, 9999, 10000):
            raw = struct.pack("<BBIQH", 0x15, 7, 5, epoch, offset)
            with self.assertRaisesRegex(ValueError, "not representable"):
                capture.meter_result(meter_frame(raw), ua.VariantType.UInt32)

    def test_good_missing_value_and_wrong_type_never_form_a_reading(self):
        kind = ua.VariantType.UInt32
        for bits in [0, 0x80]:
            with self.assertRaises(ValueError):
                capture.meter_result(meter_frame(bytes([bits])), kind)
        for variant in [
            ua.VariantType.Null.value,
            ua.VariantType.UInt64.value,
            kind.value | 128,
        ]:
            with self.assertRaises(ValueError):
                capture.meter_result(meter_frame(bytes([1, variant])), kind)
        unsigned = struct.pack("<BBI", 1, kind.value, 2**32 - 1)
        self.assertEqual(
            capture.meter_result(meter_frame(unsigned), kind)["value"], 2**32 - 1
        )
        for frame in [
            meter_frame(unsigned, trailer=b"extra"),
            meter_frame(unsigned, count=2),
        ]:
            with self.assertRaises(ValueError):
                capture.meter_result(frame, kind)

    def test_float_reads_preserve_binary32_payload_and_obey_variant_and_status(self):
        # 007-float-meter/SR-001
        kind = ua.VariantType.Float
        for bits in [
            0,
            0x80000000,  # negative zero
            0x00000001,  # minimum positive subnormal
            0xC0D00000,  # -6.5, OPC UA Part 6 Figure 3
            0x4B800000,  # first value whose next larger Float is two Wh away
            0x7F800000,  # infinity
            0xFFC00000,  # OPC UA quiet NaN
            0x7F801234,  # even a noncanonical NaN from a peer remains observable
        ]:
            for status in [0, 0x0400, 0x40900001, 0x80340000]:
                frame = meter_frame(struct.pack("<BBII", 3, kind.value, bits, status))
                expected = {"status": status, "sourceAt": None, "serverAt": None}
                if status >> 30 == 0:
                    expected["valueBits"] = bits
                with self.subTest(bits=bits, status=status):
                    self.assertEqual(capture.meter_result(frame, kind), expected)
        # UInt32 has the same width, but only a scalar Float matches the contract.
        for variant in [ua.VariantType.UInt32.value, 0x80 | kind.value]:
            with self.assertRaisesRegex(ValueError, "unexpected scalar or array type"):
                capture.meter_result(meter_frame(bytes([1, variant])), kind)

    def test_double_reads_preserve_binary64_word_and_obey_variant_and_status(self):
        # 008-double-meter/SR-001
        kind = ua.VariantType.Double
        # The fixed reference word also exercises byte order independently of
        # the scalar encoder and of the collector's integer-to-hex conversion.
        vectors = [
            ("0000000000000000", bytes(8)),
            ("8000000000000000", bytes.fromhex("00 00 00 00 00 00 00 80")),
            ("0000000000000001", bytes.fromhex("01 00 00 00 00 00 00 00")),
            ("3ff0000000000001", bytes.fromhex("01 00 00 00 00 00 f0 3f")),
            ("4340000000000000", bytes.fromhex("00 00 00 00 00 00 40 43")),
            ("7ff0000000000000", bytes.fromhex("00 00 00 00 00 00 f0 7f")),
            ("7ff8000000001234", bytes.fromhex("34 12 00 00 00 00 f8 7f")),
            ("7ff8000000001235", bytes.fromhex("35 12 00 00 00 00 f8 7f")),
            ("ffffffffffffffff", bytes.fromhex("ff ff ff ff ff ff ff ff")),
        ]
        for word, raw in vectors:
            for status in (0, 0x0400, 0x40900001, 0x80340000):
                frame = meter_frame(
                    bytes([3, kind.value]) + raw + struct.pack("<I", status)
                )
                expected = {"status": status, "sourceAt": None, "serverAt": None}
                if status >> 30 == 0:
                    expected["valueBits"] = word
                with self.subTest(word=word, status=status):
                    self.assertEqual(capture.meter_result(frame, kind), expected)
        for variant in [
            ua.VariantType.UInt64.value,
            ua.VariantType.Float.value,
            0x80 | kind.value,
        ]:
            with self.assertRaisesRegex(ValueError, "unexpected scalar or array type"):
                capture.meter_result(meter_frame(bytes([1, variant])), kind)

    def test_unusable_status_retains_full_code_without_value_or_invented_time(self):
        for status in (0x40900001, 0x80340000, 0xC0000000):
            for frame in [
                struct.pack("<BI", 2, status),
                struct.pack("<BBII", 3, 7, 10, status),
            ]:
                self.assertEqual(
                    capture.meter_result(meter_frame(frame), ua.VariantType.UInt32),
                    {"status": status, "sourceAt": None, "serverAt": None},
                )

    async def test_only_matching_meter_metadata_unlocks_the_selected_value(self):
        doc = contract()
        signal = doc["signals"][0]
        doc["signals"] = [signal]
        signal.update(
            dataType={"id": "i=7", "namespace": capture.UA_NAMESPACE},
            engineeringUnits=capture.METER_UNITS,
        )
        capture.validate_meter_contract(doc)
        for altered in [
            {"signals": []},
            {"signals": [signal, signal]},
            {"signals": [{**signal, "valueRank": 0}]},
            {
                "signals": [
                    {
                        **signal,
                        "dataType": {"namespace": capture.UA_NAMESPACE, "id": "i=6"},
                    }
                ]
            },
            {
                "signals": [
                    {**signal, "engineeringUnits": {**capture.METER_UNITS, "unitId": 1}}
                ]
            },
        ]:
            with self.assertRaises(capture.CaptureError):
                capture.validate_meter_contract({**doc, **altered})
        client = AsyncMock()
        node = SimpleNamespace(nodeid=ua.NodeId(1, 2))
        scope = {k: v for k, v in doc.items() if k != "signals"}
        metadata = {
            k: {"value": signal[k], "status": 0}
            for k in ["dataType", "valueRank", "engineeringUnits"]
        }
        for field in metadata:
            for invalid in [{"status": 0x80340000}, {"value": 99, "status": 0}]:
                with self.assertRaises(capture.CaptureError):
                    await capture.read_meter(
                        client, node, signal, {**metadata, field: invalid}, scope
                    )
        client.uaclient.session._send_request.assert_not_awaited()
        client.uaclient.session._send_request.return_value = meter_frame(
            struct.pack("<BBI", 1, 7, 42)
        )
        record = await capture.read_meter(client, node, signal, metadata, scope)
        self.assertEqual(record["value"], 42)
        (request,) = client.uaclient.session._send_request.await_args.args
        self.assertEqual(
            request.Parameters.TimestampsToReturn, ua.TimestampsToReturn.Both
        )
        self.assertEqual(
            [(r.NodeId, r.AttributeId) for r in request.Parameters.NodesToRead],
            [(node.nodeid, ua.AttributeIds.Value)],
        )


class CapturePreflight(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.folder = Path(temp.name)
        certificate(cls.folder, "server", uri="urn:test:server")
        certificate(cls.folder, "client", uri="urn:test:client")
        expired = cls.folder / "expired"
        expired.mkdir()
        certificate(expired, "client", uri="urn:test:client", expired=True)

    def args(self):
        return Namespace(
            endpoint="opc.tcp://localhost:4840",
            server_cert=self.folder / "server.pem",
            client_cert=self.folder / "client.der",
            client_key=self.folder / "client.key",
            insecure_loopback=False,
            timeout=5,
            preflight=True,
            meter_read=False,
        )

    async def test_secure_preflight_uses_no_network(self):
        # 005-capture-preflight/SR-001, 005-capture-preflight/SR-002
        args = self.args()
        key = serialization.load_pem_private_key(args.client_key.read_bytes(), None)
        der_key = self.folder / "client-key.der"
        der_key.write_bytes(
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        # Keep the real client constructor and security-policy preparation.
        # A regression into discovery, name resolution or a socket must fail the test.
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS")),
            patch("socket.socket.connect", side_effect=AssertionError("connection")),
            patch.object(
                capture.Client, "__aenter__", side_effect=AssertionError("session")
            ),
            patch.object(capture, "observe", side_effect=AssertionError("read")),
        ):
            for key_path in [args.client_key, der_key]:
                args.client_key = key_path
                self.assertIsNone(await capture.run(args, contract()))
            args.insecure_loopback = True
            args.server_cert = args.client_cert = args.client_key = None
            args.endpoint = "opc.tcp://[::1]:4840"
            self.assertIsNone(await capture.run(args, contract()))

    async def test_invalid_credentials_fail_before_connection_in_both_modes(self):
        # 005-capture-preflight/SR-001, 005-capture-preflight/SR-002
        for preflight in (True, False):
            for option, value, message, code in (
                ("client_key", self.folder / "server.key", "does not match", 72),
                (
                    "client_key",
                    self.folder / "client.pem",
                    "unencrypted PEM or DER",
                    71,
                ),
                (
                    "server_cert",
                    self.folder / "server.key",
                    "cannot load server certificate",
                    67,
                ),
                (
                    "client_cert",
                    self.folder / "client.key",
                    "cannot load client certificate",
                    67,
                ),
                (
                    "client_cert",
                    self.folder / "server.der",
                    "client certificate key usage",
                    70,
                ),
                (
                    "client_cert",
                    self.folder / "expired/client.der",
                    "client certificate expired",
                    68,
                ),
                ("endpoint", "opc.tcp://wrong.example:4840", "certificate SAN", 69),
                ("endpoint", "opc.tcp://localhost", "TCP port", 64),
                ("insecure_loopback", True, "literal loopback", 64),
            ):
                args = self.args()
                args.preflight = preflight
                setattr(args, option, value)
                with (
                    self.subTest(
                        preflight=preflight, option=option, diagnostic=message
                    ),
                    patch.object(
                        capture.Client,
                        "__aenter__",
                        side_effect=AssertionError("session"),
                    ),
                    self.assertRaisesRegex(capture.CaptureError, message) as failure,
                ):
                    await capture.run(args, contract())
                self.assertEqual(failure.exception.preflight_exit, code)

    def test_preflight_errors_use_only_reserved_exits(self):
        # 005-capture-preflight/SR-003
        args = ["capture", "--preflight", "--endpoint", "opc.tcp://127.0.0.1:4840"]
        for backend_error, code in [
            (capture.CaptureError("private detail", category), category.value)
            for category in capture.PreflightExit
        ] + [(RuntimeError("private detail"), 73)]:
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                self.subTest(code=code),
                patch.object(sys, "argv", args),
                patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"{}"))),
                patch.object(capture, "run", new=AsyncMock(side_effect=backend_error)),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                self.assertEqual(capture.main(), code)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")


class CaptureLimits(unittest.IsolatedAsyncioTestCase):
    async def test_batch_and_attributes(self):
        # 001-commissioning-check/SR-003, 001-commissioning-check/SR-005
        class Peer:
            def __init__(self):
                self.operations = []
                self.get_namespace_array = AsyncMock(
                    return_value=[
                        capture.UA_NAMESPACE,
                        "urn:test:server",
                        "urn:test:nodes",
                    ]
                )

            def get_node(self, node_id):
                return node_id

            async def read_attributes(self, nodes, attribute):
                self.operations.append((len(nodes), attribute))
                if len(nodes) > 23:
                    raise ua.UaStatusCodeError(ua.StatusCodes.BadTooManyOperations)
                variant = (
                    ua.Variant(ua.NodeId(6), ua.VariantType.NodeId)
                    if attribute == ua.AttributeIds.DataType
                    else ua.Variant(-1, ua.VariantType.Int32)
                )
                return [ua.DataValue(variant) for _ in nodes]

        client = Peer()
        result = await capture.observe(client, contract())
        self.assertEqual(len(result["signals"]), 130)
        self.assertEqual(max(size for size, _ in client.operations), capture.BATCH_SIZE)
        self.assertEqual(
            {attribute for _, attribute in client.operations},
            {ua.AttributeIds.DataType, ua.AttributeIds.ValueRank},
        )
        self.assertEqual(
            [row["valueRank"]["value"] for row in result["signals"]], [-1] * 130
        )
        self.assertEqual(
            [row["dataType"]["value"]["id"] for row in result["signals"]], ["i=6"] * 130
        )

    async def test_opt_in_unit_requests_are_bounded_and_exact(self):
        # 002-engineering-units/SR-001, 002-engineering-units/SR-002, 002-engineering-units/SR-003
        doc = contract()
        for signal in doc["signals"][:-1]:
            signal["engineeringUnits"] = {
                "namespaceUri": "urn:test:units",
                "unitId": 12,
            }
        doc["signals"][-2]["node"]["namespace"] = "urn:unknown"
        client = UnitPeer()
        client.units[1001] = ua.EUInformation(
            None, -1, ua.LocalizedText("private"), ua.LocalizedText("secret")
        )
        result = await capture.observe(client, doc)
        rows = result["signals"]
        self.assertEqual(
            rows[0]["engineeringUnits"],
            {"status": 0, "value": {"namespaceUri": "", "unitId": -1}},
        )
        for row in rows[1:-2]:
            self.assertEqual(
                row["engineeringUnits"],
                {
                    "status": 0,
                    "value": {"namespaceUri": "urn:test:units", "unitId": 12},
                },
            )
        for row in rows[-2:]:
            self.assertNotIn("engineeringUnits", row)
        self.assertNotIn("private", str(result))
        self.assertNotIn("secret", str(result))
        paths = [path for batch in client.translations for path in batch]
        self.assertEqual(
            {path.StartingNode.Identifier for path in paths}, set(range(1, 129))
        )
        self.assertEqual(max(map(len, client.translations)), capture.BATCH_SIZE)
        for path in paths:
            (step,) = path.RelativePath.Elements
            self.assertEqual(step.ReferenceTypeId, ua.NodeId(ua.ObjectIds.HasProperty))
            self.assertEqual(step.TargetName, ua.QualifiedName("EngineeringUnits", 0))
            self.assertFalse(step.IsInverse)
            self.assertFalse(step.IncludeSubtypes)
        self.assertLessEqual(
            max(len(nodes) for _, nodes in client.reads), capture.BATCH_SIZE
        )
        self.assertEqual(
            {
                n.Identifier
                for attr, nodes in client.reads
                if attr == ua.AttributeIds.Value
                for n in nodes
            },
            set(range(1001, 1129)),
        )

    async def test_per_operation_status_without_reading_unverified_properties(self):
        # 002-engineering-units/SR-002
        doc = contract()
        doc["signals"] = doc["signals"][:4]
        for signal in doc["signals"]:
            signal["engineeringUnits"] = {
                "namespaceUri": "urn:test:units",
                "unitId": 12,
            }
        client = UnitPeer()
        codes = [
            ua.StatusCodes.BadNoMatch,
            ua.StatusCodes.Uncertain,
            ua.StatusCodes.BadNotReadable,
            ua.StatusCodes.UncertainLastUsableValue,
        ]
        client.statuses = dict(
            zip(
                [
                    (1, "path"),
                    (1002, ua.AttributeIds.DataType),
                    (1003, ua.AttributeIds.ValueRank),
                    (1004, ua.AttributeIds.Value),
                ],
                codes,
                strict=True,
            )
        )
        rows = (await capture.observe(client, doc))["signals"]
        self.assertEqual(
            [r["engineeringUnits"] for r in rows], [{"status": code} for code in codes]
        )
        self.assertEqual(
            [
                n.Identifier
                for attr, nodes in client.reads
                if attr == ua.AttributeIds.Value
                for n in nodes
            ],
            [1004],
        )

    async def test_unsafe_unit_targets_and_wrong_type_do_not_request_value(self):
        # 002-engineering-units/SR-001, 002-engineering-units/SR-002
        doc = contract()
        doc["signals"] = doc["signals"][:2]
        doc["signals"][0]["engineeringUnits"] = {
            "namespaceUri": "urn:test:units",
            "unitId": 12,
        }
        good = ua.BrowsePathTarget(ua.NodeId(1001, 2), 0xFFFFFFFF)
        for targets in [
            [],
            [good, good],
            [ua.BrowsePathTarget(good.TargetId, 0)],
            [
                ua.BrowsePathTarget(
                    ua.ExpandedNodeId(1001, 2, ServerIndex=1), 0xFFFFFFFF
                )
            ],
            [
                ua.BrowsePathTarget(
                    ua.ExpandedNodeId(1001, NamespaceUri="urn:unknown"), 0xFFFFFFFF
                )
            ],
            [
                ua.BrowsePathTarget(
                    ua.ExpandedNodeId(1001, NamespaceUri="urn:test:nodes"), 0xFFFFFFFF
                )
            ],
            [ua.BrowsePathTarget(ua.NodeId(1001, 99), 0xFFFFFFFF)],
            [ua.BrowsePathTarget(ua.NodeId("bad\u0085id", 2), 0xFFFFFFFF)],
            [ua.BrowsePathTarget(ua.NodeId(), 0xFFFFFFFF)],
            [ua.BrowsePathTarget(ua.NodeId(2, 2), 0xFFFFFFFF)],
        ]:
            with self.subTest(targets=targets):
                peer = UnitPeer()
                peer.targets[1] = targets
                with self.assertRaises(capture.CaptureError):
                    await capture.observe(peer, doc)
                self.assertNotIn(
                    ua.AttributeIds.Value, [attr for attr, _ in peer.reads]
                )
        for attribute in ("types", "ranks"):
            with self.subTest(attribute=attribute):
                peer = UnitPeer()
                getattr(peer, attribute)[1001] = 1
                with self.assertRaisesRegex(
                    capture.CaptureError, "scalar EUInformation"
                ):
                    await capture.observe(peer, doc)
                self.assertNotIn(
                    ua.AttributeIds.Value, [attr for attr, _ in peer.reads]
                )
        peer = UnitPeer()
        peer.units[1001] = ua.Range()
        with self.assertRaisesRegex(capture.CaptureError, "must contain EUInformation"):
            await capture.observe(peer, doc)

    async def test_unit_namespace_strings_share_the_output_budget(self):
        # 002-engineering-units/SR-003
        doc = contract()
        doc["signals"] = doc["signals"][:2]
        for signal in doc["signals"]:
            signal["engineeringUnits"] = {
                "namespaceUri": "urn:test:units",
                "unitId": 12,
            }
        with (
            patch.object(capture, "MAX_BYTES", 25),
            self.assertRaisesRegex(capture.CaptureError, "snapshot exceeds"),
        ):
            await capture.observe(UnitPeer(), doc)

    async def test_limits_serialized_snapshot(self):
        # 001-commissioning-check/SR-003
        item = "x" * 65536
        with self.assertRaisesRegex(capture.CaptureError, "snapshot exceeds"):
            capture.encode_snapshot({"signals": [item] * 1000})

    def test_missing_metadata_preserves_raw_status(self):
        for value in (None, ua.Variant(None, ua.VariantType.Null)):
            for status in (0, 0x00000480):
                result = SimpleNamespace(Value=value, StatusCode=ua.StatusCode(status))
                for attr in (
                    ua.AttributeIds.DataType,
                    ua.AttributeIds.ValueRank,
                    ua.AttributeIds.Value,
                ):
                    self.assertEqual(
                        capture.attribute_evidence(result, attr, []), {"status": status}
                    )

    async def test_snapshot_bootstrap_nodes_rejected_before_preparation(self):
        args = Namespace(
            endpoint="opc.tcp://127.0.0.1:4840",
            insecure_loopback=True,
            timeout=3,
            meter_read=False,
        )
        for identifier in ("i=2254", "i=2255", "i=11705"):
            doc = contract()
            doc["signals"][-1]["node"] = {
                "namespace": capture.UA_NAMESPACE,
                "id": identifier,
            }
            with (
                patch.object(capture, "Client", side_effect=AssertionError("session")),
                self.assertRaisesRegex(capture.CaptureError, "bootstrap"),
            ):
                await capture.run(args, doc)

    async def test_wrong_wire_type_is_rejected(self):
        peer = AsyncMock()
        peer.read_attributes.return_value = [
            ua.DataValue(ua.Variant(-1, ua.VariantType.Int64))
        ]
        with self.assertRaisesRegex(capture.CaptureError, "wrong wire type"):
            await capture.read_batches(
                peer, [({}, ua.NodeId(5))], ua.AttributeIds.ValueRank, "valueRank", []
            )

    def test_nonanonymous_principal_fails_before_connection(self):
        # 001-commissioning-check/SR-001
        doc = {**contract(), "principal": "engineer"}
        stdin = io.TextIOWrapper(io.BytesIO(json.dumps(doc).encode("utf-8")))
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "capture",
                    "--endpoint",
                    "opc.tcp://127.0.0.1:4840",
                    "--insecure-loopback",
                ],
            ),
            patch.object(sys, "stdin", stdin),
            patch.object(capture, "Client") as client,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = capture.main()
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("anonymous principal", stderr.getvalue())
        client.assert_not_called()

    async def test_deadline(self):
        # 001-commissioning-check/SR-003
        args = Namespace(
            endpoint="opc.tcp://127.0.0.1:4840",
            timeout=1,
            insecure_loopback=True,
            server_cert=None,
            client_cert=None,
            client_key=None,
            preflight=False,
            meter_read=False,
        )

        async def stall(_):
            await asyncio.sleep(60)

        with (
            patch.object(capture.Client, "__aenter__", stall),
            self.assertRaises(TimeoutError),
        ):
            await asyncio.wait_for(capture.run(args, contract()), 3)

    async def test_rejects_different_namespace_identity(self):
        client = AsyncMock()
        for entries in (
            [capture.UA_NAMESPACE, "urn:test:server", "duplicate", "duplicate"],
            [capture.UA_NAMESPACE, "urn:other"],
            [capture.UA_NAMESPACE],
        ):
            client.get_namespace_array.return_value = entries
            with self.assertRaises(capture.CaptureError):
                await capture.observe(client, contract())
            client.read_attributes.assert_not_called()

    async def test_node_identifiers_round_trip(self):
        ns = [capture.UA_NAMESPACE, "urn:test:server"]
        for id_ in [
            "s= leading ;=尾 ",
            "b=AQIDBA==",
            "i=4294967295",
            "g=3ec3dcc3-e4b1-4220-8e3f-cde18546f86d",
        ]:
            node = capture.node_id(id_, 1)
            self.assertEqual(
                capture.qualified_id(node, ns), {"namespace": ns[1], "id": id_}
            )


if __name__ == "__main__":
    unittest.main()
