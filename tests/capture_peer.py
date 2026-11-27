"""Independent, loopback-only OPC UA interoperability tests. See tests/peers/run.sh."""

import asyncio
import copy
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
UA = "http://opcfoundation.org/UA/"
SIGNAL = {"namespace": "urn:fixture:hvac", "id": "s=Sensor"}
CONTRACT = {
    "schemaVersion": 1,
    "device": "ahu",
    "principal": "anonymous",
    "applicationUri": "urn:fixture:server",
    "signals": [
        {
            "name": "sensor",
            "node": SIGNAL,
            "dataType": {"namespace": UA, "id": "i=12"},
            "valueRank": -1,
        },
        {
            "name": "unknown",
            "node": {**SIGNAL, "id": "s=absent"},
            "dataType": {"namespace": UA, "id": "i=11"},
        },
    ],
}


def meter_contract(node, dtype):
    return {
        **CONTRACT,
        "signals": [
            {
                "name": "GridImportRegister",
                "node": {**SIGNAL, "id": f"s={node}"},
                "dataType": {"namespace": UA, "id": dtype},
                "valueRank": -1,
                "engineeringUnits": {
                    "namespaceUri": "http://www.opcfoundation.org/UA/units/un/cefact",
                    "unitId": int.from_bytes(b"WHR", "big"),
                },
            }
        ],
    }


def snapshot_signal(name, dtype="i=11", *, rank=False, unit=False):
    signal = {
        "name": name,
        "node": {**SIGNAL, "id": f"s={name}"},
        "dataType": {"namespace": UA, "id": dtype} if isinstance(dtype, str) else dtype,
    }
    if rank:
        signal["valueRank"] = -1
    if unit:
        signal["engineeringUnits"] = {
            "namespaceUri": "http://www.opcfoundation.org/UA/units/un/cefact",
            "unitId": 0x43454C,
        }
    return signal


def certificate(
    folder,
    stem,
    *,
    uri=None,
    host="127.0.0.1",
    expired=False,
    key_bits=2048,
    extra_uri=None,
    ca=False,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, stem)])
    now = datetime.now(UTC)
    usage = (
        ExtendedKeyUsageOID.CLIENT_AUTH
        if stem == "client"
        else ExtendedKeyUsageOID.SERVER_AUTH
    )
    names = [
        x509.IPAddress(ipaddress.ip_address(host)),
        x509.DNSName("localhost"),
        x509.UniformResourceIdentifier("urn:fixture:server" if uri is None else uri),
    ]
    if extra_uri is not None:
        names.append(x509.UniformResourceIdentifier(extra_uri))
    if stem == "server" and socket.gethostname() != "localhost":
        names.append(x509.DNSName(socket.gethostname().encode("idna").decode("ascii")))
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=3))
        .not_valid_after(now + timedelta(days=-1 if expired else 2))
        .add_extension(x509.SubjectAlternativeName(names), False)
        .add_extension(
            x509.KeyUsage(True, True, True, True, False, False, False, None, None), True
        )
        .add_extension(x509.ExtendedKeyUsage([usage]), False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False
        )
    )
    if ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), True
        )
    cert = builder.sign(key, hashes.SHA256())
    (folder / f"{stem}.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))
    (folder / f"{stem}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if stem == "client":
        (folder / "client-key.der").write_bytes(
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    (folder / f"{stem}.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class CapturePeer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.folder = Path(temp.name)
        cls.limited = {}
        for stem, options in (
            ("server", {}),
            ("client", {"uri": "urn:fixture:client"}),
            ("imposter", {}),
            ("wronghost", {"host": "127.0.0.2"}),
            ("expired", {"expired": True}),
        ):
            certificate(cls.folder, stem, **options)
        cls.url = cls.start_peer("server")
        cls.other_uri = cls.start_peer("other")
        cls.reordered = cls.start_peer("reordered")
        cls.uncertain = cls.start_peer("uncertain")
        cls.wrong_unit = cls.start_peer("wrongunit")
        cls.coarse = cls.start_peer("coarse")

    @classmethod
    def start_peer(cls, label):
        log_path = cls.folder / f"{label}.log"
        log = log_path.open("w")
        cls.addClassCleanup(log.close)
        peer = subprocess.Popen(
            ["node", str(ROOT / "tests/peers/server.cjs"), label],
            cwd=cls.folder,
            stderr=log,
            stdout=log,
        )

        def stop():
            peer.terminate()
            try:
                peer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                peer.kill()
                peer.wait()

        cls.addClassCleanup(stop)
        deadline = time.monotonic() + 30
        port = cls.folder / f"{label}.port"
        while not port.exists():
            if peer.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(log_path.read_text())
            time.sleep(0.05)
        return "opc.tcp://127.0.0.1:" + port.read_text()

    def collect(self, *args, contract=None, endpoint=None, env=None, meter=False):
        contract = contract or CONTRACT
        file = self.folder / "contract.json"
        file.write_text(json.dumps(contract))
        action = ["meter", "read"] if meter else ["capture"]
        binary = os.environ.get("OPCUA_KIT_BIN") or str(ROOT / "target/debug/opcua-kit")
        return subprocess.run(
            [
                binary,
                *action,
                "--contract",
                str(file),
                "--endpoint",
                endpoint or self.url,
                *args,
            ],
            check=False,
            capture_output=True,
            text=True,
            cwd=self.folder,
            env=env if env is not None else {**os.environ, "PATH": ""},
            timeout=45,
        )

    def secure(self, pin="server"):
        return [
            "--server-cert",
            str(self.folder / f"{pin}.pem"),
            "--client-cert",
            str(self.folder / "client.pem"),
            "--client-key",
            str(self.folder / "client.key"),
        ]

    def capture_native(self, route, endpoint, contract, *, output=None, timeout=5):
        env = {**os.environ, "PATH": ""}
        if route == "cli":
            args = [
                "--client-uri",
                "urn:fixture:client",
                "--server-cert",
                "server.der",
                "--client-cert",
                "client.der",
                "--client-key",
                "client-key.der",
                "--timeout",
                str(timeout),
            ]
            if output is not None:
                args.extend(["--output", str(output)])
            return self.collect(*args, contract=contract, endpoint=endpoint, env=env)
        (self.folder / "contract.json").write_text(json.dumps(contract))
        return subprocess.run(
            [
                os.environ["OPCUA_KIT_NATIVE_COMMISSIONING_BIN"],
                self.folder,
                endpoint,
                "server",
                "snapshot",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            cwd=self.folder,
            env=env,
        )

    def run_native(self, endpoint, pin, expected):
        binary = os.environ.get("OPCUA_KIT_NATIVE_PEER_BIN")
        if not binary:
            self.skipTest("run tests/peers/run.sh to build the external Rust consumer")
        result = subprocess.run(
            [binary, str(self.folder), endpoint, pin, expected],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            cwd=self.folder,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_client_pins_peer_and_resolves_session_namespaces(self):
        # 012-native-client/SR-001 012-native-client/SR-002
        for label, endpoint, pin, expected, reads in [
            ("server", self.url, "imposter", "reject", 0),
            ("server", self.url, "server", str(2**53 + 1), 2),
            ("reordered", self.reordered, "server", str(2**53 + 285001), 2),
        ]:
            with self.subTest(label=label, pin=pin):
                counter = self.folder / f"{label}.GridImportWh.reads"
                before = int(counter.read_text())
                self.run_native(endpoint, pin, expected)
                self.assertEqual(int(counter.read_text()) - before, reads)

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_PEER_BIN"), "requires native Rust consumer"
    )
    def test_navigation_and_data_change_subscriptions(self):
        # 019-protocol-client/SR-001 019-protocol-client/SR-002
        from peers.asyncua_server import attribute_peer

        self.run_native(self.start_peer("navigation"), "server", "navigation-node")
        page_actions = (self.folder / "navigation.pages").read_text().splitlines()
        self.assertIn("next", page_actions)
        self.assertIn("release", page_actions)

        async def exercise():
            monitored = {"created": [], "deleted": set()}
            async with attribute_peer(
                self.folder, navigation=True, monitored=monitored
            ) as endpoint:
                await asyncio.to_thread(
                    self.run_native, endpoint, "server", "navigation-python"
                )
            requests = {
                tuple(node for node, _, _ in items): (sub, items)
                for sub, items in monitored["created"]
            }
            self.assertIn(("Steady", "Counter", "Steady"), requests)
            self.assertIn(("Steady",) * 32, requests)
            sub, siblings = requests[("Steady", "NoSuchItem")]
            self.assertEqual([ok for _, _, ok in siblings], [True, False])
            self.assertIn((sub, siblings[0][1]), monitored["deleted"])

        asyncio.run(exercise())

    def limited_peer(self, limit):
        label = f"limit{limit}"
        if label not in self.limited:
            self.limited[label] = self.start_peer(label)
        return self.limited[label]

    def observed_target_reads(self, limit):
        label = f"limit{limit}"
        log = self.folder / f"{label}.batches"
        calls = (
            [json.loads(line) for line in log.read_text().splitlines()]
            if log.exists()
            else []
        )
        log.unlink(missing_ok=True)
        self.assertTrue(all(len(call) <= limit for call in calls), calls)
        indexes = json.loads((self.folder / f"{label}.indexes").read_text())
        prefix = f"ns={indexes['signal']};"
        targets = [
            [(node.removeprefix(prefix), attr) for node, attr in call]
            for call in calls
            if any(node.startswith(prefix) for node, attr in call)
        ]
        return calls, targets

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_PEER_BIN"), "requires native Rust consumer"
    )
    def test_native_batches_obey_server_limits_and_discard_failed_batches(self):
        # 013-read-limits/SR-001 013-read-limits/SR-002
        meter = "s=GridImportWh"
        nodes = [meter, "s=absent", "s=Temperature", meter, meter]
        for limit in [1, 2]:
            with self.subTest(max_nodes_per_read=limit):
                label = f"limit{limit}"
                endpoint = self.limited_peer(limit)
                self.run_native(endpoint, "server", label)
                wire, data = self.observed_target_reads(limit)
                expected = [nodes[i : i + limit] for i in range(0, len(nodes), limit)]
                if limit == 2:
                    expected.extend([[meter, meter], ["s=LowerLimit", meter]])
                self.assertEqual(
                    data, [[(node, 13) for node in call] for call in expected]
                )
                self.assertEqual(wire.count([["ns=0;i=11705", 13]]), 1, wire)

    def native_cli(
        self, command, endpoint, node="GridImportWh", pin="server", *, units=False
    ):
        binary = os.environ.get("OPCUA_KIT_BIN")
        if not binary:
            self.skipTest("run tests/peers/run.sh to build the CLI")
        return subprocess.run(
            [
                binary,
                command,
                *(["--units"] if units else []),
                "--endpoint",
                endpoint,
                "--server-uri",
                "urn:fixture:server",
                "--client-uri",
                "urn:fixture:client",
                "--server-cert",
                f"{pin}.der",
                "--client-cert",
                "client.der",
                "--client-key",
                "client-key.der",
                "--namespace",
                "urn:fixture:hvac",
                "--id",
                f"s={node}",
                "--timeout",
                "5",
            ],
            cwd=self.folder,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def test_native_cli_reads_uint64_and_rejects_unusable_results(self):
        # 012-native-client/SR-001 012-native-client/SR-002 012-native-client/SR-003
        result = self.native_cli("read", self.reordered)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("\n"), 1)
        sample = json.loads(result.stdout)
        self.assertEqual(sample["value"], 2**53 + 285001)
        self.assertEqual(sample["status"], 0)
        self.assertEqual(sample["sourceTimestamp"]["baseUtc"], "2020-10-25T01:00:00Z")
        self.assertIn("tenPicoseconds", sample["sourceTimestamp"])
        self.assertIsNotNone(sample["serverTimestamp"]["baseUtc"])

        for result, reason in [
            (self.native_cli("read", self.uncertain), "0x40900000"),
            (self.native_cli("read", self.url, node="absent"), "0x80340000"),
            (self.native_cli("read", self.url, node="GridImportDoubleWh"), "UInt64"),
            (self.native_cli("read", self.url, pin="imposter"), "secure"),
        ]:
            with self.subTest(reason=reason):
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(reason, result.stderr)

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_PEER_BIN"), "requires native Rust consumer"
    )
    def test_native_attribute_operands_and_definitions_on_reordered_peers(self):
        # 014-attribute-reads/SR-001 014-attribute-reads/SR-002
        temp, absent = "s=Temperature", "s=absent"
        definitions = [[(temp, 14), (temp, 15)], [(absent, 14), (absent, 15)]]
        mixed = [(temp, 13), (absent, 15), (temp, 14), (temp, 15), (temp, 15)]
        type_indexes = []
        for limit in [1, 2]:
            with self.subTest(max_nodes_per_read=limit):
                self.run_native(self.limited_peer(limit), "server", "attributes")
                _, recorded = self.observed_target_reads(limit)
                expected = [
                    call[i : i + limit]
                    for call in [*definitions, mixed]
                    for i in range(0, len(call), limit)
                ]
                self.assertEqual(recorded, expected)
                indexes = json.loads(
                    (self.folder / f"limit{limit}.indexes").read_text()
                )
                type_indexes.append(indexes["type"])
        self.assertEqual(len(set(type_indexes)), 2)

    def test_describe_reads_only_metadata_and_preserves_field_status(self):
        # 014-attribute-reads/SR-001 014-attribute-reads/SR-002
        endpoint = self.limited_peer(2)
        for name, code in [("Temperature", 0), ("absent", 3)]:
            with self.subTest(node=name):
                result = self.native_cli("describe", endpoint, node=name)
                self.assertEqual(result.returncode, code, result.stderr)
                definition = json.loads(result.stdout)
                self.assertNotIn("engineeringUnits", definition)
                self.assertFalse((self.folder / "limit2.browse").exists())
                status = 0 if code == 0 else 0x80340000
                datatype = (
                    {"namespace": "urn:fixture:types", "id": "i=7401"}
                    if code == 0
                    else None
                )
                self.assertEqual(
                    definition["dataType"], {"status": status, "value": datatype}
                )
                self.assertEqual(
                    definition["valueRank"],
                    {"status": status, "value": -1 if code == 0 else None},
                )
                _, recorded = self.observed_target_reads(2)
                self.assertEqual(recorded, [[(f"s={name}", 14), (f"s={name}", 15)]])
        refused = self.native_cli(
            "describe", endpoint, node="Temperature", pin="imposter"
        )
        self.assertEqual(refused.returncode, 1, refused.stderr)
        self.assertEqual(refused.stdout, "")
        self.assertEqual(self.observed_target_reads(2)[1], [])

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_PEER_BIN"), "requires native Rust consumer"
    )
    def test_native_attributes_interoperate_with_asyncua_and_keep_partial_definitions(
        self,
    ):
        # 014-attribute-reads/SR-001 014-attribute-reads/SR-002
        from peers.asyncua_server import attribute_peer

        async def exercise():
            async with attribute_peer(self.folder) as endpoint:
                await asyncio.to_thread(self.run_native, endpoint, "imposter", "reject")
                await asyncio.to_thread(self.run_native, endpoint, "server", "asyncua")
                denied = await asyncio.to_thread(
                    self.native_cli, "describe", endpoint, "DeniedRank"
                )
                self.assertEqual(denied.returncode, 3, denied.stderr)
                fields = json.loads(denied.stdout)
                self.assertEqual(
                    fields["dataType"]["value"],
                    {"namespace": "urn:fixture:types", "id": "i=7401"},
                )
                self.assertEqual(
                    fields["valueRank"], {"status": 0x801F0000, "value": None}
                )
                malformed = await asyncio.to_thread(
                    self.native_cli, "describe", endpoint, "MalformedRank"
                )
                self.assertEqual(malformed.returncode, 1, malformed.stderr)
                self.assertEqual(malformed.stdout, "")

        asyncio.run(exercise())

    def observe_unit_browses(self, limit, expected):
        label = f"limit{limit}"
        log = self.folder / f"{label}.browse"
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        log.unlink()
        index = json.loads((self.folder / f"{label}.indexes").read_text())["signal"]
        self.assertEqual(
            calls,
            [[f"ns={index};s={node}", "ns=0;i=46", 0, False, 256] for node in expected],
        )

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_PEER_BIN"), "requires native Rust consumer"
    )
    def test_engineering_units_follow_one_property_and_gate_its_value(self):
        # 015-engineering-units/SR-001 015-engineering-units/SR-002
        for limit, case, code in [
            (1, "units-celsius", "CEL"),
            (2, "units-fahrenheit", "FAH"),
        ]:
            with self.subTest(limit=limit):
                endpoint = self.limited_peer(limit)
                self.run_native(endpoint, "server", case)
                nodes = ["Temperature", "Sensor"]
                expected = [("s=UnitProperty", attribute) for attribute in (14, 15, 13)]
                if limit == 1:
                    for name, attrs in [
                        ("WrongUnitType", [14]),
                        ("WrongUnitRank", [14, 15]),
                        ("UncertainUnit", [14, 15, 13]),
                    ]:
                        nodes.append(name)
                        expected.extend((f"s={name}Property", attr) for attr in attrs)
                self.observe_unit_browses(limit, nodes)
                _, reads = self.observed_target_reads(limit)
                self.assertEqual([row for call in reads for row in call], expected)

                result = self.native_cli(
                    "describe", endpoint, "Temperature", units=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                units = json.loads(result.stdout)["engineeringUnits"]
                identity = {
                    "namespaceUri": "http://www.opcfoundation.org/UA/units/un/cefact",
                    "unitId": int.from_bytes(code.encode(), "big"),
                }
                self.assertEqual(
                    units,
                    {
                        "stage": "value",
                        "property": {
                            "namespace": "urn:fixture:hvac",
                            "id": "s=UnitProperty",
                        },
                        "status": 0,
                        "value": identity,
                    },
                )
                self.assertNotIn("PRIVATE", result.stdout + result.stderr)
                self.observe_unit_browses(limit, ["Temperature"])
                _, reads = self.observed_target_reads(limit)
                self.assertEqual(
                    [row for call in reads for row in call],
                    [
                        ("s=Temperature", 14),
                        ("s=Temperature", 15),
                        *expected[:3],
                    ],
                )

        endpoint = self.limited_peer(1)
        for name, exit_code in [
            ("Sensor", 3),
            ("UncertainUnit", 3),
            ("WrongUnitType", 1),
            ("WrongUnitRank", 1),
        ]:
            with self.subTest(node=name):
                result = self.native_cli("describe", endpoint, name, units=True)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                if exit_code == 1:
                    self.assertEqual(result.stdout, "")
                else:
                    unit = json.loads(result.stdout)["engineeringUnits"]
                    self.assertEqual(unit["value"], None)
                    self.assertEqual(
                        (unit["stage"], unit["status"]),
                        ("browse", 0) if name == "Sensor" else ("value", 0x40904000),
                    )
                self.assertNotIn("PRIVATE", result.stdout + result.stderr)
                self.observe_unit_browses(1, [name])
                _, reads = self.observed_target_reads(1)
                self.assertNotIn(
                    (f"s={name}", 13), [row for call in reads for row in call]
                )
                if exit_code == 1:
                    self.assertNotIn(
                        (f"s={name}Property", 13),
                        [row for call in reads for row in call],
                    )

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_PEER_BIN"), "requires native Rust consumer"
    )
    def test_engineering_units_preserve_catalog_and_unavailable_gate_on_asyncua(self):
        # 015-engineering-units/SR-001 015-engineering-units/SR-002
        from peers.asyncua_server import attribute_peer

        async def exercise():
            async with attribute_peer(self.folder) as endpoint:
                await asyncio.to_thread(
                    self.run_native, endpoint, "server", "units-asyncua"
                )
                for name, code, stage, status, value in [
                    (
                        "Temperature",
                        0,
                        "value",
                        0,
                        {
                            "namespaceUri": "urn:fixture:unit-catalog",
                            "unitId": 0x43454C,
                        },
                    ),
                    ("DeniedUnitType", 3, "dataType", 0x801F0000, None),
                    (
                        "UnidentifiedUnit",
                        3,
                        "value",
                        0,
                        {"namespaceUri": "", "unitId": -1},
                    ),
                ]:
                    result = await asyncio.to_thread(
                        self.native_cli, "describe", endpoint, name, units=True
                    )
                    self.assertEqual(result.returncode, code, result.stderr)
                    unit = json.loads(result.stdout)["engineeringUnits"]
                    self.assertEqual(
                        (unit["stage"], unit["status"], unit["value"]),
                        (stage, status, value),
                    )
                    self.assertNotIn("PRIVATE", result.stdout + result.stderr)

        asyncio.run(exercise())

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_PEER_BIN"), "requires native Rust consumer"
    )
    def test_unit_browse_follows_small_pages_and_releases_on_ambiguity(self):
        # 015-engineering-units/SR-001
        self.run_native(self.limited_peer(1), "server", "units-pages")
        self.observe_unit_browses(1, ["PagedTemperature", "AmbiguousUnits"])
        path = self.folder / "limit1.pages"
        pages = [json.loads(line) for line in path.read_text().splitlines()]
        path.unlink()
        self.assertEqual(
            [entry[1:] for entry in pages if entry[0] == "PagedTemperature"],
            [
                ["page", ["DeviceTag"], True],
                ["next"],
                ["page", ["EngineeringUnits"], False],
            ],
        )
        ambiguous = [entry[1:] for entry in pages if entry[0] == "AmbiguousUnits"]
        self.assertEqual(
            ambiguous[:4],
            [
                ["page", ["EngineeringUnits"], True],
                ["next"],
                ["page", ["EngineeringUnits"], True],
                ["release"],
            ],
        )
        _, reads = self.observed_target_reads(1)
        self.assertEqual(
            reads, [[("s=PagedTemperature1", attr)] for attr in [14, 15, 13]]
        )

    def test_prepare_offline_then_capture_with_the_same_credentials(self):
        # 005-capture-preflight/SR-001 005-capture-preflight/SR-002
        options = self.secure()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            endpoint = f"opc.tcp://127.0.0.1:{listener.getsockname()[1]}"
            wrong_key = [*options[:-1], str(self.folder / "imposter.key")]
            rejected = self.collect("--preflight", *wrong_key, endpoint=endpoint)
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(rejected.stdout, "")
            self.assertIn("key", rejected.stderr.lower())

            ready = self.collect("--preflight", *options, endpoint=endpoint)
            self.assertEqual(ready.returncode, 0, ready.stderr)
            self.assertIn("preflight", ready.stdout.lower())
            listener.setblocking(False)
            with self.assertRaises(BlockingIOError):
                listener.accept()
        captured = self.collect(*options)
        self.assertEqual(captured.returncode, 0, captured.stderr)
        self.assertEqual(
            json.loads(captured.stdout)["applicationUri"], CONTRACT["applicationUri"]
        )

    # 022-native-commissioning/SR-001
    def test_preflight_checks_pem_der_local_identity_and_signing_key(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            endpoint = f"opc.tcp://127.0.0.1:{listener.getsockname()[1]}"
            pem = self.secure()
            der = [
                "--server-cert",
                "server.der",
                "--client-cert",
                "client.der",
                "--client-key",
                "client-key.der",
            ]
            key = serialization.load_pem_private_key(
                (self.folder / "client.key").read_bytes(), None
            )
            encodings = [pem, der]
            for suffix, encoding in [
                ("pem", serialization.Encoding.PEM),
                ("der", serialization.Encoding.DER),
            ]:
                legacy_key = self.folder / f"pkcs1.{suffix}"
                legacy_key.write_bytes(
                    key.private_bytes(
                        encoding,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    )
                )
                encodings.append([*der[:-1], legacy_key])
            for options in encodings:
                for assertion in [[], ["--client-uri", "urn:fixture:client"]]:
                    ready = self.collect(
                        "--preflight", *options, *assertion, endpoint=endpoint
                    )
                    self.assertEqual(ready.returncode, 0, ready.stderr)
                    self.assertIn("offline", ready.stdout.lower())
                    self.assertEqual(ready.stderr, "")
            ambiguous = self.folder / "ambiguous-identity"
            ambiguous.mkdir()
            certificate(
                ambiguous,
                "client",
                uri="urn:fixture:client",
                extra_uri="urn:fixture:second",
            )
            multiple_uris = [
                *pem[:3],
                str(ambiguous / "client.pem"),
                "--client-key",
                str(ambiguous / "client.key"),
            ]
            for options in [
                multiple_uris,
                [*multiple_uris, "--client-uri", "urn:fixture:client"],
                [*pem, "--client-uri", "urn:fixture:wrong-client"],
                self.secure("expired"),
                self.secure("wronghost"),
                [*pem[:3], "server.pem", *pem[4:]],
                [*pem[:-1], "client.pem"],
            ]:
                with self.subTest(options=options):
                    refused = self.collect("--preflight", *options, endpoint=endpoint)
                    self.assertEqual(refused.returncode, 1, refused.stderr)
                    self.assertEqual(refused.stdout, "")
                    self.assertNotIn("BEGIN", refused.stderr)
            listener.setblocking(False)
            with self.assertRaises(BlockingIOError):
                listener.accept()

    def test_preflight_requires_an_application_leaf_and_absolute_uri(self):
        for label, profile in [
            ("issuer", {"ca": True}),
            ("unconstrained", {"ca": None}),
            ("relative", {"uri": "relative"}),
            ("empty", {"uri": ""}),
        ]:
            with self.subTest(profile=label):
                case = self.folder / label
                case.mkdir()
                certificate(case, "client", **profile)
                options = [
                    "--server-cert",
                    "server.pem",
                    "--client-cert",
                    case / "client.pem",
                    "--client-key",
                    case / "client.key",
                ]
                refused = self.collect("--preflight", *options)
                self.assertEqual(refused.returncode, 1, refused.stderr)
                self.assertEqual(refused.stdout, "")
                self.assertNotIn("PRIVATE KEY", refused.stderr)

    def test_encrypted_meter_evidence_preserves_register_and_clock(self):
        # 006-meter-pilot/SR-001 006-meter-pilot/SR-002
        self.check_meter_handoff("GridImportWh", "i=9", 2**53 + 1)

    def test_encrypted_float_meter_retains_bits_and_projects_exact_wh(self):
        # 007-float-meter/SR-001
        self.check_meter_handoff("GridImportFloatWh", "i=10", 1000000)

    def test_encrypted_double_meter_retains_low_bit_and_reconciles_wh(self):
        # 008-double-meter/SR-001 008-double-meter/SR-002
        self.check_meter_handoff("GridImportDoubleWh", "i=11", 2**52 + 1)

    def read_meter(self, path, contract, endpoint, *, repeat=False, timeout=5):
        if path == "cli-pem":
            return self.collect(
                *self.secure(), contract=contract, endpoint=endpoint, meter=True
            )
        if path == "cli":
            return self.collect(
                "--client-uri",
                "urn:fixture:client",
                "--server-cert",
                "server.der",
                "--client-cert",
                "client.der",
                "--client-key",
                "client-key.der",
                "--timeout",
                str(timeout),
                contract=contract,
                endpoint=endpoint,
                meter=True,
                env={**os.environ, "PATH": ""},
            )
        (self.folder / "contract.json").write_text(json.dumps(contract))
        return subprocess.run(
            [
                os.environ["OPCUA_KIT_NATIVE_COMMISSIONING_BIN"],
                self.folder,
                endpoint,
                "server",
                "meter-repeat" if repeat else "meter",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            cwd=self.folder,
            env={**os.environ, "PATH": ""},
        )

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_COMMISSIONING_BIN"), "requires meter consumer"
    )
    def test_native_meter_evidence_projects_all_approved_registers(self):
        # 016-native-meter-reading/SR-001 016-native-meter-reading/SR-002
        for path in ("library", "cli"):
            for node, dtype, start_wh in [
                ("GridImportU32Wh", "i=7", 4_000_000_001),
                ("GridImportWh", "i=9", 2**53 + 1),
                ("GridImportFloatWh", "i=10", 1_000_000),
                ("GridImportDoubleWh", "i=11", 2**52 + 1),
            ]:
                with self.subTest(path=path, node=node):
                    self.check_meter_handoff(node, dtype, start_wh, path)

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_COMMISSIONING_BIN"), "requires meter consumer"
    )
    def test_native_meter_preflight_observes_only_authorized_attributes(self):
        # 016-native-meter-reading/SR-001
        endpoint = self.limited_peer(1)
        contract = meter_contract("GridImportWh", "i=9")
        meter, units, missing = (
            "s=GridImportWh",
            "s=GridImportWhUnits",
            "s=MissingUnitWh",
        )
        for path in ("library", "cli"):
            for candidate in [
                {**contract, "applicationUri": "urn:fixture:other"},
                {**contract, "principal": "operator"},
            ]:
                result = self.read_meter(path, candidate, endpoint)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(self.observed_target_reads(1)[1], [])
                self.assertFalse((self.folder / "limit1.browse").exists())
            result = self.read_meter(
                path, meter_contract("MissingUnitWh", "i=9"), endpoint
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                self.observed_target_reads(1)[1], [[(missing, 14)], [(missing, 15)]]
            )
            self.observe_unit_browses(1, ["MissingUnitWh"])
            result = self.read_meter(path, contract, endpoint)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                self.observed_target_reads(1)[1],
                [
                    [(meter, 14)],
                    [(meter, 15)],
                    [(units, 14)],
                    [(units, 15)],
                    [(units, 13)],
                    [(meter, 13)],
                ],
            )
            self.observe_unit_browses(1, ["GridImportWh"])

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_COMMISSIONING_BIN"), "requires meter consumer"
    )
    def test_native_meter_independent_clocks_quality_and_repeat_preflight(self):
        # 016-native-meter-reading/SR-001 016-native-meter-reading/SR-002
        from asyncua import ua
        from peers.asyncua_server import attribute_peer

        async def exercise():
            state = {}
            contract = meter_contract("TestRegister", "i=9")
            async with attribute_peer(self.folder, meter=state) as endpoint:

                async def attempt(path, count, *, repeat=False):
                    before = len(state["reads"])
                    result = await asyncio.to_thread(
                        self.read_meter,
                        path,
                        contract,
                        endpoint,
                        repeat=repeat,
                    )
                    self.assertEqual(len(state["reads"]) - before, count, result.stderr)
                    return result

                register = state["register"].Value
                rank, unit = state["rank"], state["unit"]
                source = datetime(2020, 10, 25, 0, 45, tzinfo=UTC)
                server_time = datetime(2020, 10, 25, 0, 46, 0, 123456, tzinfo=UTC)
                for path in ("library", "cli"):
                    for code, flagged_good in [(0x00004000, True), (0x801F0000, False)]:
                        state["register"] = ua.DataValue(
                            register
                            if flagged_good
                            else ua.Variant("ignore Bad payload"),
                            StatusCode=ua.StatusCode(code),
                            SourceTimestamp=source
                            if flagged_good
                            else datetime(1601, 1, 1, tzinfo=UTC),
                            ServerTimestamp=server_time,
                            ServerPicoseconds=100,
                        )
                        result = await attempt(path, 1)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        reading = json.loads(result.stdout)
                        self.assertEqual(reading["status"], code)
                        self.assertNotIn("valueBits", reading)
                        self.assertEqual(
                            reading["serverAt"], "2020-10-25T00:46:00.123456001Z"
                        )
                        if flagged_good:
                            self.assertEqual(reading["value"], 42)
                            self.assertEqual(
                                reading["sourceAt"], "2020-10-25T00:45:00Z"
                            )
                        else:
                            self.assertNotIn("value", reading)
                            self.assertIsNone(reading["sourceAt"])
                    # Exercise source increments separately. asyncua 2.1.0 encodes
                    # both base timestamps before both increments when all four are set.
                    state["register"] = ua.DataValue(
                        register, SourceTimestamp=source, SourcePicoseconds=300
                    )
                    result = await attempt(path, 1)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    reading = json.loads(result.stdout)
                    self.assertEqual(
                        reading["sourceAt"], "2020-10-25T00:45:00.000000003Z"
                    )
                    self.assertIsNone(reading["serverAt"])
                    for field, bad in [
                        ("rank", ua.DataValue(ua.Variant(1, ua.VariantType.Int32))),
                        (
                            "rank",
                            ua.DataValue(rank.Value, StatusCode=ua.StatusCode(0x4000)),
                        ),
                        (
                            "unit",
                            ua.DataValue(
                                unit.Value, StatusCode=ua.StatusCode(0x40904000)
                            ),
                        ),
                        (
                            "unit_rank",
                            ua.DataValue(rank.Value, StatusCode=ua.StatusCode(0x4000)),
                        ),
                        (
                            "register",
                            ua.DataValue(
                                register, SourceTimestamp=source, SourcePicoseconds=1
                            ),
                        ),
                        (
                            "register",
                            ua.DataValue(ua.Variant(-42, ua.VariantType.Int64)),
                        ),
                    ]:
                        prior = state[field]
                        state[field] = bad
                        result = await attempt(path, int(field == "register"))
                        self.assertNotEqual(
                            result.returncode, 0, (field, result.stdout)
                        )
                        self.assertEqual(result.stdout, "")
                        if field == "unit_rank":
                            self.assertIn("ValueRank", result.stderr)
                            self.assertIn("0x00004000", result.stderr)
                        state[field] = prior
                state["register"] = ua.DataValue(register)
                state["unit_after_register"] = ua.DataValue(
                    StatusCode=ua.StatusCode(0x801F0000)
                )
                result = await attempt("library", 1, repeat=True)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")
                self.assertIn("0x801F0000", result.stderr)

        asyncio.run(exercise())

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_BIN"), "requires installed native CLI"
    )
    def test_native_meter_cli_total_deadline_expires_before_register(self):
        # 016-native-meter-reading/SR-001
        from peers.asyncua_server import attribute_peer

        async def exercise():
            state = {"delays": {14: 0.3, 15: 0.85}, "delayed": []}
            async with attribute_peer(self.folder, meter=state) as endpoint:
                result = await asyncio.to_thread(
                    self.read_meter,
                    "cli",
                    meter_contract("TestRegister", "i=9"),
                    endpoint,
                    timeout=1,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("deadline", result.stderr.lower())
                self.assertEqual(state["delayed"], [14, 15])
                self.assertEqual(state["reads"], [])

        asyncio.run(exercise())

    def check_meter_handoff(self, node, dtype, start_wh, path="cli-pem"):
        contract = meter_contract(node, dtype)
        signal = contract["signals"][0]

        def read_count(label):
            return int((self.folder / f"{label}.{node}.reads").read_text())

        # The peer observes the OPC UA ReadRequest, including when the server
        # can satisfy it from cache. A metadata snapshot must never read this Value.
        initial = read_count("server")
        if path == "cli-pem":
            snapshot = self.collect(*self.secure(), contract=contract)
            self.assertEqual(snapshot.returncode, 0, snapshot.stderr)
            self.assertEqual(read_count("server"), initial)
        before_wrong_unit = read_count("wrongunit")
        wrong_unit = self.read_meter(path, contract, self.wrong_unit)
        self.assertNotEqual(wrong_unit.returncode, 0)
        self.assertEqual(wrong_unit.stdout, "")
        self.assertEqual(read_count("wrongunit"), before_wrong_unit)
        records = []
        for endpoint, reading, source in [
            (self.url, start_wh, "2020-10-25T00:45:00"),
            (self.reordered, start_wh + 285000, "2020-10-25T01:00:00"),
        ]:
            started = datetime.now(UTC)
            out = self.read_meter(path, contract, endpoint)
            self.assertEqual(out.returncode, 0, out.stderr)
            record = json.loads(out.stdout)
            for key in ("schemaVersion", "applicationUri", "device", "principal"):
                self.assertEqual(record[key], contract[key], key)
            for key, value in signal.items():
                self.assertEqual(record[key], value, key)
            self.assertEqual(record["status"], 0)
            if dtype in ("i=10", "i=11"):
                expected_bits = (
                    int.from_bytes(struct.pack("<f", reading), "little")
                    if dtype == "i=10"
                    else struct.pack(">d", reading).hex()
                )
                self.assertEqual(record["valueBits"], expected_bits)
                self.assertNotIn("value", record)
            else:
                self.assertEqual(record["value"], reading)
                self.assertNotIn("valueBits", record)
            self.assertEqual(
                datetime.fromisoformat(record["sourceAt"]),
                datetime.fromisoformat(source).replace(tzinfo=UTC),
            )
            self.assertIsNotNone(datetime.fromisoformat(record["serverAt"]).tzinfo)
            receipt = datetime.fromisoformat(record["receivedAt"])
            self.assertLessEqual(started, receipt)
            self.assertLessEqual(receipt, datetime.now(UTC))
            records.append(record)
        self.assertEqual(read_count("server") - initial, 1)
        degraded = self.read_meter(path, contract, self.uncertain)
        self.assertEqual(degraded.returncode, 0, degraded.stderr)
        unusable = json.loads(degraded.stdout)
        self.assertEqual(unusable["status"], 0x40900000)
        self.assertNotIn("value", unusable)
        self.assertNotIn("valueBits", unusable)
        cases = [
            (
                records,
                [start_wh, start_wh + 285000],
                "within_tolerance",
                self.reordered,
            ),
            ([records[0], unusable], [start_wh], "missing_boundary", self.uncertain),
        ]
        if dtype in ("i=10", "i=11"):
            coarse = self.read_meter(path, contract, self.coarse)
            self.assertEqual(coarse.returncode, 0, coarse.stderr)
            record = json.loads(coarse.stdout)
            self.assertEqual(record["status"], 0)
            cutoff = 0x4B800000 if dtype == "i=10" else "4340000000000000"
            self.assertEqual(record["valueBits"], cutoff)
            self.assertNotIn("value", record)
            cases.append(
                ([records[0], record], [start_wh], "missing_boundary", self.coarse)
            )
        if binary := os.environ.get("OPCUA_KIT_BIN"):
            window = self.folder / "meter-window.json"
            window.write_text(
                json.dumps(
                    {
                        "meter": {
                            "device": contract["device"],
                            "applicationUri": contract["applicationUri"],
                            "node": signal["node"],
                        },
                        "start": "2020-10-25T02:45:00+02:00",
                        "end": "2020-10-25T02:00:00+01:00",
                        "tolerance_wh": 1,
                        "closed": [{"at": "2020-10-25T02:45:00+02:00", "wh": 284999}],
                    }
                )
            )
            for rows, projected_wh, expected_status, second_endpoint in cases:
                trace = subprocess.run(
                    [
                        binary,
                        "meter",
                        "trace",
                        "--contract",
                        str(self.folder / "contract.json"),
                        "--window",
                        str(window),
                        "--readings",
                        "-",
                    ],
                    input="".join(json.dumps(record) + "\n" for record in rows),
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(trace.returncode, 0, trace.stderr)
                self.assertEqual(
                    [p["wh"] for p in json.loads(trace.stdout)["register"]],
                    projected_wh,
                )
                summary, *details = trace.stderr.splitlines()
                if second_endpoint == self.reordered:
                    self.assertEqual(details, [])
                else:
                    reason = (
                        "OPC UA status 0x40900000"
                        if second_endpoint == self.uncertain
                        else "register cannot resolve 1 Wh increments"
                    )
                    self.assertEqual(
                        details,
                        [f"First exclusion at readings line 2 (source 2020-10-25T01:00:00Z): {reason}."],
                    )
                artifact = trace.stdout
                if path == "library":
                    # Push two authenticated readings directly in Rust; only the
                    # finished trace crosses this process boundary.
                    direct = subprocess.run(
                        [
                            os.environ["OPCUA_KIT_NATIVE_COMMISSIONING_BIN"],
                            self.folder,
                            self.url,
                            "server",
                            "meter-project",
                            second_endpoint,
                            node,
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=30,
                        env={**os.environ, "PATH": ""},
                    )
                    self.assertEqual(direct.returncode, 0, direct.stderr)
                    document = json.loads(direct.stdout)
                    self.assertEqual(document["trace"], json.loads(trace.stdout))
                    self.assertEqual(
                        [len(projected_wh), *document["counters"]],
                        [int(n) for n in re.findall(r"\d+", summary)],
                    )
                    artifact = json.dumps(document["trace"])
                if cemsd := os.environ.get("OPCUA_KIT_CEMSD_BIN"):
                    trace_file = self.folder / "peer-trace.json"
                    trace_file.write_text(artifact)
                    result = subprocess.run(
                        [cemsd, "reconcile", str(trace_file)],
                        text=True,
                        capture_output=True,
                        check=False,
                        timeout=10,
                    )
                    usable = expected_status == "within_tolerance"
                    self.assertEqual(
                        result.returncode, 0 if usable else 1, result.stderr
                    )
                    report = json.loads(result.stdout)
                    self.assertEqual(report["intervals"][0]["status"], expected_status)
                    self.assertEqual(
                        report["max_absolute_difference_wh"], 1 if usable else None
                    )
        # Select a valid Wh register contract that disagrees with the server's DataType.
        before_wrong_type = read_count("server")
        wrong_type = {
            **signal,
            "dataType": {"namespace": UA, "id": "i=9" if dtype == "i=7" else "i=7"},
        }
        out = self.read_meter(path, {**contract, "signals": [wrong_type]}, self.url)
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(out.stdout, "")
        self.assertEqual(read_count("server"), before_wrong_type)

    def test_secure_metadata_matches_independent_peer(self):
        # 001-commissioning-check/SR-001, 001-commissioning-check/SR-005
        result = self.collect(*self.secure())
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot = json.loads(result.stdout)
        rows = {row["name"]: row for row in snapshot["signals"]}
        self.assertEqual(
            rows["sensor"]["dataType"],
            {"status": 0, "value": {"namespace": UA, "id": "i=12"}},
        )
        self.assertEqual(rows["sensor"]["valueRank"], {"status": 0, "value": -1})
        self.assertEqual(rows["unknown"]["dataType"], {"status": 0x80340000})
        self.assertNotIn("PRIVATE PROCESS VALUE", result.stdout + result.stderr)
        self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_COMMISSIONING_BIN"),
        "requires native commissioning consumer",
    )
    def test_native_snapshot_reads_only_scoped_metadata_and_supports_offline_tools(
        self,
    ):
        # 018-native-snapshot/SR-001 018-native-snapshot/SR-002
        endpoint = self.limited_peer(1)
        custom = {"namespace": "urn:fixture:types", "id": "i=7401"}
        missing = snapshot_signal("MissingNamespace", rank=True, unit=True)
        missing["node"]["namespace"] = "urn:fixture:absent"
        signals = [
            snapshot_signal("UncertainUnit", unit=True),
            missing,
            snapshot_signal("Sensor", "i=12", unit=True),
            snapshot_signal("Temperature", custom, rank=True, unit=True),
            snapshot_signal("GridImportWh", "i=9"),
            snapshot_signal("absent", rank=True),
        ]
        contract = {**CONTRACT, "signals": signals}
        bad_node = {"status": 0x80340000}

        def good(value):
            return {"status": 0, "value": value}

        fields = [
            {
                "dataType": good(signals[0]["dataType"]),
                "engineeringUnits": {"status": 0x40904000},
            },
            {},
            {
                "dataType": good(signals[2]["dataType"]),
                "engineeringUnits": {"status": 0},
            },
            {
                "dataType": good(custom),
                "valueRank": good(-1),
                "engineeringUnits": good(signals[3]["engineeringUnits"]),
            },
            {"dataType": good(signals[4]["dataType"])},
            {"dataType": bad_node, "valueRank": bad_node},
        ]
        expected = {
            **CONTRACT,
            "signals": [
                {"name": s["name"], "node": s["node"], **f}
                for s, f in zip(signals, fields, strict=True)
            ],
        }
        for route in ("library", "cli"):
            result = self.capture_native(route, endpoint, contract)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), expected)
            self.assertNotIn("PRIVATE", result.stdout + result.stderr)
            _, calls = self.observed_target_reads(1)
            self.assertCountEqual(
                [operand for call in calls for operand in call],
                [
                    (f"s={node}", attr)
                    for node, attrs in [
                        ("UncertainUnit", (14,)),
                        ("UncertainUnitProperty", (14, 15, 13)),
                        ("Sensor", (14,)),
                        ("Temperature", (14, 15)),
                        ("UnitProperty", (14, 15, 13)),
                        ("GridImportWh", (14,)),
                        ("absent", (14, 15)),
                    ]
                    for attr in attrs
                ],
            )
            self.observe_unit_browses(1, ["UncertainUnit", "Sensor", "Temperature"])

        binary = os.environ["OPCUA_KIT_BIN"]
        report = subprocess.run(
            [
                binary,
                "check",
                "--contract",
                self.folder / "contract.json",
                "--snapshot",
                "-",
                "--json",
            ],
            input=result.stdout,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(report.returncode, 3, report.stderr)
        (unavailable,) = [
            f
            for f in json.loads(report.stdout)["findings"]
            if f["name"] == "Sensor" and f["attribute"] == "EngineeringUnits"
        ]
        self.assertEqual(
            (unavailable["after"], unavailable["outcome"]),
            ({"status": 0}, "unverified"),
        )

        single = {**CONTRACT, "signals": [signals[3]]}
        saved = self.folder / "native-reviewed.json"
        saved.write_bytes(b"previous capture")
        published = self.capture_native("cli", self.url, single, output=saved)
        self.assertEqual(
            (published.returncode, published.stdout), (0, ""), published.stderr
        )
        self.assertEqual(
            json.loads(saved.read_text())["signals"], [expected["signals"][3]]
        )
        draft = subprocess.run(
            [binary, "contract", "draft", "--snapshot", saved],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(draft.returncode, 0, draft.stderr)
        self.assertEqual(json.loads(draft.stdout), single)

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_COMMISSIONING_BIN"),
        "requires native commissioning consumer",
    )
    def test_native_snapshot_late_service_error_discards_earlier_rows(self):
        # 018-native-snapshot/SR-002
        endpoint = self.limited_peer(2)
        # The peer advertises two Read operands, then changes its limit to one
        # before serving LowerLimit. The first row was already collected.
        signals = [
            snapshot_signal("Sensor", "i=12"),
            snapshot_signal("LowerLimit", rank=True),
            snapshot_signal("GridImportWh", "i=9"),
        ]
        output = self.folder / "prior-service-error.json"
        output.write_bytes(b"prior snapshot")
        for route in ("library", "cli"):
            result = self.capture_native(
                route, endpoint, {**CONTRACT, "signals": signals}, output=output
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("signals[1]", result.stderr)
            self.assertEqual(output.read_bytes(), b"prior snapshot")
            self.assertEqual(
                self.observed_target_reads(2)[1],
                [
                    [("s=Sensor", 14)],
                    [("s=LowerLimit", 14), ("s=LowerLimit", 15)],
                ],
            )

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_COMMISSIONING_BIN"),
        "requires native commissioning consumer",
    )
    def test_native_snapshot_structural_failure_preserves_output_and_scope(self):
        # 018-native-snapshot/SR-001
        endpoint = self.limited_peer(1)
        output = self.folder / "native-last-known-good.json"
        output.write_bytes(b"previous reviewed snapshot")
        temp = snapshot_signal("Temperature", unit=True)
        alias = snapshot_signal("UnitProperty")
        for signals, browse in [
            ([temp, alias], "Temperature"),
            ([alias, temp], "Temperature"),
            ([snapshot_signal("WrongUnitRank", unit=True)], "WrongUnitRank"),
            ([snapshot_signal("AmbiguousUnits", unit=True)], "AmbiguousUnits"),
        ]:
            for route in ("cli", "library"):
                result = self.capture_native(
                    route, endpoint, {**CONTRACT, "signals": signals}, output=output
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(output.read_bytes(), b"previous reviewed snapshot")
                _, calls = self.observed_target_reads(1)
                operands = [operand for call in calls for operand in call]
                self.assertTrue(all(attr != 13 for _, attr in operands), operands)
                if signals[0] is temp:
                    self.assertFalse(
                        any(node == "s=UnitProperty" for node, _ in operands), operands
                    )
                self.observe_unit_browses(1, [browse])
                if browse == "AmbiguousUnits":
                    (self.folder / "limit1.pages").unlink()

        reserved = snapshot_signal("ReadLimit")
        reserved["node"] = {"namespace": UA, "id": "i=11705"}
        for bad in [
            {"principal": "operator"},
            {"applicationUri": "urn:fixture:other"},
            {"signals": [*CONTRACT["signals"], reserved]},
        ]:
            for route in ("library", "cli"):
                failed = self.capture_native(
                    route, endpoint, {**CONTRACT, **bad}, output=output
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertEqual(failed.stdout, "")
                wire, targets = self.observed_target_reads(1)
                self.assertEqual(targets, [])
                self.assertFalse(
                    any(["ns=0;i=11705", 13] in request for request in wire), wire
                )
                self.assertEqual(output.read_bytes(), b"previous reviewed snapshot")

    @unittest.skipUnless(
        os.environ.get("OPCUA_KIT_NATIVE_COMMISSIONING_BIN"),
        "requires native commissioning consumer",
    )
    def test_native_snapshot_on_asyncua_preserves_field_quality_and_rejects_unsafe_references(
        self,
    ):
        # 018-native-snapshot/SR-001 018-native-snapshot/SR-002
        from peers.asyncua_server import attribute_peer

        async def exercise():
            reads = []
            state = {"delays": {14: 0.3, 15: 0.85}, "delayed": []}
            async with attribute_peer(
                self.folder, read_log=reads, meter=state
            ) as endpoint:
                custom = {"namespace": "urn:fixture:types", "id": "i=7401"}
                signals = [
                    snapshot_signal(name, custom, rank=True)
                    for name in ("FlaggedRank", "DeniedRank")
                ]
                signals.append(snapshot_signal("Temperature", custom, unit=True))
                contract = {**CONTRACT, "signals": signals}
                previous = self.folder / "last-asyncua-snapshot.json"
                previous.write_bytes(b"trusted prior bytes")
                for route in ("cli", "library"):
                    result = await asyncio.to_thread(
                        self.capture_native, route, endpoint, contract
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    flagged, denied, temp = json.loads(result.stdout)["signals"]
                    self.assertEqual(
                        flagged["valueRank"], {"status": 0x4000, "value": -1}
                    )
                    self.assertEqual(denied["valueRank"], {"status": 0x801F0000})
                    for row in [flagged, denied, temp]:
                        self.assertEqual(
                            row["dataType"], {"status": 0, "value": custom}
                        )
                    self.assertNotIn("valueRank", temp)
                    self.assertEqual(
                        temp["engineeringUnits"],
                        {
                            "status": 0,
                            "value": {
                                "namespaceUri": "urn:fixture:unit-catalog",
                                "unitId": 0x43454C,
                            },
                        },
                    )
                    self.assertEqual(
                        [n for n, attr in reads if attr == 13], ["TemperatureUnits"]
                    )
                    for rows in [
                        [snapshot_signal("MalformedRank", rank=True)],
                        [snapshot_signal("RemoteUnit", unit=True)],
                        [
                            snapshot_signal("AliasViaUri", unit=True),
                            snapshot_signal("TemperatureUnits"),
                        ],
                    ]:
                        reads.clear()
                        failed = await asyncio.to_thread(
                            self.capture_native,
                            route,
                            endpoint,
                            {**CONTRACT, "signals": rows},
                            output=previous,
                        )
                        self.assertNotEqual(failed.returncode, 0)
                        self.assertEqual(failed.stdout, "")
                        self.assertTrue(
                            all(n != "TemperatureUnits" and a != 13 for n, a in reads),
                            reads,
                        )
                        self.assertEqual(previous.read_bytes(), b"trusted prior bytes")
                    reads.clear()
                expired = await asyncio.to_thread(
                    self.capture_native,
                    "cli",
                    endpoint,
                    {
                        **CONTRACT,
                        "signals": [snapshot_signal("TestRegister", unit=True)],
                    },
                    output=previous,
                    timeout=1,
                )
                self.assertNotEqual(expired.returncode, 0)
                self.assertEqual(expired.stdout, "")
                self.assertEqual(previous.read_bytes(), b"trusted prior bytes")
                self.assertEqual(state["delayed"], [14, 15])
                self.assertFalse(any(a == 13 for _, a in reads))

        asyncio.run(exercise())

    def test_first_inspection_of_encrypted_capture(self):
        # 003-first-inspection/SR-001, 003-first-inspection/SR-002
        captured = self.collect(*self.secure())
        self.assertEqual(captured.returncode, 0, captured.stderr)
        contract = self.folder / "inspection-contract.json"
        contract.write_text(json.dumps(CONTRACT))
        binary = os.environ.get("OPCUA_KIT_BIN") or str(ROOT / "target/debug/opcua-kit")
        result = subprocess.run(
            [binary, "check", "--contract", str(contract), "--snapshot", "-", "--json"],
            input=captured.stdout,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["schemaVersion"], 2)
        self.assertFalse(report["baselineProvided"])
        self.assertFalse(report["complete"])
        self.assertEqual(
            report["counts"], {"matched": 2, "unverified": 1, "mismatch": 0}
        )
        for key in ("device", "applicationUri", "principal"):
            self.assertEqual(report[key], CONTRACT[key])
        for finding in report["findings"]:
            self.assertIsNone(finding["before"])
            self.assertIsNone(finding["beforeOutcome"])
        (unreadable,) = [f for f in report["findings"] if f["name"] == "unknown"]
        self.assertEqual(unreadable["outcome"], "unverified")
        self.assertEqual(unreadable["after"], {"status": 0x80340000})

    def test_draft_and_validate_from_encrypted_reference(self):
        # 004-contract-authoring/SR-001 004-contract-authoring/SR-003
        # A selected known signal exposes its stable type and scalar rank.
        contract = {**CONTRACT, "signals": CONTRACT["signals"][:1]}
        captured = self.collect(*self.secure(), contract=contract)
        self.assertEqual(captured.returncode, 0, captured.stderr)
        binary = os.environ.get("OPCUA_KIT_BIN") or str(ROOT / "target/debug/opcua-kit")

        def run(*args, data):
            return subprocess.run(
                [binary, *args],
                input=data,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

        drafted = run("contract", "draft", "--snapshot", "-", data=captured.stdout)
        self.assertEqual(drafted.returncode, 0, drafted.stderr)
        self.assertEqual(json.loads(drafted.stdout), contract)
        valid = run("contract", "validate", "--contract", "-", data=drafted.stdout)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        reviewed = self.folder / "reference-contract.json"
        reviewed.write_text(drafted.stdout)
        assessed = run(
            "check",
            "--contract",
            str(reviewed),
            "--snapshot",
            "-",
            "--json",
            data=captured.stdout,
        )
        self.assertEqual(assessed.returncode, 0, assessed.stderr)
        self.assertEqual(
            json.loads(assessed.stdout)["counts"],
            {"matched": 2, "unverified": 0, "mismatch": 0},
        )

        # The same endpoint returns BadNodeIdUnknown for the extra contracted row.
        partial = self.collect(*self.secure())
        self.assertEqual(partial.returncode, 0, partial.stderr)
        rejected = run("contract", "draft", "--snapshot", "-", data=partial.stdout)
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(rejected.stdout, "")
        self.assertIn("0x80340000", rejected.stderr)

    def test_reordered_signal_and_custom_datatype_check_cleanly(self):
        signal_node = {"namespace": "urn:fixture:hvac", "id": "s=Temperature"}
        custom_type = {"namespace": "urn:fixture:types", "id": "i=7401"}
        signal = {
            "name": "temp",
            "node": signal_node,
            "dataType": custom_type,
            "valueRank": -1,
        }
        contract = {**CONTRACT, "signals": [signal]}
        original = json.loads((self.folder / "server.indexes").read_text())
        reordered = json.loads((self.folder / "reordered.indexes").read_text())
        self.assertNotEqual(original["signal"], reordered["signal"])
        self.assertNotEqual(original["type"], reordered["type"])
        files = []
        for name, endpoint in (("before", self.url), ("after", self.reordered)):
            result = self.collect(*self.secure(), endpoint=endpoint, contract=contract)
            self.assertEqual(result.returncode, 0, result.stderr)
            snap = json.loads(result.stdout)
            self.assertEqual(snap["applicationUri"], contract["applicationUri"])
            self.assertEqual(snap["signals"][0]["node"], signal_node)
            self.assertEqual(
                snap["signals"][0]["dataType"], {"status": 0, "value": custom_type}
            )
            path = self.folder / f"{name}.json"
            path.write_text(result.stdout)
            files.append(path)
        checked = self.check_captures(contract, files)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        report = json.loads(checked.stdout)
        self.assertEqual(report["decision"], "matched")
        self.assertTrue(report["complete"])
        self.assertEqual(
            report["counts"], {"matched": 2, "mismatch": 0, "unverified": 0}
        )

    def check_captures(self, contract, files):
        contract_file = self.folder / "contract.json"
        contract_file.write_text(json.dumps(contract))
        binary = os.environ.get("OPCUA_KIT_BIN") or str(ROOT / "target/debug/opcua-kit")
        return subprocess.run(
            [
                binary,
                "check",
                "--contract",
                str(contract_file),
                "--before",
                str(files[0]),
                "--after",
                str(files[1]),
                "--json",
            ],
            check=False,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def test_secure_unit_only_drift(self):
        # 002-engineering-units/SR-002, 002-engineering-units/SR-004
        namespace = "http://www.opcfoundation.org/UA/units/un/cefact"
        expected = {"namespaceUri": namespace, "unitId": 0x43454C}
        signal = {
            "name": "temp",
            "node": {**SIGNAL, "id": "s=Temperature"},
            "dataType": {"namespace": "urn:fixture:types", "id": "i=7401"},
            "valueRank": -1,
            "engineeringUnits": expected,
        }
        contract = {**CONTRACT, "signals": [signal]}
        files = []
        for name, endpoint, unit in (
            ("baseline", self.url, 0x43454C),
            ("replacement", self.reordered, 0x464148),
        ):
            result = self.collect(*self.secure(), endpoint=endpoint, contract=contract)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("PRIVATE", result.stdout + result.stderr)
            row = json.loads(result.stdout)["signals"][0]
            self.assertEqual(
                row["engineeringUnits"],
                {"status": 0, "value": {**expected, "unitId": unit}},
            )
            path = self.folder / f"{name}.json"
            path.write_text(result.stdout)
            files.append(path)
        checked = self.check_captures(contract, files)
        self.assertEqual(checked.returncode, 2, checked.stderr)
        report = json.loads(checked.stdout)
        self.assertEqual(
            report["counts"], {"matched": 2, "mismatch": 1, "unverified": 0}
        )
        (finding,) = [
            item for item in report["findings"] if item["outcome"] == "mismatch"
        ]
        self.assertEqual(
            (finding["attribute"], finding["beforeOutcome"]),
            ("EngineeringUnits", "matched"),
        )

        repaired = self.check_captures(contract, list(reversed(files)))
        self.assertEqual(repaired.returncode, 0, repaired.stderr)
        (unit_finding,) = [
            item
            for item in json.loads(repaired.stdout)["findings"]
            if item["attribute"] == "EngineeringUnits"
        ]
        self.assertEqual(
            (unit_finding["beforeOutcome"], unit_finding["outcome"]),
            ("mismatch", "matched"),
        )

    def test_unit_path_ignores_vendor_property_with_same_name(self):
        # 002-engineering-units/SR-001, 002-engineering-units/SR-002
        signal = {
            **CONTRACT["signals"][0],
            "engineeringUnits": {"namespaceUri": "urn:test:units", "unitId": 12},
        }
        contract = {**CONTRACT, "signals": [signal]}
        result = self.collect(*self.secure(), contract=contract)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("PRIVATE", result.stdout + result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["signals"][0]["engineeringUnits"],
            {
                "status": 0
            },  # The peer completed Browse and returned no matching property.
        )
        snapshot = self.folder / "missing-property.json"
        snapshot.write_text(result.stdout)
        checked = self.check_captures(contract, [snapshot, snapshot])
        self.assertEqual(checked.returncode, 3, checked.stderr)
        self.assertEqual(
            json.loads(checked.stdout)["counts"],
            {"matched": 2, "mismatch": 0, "unverified": 1},
        )

    # 022-native-commissioning/SR-003
    def test_unit_target_alias_preserves_previous_snapshot(self):
        # 002-engineering-units/SR-001, 002-engineering-units/SR-003
        if not os.environ.get("OPCUA_KIT_BIN"):
            self.skipTest("atomic file publication is provided by the Rust CLI")
        expected = {"namespaceUri": "urn:test:units", "unitId": 1}
        contract = {
            **CONTRACT,
            "signals": [
                {
                    **CONTRACT["signals"][0],
                    "node": {**SIGNAL, "id": "s=Temperature"},
                    "engineeringUnits": expected,
                },
                {**CONTRACT["signals"][1], "node": {**SIGNAL, "id": "s=UnitProperty"}},
            ],
        }
        previous = self.folder / "last-known-good.json"
        previous.write_bytes(b"previous snapshot")
        rejected = self.collect(
            *self.secure(), "--output", str(previous), contract=contract
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, "")
        self.assertIn("aliases a contracted signal", rejected.stderr)
        self.assertEqual(previous.read_bytes(), b"previous snapshot")

    def test_rejects_unapproved_pin_host_time_and_uri(self):
        # 001-commissioning-check/SR-001
        for pin in ["imposter", "wronghost", "expired"]:
            with self.subTest(pin=pin):
                result = self.collect(*self.secure(pin))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        other = copy.deepcopy(CONTRACT)
        other["applicationUri"] = "urn:fixture:wrong-app"
        result = self.collect(*self.secure(), contract=other)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_correct_pin_wrong_signed_session_identity(self):
        # 001-commissioning-check/SR-001
        result = self.collect(*self.secure(), endpoint=self.other_uri)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("BadCertificateUriInvalid", result.stderr)

    def test_live_timeout(self):
        # 001-commissioning-check/SR-003
        with socket.socket() as stalled:
            stalled.bind(("127.0.0.1", 0))
            stalled.listen()
            endpoint = f"opc.tcp://127.0.0.1:{stalled.getsockname()[1]}"
            started = time.monotonic()
            result = self.collect(*self.secure(), "--timeout", "1", endpoint=endpoint)
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(result.returncode, 1)
            self.assertTrue(result.stderr)
            self.assertEqual(result.stdout, "")
            stalled.setblocking(False)
            connection, _ = stalled.accept()
            connection.close()

    def test_capture_refuses_cleartext_even_on_loopback(self):
        # 001-commissioning-check/SR-001
        for host in ("127.0.0.1", "localhost", "192.0.2.1"):
            result = self.collect(
                "--insecure-loopback", endpoint=f"opc.tcp://{host}:4840"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("loopback", result.stderr.lower())
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
