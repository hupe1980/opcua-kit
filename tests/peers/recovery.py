"""Authenticated fresh-session recovery using separate server instances on the same endpoint."""

import asyncio
import socket
import sys
import tempfile
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from unittest.mock import patch

from asyncua import Server, ua
from asyncua.common.callback import CallbackType
from asyncua.common.connection import SecureConnection
from asyncua.server.user_managers import User, UserRole
from cryptography.hazmat.primitives.serialization import Encoding

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capture_peer import certificate


class Readers:
    def __init__(self):
        self.logins = 0

    def get_user(self, iserver, username=None, password=None, certificate=None):
        if (username, password) != ("read-fixture", "local-restart-fixture"):
            return None
        self.logins += 1
        return User(role=UserRole.User)


@asynccontextmanager
async def peer(directory, endpoint, *, generation, wrong_pin=False):
    users = Readers()
    server = Server(user_manager=users)
    await server.init()
    server.set_endpoint(endpoint)
    await server.set_application_uri("urn:fixture:server")
    stem = "wrong" if wrong_pin else "server"
    await server.load_certificate(directory / f"{stem}.der")
    await server.load_private_key(directory / f"{stem}.key", format="pem")
    server.set_security_policy(
        [ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt]
    )
    server.set_identity_tokens([ua.UserNameIdentityToken])
    client_leaf = (directory / "client.der").read_bytes()

    async def check_cert(cert, app):
        if (
            cert.public_bytes(Encoding.DER) != client_leaf
            or app.ApplicationUri != "urn:fixture:client"
        ):
            raise ua.UaStatusCodeError(ua.StatusCodes.BadCertificateUntrusted)

    server.set_certificate_validator(check_cert)
    order = ["meter", "other"] if generation == 1 else ["other", "meter"]
    for name in order:
        ns = await server.register_namespace("urn:recovery:" + name)
        await server.nodes.objects.add_variable(
            ua.NodeId("Counter", ns),
            ua.QualifiedName("Counter", ns),
            ua.Variant(
                generation * 111 if name == "meter" else 999, ua.VariantType.UInt64
            ),
        )
    limit = server.get_node(
        ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead
    )
    await limit.write_value(
        ua.Variant(2 if generation == 1 else 1, ua.VariantType.UInt32)
    )
    reads = []

    async def log(event, service):
        if not event.is_external:
            return
        reads.append(
            [
                (r.NodeId.NamespaceIndex, r.NodeId.Identifier, r.AttributeId)
                for r in event.request_params.NodesToRead
            ]
        )

    server.subscribe_server_callback(CallbackType.PreRead, log)
    async with server:
        yield users, reads


@contextmanager
def short_tokens():
    """Force two renewals with no application requests between them."""
    renewed = asyncio.Event()
    count = 0
    original = SecureConnection.open

    def open_channel(connection, params, server):
        nonlocal count
        if connection.security_policy.URI.endswith("Aes256_Sha256_RsaPss"):
            params.RequestedLifetime = 4000
            if params.RequestType == ua.SecurityTokenRequestType.Renew:
                count += 1
                if count == 2:
                    renewed.set()
        return original(connection, params, server)

    with patch.object(SecureConnection, "open", open_channel):
        yield renewed


async def marker(child, expected):
    async with asyncio.timeout(30):
        while line := await child.stdout.readline():
            if line.decode().strip() == f"TEST {expected}":
                return
    raise AssertionError(f"missing consumer marker {expected}")


async def command(child, text):
    child.stdin.write((text + "\n").encode())
    await child.stdin.drain()


def check_reads(reads, namespace, expected_lengths):
    targets = [ops for ops in reads if any(node == "Counter" for _, node, _ in ops)]
    assert [len(ops) for ops in targets] == expected_lengths, targets
    assert all(index == namespace for ops in targets for index, _, _ in ops), targets
    read_ids = [node for ops in reads for index, node, _ in ops if index == 0]
    assert all(node in read_ids for node in [2254, 2255, 11705]), read_ids


async def run(binary):
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        for stem in ["server", "wrong", "client"]:
            certificate(
                directory,
                stem,
                uri="urn:fixture:client" if stem == "client" else "urn:fixture:server",
            )
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        endpoint = f"opc.tcp://127.0.0.1:{port}/"
        child = None
        try:
            async with peer(directory, endpoint, generation=1) as (users, reads):
                with short_tokens() as renewed:
                    child = await asyncio.create_subprocess_exec(
                        binary,
                        endpoint,
                        directory,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                    )
                    await marker(child, "ready")
                    idle_start = len(reads)
                    await asyncio.wait_for(renewed.wait(), 30)
                    probes = reads[idle_start:]
                    assert probes and all(
                        ops == [(0, ua.ObjectIds.Server, ua.AttributeIds.NodeClass)]
                        for ops in probes
                    ), probes
                    await command(child, "renewed")
                    await marker(child, "initial")
                    assert users.logins == 1
                    check_reads(reads, 2, [2, 1])
            await command(child, "disconnected")
            await marker(child, "gap")
            async with peer(directory, endpoint, generation=2, wrong_pin=True) as (
                users,
                reads,
            ):
                await command(child, "wrong-pin")
                await marker(child, "rejected")
                assert users.logins == 0
                assert all(node != "Counter" for ops in reads for _, node, _ in ops)
            async with peer(directory, endpoint, generation=2) as (users, reads):
                await command(child, "restarted")
                await marker(child, "recovered")
                assert users.logins == 1
                check_reads(reads, 3, [1, 1])
                assert await asyncio.wait_for(child.wait(), 10) == 0
        finally:
            if child and child.returncode is None:
                child.kill()
                await child.wait()
    print(
        "Pinned restart, changed namespace/read limits, one visible gap, named identity and rejected replacement pin passed."
    )


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
