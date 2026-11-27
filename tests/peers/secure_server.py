"""Use independent trusted, untrusted and downgraded clients with the embedded server."""

import asyncio
import socket
import sys
import tempfile
from pathlib import Path

from asyncua import Client, ua
from asyncua.crypto.security_policies import (
    SecurityPolicyAes128Sha256RsaOaep,
    SecurityPolicyAes256Sha256RsaPss,
    SecurityPolicyBasic256Sha256,
)
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capture_peer import certificate
from local_server import denied


async def run(binary, tmp, policy, read_binary=None):
    certificate(tmp, "server", uri="urn:example:server")
    certificate(tmp, "client", uri="urn:example:reader")
    foreign = tmp / "foreign"
    foreign.mkdir()
    certificate(foreign, "client", uri="urn:example:reader")
    key = serialization.load_pem_private_key((tmp / "server.key").read_bytes(), None)
    (tmp / "server-key.der").write_bytes(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    endpoint = f"opc.tcp://127.0.0.1:{port}"
    process = await asyncio.create_subprocess_exec(
        binary,
        str(port),
        "urn:example:server",
        str(tmp / "server.der"),
        str(tmp / "server-key.der"),
        "urn:example:reader",
        str(tmp / "client.der"),
        policy.URI.rsplit("#", 1)[1],
        stdin=asyncio.subprocess.PIPE,
    )

    async def configured(folder, mode):
        client = Client(endpoint, timeout=2)
        client.application_uri = "urn:example:reader"
        await client.set_security(
            policy,
            certificate=folder / "client.der",
            private_key=folder / "client-key.der",
            server_certificate=tmp / "server.der",
            mode=mode,
        )
        return client

    try:
        async with asyncio.timeout(10):
            while True:
                if process.returncode is not None:
                    raise RuntimeError("secure server stopped during startup")
                client = await configured(tmp, ua.MessageSecurityMode.SignAndEncrypt)
                try:
                    await client.connect()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
        async with asyncio.timeout(10):
            try:
                endpoints = await Client(
                    endpoint, timeout=2
                ).connect_and_get_server_endpoints()
                assert endpoints and all(
                    item.SecurityMode == ua.MessageSecurityMode.SignAndEncrypt
                    and item.Server.ApplicationUri == "urn:example:server"
                    and item.SecurityPolicyUri == policy.URI
                    and {token.TokenType for token in item.UserIdentityTokens}
                    == {ua.UserTokenType.Anonymous}
                    for item in endpoints
                )
                ns = await client.get_namespace_index("urn:example:line")
                node = client.get_node(ua.NodeId("PartsProduced", ns))
                assert await node.read_value() == 0
                await client.open_secure_channel(renew=True)
                assert await node.read_value() == 0
                await denied(node.write_value(42, ua.VariantType.UInt64))
            finally:
                await client.disconnect()
        if read_binary:
            native = await asyncio.create_subprocess_exec(
                read_binary,
                endpoint,
                "urn:example:server",
                str(tmp / "server.der"),
                "urn:example:reader",
                str(tmp / "client.der"),
                str(tmp / "client-key.der"),
                "urn:example:line",
                "s=PartsProduced",
                stdout=asyncio.subprocess.PIPE,
            )
            output, _ = await asyncio.wait_for(native.communicate(), 10)
            assert native.returncode == 0 and b"0" in output, output
        wrong_uri = await configured(tmp, ua.MessageSecurityMode.SignAndEncrypt)
        wrong_uri.application_uri = "urn:example:unexpected"
        for candidate, rejection in [
            (wrong_uri, ua.StatusCodes.BadCertificateUriInvalid),
            (Client(endpoint, timeout=2), ua.StatusCodes.BadSecurityPolicyRejected),
            (
                await configured(foreign, ua.MessageSecurityMode.SignAndEncrypt),
                ua.StatusCodes.BadSecurityChecksFailed,
            ),
            (
                await configured(tmp, ua.MessageSecurityMode.Sign),
                ua.StatusCodes.BadSecurityModeRejected,
            ),
        ]:
            try:
                await candidate.connect()
            except ua.UaStatusCodeError as error:
                assert error.code == rejection, error
                continue
            await candidate.disconnect()
            raise AssertionError("untrusted client or downgrade acquired a session")
    finally:
        process.stdin.close()
        try:
            assert await asyncio.wait_for(process.wait(), 5) == 0
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
    print(
        f"Verified {policy.URI.rsplit('#', 1)[1]} renewal, pinned reads and downgrade rejection."
    )


if __name__ == "__main__":
    for policy in (
        SecurityPolicyBasic256Sha256,
        SecurityPolicyAes128Sha256RsaOaep,
        SecurityPolicyAes256Sha256RsaPss,
    ):
        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(
                run(
                    sys.argv[1],
                    Path(directory),
                    policy,
                    sys.argv[2]
                    if len(sys.argv) == 3 and policy is SecurityPolicyBasic256Sha256
                    else None,
                )
            )
