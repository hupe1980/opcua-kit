"""Verify pinned Write and Call against in-memory variables and methods on an independent peer."""

import asyncio
import sys
import tempfile
from pathlib import Path

from asyncua import Server, ua
from cryptography.hazmat.primitives.serialization import Encoding
from recovery import Readers, certificate


async def run(binary):
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        certificate(directory, "client", uri="urn:fixture:client")
        certificate(directory, "server")
        server = Server(user_manager=Readers())
        await server.init()
        server.set_endpoint("opc.tcp://127.0.0.1:0/")
        await server.set_application_uri("urn:fixture:server")
        await server.load_certificate(directory / "server.der")
        await server.load_private_key(directory / "server.key", format="pem")
        server.set_identity_tokens([ua.UserNameIdentityToken])
        server.set_security_policy(
            [ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt]
        )
        client_leaf = (directory / "client.der").read_bytes()

        async def check_cert(cert, app):
            if (
                cert.public_bytes(Encoding.DER) != client_leaf
                or app.ApplicationUri != "urn:fixture:client"
            ):
                raise ua.UaStatusCodeError(ua.StatusCodes.BadCertificateUntrusted)

        server.set_certificate_validator(check_cert)
        ns = await server.register_namespace("urn:control:fixture")
        memory = await server.nodes.objects.add_object(
            ua.NodeId("Memory", ns), "Memory"
        )
        values = {}
        for name in ("Writable", "ReadOnly"):
            values[name] = await memory.add_variable(
                ua.NodeId(name, ns), name, ua.Variant(0, ua.VariantType.UInt64)
            )
        await values["Writable"].set_writable()
        calls = []

        async def echo(parent, arg):
            assert parent == memory.nodeid
            calls.append("echo")
            if arg.VariantType != ua.VariantType.UInt64:
                return ua.CallMethodResult(
                    StatusCode=ua.StatusCode(ua.StatusCodes.BadInvalidArgument),
                    InputArgumentResults=[
                        ua.StatusCode(ua.StatusCodes.BadTypeMismatch)
                    ],
                )
            return [arg]

        async def mixed(parent, text, enabled, count):
            assert parent == memory.nodeid
            assert text.VariantType == ua.VariantType.String
            assert enabled.VariantType == ua.VariantType.Boolean
            assert count.VariantType == ua.VariantType.UInt64
            calls.append("mixed")
            return [count, enabled, text]

        async def excess(parent):
            calls.append("excess")
            return [ua.Variant(b"x" * (128 * 1024), ua.VariantType.ByteString)]

        async def slow(parent):
            calls.append("slow")
            await asyncio.sleep(0.7)
            return []

        async def late(parent):
            calls.append("late")
            await asyncio.sleep(4.5)
            return []

        for name, handler, args, outputs in [
            ("Echo", echo, [ua.VariantType.UInt64], [ua.VariantType.UInt64]),
            (
                "Mixed",
                mixed,
                [ua.VariantType.String, ua.VariantType.Boolean, ua.VariantType.UInt64],
                [ua.VariantType.UInt64, ua.VariantType.Boolean, ua.VariantType.String],
            ),
            ("Excess", excess, [], [ua.VariantType.ByteString]),
            ("Slow", slow, [], []),
            ("Late", late, [], []),
        ]:
            await memory.add_method(ua.NodeId(name, ns), name, handler, args, outputs)

        async with server:
            child = await asyncio.create_subprocess_exec(
                binary, f"opc.tcp://127.0.0.1:{server.bserver.port}/", directory
            )
            try:
                assert await asyncio.wait_for(child.wait(), 40) == 0
            finally:
                if child.returncode is None:
                    child.kill()
                    await child.wait()
            assert await values["Writable"].read_value() == 2**57 + 3
            assert await values["ReadOnly"].read_value() == 0
        assert calls == ["echo", "mixed", "echo", "excess", "slow", "late"], calls
        print(
            "Verified exact writes, denied operations, method diagnostics and one-shot cancellation."
        )


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
