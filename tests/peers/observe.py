"""Exercise event selection, metadata, typed values and reviewed leaf rotation over OPC TCP."""

import asyncio
import socket
import sys
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from asyncua import Server, ua
from asyncua.common.callback import CallbackType
from cryptography.hazmat.primitives.serialization import Encoding
from recovery import certificate, command, marker


@asynccontextmanager
async def peer(directory, endpoint, stem):
    server = Server()
    await server.init()
    server.set_endpoint(endpoint)
    await server.set_application_uri("urn:fixture:server")
    await server.load_certificate(directory / f"{stem}.der")
    await server.load_private_key(directory / f"{stem}.key", format="pem")
    server.set_identity_tokens([ua.AnonymousIdentityToken])
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    expected = (directory / "client.der").read_bytes()

    async def check_cert(cert, app):
        if (
            cert.public_bytes(Encoding.DER) != expected
            or app.ApplicationUri != "urn:fixture:client"
        ):
            raise ua.UaStatusCodeError(ua.StatusCodes.BadCertificateUntrusted)

    server.set_certificate_validator(check_cert)
    ns = await server.register_namespace("urn:example:observe")
    for name, value, type_ in [
        (
            "Buffer",
            bytes([0, 255, 42]) if stem == "server" else bytes([2]),
            ua.VariantType.ByteString,
        ),
        ("EmptyBuffer", b"", ua.VariantType.ByteString),
        ("Job", UUID("12345678-90ab-cdef-8888-1234567890ab"), ua.VariantType.Guid),
        (
            "Started",
            datetime(2021, 1, 1, 0, 0, 0, 123456, tzinfo=UTC),
            ua.VariantType.DateTime,
        ),
    ]:
        await server.nodes.objects.add_variable(
            ua.NodeId(name, ns), ua.QualifiedName(name, ns), ua.Variant(value, type_)
        )
    base = await server.get_event_generator(ua.ObjectIds.BaseEventType)
    alarm = await server.get_event_generator(ua.ObjectIds.AlarmConditionType)
    setattr(alarm.event, "ActiveState/Id", True)
    alarm.event.Severity = 904
    # The standard overflow type is abstract. Exercise a concrete vendor subtype
    # with the Server source and name mandated by OPC UA Part 5 §6.4.34.
    overflow_type = await server.create_custom_event_type(
        ns, "LineQueueOverflow", ua.ObjectIds.EventQueueOverflowEventType
    )
    overflow = await server.get_event_generator(overflow_type)
    assert overflow.event.EventType == overflow_type.nodeid
    assert overflow.event.SourceNode == server.nodes.server.nodeid
    overflow.event.SourceName = "Internal/EventQueueOverflow"
    base.event.Severity = 702
    filters = []

    async def record(event, service):
        for item in event.request_params.ItemsToCreate:
            assert item.ItemToMonitor.AttributeId == ua.AttributeIds.EventNotifier
            assert item.ItemToMonitor.NodeId == server.nodes.server.nodeid
            filters.append(
                [
                    tuple(part.Name for part in clause.BrowsePath)
                    for clause in item.RequestedParameters.Filter.SelectClauses
                ]
            )

    server.subscribe_server_callback(CallbackType.ItemSubscriptionCreated, record)
    async with server:
        yield (
            base,
            alarm,
            overflow,
            filters,
            server.iserver.subscription_service.subscriptions,
        )


async def run(binary):
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        certificate(directory, "client", uri="urn:fixture:client")
        for stem in ("server", "successor", "unlisted"):
            certificate(directory, stem)
        certificate(directory, "wrong-uri", uri="urn:fixture:unrelated")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        endpoint = f"opc.tcp://127.0.0.1:{port}/"
        child = None
        try:
            async with peer(directory, endpoint, "server") as (
                base,
                alarm,
                overflow,
                filters,
                subscriptions,
            ):
                child = await asyncio.create_subprocess_exec(
                    binary,
                    endpoint,
                    directory,
                    "events",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                )
                await marker(child, "events")
                assert filters == [
                    [
                        ("EventType",),
                        ("SourceNode",),
                        ("SourceName",),
                        ("Severity",),
                        ("Message",),
                        ("EventId",),
                        ("Severity",),
                        ("ActiveState", "Id"),
                    ]
                ], filters
                await base.trigger(message="fan stopped")
                await marker(child, "alarm")
                await alarm.trigger(message="motor overheated")
                await marker(child, "overflow")
                await overflow.trigger(message="lost events")
                await marker(child, "disconnected")
                assert not subscriptions, subscriptions
                await command(child, "next")
                await marker(child, "dropped")
                async with asyncio.timeout(3):
                    while subscriptions:
                        await asyncio.sleep(0.025)
                await command(child, "clean")
                assert await asyncio.wait_for(child.wait(), 10) == 0
                child = await asyncio.create_subprocess_exec(
                    binary,
                    endpoint,
                    directory,
                    "rotation",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                )
                await marker(child, "rotate")
            await command(child, "disconnected")
            await marker(child, "gap")
            async with peer(directory, endpoint, "unlisted"):
                await command(child, "unlisted")
                await marker(child, "rejected")
            async with peer(directory, endpoint, "successor"):
                await command(child, "replacement")
                await marker(child, "done")
                assert await asyncio.wait_for(child.wait(), 5) == 0
        finally:
            if child and child.returncode is None:
                child.kill()
                await child.wait()
    print("Certificate replacement and rejection across three encrypted peers passed.")
    print("Ordered event fields, null and overflow, scalar and attribute reads passed.")


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
