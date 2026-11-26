"""Exercise actual Publish, Republish and acknowledgement services on an encrypted local peer."""

import asyncio
import copy
import sys
import tempfile
from pathlib import Path

from asyncua import Server, ua
from asyncua.common.utils import ServiceError
from cryptography.hazmat.primitives.serialization import Encoding
from recovery import certificate, marker


async def run(binary):
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        certificate(directory, "client", uri="urn:fixture:client")
        certificate(directory, "server")
        server = Server()
        await server.init()
        server.set_endpoint("opc.tcp://127.0.0.1:0/")
        await server.set_application_uri("urn:fixture:server")
        await server.load_certificate(directory / "server.der")
        await server.load_private_key(directory / "server.key", format="pem")
        server.set_identity_tokens([ua.AnonymousIdentityToken])
        server.set_security_policy(
            [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt]
        )
        expected = (directory / "client.der").read_bytes()

        async def check_cert(cert, app):
            if (
                cert.public_bytes(Encoding.DER) != expected
                or app.ApplicationUri != "urn:fixture:client"
            ):
                raise ua.UaStatusCodeError(ua.StatusCodes.BadCertificateUntrusted)

        server.set_certificate_validator(check_cert)
        ns = await server.register_namespace("urn:republish")
        for name, value in [("A", 42), ("B", 97)]:
            await server.nodes.objects.add_variable(
                ua.NodeId(name, ns), name, ua.Variant(value, ua.VariantType.UInt64)
            )
        event = await server.get_event_generator(ua.ObjectIds.BaseEventType)
        event.event.Severity = 702
        svc = server.iserver.subscription_service
        new_sub = svc.create_subscription
        republish = svc.republish
        modes = {}
        requested = {}
        acked = {}

        async def create(params, callback, session_id, request_callback=None):
            mode = len(modes)
            first = True

            async def send(result, *args):
                nonlocal first
                if first and result.NotificationMessage.NotificationData:
                    # Create a deterministic retained prefix of this real fixture notification.
                    # This request delivers only message 3. Subsequent genuine Republish requests
                    # retrieve the earlier SDK notification buffers from the peer's retransmission store.
                    first = False
                    sub = svc.subscriptions[result.SubscriptionId]
                    held = sub._not_acknowledged_results
                    held.clear()
                    for seq in (1, 2):
                        if mode != 1:
                            saved = copy.deepcopy(result)
                            saved.NotificationMessage.SequenceNumber = seq
                            held[seq] = saved
                    result.NotificationMessage.SequenceNumber = 3
                    sub._notification_seq = 4
                    held[3] = result
                    result.AvailableSequenceNumbers = list(held)
                    if mode == 2:
                        del held[
                            1
                        ]  # evicted after advertisement and before the Republish request
                await callback(result, *args)

            r = await new_sub(params, send, session_id, request_callback)
            sid = r.SubscriptionId
            modes[sid] = mode
            requested[mode] = []
            acked[mode] = []
            return r

        def retrieve(params):
            mode = modes[params.SubscriptionId]
            requested[mode].append(params.RetransmitSequenceNumber)
            if mode == 2:
                raise ServiceError(ua.StatusCodes.BadMessageNotAvailable)
            return republish(params)

        original_publish = svc.publish

        def publish(acks):
            for a in acks:
                acked[modes[a.SubscriptionId]].append(a.SequenceNumber)
            return original_publish(acks)

        svc.create_subscription = create
        svc.republish = retrieve
        svc.publish = publish

        async with server:
            child = await asyncio.create_subprocess_exec(
                binary,
                f"opc.tcp://127.0.0.1:{server.bserver.port}/",
                directory,
                stdout=asyncio.subprocess.PIPE,
            )
            try:
                await marker(child, "events")
                await event.trigger(message="retained and live")
                assert await asyncio.wait_for(child.wait(), 20) == 0
            finally:
                if child.returncode is None:
                    child.kill()
                    await child.wait()
            assert not svc.subscriptions
            assert requested == {0: [1, 2], 1: [], 2: [1], 3: [1, 2]}, requested
            assert acked[0] == [1, 2, 3] and acked[3] == [1, 2, 3], acked
    print(
        "Encrypted Republish verified backfill, ordering, exact acknowledgements, missing retention and eviction for data changes and events."
    )


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
