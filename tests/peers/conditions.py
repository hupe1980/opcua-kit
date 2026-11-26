"""Run an explicit retained condition branch through the OPC UA Part 9 methods."""

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
        users = Readers()
        server = Server(user_manager=users)
        await server.init()
        server.set_endpoint("opc.tcp://127.0.0.1:0/")
        await server.set_application_uri("urn:fixture:server")
        await server.load_certificate(directory / "server.der")
        await server.load_private_key(directory / "server.key", format="pem")
        server.set_identity_tokens([ua.UserNameIdentityToken])
        server.set_security_policy(
            [ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt]
        )
        leaf = (directory / "client.der").read_bytes()

        async def check_cert(cert, app):
            if (
                cert.public_bytes(Encoding.DER) != leaf
                or app.ApplicationUri != "urn:fixture:client"
            ):
                raise ua.UaStatusCodeError(ua.StatusCodes.BadCertificateUntrusted)

        server.set_certificate_validator(check_cert)
        ns = await server.register_namespace("urn:conditions:fixture")
        condition = await server.nodes.objects.add_object(
            ua.NodeId("MotorAlarm", ns), ua.QualifiedName("MotorAlarm", ns)
        )
        branch = ua.NodeId("OlderBranch", ns)
        start = await server.get_event_generator(ua.ObjectIds.RefreshStartEventType)
        end = await server.get_event_generator(ua.ObjectIds.RefreshEndEventType)
        alarm = await server.get_event_generator(ua.ObjectIds.AlarmConditionType)
        alarm.event.add_property("NodeId", condition.nodeid, ua.VariantType.NodeId)
        alarm.event.BranchId = branch
        alarm.event.Retain = True
        calls = []
        states = []
        methods = ua.ObjectIds
        refresh_id = ua.NodeId(methods.ConditionType_ConditionRefresh)
        create_session = server.iserver.create_session
        checked_sessions = []

        def make_session(*args, **kwargs):
            session = create_session(*args, **kwargs)
            ordinary_call = session.call

            async def scoped_call(requests):
                for operation in requests:
                    if operation.MethodId == refresh_id:
                        sid = operation.InputArguments[0].Value
                        sub = session.subscription_service.subscriptions[sid]
                        assert sub.session_id == session.session_id
                        checked_sessions.append(sid)
                return await ordinary_call(requests)

            session.call = scoped_call
            return session

        server.iserver.create_session = make_session

        async def emit(sid=None):
            await alarm.trigger(message="motor overheated", subscription_id=sid)
            states.append(alarm.event.EventId.Value)

        async def refresh(obj, sub):
            assert obj == ua.NodeId(methods.ConditionType)
            assert (
                sub.VariantType == ua.VariantType.UInt32
                and sub.Value == checked_sessions[-1]
            )
            calls.append("refresh")
            await start.trigger(message="refresh start", subscription_id=sub.Value)
            await emit(sub.Value)
            await end.trigger(message="refresh complete", subscription_id=sub.Value)
            return []

        async def acknowledge(obj, event_id, comment):
            assert obj == condition.nodeid
            assert (
                event_id.VariantType == ua.VariantType.ByteString
                and event_id.Value == states[-1]
            )
            assert comment.VariantType == ua.VariantType.LocalizedText
            if comment.Value.Text == "new occurrence":
                calls.append("applied-before-timeout")
                setattr(alarm.event, "AckedState/Id", True)
                await emit()
                # The caller's three-second service timeout expires after application.
                await asyncio.sleep(4.5)
                return []
            assert (comment.Value.Locale, comment.Value.Text) == (
                "en-US",
                "operator reviewed",
            )
            calls.append("acknowledge")
            setattr(alarm.event, "AckedState/Id", True)
            await emit()
            return []

        async def confirm(obj, event_id, comment):
            assert (
                obj == condition.nodeid
                and event_id.VariantType == ua.VariantType.ByteString
            )
            assert comment.VariantType == ua.VariantType.LocalizedText
            if event_id.Value != states[-1]:
                assert (comment.Value.Locale, comment.Value.Text) == ("en-US", "")
                assert event_id.Value == states[0]
                calls.append("stale")
                return ua.StatusCode(ua.StatusCodes.BadEventIdUnknown)
            assert comment.Value.Locale is None and comment.Value.Text is None
            calls.append("confirm")
            setattr(alarm.event, "ConfirmedState/Id", True)
            await emit()
            # A new occurrence has its own EventId and requires its own action.
            setattr(alarm.event, "ConfirmedState/Id", False)
            setattr(alarm.event, "AckedState/Id", False)
            await emit()
            return []

        for method, callback in [
            (methods.ConditionType_ConditionRefresh, refresh),
            (methods.AcknowledgeableConditionType_Acknowledge, acknowledge),
            (methods.AcknowledgeableConditionType_Confirm, confirm),
        ]:
            server.link_method(server.get_node(ua.NodeId(method)), callback)
        async with server:
            endpoint = f"opc.tcp://127.0.0.1:{server.bserver.port}/"
            child = await asyncio.create_subprocess_exec(binary, endpoint, directory)
            try:
                assert await asyncio.wait_for(child.wait(), 30) == 0
            finally:
                if child.returncode is None:
                    child.kill()
                    await child.wait()
        assert calls == [
            "refresh",
            "acknowledge",
            "stale",
            "confirm",
            "applied-before-timeout",
        ], calls
        assert len(checked_sessions) == 1
        assert len(states) == len(set(states)) == 5
        assert users.logins == 2
    print(
        "Verified same-session refresh, retained branch identity, acknowledge, stale rejection, confirm and exactly one applied acknowledgement with an indeterminate reply."
    )


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
