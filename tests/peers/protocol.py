"""Inspect discovery, array and raw historian protocol behavior on an authenticated asyncua peer."""

import asyncio
import sys
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from asyncua import Server, ua
from asyncua.common.callback import CallbackType
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
        server.set_security_policy(
            [
                ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
                ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
            ]
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
        decoy = await server.register_namespace("urn:protocol:decoy")
        ns = await server.register_namespace("urn:protocol:meter")
        for index in [decoy, ns]:
            for name in ["Archived", "Denied", "Outside", "Backwards"]:
                await server.nodes.objects.add_variable(
                    ua.NodeId(name, index),
                    ua.QualifiedName(name, index),
                    ua.Variant(42, ua.VariantType.UInt64),
                )
        matrix = await server.nodes.objects.add_variable(
            ua.NodeId("Matrix", ns),
            ua.QualifiedName("Matrix", ns),
            ua.Variant([[0, 2], [6, 2**32 - 1]], ua.VariantType.UInt32),
        )
        server.set_attribute_value_callback(
            matrix.nodeid,
            lambda *_: ua.DataValue(
                ua.Variant([[0, 2], [6, 2**32 - 1]], ua.VariantType.UInt32),
                ua.StatusCode(0x400),
            ),
        )
        line = await server.nodes.objects.add_variable(
            ua.NodeId("Line", ns),
            ua.QualifiedName("Line", ns),
            ua.Variant([91, 3, 7, 88], ua.VariantType.UInt32),
        )
        ranges = []

        async def numeric_range(event, service):
            # asyncua's default attribute provider ignores IndexRange. Implement this
            # fixture variable's slice against the decoded, independent service operand.
            for i, operand in enumerate(event.request_params.NodesToRead):
                if operand.NodeId == line.nodeid and operand.IndexRange is not None:
                    ranges.append(operand.IndexRange)
                    assert operand.IndexRange == "1:2"
                    full = event.response_params[i].Value.Value
                    event.response_params[i] = ua.DataValue(
                        ua.Variant(full[1:3], ua.VariantType.UInt32)
                    )

        server.subscribe_server_callback(CallbackType.PostRead, numeric_range)
        manager = server.iserver.history_manager
        store = manager.storage
        store.max_history_data_response_size = 1
        archived = ua.NodeId("Archived", ns)
        await store.new_historized_node(archived, None)
        start = datetime(2021, 1, 1, tzinfo=UTC)
        for i, (status, value) in enumerate(
            [(0, 2**64 - 1), (0x400, 2**53 + 1), (0x40900400, 91)]
        ):
            at = start + timedelta(seconds=i)
            await store.save_node_value(
                archived,
                ua.DataValue(
                    Value=ua.Variant(value, ua.VariantType.UInt64),
                    StatusCode=ua.StatusCode(status),
                    # asyncua 2.1.0 encodes its dataclass fields in declaration order. Separate
                    # source fractions from rows with a server clock to produce canonical Part 6 bytes.
                    SourceTimestamp=at,
                    ServerTimestamp=None if i == 0 else at + timedelta(milliseconds=1),
                    SourcePicoseconds=100 if i == 0 else None,
                    ServerPicoseconds=None if i == 0 else 700,
                ),
            )
        active = set()
        releases = []
        live_reads = []

        async def record_read(event, service):
            live_reads.extend(r.NodeId for r in event.request_params.NodesToRead)

        server.subscribe_server_callback(CallbackType.PreRead, record_read)
        ordinary_history = manager.read_history

        async def history(params):
            # asyncua's memory historian uses stateless timestamp cursors. Track and release
            # those cursors to independently check the client's requests on the wire.
            assert len(params.NodesToRead) == 1
            operand = params.NodesToRead[0]
            assert operand.NodeId.NamespaceIndex == ns
            if operand.ContinuationPoint:
                assert operand.ContinuationPoint in active
                active.remove(operand.ContinuationPoint)
            if params.ReleaseContinuationPoints:
                assert operand.ContinuationPoint
                releases.append(operand.NodeId)
                return [ua.HistoryReadResult()]
            assert params.TimestampsToReturn == ua.TimestampsToReturn.Both
            assert isinstance(params.HistoryReadDetails, ua.ReadRawModifiedDetails)
            assert not params.HistoryReadDetails.IsReadModified
            assert not params.HistoryReadDetails.ReturnBounds
            assert (
                params.HistoryReadDetails.StartTime <= params.HistoryReadDetails.EndTime
            )
            if operand.NodeId.Identifier == "Denied":
                return [
                    ua.HistoryReadResult(
                        StatusCode=ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
                    )
                ]
            # Two variables intentionally return inconsistent timestamp evidence. Read
            # the same historian, then change only the source clock in that response.
            name = operand.NodeId.Identifier
            assert name in ("Archived", "Outside", "Backwards")
            params = replace(params, NodesToRead=[replace(operand, NodeId=archived)])
            results = await ordinary_history(params)
            page = results[0].HistoryData.DataValues
            if name == "Outside" and not operand.ContinuationPoint:
                # Timestamp exactly at end, plus one extra 10 ps.
                page[0] = replace(
                    page[0],
                    SourceTimestamp=params.HistoryReadDetails.EndTime,
                    SourcePicoseconds=1,
                )
            if name == "Backwards" and operand.ContinuationPoint:
                # The previous page had source time start + 100 increments.
                page[0] = replace(
                    page[0], SourceTimestamp=params.HistoryReadDetails.StartTime
                )
            if results[0].ContinuationPoint:
                active.add(results[0].ContinuationPoint)
            if operand.ContinuationPoint:
                results[0].StatusCode = ua.StatusCode(0x400)
            return results

        manager.read_history = history
        async with server:
            port = server.bserver.port
            child = await asyncio.create_subprocess_exec(
                binary, f"opc.tcp://127.0.0.1:{port}/", directory
            )
            try:
                assert await asyncio.wait_for(child.wait(), 60) == 0
            finally:
                if child.returncode is None:
                    child.kill()
                    await child.wait()
        assert not active, active
        # Per policy: two sample limits, two bad source clocks and a wrong scalar.
        assert (
            releases
            == [
                archived,
                archived,
                ua.NodeId("Outside", ns),
                ua.NodeId("Backwards", ns),
                archived,
            ]
            * 2
        ), releases
        assert users.logins == 2, users.logins
        assert ranges == ["1:2", "1:2"], ranges
        assert archived not in live_reads
        assert ua.NodeId("Archived", decoy) not in live_reads
    print(
        "Historian observed complete continuation cleanup and zero live register Value reads."
    )


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
