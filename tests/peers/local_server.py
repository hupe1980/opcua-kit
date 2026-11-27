"""Exercise the embedded read-only server through an independent OPC UA client."""

import asyncio
import socket
import sys

from asyncua import Client, ua
from asyncua.ua.ua_binary import struct_from_binary


async def denied(operation):
    try:
        await operation
    except ua.UaStatusCodeError as error:
        assert error.code in {
            ua.StatusCodes.BadUserAccessDenied,
            ua.StatusCodes.BadNotWritable,
            ua.StatusCodes.BadNotExecutable,
        }, error
        return
    raise AssertionError("peer changed the read-only address space")


async def verify_republish(client, node):
    # Issue Publish explicitly so the client does not acknowledge before Republish.
    request = ua.CreateSubscriptionRequest()
    request.Parameters = ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=20,
        RequestedLifetimeCount=20,
        RequestedMaxKeepAliveCount=2,
        PublishingEnabled=True,
    )
    raw = await client.uaclient.protocol.send_request(request)
    subscription_id = struct_from_binary(
        ua.CreateSubscriptionResponse, raw
    ).Parameters.SubscriptionId
    try:
        item = ua.MonitoredItemCreateRequest(
            ItemToMonitor=ua.ReadValueId(
                NodeId=node.nodeid, AttributeId=ua.AttributeIds.Value
            ),
            MonitoringMode=ua.MonitoringMode.Reporting,
            RequestedParameters=ua.MonitoringParameters(
                ClientHandle=7, SamplingInterval=10
            ),
        )
        (created,) = await client.uaclient.create_monitored_items(
            ua.CreateMonitoredItemsParameters(
                SubscriptionId=subscription_id,
                TimestampsToReturn=ua.TimestampsToReturn.Both,
                ItemsToCreate=[item],
            )
        )
        created.StatusCode.check()
        async with asyncio.timeout(3):
            published = (await client.uaclient.publish([])).Parameters
            sequence = published.NotificationMessage.SequenceNumber
            assert published.AvailableSequenceNumbers == [sequence]
            replay = await client.uaclient.session.republish(subscription_id, sequence)
            assert replay == published.NotificationMessage
            ack = ua.SubscriptionAcknowledgement(
                SubscriptionId=subscription_id, SequenceNumber=sequence
            )
            confirmed = (await client.uaclient.publish([ack])).Parameters
            confirmed.Results[0].check()
            assert sequence not in confirmed.AvailableSequenceNumbers
            try:
                await client.uaclient.session.republish(subscription_id, sequence)
            except ua.UaStatusCodeError as error:
                assert error.code == ua.StatusCodes.BadMessageNotAvailable
            else:
                raise AssertionError("acknowledged message retained")
    finally:
        await client.uaclient.delete_subscriptions([subscription_id])


class Changes:
    def __init__(self):
        self.values = asyncio.Queue()

    def datachange_notification(self, node, value, data):
        self.values.put_nowait((node.nodeid, value))


async def run(binary):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = await asyncio.create_subprocess_exec(
        binary, str(port), stdin=asyncio.subprocess.PIPE
    )
    try:
        async with asyncio.timeout(10):
            while True:
                if process.returncode is not None:
                    raise RuntimeError("server stopped during startup")
                client = Client(f"opc.tcp://127.0.0.1:{port}")
                try:
                    await client.connect()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
        try:
            ns = await client.get_namespace_index("urn:example:line")
            node = await client.nodes.objects.get_child([f"{ns}:PartsProduced"])
            assert node.nodeid == ua.NodeId("PartsProduced", ns)
            assert await node.read_value() == 0
            assert (await node.read_data_type()) == ua.NodeId(ua.ObjectIds.UInt64)
            assert await node.read_value_rank() == -1
            status = await client.get_node(
                ua.ObjectIds.Server_ServerStatus
            ).read_value()
            assert status.State == ua.ServerState.Running
            params = ua.BrowseParameters(
                RequestedMaxReferencesPerNode=1,
                NodesToBrowse=[
                    ua.BrowseDescription(
                        NodeId=client.nodes.objects.nodeid,
                        BrowseDirection=ua.BrowseDirection.Forward,
                        ResultMask=ua.BrowseResultMask.All,
                    )
                ],
            )
            (page,) = await client.uaclient.browse(params)
            page.StatusCode.check()
            assert page.ContinuationPoint
            (second,) = await client.uaclient.browse_next(
                ua.BrowseNextParameters(
                    ReleaseContinuationPoints=False,
                    ContinuationPoints=[page.ContinuationPoint],
                )
            )
            second.StatusCode.check()
            assert not second.ContinuationPoint
            assert {page.References[0].NodeId, second.References[0].NodeId} == {
                client.nodes.server.nodeid,
                node.nodeid,
            }
            await denied(node.write_value(123, ua.VariantType.UInt64))
            await denied(client.nodes.objects.add_variable(ns, "Other", False))
            await denied(node.delete())
            await denied(
                client.nodes.server.call_method(
                    ua.NodeId(ua.ObjectIds.Server_GetMonitoredItems),
                    ua.Variant(1, ua.VariantType.UInt32),
                )
            )
            await verify_republish(client, node)
            changes = Changes()
            subscription = await client.create_subscription(50, changes)
            handle = await subscription.subscribe_data_change(node)
            assert await asyncio.wait_for(changes.values.get(), 5) == (node.nodeid, 0)
            process.stdin.write(b"9007199254740993\n")
            await process.stdin.drain()
            assert await asyncio.wait_for(changes.values.get(), 5) == (
                node.nodeid,
                9007199254740993,
            )
            await subscription.unsubscribe(handle)
            await subscription.delete()
            async with asyncio.timeout(5):
                while await node.read_value() != 9007199254740993:
                    await asyncio.sleep(0.02)
        finally:
            await client.disconnect()
    finally:
        process.stdin.close()
        try:
            returncode = await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        assert returncode == 0, returncode
    print(
        "Verified paged browse, typed reads, monitored changes, Republish, read-only access and shutdown."
    )


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
