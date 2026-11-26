"""Exercise the embedded read-only server through an independent OPC UA client."""

import asyncio
import socket
import sys

from asyncua import Client, ua


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
            await denied(node.write_value(123, ua.VariantType.UInt64))
            await denied(client.nodes.objects.add_variable(ns, "Other", False))
            await denied(node.delete())
            await denied(
                client.nodes.server.call_method(
                    ua.NodeId(ua.ObjectIds.Server_GetMonitoredItems),
                    ua.Variant(1, ua.VariantType.UInt32),
                )
            )
            process.stdin.write(b"9007199254740993\n")
            await process.stdin.drain()
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
        "Verified local namespace, typed reads, live updates, write and node-management denial, shutdown."
    )


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
