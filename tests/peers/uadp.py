"""Cross-check the unsigned UADP Variant key-frame profile over actual loopback UDP."""

import socket
import subprocess
import sys

from asyncua import ua
from asyncua.common.utils import Buffer
from asyncua.pubsub.uadp import (
    UadpDataSetMessageHeader,
    UadpDataSetVariant,
    UadpGroupHeader,
    UadpHeader,
    UadpNetworkMessage,
)


def run(binary):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(5)
        with subprocess.Popen(
            [binary, str(sock.getsockname()[1])], stdout=subprocess.PIPE, text=True
        ) as process:
            packet, sender = sock.recvfrom(1024)
            data = Buffer(packet)
            frame = UadpNetworkMessage.from_binary(data)
            assert len(data) == 0
            assert frame.Header.PublisherId == 12
            assert frame.GroupHeader.WriterGroupId == 34
            assert frame.DataSetPayloadHeader == [56]
            [dataset] = frame.Payload
            assert dataset.Header.Valid and dataset.Header.SequenceNo == 65535
            assert dataset.Data == [
                ua.Variant(9007199254740993, ua.VariantType.UInt64),
                ua.Variant(True, ua.VariantType.Boolean),
            ]
            reply = UadpNetworkMessage(
                Header=UadpHeader(PublisherId=ua.UInt16(12)),
                GroupHeader=UadpGroupHeader(WriterGroupId=34),
                DataSetPayloadHeader=[56],
                Payload=[
                    UadpDataSetVariant(
                        UadpDataSetMessageHeader(SequenceNo=0),
                        [
                            ua.Variant(9007199254740994, ua.VariantType.UInt64),
                            ua.Variant(False, ua.VariantType.Boolean),
                        ],
                    )
                ],
            )
            sock.sendto(reply.to_binary(), sender)
            stdout, _ = process.communicate(timeout=5)
            assert (
                process.returncode == 0
                and stdout.strip() == "parts=9007199254740994 running=false"
            )
    print("Verified Rust to asyncua and asyncua to Rust UADP frames over UDP.")


if __name__ == "__main__":
    run(sys.argv[1])
