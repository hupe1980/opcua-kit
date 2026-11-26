"""Exercise native operator commands against an encrypted, named-user-only endpoint."""

import asyncio
import json
import socket
import sys
import tempfile
from pathlib import Path

from recovery import certificate, peer


async def run(binary):
    # 019-protocol-client/SR-001: authenticate the named user and protect its input file.
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        for name in ("server", "client"):
            certificate(directory, name, uri=f"urn:fixture:{name}")
        (directory / "password").write_bytes(b"local-restart-fixture\r\n")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            endpoint = f"opc.tcp://127.0.0.1:{reservation.getsockname()[1]}/"

        async def command(*args, code=0):
            process = await asyncio.create_subprocess_exec(
                binary,
                *args,
                cwd=directory,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode == code, (args, stdout, stderr)
            assert b"local-restart-fixture" not in stdout + stderr
            return stdout

        secure = [
            "--endpoint",
            endpoint,
            "--client-uri",
            "urn:fixture:client",
            "--security-policy",
            "Aes256_Sha256_RsaPss",
            "--username",
            "read-fixture",
            "--password-file",
            "password",
            "--client-cert",
            "client.der",
            "--client-key",
            "client-key.der",
            "--server-cert",
            "server.der",
        ]
        ns = "http://opcfoundation.org/UA/"
        node = {"namespace": "urn:recovery:meter", "id": "s=Counter"}
        contract = {
            "schemaVersion": 1,
            "applicationUri": "urn:fixture:server",
            "device": "grid",
            "principal": "username:read-fixture",
            "signals": [
                {
                    "name": "counter",
                    "node": node,
                    "dataType": {"namespace": ns, "id": "i=9"},
                }
            ],
        }

        def save(doc):
            (directory / "contract.json").write_text(json.dumps(doc))

        async with peer(directory, endpoint, generation=1) as (users, _):
            endpoints = json.loads(await command("discover", "--endpoint", endpoint))
            assert any(
                e["security_mode"] == 3
                and any(t["kind"] == 1 for t in e["user_tokens"])
                for e in endpoints
            )
            assert users.logins == 0
            browse = json.loads(
                await command(
                    "browse",
                    *secure,
                    "--server-uri",
                    "urn:fixture:server",
                    "--namespace",
                    ns,
                    "--id",
                    "i=85",
                )
            )
            assert any(child["node"] == node for child in browse)
            save(contract)
            capture = ["capture", *secure, "--contract", "contract.json", "--output"]
            assert await command(*capture, "evidence.json") == b""
            evidence = (directory / "evidence.json").read_bytes()
            assert json.loads(evidence)["principal"] == contract["principal"]
            assert await command(
                "check", "--snapshot", "evidence.json", "--contract", "contract.json"
            )
            # Preserve password and output when a destination or reviewed principal is invalid.
            assert await command(*capture, "password", code=1) == b""
            save({**contract, "principal": "anonymous"})
            count = users.logins
            assert await command(*capture, "evidence.json", code=1) == b""
            assert (
                count == users.logins
                and (directory / "evidence.json").read_bytes() == evidence
            )
            assert (directory / "password").read_bytes() == b"local-restart-fixture\r\n"
    print("Named-user discovery, browse, capture, scope and output checks passed.")


if __name__ == "__main__":
    asyncio.run(run(str(Path(sys.argv[1]).resolve())))
