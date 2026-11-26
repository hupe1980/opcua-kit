+++
title = "Capture device metadata"
description = "Collect a scoped snapshot with pinned credentials and check what the device actually declares."
weight = 6
[extra]
keywords = "commissioning capture preflight credentials Python asyncua"
group = "Commission a device"
+++

Start with a reviewed contract. Run `opcua-kit contract validate --contract plant.json` before opening the connection. The example exported by `opcua-kit demo --export example` shows where to put the expected server application URI, signal names, namespace URIs and identifiers. Select the session principal explicitly in the contract. Native capture supports `anonymous` and `username:<account>`. The Python collector requires `anonymous`. Its client application still has a certificate and key for the secure channel.

## Capture with the native client

The installed CLI can capture the reviewed contract directly. Supply the same client application URI that appears in the client certificate, a pinned server leaf, a client certificate and an unencrypted private key, all credentials in DER. By default the client requests an anonymous user on a Basic256Sha256 SignAndEncrypt session. For a site account, include `--username cems-reader --password-file reader.secret` and set the contract principal to `username:cems-reader`. Use `--security-policy` to select another supported policy. [Discover site policies](@/recovery.md#choose-the-endpoint-and-account)

```sh
opcua-kit capture --contract plant.json --endpoint opc.tcp://ahu-01.example:4840 \
  --client-uri urn:cems:client --server-cert server.der \
  --client-cert client.der --client-key client-key.der --timeout 30 --output before.json
opcua-kit check --contract plant.json --snapshot before.json
```

With `--client-uri`, acquisition runs inside the binary. The 1–300 second budget includes the connection and metadata collection. Each service has a timeout of at most 60 seconds. Orderly disconnect can take additional time before publication. A successful capture exits 0 even if some attributes were unavailable. Use `check` for the decision. A mismatch exits 2 and incomplete evidence alone exits 3.

The snapshot includes only the declarations requested for each signal, in contract order. An unresolved namespace yields an identity-only row. A missing unit after a successful native browse keeps the browse status with no value. Capture rejects a unit property that aliases any contracted signal. Reserve the standard namespace-zero ServerArray (`i=2254`), NamespaceArray (`i=2255`) and MaxNodesPerRead (`i=11705`) for session setup. Omit `--output` to write the snapshot to stdout. On acquisition failure, a previous file remains intact.

## Prepare the Python collector

Install the CLI with `cargo install opcua-kit --locked --features cli` and make uv available on PATH. When you omit `--client-uri`, capture uses the Python collector. Its offline `--preflight` and fixture-only `--insecure-loopback` options require this mode. The first capture resolves asyncua 2.1.0 and Python 3.13. While connected, warm the dependency cache on the laptop and user account that will run capture.

```sh
uv run --no-config --isolated --no-project --python 3.13 \
  --with asyncua==2.1.0 python -I -c 'import asyncua'
```

Obtain the server leaf certificate through the site's approved channel. Its validity window, application URI and hostname or IP SAN must match. The server must expose Basic256Sha256 with SignAndEncrypt and accept the client application certificate. Supply an unencrypted private key file with restricted filesystem permissions. Use 2048–4096-bit RSA certificates with the appropriate client and server key usages for Basic256Sha256. PEM and DER are supported.

## Rehearse before traveling

Use the contract, endpoint URL and credentials selected for the visit. Specify the TCP port explicitly. On a prepared laptop this check can run with the network disconnected.

```sh
opcua-kit capture --preflight --contract plant.json --endpoint opc.tcp://ahu-01.example:4840 \
  --server-cert server.der --client-cert client.der --client-key client.key
```

A pass exits 0. The command starts the installed collector from the local uv cache, checks both certificates against the laptop clock and their intended roles, compares the server pin with the configured host and application URI, and verifies that the private key belongs to the client certificate. It performs no DNS lookup, opens no server connection and writes no snapshot. If the cache is incomplete, run the warm-up above while connected and repeat the preflight. For a credential error, correct the indicated file or endpoint and rerun the same command.

At the site, remove `--preflight` and add `--output` to save evidence. A live session establishes reachability, verifies the actual peer, and tests whether the server accepts the client and permits the metadata reads. Set `UV_OFFLINE=1` on the live command to keep dependency resolution offline there too.

## Collect and check a first observation

```sh
opcua-kit capture --contract plant.json --endpoint opc.tcp://ahu-01.example:4840 \
  --server-cert server.der --client-cert client.der --client-key client.key \
  --timeout 30 --output before.json
```

Assess the file immediately. A clean first inspection exits 0. Keep before.json as evidence for the return visit.

```sh
opcua-kit check --contract plant.json --snapshot before.json
```

For an immediate machine-readable decision, omit the capture output path and pipe directly into the checker. Use the saved-file workflow above when you need the original snapshot for a later comparison.

```sh
opcua-kit capture --contract plant.json --endpoint opc.tcp://ahu-01.example:4840 \
  --server-cert server.der --client-cert client.der --client-key client.key | \
  opcua-kit check --contract plant.json --snapshot - --json
```

Repeat capture after the change with `--output after.json`. The collector resolves each namespace URI for the active session, reads DataType and any requested ValueRank in groups of up to 64, and retains each operation's raw status. It also reads the server's namespace table. For each requested engineering unit, the collector resolves a single forward HasProperty step to the standard EngineeringUnits property. It verifies the local target declares scalar EUInformation, then reads the property's Value. The collector never requests the Value of a contracted signal. The network deadline defaults to 30 seconds and accepts 1–300 seconds. Runtime provisioning has an additional allowance of 60 seconds.

An unknown namespace produces a row with absent attribute evidence. A service-level failure aborts the capture. A rejected certificate, wrong application URI, timeout or invalid response leaves existing output intact. After validation, the CLI atomically replaces the destination file. Omitting `--output` writes the snapshot to stdout.

| Symptom | Action |
| --- | --- |
| Server certificate rejected | Verify its fingerprint and identity independently. For a legitimate rotation, supply the newly approved leaf. |
| BadNodeIdUnknown | Recheck the namespace URI and identifier under this principal. |
| BadUserAccessDenied | Have the site owner confirm the selected account can read the required metadata. |
| BadNoMatch on EngineeringUnits | Confirm the signal exposes the standard namespace-zero property. The check stays unverified until the account can read it. |
| Good status with unidentified unit | Inspect the device configuration for a defining namespace URI and a unit ID other than -1. |
| Ambiguous or invalid property target | Check the server model for a single local EngineeringUnits property of scalar EUInformation type. Capture exits 1 and preserves earlier output. |
| Operation timed out | Check endpoint connectivity and the selected deadline. For a cold laptop, prepare the runtime cache first. |

For a site-approved cumulative grid-import register, use the separate [meter reading workflow](@/meter.md) to retain the register value and its clocks.
