+++
title = "Capture device metadata"
description = "Check credentials offline, then capture and verify the metadata a device declares for a reviewed signal contract."
weight = 6
[extra]
keywords = "commissioning capture preflight PEM DER certificate application URI metadata signal contract"
group = "Commission a device"
+++

A capture records the metadata a device exposes for the signals in your contract. It reads their declarations and requested engineering units. To record a process value, use the [client](@/client.md) or [meter](@/meter.md) commands.

## Prepare the field laptop

Install the CLI with `cargo install opcua-kit --locked --features cli`. Supply a [reviewed contract](@/authoring.md), the server leaf certificate obtained through the site’s trust process, and your client application certificate and matching unencrypted RSA private key. The CLI reads PEM and DER files. Restrict access to the private key.

Use the server application URI from the contract and an endpoint whose DNS name or IP address appears in the server certificate. The CLI takes its client application URI from the single URI in the client certificate’s subject alternative names. Set `--client-uri` when you also want to check that identity against an expected value. The server must trust the client certificate. [OPC UA application certificates](https://reference.opcfoundation.org/specs/OPC-10000-6/6.2.2)

The default session uses Basic256Sha256 with SignAndEncrypt and the `anonymous` principal. For a named account, set the contract principal to `username:<account>` and pass `--username <account> --password-file reader.secret`. Select a different supported channel policy with `--security-policy`. [Endpoint and account selection](@/recovery.md#choose-the-endpoint-and-account)

## Check the setup offline

Run preflight with the exact contract, endpoint and credentials for the visit. Specify the port explicitly.

```sh
opcua-kit capture --preflight --contract plant.json --endpoint opc.tcp://ahu-01.example:4840 \
  --server-cert server.der --client-cert client.pem --client-key client-key.pem
```

Preflight checks the contract, the selected principal, certificate validity and usage, endpoint host, application URIs and private-key match. It runs locally with the network disconnected. Exit 0 means the local configuration passed. A live capture verifies the responding peer and exercises its read permissions.

## Capture and assess

```sh
opcua-kit capture --contract plant.json --endpoint opc.tcp://ahu-01.example:4840 \
  --server-cert server.der --client-cert client.pem --client-key client-key.pem \
  --output before.json
opcua-kit check --contract plant.json --snapshot before.json
```

Capture writes one row per signal in contract order. It resolves each namespace URI in the session, reads the requested declarations, and verifies each selected EngineeringUnits property before reading its value. An unresolved namespace leaves an identity-only row. A valid snapshot can contain incomplete evidence. `check` exits 0 for a match, 2 for a mismatch or 3 when only incomplete evidence prevents a decision.

The collection budget includes session setup and shutdown. It defaults to 30 seconds. Use `--timeout` to select 1–300 seconds. Each service request has a timeout of at most 60 seconds. A successful capture atomically replaces the output file. If acquisition fails, an existing snapshot stays intact. Omit `--output` to write JSON to stdout.

To compare a later visit, save the new capture under a different name. For an immediate decision in automation, pipe the snapshot to `opcua-kit check --contract plant.json --snapshot - --json`. [Automation and evidence](@/automation.md)

| Observation | What to check |
| --- | --- |
| Server certificate rejected | Verify the endpoint name, server application URI and approved leaf. Obtain a rotated pin through the site’s trust process. |
| BadNodeIdUnknown | Check the namespace URI and identifier for the selected device. |
| BadUserAccessDenied | Verify read permissions for the selected account. |
| Missing or unidentified EngineeringUnits | Inspect the property’s declared type, namespace and unit ID in the device model. |
| Ambiguous or conflicting unit target | Check for one local scalar EUInformation property. A contracted process signal cannot also supply a unit property’s value. |
