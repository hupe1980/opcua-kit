+++
title = "Draft a signal contract"
description = "Turn a trusted reference snapshot into a reviewable contract for types, units and signal identity."
weight = 5
[extra]
keywords = "commissioning draft validate"
group = "Commission a device"
+++

Use a saved snapshot from a device configuration that the site owner trusts. Drafting copies observed metadata into an editable list of gateway requirements. It works offline. To obtain a live snapshot, capture still needs a contract that selects the signals and metadata to read.

## Start from a reference observation

Install the field tool with `cargo install opcua-kit --locked --features cli`. Use a fresh directory for the temperature example. The demo reports a unit mismatch and exits 2 after exporting its fixtures.

```sh
opcua-kit demo --scenario units --export reference
opcua-kit contract draft --snapshot reference/before.json --output draft.json &&
  opcua-kit contract validate --contract draft.json &&
  opcua-kit check --contract draft.json --snapshot reference/before.json
```

Validation reports one signal. Checking that snapshot exits 0 because the observed DataType and Celsius unit match the draft. Compare the draft with the gateway configuration before using it for sign-off. In particular, confirm the device, application URI, principal, signal list and each required attribute.

The named file contains exactly the JSON that drafting sends to stdout by default. Choose an existing directory you control and an unused file name. If a colleague has edited the draft or another process wins the same name, the save exits 1 and preserves that file. Choose a new name to save another version. Omit `--output` to pipe the JSON to another tool.

## Review what was captured

Every row needs a readable DataType. A Good status with an omitted value is insufficient for drafting. A recorded ValueRank or EngineeringUnits result must also be readable. A unit needs a defining namespace and an identifier other than -1. If any row fails, the command exits 1, identifies the field and emits no contract. When a decoded operation contains an invalid value, the diagnostic includes the field and its full hexadecimal status. For example, a ValueRank of -4 is invalid even if the read reports Good.

An optional attribute absent from the snapshot stays absent in the draft. Signals outside the original capture are also outside the draft. Signal rows are sorted by name so two exports with different row ordering can be reviewed with a text diff.

For example, if the gateway requires a scalar temperature, add the rank constraint. These commands use jq to save the edit separately.

```sh
jq '.signals[0].valueRank = -1' draft.json > scalar.json
opcua-kit contract validate --contract scalar.json
opcua-kit check --contract scalar.json --snapshot reference/before.json
```

The edited contract is valid. Checking the original observation now exits 3 because that capture contains no rank evidence. A fresh capture using the edited contract will request the rank.

## Check a later observation

With the original Celsius requirement reviewed, check the second fixture.

```sh
opcua-kit check --contract draft.json --snapshot reference/after.json
```

The checker names SupplyTemp, shows the expected Celsius and observed Fahrenheit units, and exits 2. Retain the approved requirement when investigating a device change.

Both authoring commands accept a file or an explicit dash for a pipe or redirection. A dash attached to a terminal gives a usage hint. Each command accepts one JSON document up to 4 MiB. Draft JSON shows directional formatting characters as Unicode escapes, preserving their values when parsed. A successful draft includes a trailing newline and fits the same limit. If even compact, escaped JSON would be too large, drafting exits 1 before writing the document.

[Capture a device observation](@/capture.md) · [Use decisions in CI](@/automation.md)
