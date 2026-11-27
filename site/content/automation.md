+++
title = "Check contracts in CI"
description = "Interpret comparison results, preserve reports and use exit codes to gate changes."
weight = 7
[extra]
keywords = "commissioning assess compare CLI exit codes"
group = "Commission a device"
+++

A contract contains a version, scope and required signals. Each signal has a name, a stable node identity, an exact declared DataType and optional ValueRank and EngineeringUnits checks. Numeric, string, GUID and opaque identifiers use the prefixes `i=`, `s=`, `g=` and `b=`. Namespace URIs are case sensitive. A scalar has rank -1.

```json
{
  "schemaVersion": 1,
  "device": "ahu-01",
  "applicationUri": "urn:opcua-kit:fixture",
  "principal": "anonymous",
  "signals": [{
    "name": "SupplyTemp",
    "node": {"namespace": "urn:fixture:hvac", "id": "s=SupplyTemp"},
    "dataType": {"namespace": "http://opcfoundation.org/UA/", "id": "i=11"},
    "valueRank": -1,
    "engineeringUnits": {
      "namespaceUri": "http://www.opcfoundation.org/UA/units/un/cefact",
      "unitId": 4408652
    }
  }]
}
```

A snapshot uses the same scope and identity fields. An observed attribute carries its raw UInt32 operation status. A Good-severity result includes the value when one was returned. A completed operation with no usable value, including Good, carries only its status. An attribute with no observation is omitted. Explicit JSON null is invalid. Assessment marks unavailable evidence unverified. The checker rejects unknown fields, duplicate identities, scope changes and unsupported versions. A contract accepts up to 1,024 signals. Each input document is limited to 4 MiB. Keep evidence files in a trusted store.

Validate contract edits offline with `opcua-kit contract validate --contract plant.json`. For an example that starts with a known device configuration, see the [contract authoring guide](@/authoring.md).

## Specify the unit the gateway expects

The example requires degrees Celsius (CEL, 4408652). Degrees Fahrenheit (FAH, 4604232) would produce a mismatch even if the signal still declares Double. Omit `engineeringUnits` to skip this property. Use the exact, case-sensitive defining namespace URI and signed Int32 identifier from the device model. Custom unit authorities are supported. Localized labels never participate in equality.

A captured unit with a blank defining URI or unitId -1 remains unverified even with a Good status. An Uncertain or Bad result retains its raw status and omits the value. An unknown signal namespace leaves the observation absent. All three cases count toward incomplete evidence. A service-level failure or an invalid property response prevents capture from replacing the snapshot. [OPC UA definition](https://reference.opcfoundation.org/specs/OPC-10000-8/5.6.4.3) · [UN/CEFACT mapping](https://reference.opcfoundation.org/specs/OPC-10000-8/5.6.4.4)

### Reproduce incomplete evidence

Export the temperature example into a new directory. With jq installed, create a copy in which the server reports that the unit identifier is unavailable.

```sh
opcua-kit demo --scenario units --export temperature
jq '.signals[0].engineeringUnits.value.unitId = -1' \
  temperature/after.json > temperature/unknown.json
opcua-kit check --contract temperature/contract.json \
  --before temperature/before.json --after temperature/unknown.json --json
```

The checker exits 3. The type still matches, the unit is unverified, and the JSON report preserves the Good status and unitId -1. For the repair, use the original after.json as the baseline and before.json as the current observation.

## Inspect a device on its first visit

Run the check with one snapshot. Use a new export directory for this example.

```sh
opcua-kit demo --scenario units --export visit
opcua-kit check --contract visit/contract.json --snapshot visit/before.json
opcua-kit check --contract visit/contract.json --snapshot - --json < visit/after.json
```

The file check exits 0. The redirected check finds the Fahrenheit mismatch and exits 2. A dash in the current snapshot position reads exactly one JSON document from a pipe or redirected file. To open a current file literally named `-`, use `./-`. Contract and baseline operands always name regular files.

### Read the history fields

Contracts and snapshots use schema version 1. Check and demo reports use **schema version 2**. In both modes, `after` contains the current observation. The overall decision, counts, and completeness depend on the current snapshot.

| Available history | Fields in the report |
| --- | --- |
| First visit | `baselineProvided` is false. Both `before` and `beforeOutcome` are null. |
| Earlier snapshot, missing observation | `baselineProvided` is true. `before` is null and `beforeOutcome` is unverified. |
| Earlier operation result | `baselineProvided` is true. `before` contains the evidence and `beforeOutcome` gives its decision. |

Pass `--before baseline.json` to include history. Either `--snapshot` or its alias `--after` selects the current snapshot. A mismatch followed by a match produces a resolved finding in the terminal report.

## Preserve the report in CI

```sh
rc=0
opcua-kit check --contract plant.json --before before.json \
  --after after.json --json > report.json || rc=$?
case "$rc" in
  0) echo "All required attributes matched" ;;
  1) echo "Check the input or command diagnostic" >&2 ;;
  2) echo "Review confirmed mismatches" >&2 ;;
  3) echo "Collect the missing evidence" >&2 ;;
esac
exit "$rc"
```

Save the report as a CI artifact on exits 0, 2 and 3. Exit 1 writes a diagnostic to stderr. A report names the device, application URI and principal. Each finding preserves the expected attribute, before and after evidence, `beforeOutcome` and current `outcome`. Findings sort by signal name and attribute. A previous mismatch that now matches is resolved. A current mismatch wins exit 2 even when other evidence is unknown; `complete` records whether all current checks were verifiable.

## Use the Rust API

For an offline checker, run `cargo add opcua-kit --no-default-features --features commissioning` in your application directory. Add `client` to the feature list for authenticated device sessions. Pass JSON bytes to `parse_contract` and `parse_snapshot`, then call `assess` with one snapshot or `compare` with the baseline and current snapshots. `Report::exit_code` gives the CLI decision. Run `cargo doc -p opcua-kit --open` to browse the types.
