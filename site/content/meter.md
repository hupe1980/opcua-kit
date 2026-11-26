+++
title = "Integrate an import meter"
description = "Read cumulative energy and reconcile source-timed measurements against independent interval closes."
weight = 8
[extra]
keywords = "cems energy meter trace cemsd Wh kWh"
group = "Application guides"
+++

Use this workflow to compare a cumulative grid-import register with independently closed quarter hours. It has two inputs with different owners. The meter supplies timestamped register readings. The site metering system supplies closed interval energies and the acceptable difference in Wh.

## Replay a shift offline

Install the meter commands with `cargo install opcua-kit --locked --features cli,cems`. Run the following in a fresh directory. The example and projection run entirely in Rust.

```sh
opcua-kit meter example --register-type double --export shift
opcua-kit meter trace --contract shift/contract.json \
  --window shift/window.json --readings shift/readings.ndjson --output trace.json
```

After the export succeeds, run the independent reconciliation with the industrial EMS CLI.

```sh
cemsd reconcile trace.json
```

The Double example starts at **4,001,000,001 Wh**. It includes one fractional interior observation. The projection reports `1 excluded by floating-point precision` on stderr and preserves the exact whole-Wh boundaries. For a Float or UInt64 meter, choose `--register-type float` or `--register-type uint64` when exporting into a fresh directory.

The shift spans the repeated local hour in Berlin. The first register increase is 285,000 Wh, exactly the independent close. The second is 275,000 Wh against a close of 274,999 Wh. Both quarters meet the example's 1 Wh tolerance. Use the precision and tolerance agreed for your site.

`--output` publishes the complete trace under a new name in an existing directory you control. If the name is occupied, the command exits 1 and preserves the previous file. Choose a fresh name for another run. A named export leaves stdout empty and prints qualification counts on stderr. Omit the option to stream JSON. In scripts, connect the export and reconciliation with `&&` so a failed export cannot start reconciliation on an older trace.

## Read an approved register

Start with the site-approved point list and the meter's data sheet. Verify the physical meter, grid connection point, import direction and the meaning of the meter's source clock. Choose one scalar OPC UA UInt32, UInt64, Float or Double register with declared UN/CEFACT Wh units. Confirm it is cumulative across the quarters you want to compare, and record when it latches and resets. The OPC UA E2 profile gives import and export distinct measurement IDs (1001 and 1004). Both use Float Wh and may aggregate over a resettable measurement period. Source time may mean the last change. Check the device’s measurement period and timestamp convention with the site owner. [OPC Foundation E2 profile](https://reference.opcfoundation.org/specs/OPC-34100/7.1.3.3) · [Measurement periods and resets](https://reference.opcfoundation.org/specs/OPC-34100/6.2.2.1)

From the driver’s crate directory, run `cargo add opcua-kit --features cems`. Load the contract with `parse_contract` at startup. Open the pinned session with the contract’s `application_uri()` and the approved DER credentials. Reuse the client for each poll. [Open a native session](@/client.md#open-a-session)

The method returns a typed `MeterReading`. If your driver stores NDJSON for later reconciliation, run `cargo add serde_json@1` and pass the resulting line to its writer.

```rust
use opcua_kit::{Client, commissioning::Contract};
use std::error::Error;

async fn poll_line(client: &Client, contract: &Contract) -> Result<Vec<u8>, Box<dyn Error>> {
    let reading = client.read_meter(contract).await?;
    let mut line = serde_json::to_vec(&reading)?;
    line.push(b'\n');
    Ok(line)
}
```

The native meter check requires status zero for the target declaration, the unit browse results, and the unit property’s declaration and value. On a metadata error, the native API identifies the failed declaration or unit check and its raw status when available. A proved mismatch calls for reviewing the mapping. An unverified result means the client could not establish a match, for example because the server denied the unit read. Both stop collection before the process value. Once the metadata matches, an unavailable process value can still supply its own status and clocks.

For a field reading, the equivalent native command uses the client application URI from your certificate, a pinned server leaf, and an unencrypted DER client key. The contract supplies the expected server URI and register.

```sh
opcua-kit meter read --contract grid-import.json --endpoint opc.tcp://meter.example:4840 \
  --client-uri urn:cems:client --server-cert server.der \
  --client-cert client.der --client-key client-key.der >> readings.ndjson
```

Named-user native meter reads accept `--username`, `--password-file` and `--security-policy`. Set the reviewed contract principal to `username:<account>`. The native command runs in process. Its `--timeout` sets the collection budget in seconds, including time spent opening the session. Each native service request is limited to at most 60 seconds. Session shutdown follows collection. For a site already using the Python collector with PEM credentials, omit `--client-uri` and use the preparation instructions in the [capture guide](@/capture.md).

Each invocation verifies the live type, scalar rank and unit in the session before reading the selected Value. Metadata verification and the Value read are separate services, so a device can still change between them. It writes one JSON line containing the register identity, raw status, available source and server timestamps, and local receipt time. A Good-severity reading retains the payload shown in the table below. A Bad or Uncertain reading carries its status and omits both payload fields. Clocks are preserved to nanoseconds. A timestamp that would require rounding fails the read. If a qualification check or a service request fails, the CLI exits 1 with empty stdout. A successfully observed Bad or Uncertain process status produces a reading and exits 0. The native reader discards any attached payload for those severities. The Python collector uses a restricted decoder for the four supported register formats. The projection later applies its own quality rules. Run one writer per evidence file. These are unsigned measurements, so retain them with the original site records and restrict access.

## Choose a register for reconciliation

Qualify the site’s cumulative register by its declared type and unit. A floating-point reading must be finite, nonnegative, and a whole number of Wh. Either signed zero qualifies as zero.

| OPC UA type in Wh | Good-severity evidence | Largest eligible whole Wh |
| --- | --- | ---: |
| UInt32 / UInt64 | `value`, unsigned JSON integer | Full range of the declared type |
| Float | `valueBits`, unsigned 32-bit JSON integer | 16,777,215 |
| Double | `valueBits`, JSON string of 16 lowercase hexadecimal digits | 9,007,199,254,740,991 |

For a Double, the string is the original 64-bit word, with the most significant digit first. Keep it as text when passing it through JSON tools. For example, `"3ff0000000000000"` represents 1 Wh. For UInt64 `value`, use tooling that preserves 64-bit integers.

At the next value above each floating-point limit, the following representable reading is already two Wh away. If the meter’s Float is past its limit, seek an approved cumulative Double or UInt64 register. The energy companion specification uses *Hp* for Double measurements. Check the accumulation period and reset behavior of the specific point. [OPC Foundation measurement conventions](https://reference.opcfoundation.org/specs/OPC-34100/6.2.2.2)

The precision counter includes otherwise-eligible readings from either floating-point type. The other counters identify out-of-window readings, nonzero status, and missing or future source time, checked in that order. A missing shared boundary affects both adjacent quarters. An excluded **interior** reading leaves a gap between usable points; a successful comparison cannot tell you what the counter did in that gap.

## Supply independent closes

Copy the structure of `shift/window.json`. Set `meter.device`, `meter.applicationUri` and `meter.node` from the reviewed meter mapping when preparing the independent closes. This catches a window accidentally selected for another meter. The site is responsible for correctly assigning that identity to its close source. Set `start` and `end` to offset-bearing quarter boundaries (up to 31 days), `tolerance_wh` to the agreed tolerance and `closed` to an array of `{"at": ..., "wh": ...}` values. Each close is keyed by **interval start**. Keep the independent close source separate from the register. Use an empty array for unavailable closes.

Run `meter trace` with the reviewed contract, window and site readings. Use `--readings -` to read NDJSON from a pipe. Each input and the output trace must fit within 4 MiB. A projected point requires raw status zero, an in-window source time at or before receipt, and an exact integer. The command preserves usable interior readings so a decrease inside a quarter remains visible. It reports exclusions on stderr. Unavailable source time is never replaced by server or receipt time. At a repeated in-window source instant, conflicting raw statuses, register payloads (including a one-bit difference in either floating-point format) or eligibility fail the projection, even if both records would have been excluded.

Projection exit 0 means the trace is valid input. **Run `cemsd reconcile` for the interval decision.** Missing boundaries and closes remain absent. A decrease or an out-of-tolerance interval is reported by the reconciler. Preserve the NDJSON alongside the trace to investigate a specific raw status or timestamp. The fixture and encrypted software peer exercise the workflow; qualify the physical meter, counter resolution and site access before relying on its output.

## Rehearse a missing boundary

With the exported **Double** example and `jq`, replace the shared boundary in a copy of the readings. The word `"4340000000000000"` encodes 9,007,199,254,740,992 Wh. Keep the original evidence for comparison.

```sh
jq -c --slurpfile window shift/window.json '
  if .sourceAt == $window[0].closed[1].at then .valueBits = "4340000000000000" else . end
' shift/readings.ndjson > coarse.ndjson
opcua-kit meter trace --contract shift/contract.json --window shift/window.json \
  --readings coarse.ndjson --output coarse-trace.json &&
  cemsd reconcile coarse-trace.json
```

The projection succeeds and reports two precision exclusions, the fractional interior observation and the coarse shared boundary. The reconciler reports `missing_boundary` for both quarters and exits 1.

## Build a trace as readings arrive

Enable `commissioning` and construct a `MeterWindow` from the **independent close feed’s configuration**. Supply its device, server application URI, register NodeId, start, end and tolerance in Wh. `MeterProjector::new(&contract, window)?` checks that identity against the approved register. The application is responsible for routing the correct close feed to that window.

Keep the projector alongside your polling state. The following function records one observation in an already-open window.

```rust
use opcua_kit::{Client, commissioning::{Contract, meter::MeterProjector}};
use std::error::Error;

async fn record_poll(
    client: &Client,
    contract: &Contract,
    projector: &mut MeterProjector<'_>,
) -> Result<(), Box<dyn Error>> {
    let reading = client.read_meter(contract).await?;
    projector.push(&reading)?;
    Ok(())
}
```

After the window ends, call `projector.finish(&closes)?`. Each close is a pair of `(OffsetDateTime, u64)` giving the quarter’s **start** and its independently measured Wh. An empty slice records that no closes were available. The trace includes eligible register observations at either window boundary, keeps interior observations, and sorts points by UTC instant. Use `projection.trace` for reconciliation and the counters on `projection` to explain exclusions. You can inspect `start()`, `end()` and `tolerance_wh()` directly on the trace.

Every push checks the reading’s scope and declared register metadata, including for readings outside the window. A conflicting observation or failed push invalidates that projection. Rebuild the window from retained evidence after correcting the cause. A Bad status is a valid observation that the projector counts and excludes. A read operation that fails before returning a `MeterReading` has supplied nothing to push.

The typed input budget is 4 MiB, counted using each reading’s compact JSON size plus one newline. Compare `reading.compact_line_bytes()` with `projector.remaining_input_bytes()` to monitor capacity before a push. The cost is cached when the reading is validated. Duplicate, skipped and out-of-window observations all consume budget. For higher-frequency capture, plan shorter aligned windows or replay retained readings into them. The projector retains the facts needed to detect conflicts and qualify points. Keep original readings separately if the site needs a replayable record. A window accepts up to 131,072 supplied closes, including duplicates, and the compact output with its newline must fit in 4 MiB. File replay continues to measure the actual input bytes.

Run the offline Rust example from the checkout. Its two quarters span Berlin’s repeated local hour. The output is ready for `cemsd reconcile`.

```sh
cargo run --quiet --locked --no-default-features --features cems \
  --example project_meter > trace.json && cemsd reconcile trace.json
```

## Use meter readings in Rust

Enable the `cems` Cargo feature to use the meter API. It validates a reading against your reviewed contract. The source and server clocks are optional. Receipt time is always present. Each accessor returns a UTC `time::OffsetDateTime` or its `Option`. The library re-exports the type so you can name it in your own interfaces.

```rust
use opcua_kit::commissioning::{Contract, Error};
use opcua_kit::commissioning::meter::{OffsetDateTime, parse_meter_reading};

fn source_clock(contract: &Contract, record: &[u8]) -> Result<Option<OffsetDateTime>, Error> {
    Ok(parse_meter_reading(contract, record)?.source_at())
}
```

For quarter-hour reconciliation, use `project_meter_trace` to apply status, precision and clock checks before consuming its register points. A 100 ns source tick survives the round trip. JSON output uses `Z` and omits trailing fractional zeros. Unknown offsets (`-00:00`), leap seconds and more than nine fractional digits are rejected.
