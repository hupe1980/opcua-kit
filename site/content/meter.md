+++
title = "Integrate an import meter"
description = "Read cumulative energy and reconcile source-timed measurements against independent interval closes."
weight = 8
[extra]
keywords = "cems energy meter trace cemsd Wh kWh"
group = "Application guides"
+++

Compare timestamped readings from a cumulative grid-import register with the energy your site metering system independently recorded for each quarter hour. Both use watt-hours (Wh).

## Replay a shift offline

Install the CLI with `cargo install opcua-kit --locked --features cli,cems`. In a fresh directory, export the Double example and build a trace.

```sh
opcua-kit meter example --register-type double --export shift
opcua-kit meter trace --contract shift/contract.json \
  --window shift/window.json --readings shift/readings.ndjson --output trace.json
```

With the industrial EMS CLI installed, run `cemsd reconcile trace.json`. The register starts at **4,001,000,001 Wh**. Its increases of 285,000 and 275,000 Wh match the independent closes within the 1 Wh tolerance, across Berlin’s repeated local hour. One interior reading is fractional. The diagnostic identifies its line and source time. Use `--register-type float` or `uint64` for the other examples.

`--output` writes to a new file. An occupied name exits 1. In scripts, join export and reconciliation with `&&` so a failed export cannot reuse an older trace. Omit `--output` to stream the trace as JSON. Diagnostics go to stderr.

## Read an approved register

Choose a cumulative grid-import register from the approved point list. It must be a scalar UInt32, UInt64, Float or Double with declared UN/CEFACT Wh units. Check when it latches, when it resets, and what its source timestamp means.

For example, the OPC UA E2 profile assigns different IDs to import (1001) and export (1004), but both use Float Wh. Either may aggregate over a resettable period. Confirm the period and direction against the meter’s data sheet. [E2 measurements](https://reference.opcfoundation.org/specs/OPC-34100/7.1.3.3) · [Periods and resets](https://reference.opcfoundation.org/specs/OPC-34100/6.2.2.1)

From the driver’s crate directory, run `cargo add opcua-kit --features client,cems`. Load the contract with `parse_contract` at startup. Open the pinned session with the contract’s `application_uri()` and the approved DER credentials. Reuse the client for each poll. [Open a client session](@/client.md#open-a-session)

`client.read_meter(&contract)` returns a typed `MeterReading`. If your driver stores NDJSON for later reconciliation, run `cargo add serde_json@1` and pass the resulting line to its writer.

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

Before reading the Value, `read_meter` checks the live type, rank and unit. A mismatch identifies a changed declaration. An unverified result identifies missing evidence, such as a denied unit read. The error includes the raw status when available. Metadata and Value are separate requests and can change between reads.

For a field reading, supply the approved server leaf, client certificate and matching unencrypted private key in PEM or DER. The contract identifies the expected server and register.

```sh
opcua-kit meter read --contract grid-import.json --endpoint opc.tcp://meter.example:4840 \
  --server-cert server.der --client-cert client.der --client-key client-key.der >> readings.ndjson
```

For a named account, set the contract principal to `username:<account>` and supply `--username` and `--password-file`. The CLI uses the client certificate’s application URI. Its collection deadline includes opening the session and reading the register. You can rehearse the same credentials and endpoint offline. [Capture preflight](@/capture.md#check-the-setup-offline)

Each successful read writes one NDJSON line with the register identity, raw status, available source and server clocks, and local receipt time. A Good-severity reading includes the payload below. A Bad or Uncertain reading exits 0 with status and clocks only. A failed service, invalid declaration or timestamp requiring rounding exits 1 with empty stdout. Keep the original capture and use one writer per file.

## Choose a register for reconciliation

Qualify the site’s cumulative register by its declared type and unit. A floating-point reading must be finite, nonnegative, and a whole number of Wh. Either signed zero qualifies as zero.

| OPC UA type in Wh | Good-severity evidence | Largest eligible whole Wh |
| --- | --- | ---: |
| UInt32 / UInt64 | `value`, unsigned JSON integer | Full range of the declared type |
| Float | `valueBits`, unsigned 32-bit JSON integer | 16,777,215 |
| Double | `valueBits`, JSON string of 16 lowercase hexadecimal digits | 9,007,199,254,740,991 |

For a Double, the string is the original 64-bit word, with the most significant digit first. Keep it as text when passing it through JSON tools. For example, `"3ff0000000000000"` represents 1 Wh. For UInt64 `value`, use tooling that preserves 64-bit integers.

At 2²⁴ Wh for Float or 2⁵³ Wh for Double, the next representable value is 2 Wh away. If the register has reached that limit, select an approved higher-resolution register. A negative, fractional or non-finite value has a different cause.

## Supply independent closes

Use the exported `shift/window.json` as a template.

| Field | What to supply |
| --- | --- |
| `meter.device`, `meter.applicationUri`, `meter.node` | The identity bound to your independent close feed. It must match the reviewed register. |
| `start`, `end` | Offset-bearing quarter-hour boundaries up to 31 days apart. Register readings at either boundary are eligible. |
| `tolerance_wh` | The largest accepted absolute difference in Wh. |
| `closed` | Independent interval energies as `{"at": ..., "wh": ...}`, keyed by quarter **start**. Use `[]` if unavailable. |

Pass the contract, window and readings to `meter trace`. Use `--readings -` for stdin. Each input and the compact trace must fit within 4 MiB.

## Interpret an exclusion

Stderr gives the counts and identifies the first rejected observation in input order. For example, a Double encoding −1.0 at the start of this window produces:

```text
First exclusion at readings line 1 (source 2026-10-25T00:45:00Z): negative cumulative Wh.
```

Use the one-based line number to locate the original observation, including when its source time is missing. Timed readings outside the window are counted separately. Inside the window, the first failed check determines the reason.

1. **Status** must be exactly zero. The diagnostic preserves all 32 bits in hexadecimal, including flags on Good-severity readings.
2. **Source time** must be present and at or before receipt. Server and receipt times cannot supply a missing boundary.
3. **Whole Wh** must be finite, nonnegative, integral and within the wire type’s 1 Wh resolution.

Identical usable readings at one instant coalesce. Conflicting raw statuses, payloads or eligibility at an in-window instant fail the projection. Exit 0 means the trace is ready for `cemsd reconcile`. A missing shared boundary affects both adjacent quarters. Usable interior points can reveal a decrease, while an excluded interior point leaves a gap in coverage.

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

The projection succeeds and counts two whole-Wh exclusions. The first is the fractional interior observation. The second is the coarse shared boundary. The reconciler reports `missing_boundary` for both quarters and exits 1.

## Build a trace as readings arrive

Enable `cems` for offline projection or `client,cems` for the live example below. Construct a `MeterWindow` from the **independent close feed’s configuration**. Supply its device, server application URI, register NodeId, start, end and tolerance in Wh. `MeterProjector::new(&contract, window)?` checks that identity against the approved register. The application is responsible for routing the correct close feed to that window.

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

Call `projector.finish(&closes)?` with `(OffsetDateTime, u64)` pairs giving quarter starts and independently measured Wh. Use an empty slice if closes are unavailable. The returned `projection.trace` contains the register points sorted by UTC instant and exposes `start()`, `end()` and `tolerance_wh()`.

Use `projection.first_exclusion` for a review. It holds a one-based push number (physical line for NDJSON replay), optional UTC source time, and typed reason. Match `MeterExclusionReason::Status(code)` for the raw `u32`. Outside-window readings and usable duplicates have separate counters.

Every push checks scope and metadata. A failed push invalidates the projection. Correct the cause and replay the retained evidence. To budget a window, compare `reading.compact_line_bytes()` with `projector.remaining_input_bytes()`. Every push counts its compact JSON size plus one newline toward 4 MiB. File replay counts the actual bytes. A window accepts up to 131,072 supplied closes, including duplicates.

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

For quarter-hour reconciliation, use `project_meter_trace` to apply status, whole-Wh and clock checks before consuming its register points. A 100 ns source tick survives the round trip. JSON output uses `Z` and omits trailing fractional zeros. Unknown offsets (`-00:00`), leap seconds and more than nine fractional digits are rejected.
