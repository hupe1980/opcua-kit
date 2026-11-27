# Changelog

## 0.2.0 — 2026-11-27

- `MeterProjection::first_exclusion` identifies the first rejected reading by input position, optional UTC source time and reason. Quality exclusions preserve the full OPC UA status code. When constructing a projection directly, supply the new field. Use `..` in patterns that only need selected fields.
- `meter trace` reports the line and cause on stderr. It distinguishes negative, fractional and non-finite Wh from insufficient register resolution.

## 0.1.0 — 2026-11-27

- Added dependency-free endpoint discovery and unsigned UADP scalar key frames.
- Added a Rust client for certificate-pinned sessions, typed reads, browsing, subscriptions, events, and raw history. The optional control API supports writes, method calls, and alarm acknowledgement.
- Added a Rust server for application-owned, read-only variables and data-change subscriptions.
- Added a commissioning CLI for offline credential checks, live metadata capture, and signal-contract assessment. The optional CEMS profile prepares meter traces for interval reconciliation.

## 0.0.1 — 2026-11-24

- Published the initial OPC UA status classifier.
