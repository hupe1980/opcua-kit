#![cfg(feature = "cems")]

use opcua_kit::commissioning::{
    Contract, MAX_DOCUMENT_BYTES,
    meter::{
        MeterExclusion, MeterExclusionReason, MeterProjector, MeterWindow, parse_meter_reading,
        project_meter_trace, validate_meter_contract,
    },
    parse_contract,
};
use serde_json::{Value, json};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

const START: &str = "2026-10-25T02:45:00+02:00";
const MID: &str = "2026-10-25T02:00:00+01:00";
const END: &str = "2026-10-25T02:15:00+01:00";
const RECEIPT: &str = "2026-10-25T02:15:30+01:00";

fn row(at: &str, wh: u64) -> Value {
    json!({
        "schemaVersion": 1,
        "device": "incomer",
        "applicationUri": "urn:meter",
        "principal": "anonymous",
        "name": "ImportWh",
        "node": {"namespace": "urn:plant", "id": "i=123"},
        "dataType": {"namespace": "http://opcfoundation.org/UA/", "id": "i=9"},
        "valueRank": -1,
        "engineeringUnits": {"namespaceUri":"http://www.opcfoundation.org/UA/units/un/cefact", "unitId": 5720146},
        "status": 0,
        "receivedAt": RECEIPT,
        "sourceAt": at,
        "serverAt": null,
        "value": wh,
    })
}

fn requirements() -> Value {
    let record = row(START, 0);
    let mut signal = json!({});
    for key in ["name", "node", "dataType", "valueRank", "engineeringUnits"] {
        signal[key] = record[key].clone();
    }
    json!({"schemaVersion":1, "device":"incomer","applicationUri":"urn:meter",
           "principal":"anonymous","signals":[signal]})
}

fn contract() -> Contract {
    parse_contract(&bytes(&requirements())).unwrap()
}

fn typed_contract(id: &str) -> Contract {
    let mut spec = requirements();
    spec["signals"][0]["dataType"]["id"] = id.into();
    parse_contract(&bytes(&spec)).unwrap()
}

fn float_row(at: &str, bits: u32) -> Value {
    let mut record = row(at, 0);
    record["dataType"]["id"] = "i=10".into();
    record.as_object_mut().unwrap().remove("value");
    record["valueBits"] = bits.into();
    record
}

fn window() -> Value {
    json!({
        "meter":{"device":"incomer","applicationUri":"urn:meter","node":{"namespace":"urn:plant","id":"i=123"}},
        "start": START, "end": END, "tolerance_wh":1,
        "closed":[{"at": MID, "wh": 274999}, {"at": START, "wh": 285000}]
    })
}

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn ndjson(rows: &[Value]) -> Vec<u8> {
    rows.iter().map(bytes).collect::<Vec<_>>().join(&b'\n')
}

fn typed_window(contract: &Contract) -> MeterWindow<'_> {
    MeterWindow {
        device: contract.device(),
        application_uri: contract.application_uri(),
        node: &contract.signals()[0].node,
        start: OffsetDateTime::parse(START, &Rfc3339).unwrap(),
        end: OffsetDateTime::parse(END, &Rfc3339).unwrap(),
        tolerance_wh: 1,
    }
}

#[test]
fn typed_projection_matches_replay_counters_and_evidence_order() {
    // 017-typed-meter-projection/SR-001
    let c = typed_contract("i=10");
    let valid = float_row(START, 1.0_f32.to_bits());
    let mut flagged = float_row(MID, 9.0_f32.to_bits());
    flagged["status"] = 0x4000.into();
    let mut untimed = float_row(START, 7.0_f32.to_bits());
    untimed["sourceAt"] = Value::Null;
    let mut future = float_row(END, 3.5_f32.to_bits());
    future["receivedAt"] = MID.into();
    let rows = [
        float_row("2026-10-24T00:00:00Z", 0xffc0_0042),
        valid.clone(),
        flagged,
        untimed,
        future,
        float_row("2026-10-25T00:48:00.000000001Z", 1.25_f32.to_bits()),
        valid,
    ];
    let replay = project_meter_trace(&c, &ndjson(&rows), &bytes(&window())).unwrap();
    let mut cursor = MeterProjector::new(&c, typed_window(&c)).unwrap();
    for row in rows {
        cursor
            .push(&parse_meter_reading(&c, &bytes(&row)).unwrap())
            .unwrap();
    }
    let closes = [
        (OffsetDateTime::parse(START, &Rfc3339).unwrap(), 285_000),
        (OffsetDateTime::parse(MID, &Rfc3339).unwrap(), 274_999),
    ];
    let direct = cursor.finish(&closes).unwrap();
    for result in [&direct, &replay] {
        assert_eq!(
            result.first_exclusion,
            Some(MeterExclusion {
                input_position: 3,
                source_at: Some(OffsetDateTime::parse(MID, &Rfc3339).unwrap()),
                reason: MeterExclusionReason::Status(0x4000),
            })
        );
        assert_eq!(
            (
                result.skipped_status,
                result.skipped_source_time,
                result.skipped_precision,
                result.outside_window,
                result.duplicate_readings
            ),
            (1, 2, 1, 1, 1)
        );
    }
    assert_eq!(
        serde_json::to_vec(&direct.trace).unwrap(),
        serde_json::to_vec(&replay.trace).unwrap()
    );
}

#[test]
fn first_clock_exclusion_locates_the_physical_line_even_without_source_time() {
    let contract = contract();
    let window = bytes(&window());
    let valid = row(START, 10);
    let outside = row("2026-10-24T00:00:00Z", 0);
    let mut capture = ndjson(&[outside, valid.clone(), valid]);
    assert!(
        project_meter_trace(&contract, &capture, &window)
            .unwrap()
            .first_exclusion
            .is_none()
    );
    capture.extend_from_slice(b"\n \r\n");
    for (source, reason) in [
        (Value::Null, MeterExclusionReason::MissingSourceTime),
        (json!(MID), MeterExclusionReason::SourceAfterReceipt),
    ] {
        let mut row = row(MID, 1);
        row["receivedAt"] = json!(START);
        row["sourceAt"] = source;
        let source_at = row["sourceAt"]
            .as_str()
            .map(|at| OffsetDateTime::parse(at, &Rfc3339).unwrap());
        let mut input = capture.clone();
        input.extend(bytes(&row));
        let projection = project_meter_trace(&contract, &input, &window).unwrap();
        assert_eq!(
            projection.first_exclusion,
            Some(MeterExclusion {
                input_position: 5,
                source_at,
                reason,
            })
        );
        assert_eq!(projection.skipped_source_time, 1);
    }
}

#[test]
fn typed_scope_and_conflict_errors_are_terminal() {
    // 017-typed-meter-projection/SR-001
    let c = contract();
    let on_time = parse_meter_reading(&c, &bytes(&row(MID, 7))).unwrap();
    // A valid reading may have been constructed with a different approved contract.
    // Its scope still matters when the time is outside this window.
    for field in ["device", "applicationUri", "name", "node", "dataType"] {
        let mut spec = requirements();
        let mut alien = row("2026-10-24T00:00:00Z", 7);
        let other = match field {
            "node" => json!({"namespace":"urn:other","id":"i=123"}),
            "dataType" => json!({"namespace":"http://opcfoundation.org/UA/","id":"i=7"}),
            _ => json!("urn:other"),
        };
        if field == "device" || field == "applicationUri" {
            spec[field] = other.clone();
        } else {
            spec["signals"][0][field] = other.clone();
        }
        alien[field] = other;
        let from = parse_contract(&bytes(&spec)).unwrap();
        let wrong_scope = parse_meter_reading(&from, &bytes(&alien)).unwrap();
        let mut cursor = MeterProjector::new(&c, typed_window(&c)).unwrap();
        cursor.push(&on_time).unwrap();
        let error = cursor.push(&wrong_scope).unwrap_err().to_string();
        assert_eq!(cursor.remaining_input_bytes(), 0);
        assert!(error.contains("reading 2"), "{field}: {error}");
        assert_eq!(cursor.push(&on_time).unwrap_err().to_string(), error);
        assert_eq!(cursor.finish(&[]).unwrap_err().to_string(), error);
    }
    let mut cursor = MeterProjector::new(&c, typed_window(&c)).unwrap();
    cursor.push(&on_time).unwrap();
    let conflict = parse_meter_reading(&c, &bytes(&row(MID, 8))).unwrap();
    let error = cursor.push(&conflict).unwrap_err().to_string();
    assert!(error.contains("conflicting"), "{error}");
    assert_eq!(cursor.finish(&[]).unwrap_err().to_string(), error);
}

#[test]
fn typed_bounds_charge_every_supplied_reading_and_close() {
    // 017-typed-meter-projection/SR-002
    let mut spec = requirements();
    let mut outside = row("2026-10-24T00:00:00Z", 0);
    let original = parse_meter_reading(&contract(), &bytes(&outside)).unwrap();
    let canonical_bytes = serde_json::to_vec(&original).unwrap().len() + 1;
    assert_eq!(original.compact_line_bytes(), canonical_bytes);
    // Exactly two copies fit the inclusive 4 MiB limit, including their newlines.
    let device = "x".repeat(MAX_DOCUMENT_BYTES / 2 - canonical_bytes + "incomer".len());
    outside["device"] = device.clone().into();
    spec["device"] = device.into();
    let c = parse_contract(&bytes(&spec)).unwrap();
    let reading = parse_meter_reading(&c, &bytes(&outside)).unwrap();
    assert_eq!(
        serde_json::to_vec(&reading).unwrap().len() + 1,
        MAX_DOCUMENT_BYTES / 2
    );
    for over in [false, true] {
        let mut cursor = MeterProjector::new(&c, typed_window(&c)).unwrap();
        assert_eq!(cursor.remaining_input_bytes(), MAX_DOCUMENT_BYTES);
        cursor.push(&reading).unwrap();
        assert_eq!(
            cursor.remaining_input_bytes(),
            MAX_DOCUMENT_BYTES - reading.compact_line_bytes()
        );
        cursor.push(&reading).unwrap();
        assert_eq!(cursor.remaining_input_bytes(), 0);
        if over {
            let error = cursor.push(&reading).unwrap_err().to_string();
            assert!(error.contains("4 MiB"), "{error}");
            assert_eq!(cursor.finish(&[]).unwrap_err().to_string(), error);
        } else {
            assert_eq!(cursor.finish(&[]).unwrap().outside_window, 2);
        }
    }
    let c = contract();
    let closes = vec![(typed_window(&c).start, u64::MAX); 131_073];
    let project = || MeterProjector::new(&c, typed_window(&c)).unwrap();
    let full = project().finish(&closes[..131_072]).unwrap();
    assert_eq!(full.trace.closed.len(), 1);
    assert_eq!(full.trace.closed[0].wh, u64::MAX);
    assert!(project().finish(&closes).is_err());
}

#[test]
fn approved_register_only() {
    // 006-meter-pilot/SR-001. Commission before reading any Value.
    for (key, value) in [
        (
            "dataType",
            json!({"namespace":"http://opcfoundation.org/UA/","id":"i=8"}),
        ),
        ("dataType", json!({"namespace":"urn:custom","id":"i=9"})),
        ("valueRank", json!(1)),
        (
            "engineeringUnits",
            json!({"namespaceUri":"urn:other","unitId":5720146}),
        ),
        (
            "engineeringUnits",
            json!({"namespaceUri":"http://www.opcfoundation.org/UA/units/un/cefact","unitId":4937544}),
        ),
    ] {
        let mut spec = requirements();
        spec["signals"][0][key] = value;
        let c = parse_contract(&bytes(&spec)).unwrap();
        assert!(validate_meter_contract(&c).is_err(), "{key}");
    }
    let mut wrong_scope = requirements();
    wrong_scope["principal"] = "plant-service".into();
    assert!(validate_meter_contract(&parse_contract(&bytes(&wrong_scope)).unwrap()).is_err());
    for key in ["valueRank", "engineeringUnits"] {
        let mut spec = requirements();
        spec["signals"][0].as_object_mut().unwrap().remove(key);
        let c = parse_contract(&bytes(&spec)).unwrap();
        assert!(validate_meter_contract(&c).is_err(), "{key}");
    }
    let mut spec = requirements();
    let mut second = spec["signals"][0].clone();
    second["node"]["id"] = "i=124".into();
    second["name"] = "Other".into();
    spec["signals"].as_array_mut().unwrap().push(second);
    assert!(validate_meter_contract(&parse_contract(&bytes(&spec)).unwrap()).is_err());
}

#[test]
fn reading_validates_scope_type_value_and_precise_nullable_clocks() {
    // 006-meter-pilot/SR-001. Whole-register identity and exact raw integer.
    let c = contract();
    let mut sample = row("2026-10-25T02:59:59.999999999+02:00", u64::MAX);
    sample["node"]["id"] = "i=0123".into();
    let valid = parse_meter_reading(&c, &bytes(&sample)).unwrap();
    assert_eq!(valid.status(), 0);
    assert_eq!(valid.value(), Some(u64::MAX));
    assert_eq!(valid.source_at().unwrap().nanosecond(), 999_999_999);
    assert!(valid.server_at().is_none());
    assert!(valid.received_at() > valid.source_at().unwrap());
    let roundtrip = serde_json::to_value(valid).unwrap();
    assert_eq!(roundtrip["value"], u64::MAX);
    assert_eq!(roundtrip["sourceAt"], "2026-10-25T00:59:59.999999999Z");
    assert_eq!(roundtrip["node"]["id"], "i=123");
    assert!(roundtrip["serverAt"].is_null());
    for (key, wrong) in [
        ("name", json!("ExportWh")),
        ("applicationUri", json!("urn:elsewhere")),
        ("device", json!("other")),
        ("principal", json!("other")),
        ("node", json!({"namespace":"urn:other","id":"i=123"})),
        (
            "dataType",
            json!({"namespace":"http://opcfoundation.org/UA/","id":"i=7"}),
        ),
        ("valueRank", json!(0)),
        (
            "engineeringUnits",
            json!({"namespaceUri":"urn:other","unitId":5720146}),
        ),
        ("status", json!(4_294_967_296u64)),
        ("schemaVersion", json!(2)),
        ("value", json!(123.0)),
        ("value", Value::Null),
        ("value", json!(-1)),
        ("undocumented", json!("secret")),
    ] {
        let mut record = sample.clone();
        record[key] = wrong;
        let err = parse_meter_reading(&c, &bytes(&record))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret"), "{key}");
    }
    for key in ["value", "sourceAt", "serverAt", "receivedAt"] {
        let mut record = sample.clone();
        record.as_object_mut().unwrap().remove(key);
        assert!(parse_meter_reading(&c, &bytes(&record)).is_err(), "{key}");
    }
    let mut spec = requirements();
    spec["signals"][0]["dataType"]["id"] = "i=7".into();
    let u32_contract = parse_contract(&bytes(&spec)).unwrap();
    sample["dataType"]["id"] = "i=7".into();
    sample["value"] = u32::MAX.into();
    assert!(parse_meter_reading(&u32_contract, &bytes(&sample)).is_ok());
    sample["value"] = (u64::from(u32::MAX) + 1).into();
    assert!(parse_meter_reading(&u32_contract, &bytes(&sample)).is_err());
}

#[test]
fn meter_clocks_round_trip_through_the_cems_rfc3339_parser() {
    let c = contract();
    for (input, canonical) in [
        ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
        (
            "1969-12-31t18:59:59.000000100-05:00",
            "1969-12-31T23:59:59.0000001Z",
        ),
        ("1970-01-01t00:00:00.100000000z", "1970-01-01T00:00:00.1Z"),
        (
            "9999-12-31T23:59:59.999999999Z",
            "9999-12-31T23:59:59.999999999Z",
        ),
    ] {
        let mut sample = row(input, 1);
        sample["serverAt"] = input.into();
        sample["receivedAt"] = input.into();
        let valid = parse_meter_reading(&c, &bytes(&sample)).unwrap();
        let expected = OffsetDateTime::parse(canonical, &Rfc3339).unwrap();
        for clock in [
            valid.source_at().unwrap(),
            valid.server_at().unwrap(),
            valid.received_at(),
        ] {
            assert_eq!(clock.offset(), UtcOffset::UTC);
            assert_eq!(clock, expected);
        }
        let encoded = serde_json::to_value(valid).unwrap();
        for key in ["sourceAt", "serverAt", "receivedAt"] {
            assert_eq!(encoded[key], canonical);
        }
    }
}

#[test]
fn meter_timestamps_reject_ambiguous_lossy_and_out_of_range_evidence() {
    // 011-library-time/SR-001
    let c = contract();
    for input in [
        "2026-10-25T00:59:59-00:00",
        "2026-10-25T00:59:59",
        "2016-12-31T23:59:60Z",
        "2026-10-25T00:59:59.9999999999Z",
        "2026-10-25 00:59:59Z",
        "2026-02-29T00:00:00Z",
        "2026-10-25T00:59:59+24:00",
        "0000-01-01T00:00:00+00:01",
        "9999-12-31T23:59:59-00:01",
    ] {
        assert!(
            parse_meter_reading(&c, &bytes(&row(input, 1))).is_err(),
            "{input}"
        );
    }
}

#[test]
fn pre_epoch_projection_preserves_adjacent_nanoseconds_and_quarter_boundaries() {
    let mut w = window();
    w["start"] = "1969-12-31T23:45:00Z".into();
    w["end"] = "1970-01-01T00:00:00Z".into();
    w["closed"] = json!([{"at": "1970-01-01T00:45:00+01:00", "wh": 4}]);
    let rows = ndjson(&[
        row("1969-12-31T23:59:59.999999999Z", 2),
        row("1970-01-01T00:59:59.999999998+01:00", 1),
    ]);
    let projection = project_meter_trace(&contract(), &rows, &bytes(&w)).unwrap();
    let instants: Vec<_> = projection
        .trace
        .register
        .iter()
        .map(|point| {
            assert_eq!(point.at().offset(), UtcOffset::UTC);
            point.at().unix_timestamp_nanos()
        })
        .collect();
    assert_eq!(instants, [-2, -1]);
    assert_eq!(projection.trace.closed[0].at().unix_timestamp(), -900);
}

#[test]
fn exact_source_times_and_independent_closes_reach_cems() {
    // 006-meter-pilot/SR-002. Normalize by instant, retain interior decreases.
    let c = contract();
    let interior = "2026-10-25T02:59:59.999999999+02:00";
    let mut duplicate = row("2026-10-25T00:45:00Z", 1_000_000);
    duplicate["receivedAt"] = END.into();
    let batch = ndjson(&[
        row(MID, 1_285_000),
        row(interior, 980_000),
        row(START, 1_000_000),
        duplicate,
        row(END, 1_560_000),
    ]);
    let projected = project_meter_trace(&c, &batch, &bytes(&window())).unwrap();
    assert_eq!(projected.duplicate_readings, 1);
    assert_eq!(
        serde_json::to_value(projected.trace).unwrap(),
        json!({
            "start":"2026-10-25T00:45:00Z","end":"2026-10-25T01:15:00Z","tolerance_wh":1,
            "register":[
                {"at":"2026-10-25T00:45:00Z","wh":1_000_000},
                {"at":"2026-10-25T00:59:59.999999999Z","wh":980_000},
                {"at":"2026-10-25T01:00:00Z","wh":1_285_000},
                {"at":"2026-10-25T01:15:00Z","wh":1_560_000}
            ],
            "closed":[{"at":"2026-10-25T00:45:00Z","wh":285_000},{"at":"2026-10-25T01:00:00Z","wh":274_999}]
        })
    );
}

#[test]
fn unavailable_qualified_future_and_untimed_are_gaps() {
    // 006-meter-pilot/SR-002. Receipt/server time never fills a missing source time.
    let mut bad = row(MID, 99);
    bad["status"] = 0x80340400u32.into();
    assert!(parse_meter_reading(&contract(), &bytes(&bad)).is_err());
    bad.as_object_mut().unwrap().remove("value");
    let mut flagged = row(START, 99);
    flagged["status"] = 0x00000400u32.into();
    let mut untimed = row(START, 40);
    untimed["sourceAt"] = Value::Null;
    untimed["serverAt"] = START.into();
    let mut future = row(END, 50);
    future["receivedAt"] = MID.into();
    let outside = row("2026-10-24T00:00:00Z", 20);
    let rows = ndjson(&[bad.clone(), flagged, untimed, future, outside]);
    let p = project_meter_trace(&contract(), &rows, &bytes(&window())).unwrap();
    assert_eq!(
        (p.skipped_status, p.skipped_source_time, p.outside_window),
        (2, 2, 1)
    );
    assert!(p.trace.register.is_empty());
    for conflict in [vec![row(MID, 1), row(MID, 2)], vec![bad, row(MID, 1)]] {
        assert!(project_meter_trace(&contract(), &ndjson(&conflict), &bytes(&window())).is_err());
    }
    assert!(
        project_meter_trace(&contract(), b"", &bytes(&window()))
            .unwrap()
            .trace
            .register
            .is_empty()
    );
}

#[test]
fn refuses_invalid_windows_closed_series_and_unbounded_or_malformed_inputs() {
    // 006-meter-pilot/SR-003. Reject incompatible independent series before publication.
    let c = contract();
    for (key, value) in [
        ("register", json!([])),
        ("closed", json!([[START, 1]])),
        ("start", json!(MID)),
        ("end", json!("2026-10-25T01:15:00.000000001Z")),
        ("end", json!("2027-10-25T00:15:00Z")),
        ("closed", json!([{"at":END,"wh":0}])),
        (
            "closed",
            json!([{"at":MID,"wh":3},{"at":"2026-10-25T01:00:00Z","wh":4}]),
        ),
    ] {
        let mut w = window();
        w[key] = value;
        assert!(project_meter_trace(&c, b"", &bytes(&w)).is_err(), "{key}");
    }
    let mut w = window();
    w["closed"] = json!([{"at":MID,"wh":3},{"at":"2026-10-25T01:00:00Z","wh":3}]);
    assert_eq!(
        project_meter_trace(&c, b"", &bytes(&w))
            .unwrap()
            .trace
            .closed
            .len(),
        1
    );
    let batch = vec![b' '; MAX_DOCUMENT_BYTES + 1];
    assert!(project_meter_trace(&c, &batch, &bytes(&window())).is_err());
    assert!(project_meter_trace(&c, b"", &batch).is_err());
    let mut lines = bytes(&row(START, 1));
    lines.extend_from_slice(b"\n{");
    let error = project_meter_trace(&c, &lines, &bytes(&window()))
        .unwrap_err()
        .to_string();
    assert!(error.contains("readings line 2"), "{error}");
}

#[test]
fn scope_is_checked_before_window_filter_and_both_boundaries_are_inclusive() {
    // 006-meter-pilot/SR-003. Time filtering cannot waive validation of the source.
    let c = contract();
    let win = bytes(&window());
    let outside = "2026-10-24T00:00:00Z";
    let rows = [row(outside, 10), row(outside, 11)];
    let result = project_meter_trace(&c, &ndjson(&rows), &win).unwrap();
    assert_eq!(result.outside_window, 2);
    assert!(result.trace.register.is_empty());
    let mut alien = rows[0].clone();
    alien["node"]["id"] = "s=elsewhere".into();
    assert!(project_meter_trace(&c, &bytes(&alien), &win).is_err());
    for at in [START, END] {
        let conflicting = ndjson(&[row(at, 1), row(at, 2)]);
        assert!(project_meter_trace(&c, &conflicting, &win).is_err());
        let repeated = ndjson(&[row(at, 1), row(at, 1)]);
        let result = project_meter_trace(&c, &repeated, &win).unwrap();
        assert_eq!(result.duplicate_readings, 1);
        assert_eq!(result.trace.register.len(), 1);
    }
}

#[test]
fn bounded_input_includes_the_reencoded_reading_and_newline() {
    // 006-meter-pilot/SR-003. Even a compact reading needs room for its newline.
    let mut record = row("2026-10-25T01:00:00.1Z", 1);
    record["receivedAt"] = "2026-10-25T01:15:30Z".into();
    record["device"] = "".into();
    let free = MAX_DOCUMENT_BYTES - bytes(&record).len();
    let device = "a".repeat(free);
    record["device"] = device.clone().into();
    let mut spec = requirements();
    spec["device"] = device.into();
    let c = parse_contract(&bytes(&spec)).unwrap();
    let encoded = bytes(&record);
    assert_eq!(encoded.len(), MAX_DOCUMENT_BYTES);
    assert!(matches!(parse_meter_reading(&c, &encoded), Err(e) if e.to_string().contains("4 MiB")));

    let w = bytes(&window());
    let whitespace = vec![b' '; MAX_DOCUMENT_BYTES];
    let result = project_meter_trace(&contract(), &whitespace, &w).unwrap();
    assert!(result.trace.register.is_empty());
    assert!(serde_json::to_vec(&result.trace).unwrap().len() < MAX_DOCUMENT_BYTES);
}

#[test]
fn independently_closed_series_requires_the_same_meter_binding() {
    // 006-meter-pilot/SR-003. An independent close series must identify this meter.
    let c = contract();
    for (field, other) in [
        ("device", json!("outgoing feeder")),
        ("applicationUri", json!("urn:meter:other")),
        ("node", json!({"namespace":"urn:plant","id":"i=124"})),
        ("node", json!({"namespace":"urn:plant:other","id":"i=123"})),
    ] {
        let mut w = window();
        w["meter"][field] = other;
        let error = project_meter_trace(&c, b"", &bytes(&w)).unwrap_err();
        assert!(error.to_string().contains("window meter"), "{field}");
    }
    let mut w = window();
    w.as_object_mut().unwrap().remove("meter");
    assert!(project_meter_trace(&c, b"", &bytes(&w)).is_err());
    let mut w = window();
    w["meter"].as_object_mut().unwrap().remove("node");
    assert!(project_meter_trace(&c, b"", &bytes(&w)).is_err());

    let mut w = window();
    w["meter"]["node"]["id"] = "i=000123".into();
    let matched = project_meter_trace(&c, b"", &bytes(&w)).unwrap();
    let output = serde_json::to_value(matched.trace).unwrap();
    assert!(output.get("meter").is_none());
    assert_eq!(output["closed"].as_array().unwrap().len(), 2);
}

#[test]
fn disqualified_duplicates_still_require_consistent_evidence() {
    // 006-meter-pilot/SR-003. Conflicting raw evidence cannot be hidden in a gap.
    let c = contract();
    let w = bytes(&window());
    let mut original = row(MID, 7);
    original["status"] = 1024.into();
    for (field, replacement) in [("value", json!(8)), ("status", json!(1025))] {
        let mut other = original.clone();
        other[field] = replacement;
        let evidence = ndjson(&[original.clone(), other]);
        assert!(project_meter_trace(&c, &evidence, &w).is_err());
    }
    let mut same = original.clone();
    same["receivedAt"] = END.into();
    same["serverAt"] = MID.into();
    let excluded = project_meter_trace(&c, &ndjson(&[original, same]), &w).unwrap();
    assert_eq!(excluded.skipped_status, 2);
    assert!(excluded.trace.register.is_empty());

    let on_time = row(MID, 7);
    let mut skewed = on_time.clone();
    skewed["receivedAt"] = START.into();
    assert!(project_meter_trace(&c, &ndjson(&[on_time, skewed]), &w).is_err());
}

#[test]
fn float_evidence_requires_only_raw_bits_for_good_status() {
    // 007-float-meter/SR-001. The type, status and integer bit representation agree.
    let c = typed_contract("i=10");
    validate_meter_contract(&c).unwrap();
    let mut sample = float_row(START, 0xffc0_1234);
    sample["status"] = 1024.into();
    let reading = parse_meter_reading(&c, &bytes(&sample)).unwrap();
    assert_eq!(reading.value_bits(), Some(0xffc0_1234));
    assert_eq!(reading.value(), None);
    let roundtrip = serde_json::to_value(reading).unwrap();
    assert_eq!(roundtrip["valueBits"], 0xffc0_1234u32);
    assert!(roundtrip.get("value").is_none());

    for wrong in [
        json!(-1),
        json!(0.0),
        json!("0"),
        json!(1u64 << 32),
        Value::Null,
    ] {
        let mut malformed = sample.clone();
        malformed["valueBits"] = wrong;
        assert!(parse_meter_reading(&c, &bytes(&malformed)).is_err());
    }
    let mut both = sample.clone();
    both["value"] = 0.into();
    assert!(parse_meter_reading(&c, &bytes(&both)).is_err());
    both.as_object_mut().unwrap().remove("valueBits");
    assert!(parse_meter_reading(&c, &bytes(&both)).is_err());
    let mut missing = sample.clone();
    missing.as_object_mut().unwrap().remove("valueBits");
    assert!(parse_meter_reading(&c, &bytes(&missing)).is_err());
    for status in [0x4000_0000u32, 0x8000_0000, 0xffff_ffff] {
        sample["status"] = status.into();
        assert!(parse_meter_reading(&c, &bytes(&sample)).is_err());
        missing["status"] = status.into();
        assert_eq!(
            parse_meter_reading(&c, &bytes(&missing))
                .unwrap()
                .value_bits(),
            None
        );
    }
    let mut integer = row(START, u64::MAX);
    assert_eq!(
        parse_meter_reading(&contract(), &bytes(&integer))
            .unwrap()
            .value_bits(),
        None
    );
    integer["valueBits"] = 0.into();
    assert!(parse_meter_reading(&contract(), &bytes(&integer)).is_err());
    integer.as_object_mut().unwrap().remove("value");
    assert!(parse_meter_reading(&contract(), &bytes(&integer)).is_err());
}

#[test]
fn float_projection_requires_whole_wh_and_forward_one_wh_resolution() {
    // 007-float-meter/SR-002. Accept only exact integral Wh in [0, 2²⁴).
    let c = typed_contract("i=10");
    let w = bytes(&window());
    for (bits, wh) in [
        (0, 0),
        (0x8000_0000, 0),
        (1.0f32.to_bits(), 1),
        (16_777_215.0f32.to_bits(), 16_777_215),
    ] {
        let projected = project_meter_trace(&c, &bytes(&float_row(MID, bits)), &w).unwrap();
        assert_eq!(projected.trace.register.len(), 1);
        assert_eq!(projected.trace.register[0].wh, wh);
        assert_eq!(projected.skipped_precision, 0);
        assert_eq!(projected.first_exclusion, None);
    }
    for bits in [
        0x0000_0001,
        0x8000_0001,
        0x7f80_0001,
        0xffc0_1234,
        f32::INFINITY.to_bits(),
        f32::NEG_INFINITY.to_bits(),
        (-1.0f32).to_bits(),
        0.5f32.to_bits(),
        16_777_216.0f32.to_bits(),
        16_777_218.0f32.to_bits(),
        f32::MAX.to_bits(),
    ] {
        let evidence = bytes(&float_row(MID, bits));
        assert_eq!(
            parse_meter_reading(&c, &evidence).unwrap().value_bits(),
            Some(bits)
        );
        let projected = project_meter_trace(&c, &evidence, &w).unwrap();
        assert!(projected.trace.register.is_empty(), "{bits:#x}");
        assert_eq!(projected.skipped_precision, 1);
    }
}

#[test]
fn float_filter_order_and_raw_duplicate_identity() {
    // 007-float-meter/SR-002. An excluded reading cannot hide contradictory bits.
    let c = typed_contract("i=10");
    let w = bytes(&window());
    let bits = 0.5f32.to_bits();
    let mut flagged = float_row(START, bits);
    flagged["status"] = 1024.into();
    let mut future = float_row(MID, bits);
    future["receivedAt"] = START.into();
    let mut untimed = float_row(END, bits);
    untimed["sourceAt"] = Value::Null;
    let outside = float_row("2026-10-24T00:00:00Z", bits);
    let rows = ndjson(&[flagged, future, untimed, outside, float_row(END, bits)]);
    let p = project_meter_trace(&c, &rows, &w).unwrap();
    assert!(p.trace.register.is_empty());
    assert_eq!(
        (
            p.outside_window,
            p.skipped_status,
            p.skipped_source_time,
            p.skipped_precision
        ),
        (1, 1, 2, 1)
    );

    for (left, right) in [(0, 0x8000_0000), (0x7fc0_0001, 0x7fc0_0002), (bits, 0)] {
        let rows = ndjson(&[float_row(MID, left), float_row(MID, right)]);
        assert!(project_meter_trace(&c, &rows, &w).is_err());
    }
    for (bits, duplicate_count, excluded) in [(0, 1, 0), (0x7fc0_0001, 0, 2)] {
        let rows = ndjson(&[float_row(MID, bits), float_row(MID, bits)]);
        let p = project_meter_trace(&c, &rows, &w).unwrap();
        assert_eq!(
            (p.duplicate_readings, p.skipped_precision),
            (duplicate_count, excluded)
        );
    }
}

fn double_row(at: &str, bits: u64) -> Value {
    let mut record = row(at, 0);
    record["dataType"]["id"] = "i=11".into();
    record.as_object_mut().unwrap().remove("value");
    record["valueBits"] = format!("{bits:016x}").into();
    record
}

#[test]
fn double_evidence_requires_canonical_hex_and_preserves_every_bit() {
    // 008-double-meter/SR-001. Bind the accepted representation to type and status.
    let c = typed_contract("i=11");
    validate_meter_contract(&c).unwrap();
    for bits in [0, 1, 0x3ff0_0000_0000_0001, 0xfff8_0000_0000_0007, u64::MAX] {
        let mut row = double_row(START, bits);
        row["status"] = 1024.into();
        let parsed = parse_meter_reading(&c, &bytes(&row)).unwrap();
        assert_eq!(parsed.double_bits(), Some(bits));
        assert_eq!((parsed.value(), parsed.value_bits()), (None, None));
        let output = serde_json::to_value(parsed).unwrap();
        assert_eq!(output["valueBits"], row["valueBits"]);
        assert!(output.get("value").is_none());
    }

    // Validate the complete input even when time later excludes this record.
    let outside = double_row("2026-10-20T00:00:00Z", 42);
    let w = bytes(&window());
    for invalid in [
        Value::Null,
        json!(0),
        json!(u64::MAX),
        json!(1.0),
        json!([]),
        json!(""),
        json!("3ff000000000000"),
        json!("03ff0000000000000"),
        json!("3FF0000000000000"),
        json!("0x3ff0000000000000"),
        json!("+ff0000000000000"),
        json!(" 000000000000000"),
        json!("000000000000000g"),
    ] {
        let mut record = outside.clone();
        record["valueBits"] = invalid;
        assert!(parse_meter_reading(&c, &bytes(&record)).is_err());
        assert!(project_meter_trace(&c, &bytes(&record), &w).is_err());
    }
    let mut both = outside.clone();
    both["value"] = 1.into();
    assert!(parse_meter_reading(&c, &bytes(&both)).is_err());
    both.as_object_mut().unwrap().remove("valueBits");
    assert!(parse_meter_reading(&c, &bytes(&both)).is_err());
    let mut absent = outside.clone();
    absent.as_object_mut().unwrap().remove("valueBits");
    assert!(parse_meter_reading(&c, &bytes(&absent)).is_err());
    for status in [0x4000_0000u32, 0x8000_0000, u32::MAX] {
        absent["status"] = status.into();
        assert_eq!(
            parse_meter_reading(&c, &bytes(&absent))
                .unwrap()
                .double_bits(),
            None
        );
        let mut wrong = outside.clone();
        wrong["status"] = status.into();
        assert!(parse_meter_reading(&c, &bytes(&wrong)).is_err());
    }
    let duplicate = outside.to_string().replace(
        "\"valueBits\":",
        "\"valueBits\":\"0000000000000001\",\"valueBits\":",
    );
    assert!(parse_meter_reading(&c, duplicate.as_bytes()).is_err());
    for id in ["i=7", "i=9", "i=10"] {
        let mut wrong = outside.clone();
        wrong["dataType"]["id"] = id.into();
        assert!(parse_meter_reading(&typed_contract(id), &bytes(&wrong)).is_err());
    }
}

#[test]
fn double_projection_requires_exact_wh_below_binary64_resolution_limit() {
    // 008-double-meter/SR-002. Preserve integer Wh through the last one-Wh step.
    let c = typed_contract("i=11");
    let w = bytes(&window());
    for (value, expected) in [
        (0.0f64, 0),
        (-0.0, 0),
        (16_777_217.0, 16_777_217),
        (9_007_199_254_740_990.0, 9_007_199_254_740_990),
        (9_007_199_254_740_991.0, 9_007_199_254_740_991),
    ] {
        let p = project_meter_trace(&c, &bytes(&double_row(MID, value.to_bits())), &w).unwrap();
        assert_eq!(p.trace.register.len(), 1);
        assert_eq!((p.trace.register[0].wh, p.skipped_precision), (expected, 0));
    }

    use MeterExclusionReason::{FractionalWh, InsufficientResolution, NegativeWh, NonFiniteWh};
    for (bits, reason) in [
        (0x0000_0000_0000_0001, FractionalWh),
        (0x8000_0000_0000_0001, NegativeWh),
        (0x7ff0_0000_0000_0001, NonFiniteWh),
        (0xfff8_0000_0000_0001, NonFiniteWh),
        (f64::INFINITY.to_bits(), NonFiniteWh),
        (f64::NEG_INFINITY.to_bits(), NonFiniteWh),
        (f64::MAX.to_bits(), InsufficientResolution),
        ((-1.0f64).to_bits(), NegativeWh),
        (1.0f64.to_bits() + 1, FractionalWh),
        (0.5f64.to_bits(), FractionalWh),
        (9_007_199_254_740_992.0f64.to_bits(), InsufficientResolution),
        (9_007_199_254_740_994.0f64.to_bits(), InsufficientResolution),
    ] {
        let raw = bytes(&double_row(MID, bits));
        assert_eq!(
            parse_meter_reading(&c, &raw).unwrap().double_bits(),
            Some(bits)
        );
        let p = project_meter_trace(&c, &raw, &w).unwrap();
        assert!(p.trace.register.is_empty(), "{bits:016x}");
        assert_eq!(p.skipped_precision, 1);
        assert_eq!(p.first_exclusion.unwrap().reason, reason);
    }
}

#[test]
fn double_conflicts_compare_all_bits_and_preserve_filter_order() {
    // 008-double-meter/SR-002. Even adjacent non-finite words must remain distinct.
    let c = typed_contract("i=11");
    let w = bytes(&window());
    let nan = 0x7ff8_0000_0000_0000;
    for (left, right) in [
        (0, (-0.0f64).to_bits()),
        (nan, nan + 1),
        (1.0f64.to_bits(), 1.0f64.to_bits() + 1),
    ] {
        let batch = ndjson(&[double_row(MID, left), double_row(MID, right)]);
        assert!(project_meter_trace(&c, &batch, &w).is_err());
    }
    let duplicate = double_row(MID, 42.0f64.to_bits());
    let matched = project_meter_trace(&c, &ndjson(&[duplicate.clone(), duplicate]), &w).unwrap();
    assert_eq!(
        (matched.duplicate_readings, matched.trace.register.len()),
        (1, 1)
    );
    let mut flagged = double_row(START, nan);
    flagged["status"] = 1024.into();
    let mut future = double_row(END, nan);
    future["receivedAt"] = MID.into();
    let outside = double_row("2026-10-24T00:00:00Z", nan);
    let batch = ndjson(&[flagged, future, outside, double_row(MID, nan)]);
    let excluded = project_meter_trace(&c, &batch, &w).unwrap();
    assert_eq!(
        (
            excluded.skipped_status,
            excluded.skipped_source_time,
            excluded.outside_window,
            excluded.skipped_precision
        ),
        (1, 1, 1, 1)
    );
    assert!(excluded.trace.register.is_empty());
}
