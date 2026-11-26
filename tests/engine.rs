#![cfg(feature = "commissioning")]

use opcua_kit::commissioning::{
    Attribute, AttributeValue, Contract, Counts, Evidence, MAX_DOCUMENT_BYTES, MAX_SIGNALS, NodeId,
    Outcome, SignalObservation, SignalRequirement, Snapshot, Unit, assess, compare, draft_contract,
    parse_contract, parse_snapshot,
};
use serde_json::{Value, json, to_value, to_vec};

const UA: &str = "http://opcfoundation.org/UA/";

fn id(namespace: &str, identifier: &str) -> Value {
    json!({"namespace": namespace, "id": identifier})
}

fn document(signals: Value) -> Value {
    json!({"schemaVersion": 1, "device": "air-handler", "applicationUri": "urn:site:ahu",
           "principal": "anonymous", "signals": signals})
}

fn expected(name: &str, identifier: &str) -> Value {
    json!({"name": name, "node": id("urn:fixture", identifier), "dataType": id(UA, "i=11")})
}

fn observed(name: &str, identifier: &str, datatype: &str) -> Value {
    json!({"name": name, "node": id("urn:fixture", identifier),
           "dataType": {"status": 0, "value": id(UA, datatype)}})
}

fn contract(rows: &[Value]) -> opcua_kit::commissioning::Contract {
    parse_contract(&to_vec(&document(json!(rows))).unwrap()).unwrap()
}

fn snapshot(rows: &[Value]) -> opcua_kit::commissioning::Snapshot {
    parse_snapshot(&to_vec(&document(json!(rows))).unwrap()).unwrap()
}

#[test]
fn native_contract_and_snapshot_preserve_identity_scope_and_assessment() {
    let node = NodeId::new("urn:fixture", "i=0007").unwrap();
    let data_type = NodeId::new(UA, "i=0011").unwrap();
    let mut required = SignalRequirement::new("Power", node.clone(), data_type.clone());
    required.value_rank = Some(-1);
    let c = Contract::new("air-handler", "urn:site:ahu", "anonymous", vec![required]).unwrap();
    assert_eq!(c.device(), "air-handler");
    assert_eq!(c.application_uri(), "urn:site:ahu");
    assert_eq!(c.principal(), "anonymous");
    assert_eq!(c.signals()[0].node.identifier(), "i=7");
    assert_eq!(c.signals()[0].data_type.identifier(), "i=11");
    let mut expected = expected("Power", "i=7");
    expected["valueRank"] = json!(-1);
    assert_eq!(to_value(&c).unwrap(), document(json!([expected])));

    let mut sampled = SignalObservation::new("Power", node);
    sampled.data_type = Some(Evidence {
        status: 0,
        value: Some(data_type),
    });
    sampled.value_rank = Some(Evidence {
        status: 0,
        value: Some(-1),
    });
    let s = Snapshot::new(
        c.device(),
        c.application_uri(),
        c.principal(),
        vec![sampled],
    )
    .unwrap();
    assert_eq!(
        (s.device(), s.application_uri(), s.principal()),
        (c.device(), c.application_uri(), c.principal())
    );
    assert_eq!(s.signals()[0].node, c.signals()[0].node);
    let mut observed = observed("Power", "i=7", "i=11");
    observed["valueRank"] = json!({"status":0,"value":-1});
    assert_eq!(to_value(&s).unwrap(), document(json!([observed])));
    assert_eq!(assess(&c, &s).unwrap().decision, Outcome::Matched);
}

#[test]
fn native_inputs_and_wire_inputs_share_validation() {
    assert!(NodeId::new(UA, "i=0").is_err());
    let requirement = SignalRequirement::new(
        "A",
        NodeId::new("urn:site", "i=8").unwrap(),
        NodeId::new(UA, "i=9").unwrap(),
    );
    let mut duplicate = requirement.clone();
    duplicate.name = "B".into();
    duplicate.node = NodeId::new("urn:site", "i=008").unwrap();
    let mut invalid_rank = requirement.clone();
    invalid_rank.value_rank = Some(-4);
    let mut invalid_unit = requirement.clone();
    invalid_unit.engineering_units = Some(Unit {
        namespace_uri: "urn:unit".into(),
        unit_id: -1,
    });
    for rows in [
        vec![],
        vec![requirement.clone(), duplicate],
        vec![invalid_rank],
        vec![invalid_unit],
        vec![requirement; MAX_SIGNALS + 1],
    ] {
        let wire = to_vec(&document(json!(&rows))).unwrap();
        let err = Contract::new("air-handler", "urn:site:ahu", "anonymous", rows).unwrap_err();
        assert_eq!(
            err.to_string(),
            parse_contract(&wire).unwrap_err().to_string()
        );
    }
    let mut observation = SignalObservation::new("A", NodeId::new("urn:site", "i=8").unwrap());
    observation.value_rank = Some(Evidence {
        status: 0x8000_0000,
        value: Some(-1),
    });
    let wire = to_vec(&document(json!([&observation]))).unwrap();
    let err = Snapshot::new(
        "air-handler",
        "urn:site:ahu",
        "anonymous",
        vec![observation],
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        parse_snapshot(&wire).unwrap_err().to_string()
    );
    assert!(Snapshot::new("d", "urn:site", " ", vec![]).is_err());
}

#[test]
fn native_documents_account_for_json_escaping_at_the_byte_limit() {
    let requirement = SignalRequirement::new(
        "Power",
        NodeId::new("urn:site", "i=8").unwrap(),
        NodeId::new(UA, "i=9").unwrap(),
    );
    let new_contract =
        |name: String| Contract::new(name, "urn:meter", "anonymous", vec![requirement.clone()]);
    let metadata_bytes = to_vec(&new_contract("d".into()).unwrap()).unwrap().len() - 1;
    let available = MAX_DOCUMENT_BYTES - metadata_bytes;
    let mut device = "\"".repeat(available / 2);
    if available % 2 == 1 {
        device.push('d');
    }
    let exact = new_contract(device.clone()).unwrap();
    assert_eq!(to_vec(&exact).unwrap().len(), MAX_DOCUMENT_BYTES);
    device.push('d');
    assert!(
        new_contract(device)
            .unwrap_err()
            .to_string()
            .contains("4 MiB")
    );
    assert!(Snapshot::new("d".repeat(MAX_DOCUMENT_BYTES), "u", "p", vec![]).is_err());
}

// 001-commissioning-check/SR-002: A confirmed failure and incomplete evidence survive in the same report.
#[test]
fn mixed_decision_keeps_prior_and_current_status_for_each_attribute() {
    let mut a = expected("A", "s=a");
    a["valueRank"] = json!(-1);
    let c = contract(&[expected("Z", "s=z"), a]);
    let mut baseline = observed("A", "s=a", "i=11");
    baseline["valueRank"] = json!({"status": 0, "value": -1});
    let before = snapshot(&[baseline, observed("Z", "s=z", "i=12")]);
    let mut current = observed("A", "s=a", "i=12");
    current["valueRank"] = json!({"status": 0x8034_0000u32});
    let mut z = observed("Z", "s=z", "i=11");
    z["dataType"]["status"] = json!(0x400u32);
    let after = snapshot(&[z, current]);

    let report = compare(&c, &before, &after).unwrap();
    assert_eq!(report.exit_code(), 2);
    assert_eq!(
        report.counts,
        Counts {
            matched: 1,
            mismatch: 1,
            unverified: 1
        }
    );
    assert!(!report.complete);
    let (first, second, third) = (
        &report.findings[0],
        &report.findings[1],
        &report.findings[2],
    );
    assert_eq!(
        (first.name.as_str(), first.attribute, first.outcome),
        ("A", Attribute::DataType, Outcome::Mismatch)
    );
    assert_eq!(
        first.before.as_ref().unwrap().value.as_ref().unwrap(),
        &first.expected
    );
    assert_eq!(second.after.as_ref().unwrap().status, 0x8034_0000);
    assert_eq!(second.expected, AttributeValue::ValueRank(-1));
    assert_eq!(third.outcome, Outcome::Matched);
    assert_eq!(third.after.as_ref().unwrap().status, 0x400);
    let wire = to_value(&report).unwrap();
    assert_eq!(
        wire["findings"][1]["after"],
        json!({"status": 0x8034_0000u32})
    );
    assert_eq!(wire["schemaVersion"], 2);
    assert_eq!(wire["baselineProvided"], true);
}

// 001-commissioning-check/SR-002 003-first-inspection/SR-002: Reject observations outside the contract's scope.
#[test]
fn rejects_scope_and_signal_identity_mismatches() {
    let c = contract(&[expected("Supply", "s=temp")]);
    let empty = snapshot(&[]);
    for field in ["device", "applicationUri", "principal"] {
        let mut other = document(json!([]));
        other[field] = json!("different");
        let other = parse_snapshot(&to_vec(&other).unwrap()).unwrap();
        assert!(assess(&c, &other).unwrap_err().to_string().contains(field));
        assert!(
            compare(&c, &empty, &other)
                .unwrap_err()
                .to_string()
                .contains(field)
        );
        assert!(compare(&c, &other, &empty).is_err());
    }
    for row in [
        observed("Wrong", "s=temp", "i=11"),
        observed("Supply", "s=TEMP", "i=11"),
    ] {
        let wrong_signal = snapshot(&[row]);
        assert!(assess(&c, &wrong_signal).is_err());
        assert!(compare(&c, &empty, &wrong_signal).is_err());
        assert!(compare(&c, &wrong_signal, &empty).is_err());
    }
}

// 003-first-inspection/SR-001: Distinguish omitted and supplied but empty baselines in the report.
#[test]
fn first_visit_preserves_current_decisions_and_records_no_baseline() {
    let mut temperature = expected("Temperature", "s=temp");
    temperature["engineeringUnits"] = unit("urn:units", 42);
    let c = contract(&[temperature, expected("Fan", "s=fan")]);
    let mut measured = observed("Temperature", "s=temp", "i=11");
    measured["engineeringUnits"] = json!({"status":0x400,"value":unit("urn:units",42)});
    let fan = observed("Fan", "s=fan", "i=11");
    let matched = snapshot(&[measured.clone(), fan.clone()]);
    measured["engineeringUnits"] = json!({"status":0x400,"value":unit("urn:units",43)});
    let mismatch = snapshot(&[measured]);
    let mut unreadable = fan;
    unreadable["dataType"] = json!({"status":0x8034_0000u32});
    let unverified = snapshot(&[unreadable]);
    let empty = snapshot(&[]);

    for (current, code) in [(&matched, 0), (&mismatch, 2), (&unverified, 3), (&empty, 3)] {
        let first = assess(&c, current).unwrap();
        let with_prior = compare(&c, &empty, current).unwrap();
        assert_eq!(first.exit_code(), code);
        assert_eq!(with_prior.exit_code(), code);
        assert_eq!(first.complete, with_prior.complete);
        assert_eq!(first.counts, with_prior.counts);
        let first = to_value(first).unwrap();
        assert_eq!(first["schemaVersion"], 2);
        assert_eq!(first["baselineProvided"], false);
        let compared = to_value(with_prior).unwrap();
        assert_eq!(compared["baselineProvided"], true);

        let first_findings = first["findings"].as_array().unwrap();
        let compared_findings = compared["findings"].as_array().unwrap();
        assert_eq!(first_findings.len(), 3);
        assert_eq!(first_findings.len(), compared_findings.len());
        for (single, paired) in first_findings.iter().zip(compared_findings) {
            assert_eq!(single.get("before"), Some(&Value::Null));
            assert_eq!(single.get("beforeOutcome"), Some(&Value::Null));
            assert_eq!(paired.get("before"), Some(&Value::Null));
            assert_eq!(paired["beforeOutcome"], "unverified");
            for field in ["name", "node", "attribute", "expected", "after", "outcome"] {
                assert_eq!(single[field], paired[field], "{field}");
            }
        }
    }
}

#[test]
fn current_gate_is_independent_of_baseline_quality() {
    let c = contract(&[expected("A", "i=1")]);
    let empty = snapshot(&[]);
    let good = snapshot(&[observed("A", "i=1", "i=11")]);
    let clean = compare(&c, &empty, &good).unwrap();
    assert!(clean.complete);
    assert_eq!(clean.exit_code(), 0);
    assert!(clean.findings[0].before.is_none());
    let missing = compare(&c, &good, &empty).unwrap();
    assert_eq!(missing.exit_code(), 3);
    assert!(missing.findings[0].after.is_none());
    for status in [0x4000_0400u32, 0x8000_0000, 0xc000_0000] {
        let mut row = observed("A", "i=1", "i=11");
        row["dataType"] = json!({"status": status});
        let uncertain = compare(&c, &empty, &snapshot(&[row])).unwrap();
        assert_eq!(uncertain.exit_code(), 3);
        assert_eq!(uncertain.findings[0].after.as_ref().unwrap().status, status);
    }
}

// 001-commissioning-check/SR-002: Equivalent representations cannot smuggle duplicate identities.
#[test]
fn typed_identities_are_normalized_and_unambiguous() {
    let c = contract(&[
        expected("num", "i=0042"),
        expected("string", "s=42"),
        expected("guid", "g=AB026989-4211-4D71-8999-FB6982B1D02E"),
        expected("bytes", "b=Kg=="),
    ]);
    let rows = snapshot(&[
        observed("bytes", "b=Kg==", "i=011"),
        observed("guid", "g=ab026989-4211-4d71-8999-fb6982b1d02e", "i=11"),
        observed("string", "s=42", "i=11"),
        observed("num", "i=42", "i=11"),
    ]);
    assert_eq!(compare(&c, &rows, &rows).unwrap().counts.matched, 4);
    for pair in [
        [expected("a", "i=42"), expected("b", "i=0042")],
        [expected("a", "s=A"), expected("a", "s=B")],
    ] {
        assert!(parse_contract(&to_vec(&document(json!(pair))).unwrap()).is_err());
    }
    let row = observed("x", "i=42", "i=11");
    assert!(parse_snapshot(&to_vec(&document(json!([row, row]))).unwrap()).is_err());
}

#[test]
fn enforces_ua_identifiers_rank_and_null_node_rules() {
    for bad in [
        "x=0",
        "i=-1",
        "i=+1",
        "i=4294967296",
        "s=a\nb",
        "g=0",
        "b=AQ",
        "b=A===",
    ] {
        let bytes = to_vec(&document(json!([expected("x", bad)]))).unwrap();
        assert!(parse_contract(&bytes).is_err(), "{bad:?}");
    }
    for bad in ["i=0", "s=", "g=00000000-0000-0000-0000-000000000000", "b="] {
        let mut row = expected("x", "s=A");
        row["dataType"] = id(UA, bad);
        assert!(parse_contract(&to_vec(&document(json!([row]))).unwrap()).is_err());
    }
    let mut row = expected("x", "s=a");
    for rank in [-3, -2, -1, 0, 1, 3] {
        row["valueRank"] = json!(rank);
        assert!(parse_contract(&to_vec(&document(json!([row]))).unwrap()).is_ok());
    }
    row["valueRank"] = json!(-4);
    assert!(parse_contract(&to_vec(&document(json!([row]))).unwrap()).is_err());
}

#[test]
fn good_status_without_metadata_remains_evidence_and_cannot_be_drafted() {
    let mut requirement = expected("x", "s=x");
    requirement["valueRank"] = json!(-1);
    requirement["engineeringUnits"] = unit("urn:units", 1);
    let c = contract(&[requirement]);
    for status in [0, 0x0400] {
        let mut row = observed("x", "s=x", "i=11");
        for key in ["dataType", "valueRank", "engineeringUnits"] {
            row[key] = json!({"status":status});
        }
        let s = snapshot(&[row.clone()]);
        assert_eq!(to_value(&s).unwrap(), document(json!([row])));
        c.validate_capture(&s).unwrap();
        let result = assess(&c, &s).unwrap();
        assert_eq!(result.counts.unverified, 3);
        assert!(result.findings.iter().all(|f| {
            f.after
                .as_ref()
                .is_some_and(|e| e.status == status && e.value.is_none())
        }));
        assert!(
            draft_contract(&s)
                .unwrap_err()
                .to_string()
                .contains(&format!("0x{status:08X}"))
        );
    }
}

#[test]
fn malformed_evidence_or_version_has_no_decision() {
    for malformed in [
        json!({"status":0,"value":null}),
        json!({"status":2147483648u32,"value":null}),
        json!({"status":1073741824,"value":id(UA,"i=11")}),
        json!({"status":-1}),
        json!({"status":0,"value":id(UA,"i=11"),"sttaus":0}),
        Value::Null,
    ] {
        let mut row = observed("x", "s=x", "i=11");
        row["dataType"] = malformed;
        assert!(parse_snapshot(&to_vec(&document(json!([row]))).unwrap()).is_err());
    }
    let mut wrong = document(json!([expected("x", "s=x")]));
    wrong["schemaVersion"] = json!(2);
    assert!(parse_contract(&to_vec(&wrong).unwrap()).is_err());
    let field = br#"{"schemaVersion":1,"schemaVersion":1,"device":"d","applicationUri":"uri","principal":"p","signals":[]}"#;
    assert!(parse_snapshot(field).is_err());
}

// 001-commissioning-check/SR-003: Bound input size, signal cardinality and OPC UA identifier sizes.
#[test]
fn rejects_oversized_documents_signals_and_identifiers() {
    let too_many: Vec<_> = (0..=MAX_SIGNALS)
        .map(|i| expected(&i.to_string(), &format!("i={i}")))
        .collect();
    assert!(parse_contract(&to_vec(&document(json!(&too_many[..MAX_SIGNALS]))).unwrap()).is_ok());
    assert!(parse_contract(&to_vec(&document(json!(too_many))).unwrap()).is_err());
    let mut padded = to_vec(&document(json!([]))).unwrap();
    padded.resize(MAX_DOCUMENT_BYTES, b' ');
    assert!(parse_snapshot(&padded).is_ok());
    padded.push(b' ');
    assert!(parse_snapshot(&padded).is_err());
    let max = format!("s={}", "温".repeat(4096));
    assert!(parse_contract(&to_vec(&document(json!([expected("a", &max)]))).unwrap()).is_ok());
    let too_long = format!("{max}x");
    assert!(
        parse_contract(&to_vec(&document(json!([expected("a", &too_long)]))).unwrap()).is_err()
    );
    let opaque = format!("b={}", "A".repeat(5464));
    assert!(parse_contract(&to_vec(&document(json!([expected("a", &opaque)]))).unwrap()).is_err());
}

// 001-commissioning-check/SR-006: A live capture must contain a result status for every requested attribute.
#[test]
fn publish_requires_exact_attribute_coverage_even_when_offline_compare_allows_partial() {
    let mut required = expected("A", "s=a");
    required["valueRank"] = json!(-1);
    let c = contract(&[required]);
    let partial = observed("A", "s=a", "i=11");
    assert!(c.validate_capture(&snapshot(&[])).is_err());
    assert!(
        c.validate_capture(&snapshot(std::slice::from_ref(&partial)))
            .is_err()
    );
    let mut complete = partial;
    complete["valueRank"] = json!({"status": 0x4034_0100u32});
    assert!(
        c.validate_capture(&snapshot(std::slice::from_ref(&complete)))
            .is_ok()
    );
    let c = contract(&[expected("A", "s=a")]);
    assert!(c.validate_capture(&snapshot(&[complete])).is_err());
    let mut missing_type = observed("A", "s=a", "i=11");
    missing_type.as_object_mut().unwrap().remove("dataType");
    assert!(
        c.validate_capture(&snapshot(std::slice::from_ref(&missing_type)))
            .is_ok()
    );
    missing_type["valueRank"] = json!({"status": 0, "value": -1});
    assert!(c.validate_capture(&snapshot(&[missing_type])).is_err());
}

#[test]
fn zero_and_empty_identifiers_are_nodes_in_nonstandard_namespaces() {
    let c = contract(&[
        expected("Numeric", "i=0"),
        expected("String", "s="),
        expected("Guid", "g=00000000-0000-0000-0000-000000000000"),
        expected("Bytes", "b="),
    ]);
    let empty = snapshot(&[]);
    assert_eq!(compare(&c, &empty, &empty).unwrap().counts.unverified, 4);
}

fn unit(namespace_uri: &str, unit_id: i32) -> Value {
    json!({"namespaceUri": namespace_uri, "unitId": unit_id})
}

// 002-engineering-units/SR-004: Match both components in the correct observation scope.
#[test]
fn unit_identity_distinguishes_namespace_and_signed_id_and_records_recovery() {
    let wanted = unit("urn:units:a", i32::MIN);
    let mut required = expected("Supply", "s=temp");
    required["valueRank"] = json!(-1);
    required["engineeringUnits"] = wanted.clone();
    let c = contract(&[required]);
    let mut row = observed("Supply", "s=temp", "i=11");
    row["valueRank"] = json!({"status":0, "value":-1});
    row["engineeringUnits"] = json!({"status":0x400, "value":wanted});
    let clean = snapshot(std::slice::from_ref(&row));
    for different in [unit("urn:units:A", i32::MIN), unit("urn:units:a", i32::MAX)] {
        row["engineeringUnits"]["value"] = different.clone();
        let changed = snapshot(std::slice::from_ref(&row));
        let report = compare(&c, &clean, &changed).unwrap();
        assert_eq!(report.exit_code(), 2);
        assert!(report.complete);
        assert_eq!((report.counts.matched, report.counts.mismatch), (2, 1));
        let finding = &report.findings[2];
        assert_eq!(finding.attribute, Attribute::EngineeringUnits);
        assert_eq!(finding.before_outcome, Some(Outcome::Matched));
        let wire = to_value(finding).unwrap();
        assert_eq!(wire["expected"], wanted);
        assert_eq!(wire["after"], json!({"status":0x400,"value":different}));
        let repaired = compare(&c, &changed, &clean).unwrap();
        assert_eq!(repaired.exit_code(), 0);
        assert_eq!(repaired.findings[2].before_outcome, Some(Outcome::Mismatch));
    }
}

// 002-engineering-units/SR-002 002-engineering-units/SR-004: Preserve raw status and sentinel evidence without concluding a unit mismatch.
#[test]
fn incomplete_unit_evidence_remains_unverified_including_good_unavailable_identity() {
    let mut required = expected("A", "s=a");
    required["engineeringUnits"] = unit("urn:units", 0);
    let c = contract(&[required]);
    let mut row = observed("A", "s=a", "i=11");
    let missing = snapshot(std::slice::from_ref(&row));
    for evidence in [
        json!({"status":0x4000_0400u32}),
        json!({"status":0x8034_0000u32}),
        json!({"status":0xc000_0000u32}),
        json!({"status":0, "value":unit("urn:other", -1)}),
        json!({"status":0x400, "value":unit("", 42)}),
    ] {
        row["engineeringUnits"] = evidence.clone();
        let current = snapshot(std::slice::from_ref(&row));
        assert!(c.validate_capture(&current).is_ok());
        let report = compare(&c, &missing, &current).unwrap();
        let finding = &report.findings[1];
        assert!(finding.before.is_none());
        assert_eq!(finding.before_outcome, Some(Outcome::Unverified));
        assert_eq!(to_value(&finding.after).unwrap(), evidence);
        assert_eq!(report.exit_code(), 3);
        assert!(!report.complete);
        assert_eq!(report.counts.unverified, 1);
    }
    assert_eq!(compare(&c, &missing, &missing).unwrap().exit_code(), 3);
    assert!(c.validate_capture(&missing).is_err());
    let unknown = snapshot(&[json!({"name":"A","node": id("urn:fixture","s=a")})]);
    assert!(c.validate_capture(&unknown).is_ok());
    let plain = contract(&[expected("A", "s=a")]);
    let extra = snapshot(std::slice::from_ref(&row));
    assert!(plain.validate_capture(&extra).is_err());
    assert_eq!(compare(&plain, &extra, &extra).unwrap().findings.len(), 1);
    row.as_object_mut().unwrap().remove("dataType");
    assert!(c.validate_capture(&snapshot(&[row])).is_err());
}

#[test]
fn unit_shapes_are_strict_and_labels_are_excluded() {
    let mut required = expected("A", "s=a");
    for invalid in [
        unit("", 1),
        unit("   ", 1),
        unit("urn:units", -1),
        unit("urn:\nunits", 42),
        json!({"namespaceUri":"urn:units","unitId":2147483648u32}),
        json!({"namespaceUri":"urn:units","unitId":42,"displayName":"C"}),
        json!({"namespaceUri":null,"unitId":42}),
        json!({"unitId":42}),
        Value::Null,
    ] {
        required["engineeringUnits"] = invalid;
        assert!(parse_contract(&to_vec(&document(json!([required]))).unwrap()).is_err());
    }
    let mut row = observed("A", "s=a", "i=11");
    for invalid in [
        json!({"status":0,"value":unit("urn:\nunits", 1)}),
        json!({"status":0,"value":{"namespaceUri":"u","unitId":42,"description":"unit"}}),
        json!({"status":0x4000_0400u32,"value":unit("u", 1)}),
        json!({"status":0x8000_0000u32,"value":unit("u", 1)}),
        json!({"status":0,"value":null}),
        Value::Null,
    ] {
        row["engineeringUnits"] = invalid;
        assert!(parse_snapshot(&to_vec(&document(json!([row]))).unwrap()).is_err());
    }
}

// 004-contract-authoring/SR-001: Preserve every observed requirement and its original scope.
#[test]
fn draft_round_trips_in_signal_order_and_checks_original_and_changed_units() {
    let mut z = observed("Z", "i=00042", "i=0011");
    z["dataType"]["status"] = json!(0x0400);
    z["valueRank"] = json!({"status": 0x0400, "value": -1});
    z["engineeringUnits"] = json!({"status": 0, "value": unit("urn:vendor", -12)});
    let a = observed("A", "s=keep Case", "i=12");
    let source = snapshot(&[z.clone(), a.clone()]);
    let draft = draft_contract(&source).unwrap();
    assert_eq!(draft.signal_count(), 2);
    let mut a_expected = expected("A", "s=keep Case");
    a_expected["dataType"] = id(UA, "i=12");
    let mut z_expected = expected("Z", "i=42");
    z_expected["valueRank"] = json!(-1);
    z_expected["engineeringUnits"] = unit("urn:vendor", -12);
    assert_eq!(
        to_value(&draft).unwrap(),
        document(json!([a_expected, z_expected]))
    );
    let bytes = to_vec(&draft).unwrap();
    let reordered = draft_contract(&snapshot(&[a.clone(), z.clone()])).unwrap();
    assert_eq!(bytes, to_vec(&reordered).unwrap());
    let reviewed = parse_contract(&bytes).unwrap();
    let report = assess(&reviewed, &source).unwrap();
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.counts.matched, 4);
    z["engineeringUnits"]["value"]["unitId"] = json!(12);
    let changed = assess(&reviewed, &snapshot(&[a, z])).unwrap();
    assert_eq!(changed.exit_code(), 2);
    assert_eq!(changed.counts.mismatch, 1);
}

// 004-contract-authoring/SR-001 004-contract-authoring/SR-002: Reject the entire draft on one unusable field.
#[test]
fn draft_reports_source_index_and_raw_status_for_unusable_evidence() {
    assert!(draft_contract(&snapshot(&[])).is_err());
    let good = observed("Z", "s=z", "i=11");
    // Diagnostics must stay bounded and safe even with a long, display-altering label.
    let name = format!("\u{202e}{}", "x".repeat(5000));
    for (field, evidence, reason) in [
        ("dataType", None, "missing"),
        (
            "dataType",
            Some(json!({"status": 0x8034_0500u32})),
            "0x80340500",
        ),
        (
            "valueRank",
            Some(json!({"status": 0x4002_0400u32})),
            "0x40020400",
        ),
        (
            "engineeringUnits",
            Some(json!({"status": 0xc003_0400u32})),
            "0xC0030400",
        ),
        (
            "engineeringUnits",
            Some(json!({"status": 0x400, "value": unit("urn:units", -1)})),
            "0x00000400",
        ),
        (
            "engineeringUnits",
            Some(json!({"status": 0, "value": unit(" ", 1)})),
            "0x00000000",
        ),
    ] {
        let mut row = observed(&name, "s=b", "i=11");
        if let Some(evidence) = evidence {
            row[field] = evidence;
        } else {
            row.as_object_mut().unwrap().remove(field);
        }
        let message = draft_contract(&snapshot(&[good.clone(), row]))
            .unwrap_err()
            .to_string();
        assert!(
            message.contains(&format!("signals[1].{field}")),
            "{message}"
        );
        assert!(message.contains(reason), "{message}");
        assert!(message.is_ascii() && message.len() < 160, "{message}");
    }
}

// 004-contract-authoring/SR-002: Compact drafts of input at the byte ceiling can be parsed again.
#[test]
fn draft_from_exactly_four_mib_has_a_consumable_compact_encoding() {
    let mut data = document(json!([observed("A", "s=a", "i=11")]));
    let overhead = to_vec(&data).unwrap().len() - data["device"].as_str().unwrap().len();
    data["device"] = json!("x".repeat(MAX_DOCUMENT_BYTES - overhead));
    let bytes = to_vec(&data).unwrap();
    assert_eq!(bytes.len(), MAX_DOCUMENT_BYTES);
    let source = parse_snapshot(&bytes).unwrap();
    let draft = draft_contract(&source).unwrap();
    let encoded = to_vec(&draft).unwrap();
    assert!(encoded.len() < MAX_DOCUMENT_BYTES);
    assert_eq!(parse_contract(&encoded).unwrap().signal_count(), 1);
}
