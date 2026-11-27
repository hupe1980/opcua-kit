// External client using only the public API against the independent node-opcua peer.
mod navigation;

use opcua_kit::{
    NodeId, ReadAttribute, ReadOperand, UnitStage,
    client::{Client, ConnectionConfig, ReadError, Sample, ua},
};
use std::{env, fs, path::Path, time::Duration};

fn node(id: &str) -> NodeId {
    NodeId::new("urn:fixture:hvac", format!("s={id}")).unwrap()
}

// 015-engineering-units/SR-001 015-engineering-units/SR-002
async fn verify_engineering_units(client: &Client, scenario: &str) {
    if scenario == "units-pages" {
        let unit = client
            .read_engineering_units(&node("PagedTemperature"))
            .await
            .unwrap();
        assert_eq!(unit.property, Some(node("PagedTemperature1")));
        assert_eq!(unit.sample.value.unwrap().unit_id, 0x43454C);
        assert!(matches!(
            client.read_engineering_units(&node("AmbiguousUnits")).await,
            Err(ReadError::InvalidUnitReference)
        ));
        return;
    }
    let python = scenario == "units-asyncua";
    let unit = client
        .read_engineering_units(&node("Temperature"))
        .await
        .unwrap();
    assert_eq!(unit.stage, UnitStage::Value);
    assert_eq!(
        unit.property,
        Some(node(if python {
            "TemperatureUnits"
        } else {
            "UnitProperty"
        }))
    );
    assert_eq!(unit.sample.status, 0);
    let identity = unit.sample.value.unwrap();
    assert!(identity.is_identified());
    let catalog = if python {
        "urn:fixture:unit-catalog"
    } else {
        "http://www.opcfoundation.org/UA/units/un/cefact"
    };
    assert_eq!(identity.namespace_uri, catalog);
    assert_eq!(
        identity.unit_id,
        if scenario == "units-fahrenheit" {
            0x464148
        } else {
            0x43454C
        }
    );

    // Sensor has a vendor-qualified property with the same name on node-opcua.
    let absent = client
        .read_engineering_units(&node(if python { "DeniedRank" } else { "Sensor" }))
        .await
        .unwrap();
    assert_eq!(absent.stage, UnitStage::Browse);
    assert_eq!(absent.property, None);
    assert_eq!(absent.sample.status, 0);
    assert_eq!(absent.sample.value, None);

    if scenario == "units-celsius" {
        for name in ["WrongUnitType", "WrongUnitRank"] {
            assert!(matches!(
                client.read_engineering_units(&node(name)).await,
                Err(ReadError::InvalidUnitProperty)
            ));
        }
        let unit = client
            .read_engineering_units(&node("UncertainUnit"))
            .await
            .unwrap();
        assert_eq!(unit.stage, UnitStage::Value);
        assert_eq!(unit.property, Some(node("UncertainUnitProperty")));
        assert_eq!(unit.sample.status, 0x4090_4000);
        assert_eq!(
            unit.sample
                .source_timestamp
                .unwrap()
                .to_datetime()
                .unwrap()
                .unix_timestamp(),
            1_603_586_700
        );
        assert!(unit.sample.server_timestamp.is_some());
        assert_eq!(unit.sample.value, None);
    }
    if python {
        let denied = client
            .read_engineering_units(&node("DeniedUnitType"))
            .await
            .unwrap();
        assert_eq!(denied.stage, UnitStage::DataType);
        assert_eq!(denied.property, Some(node("DeniedUnitTypeUnits")));
        assert_eq!(denied.sample.status, 0x801F_0000);
        assert_eq!(denied.sample.value, None);
        let unknown = client
            .read_engineering_units(&node("UnidentifiedUnit"))
            .await
            .unwrap();
        assert_eq!(unknown.sample.status, 0);
        let identity = unknown.sample.value.unwrap();
        assert!(!identity.is_identified());
        assert_eq!(
            (identity.namespace_uri.as_str(), identity.unit_id),
            ("", -1)
        );
    }
}

// 014-attribute-reads/SR-001 014-attribute-reads/SR-002
async fn verify_attributes(client: &Client, partial: bool) {
    use ReadAttribute::{DataType, Value, ValueRank};
    let temperature = node("Temperature");
    let missing = node("absent");
    let custom = NodeId::new("urn:fixture:types", "i=7401").unwrap();

    let definition = client.read_definition(&temperature).await.unwrap();
    let ty = definition.data_type.unwrap();
    let rank = definition.value_rank.unwrap();
    assert_eq!((ty.status, ty.value), (0, Some(custom.clone())));
    assert_eq!((rank.status, rank.value), (0, Some(-1)));
    let absent = client.read_definition(&missing).await.unwrap();
    let ty = absent.data_type.unwrap();
    let rank = absent.value_rank.unwrap();
    assert_eq!((ty.status, ty.value), (0x8034_0000, None));
    assert_eq!((rank.status, rank.value), (0x8034_0000, None));

    let mixed = client
        .read_attributes(&[
            ReadOperand::new(&temperature, Value),
            ReadOperand::new(&missing, ValueRank),
            ReadOperand::new(&temperature, DataType),
            ReadOperand::new(&temperature, ValueRank),
            ReadOperand::new(&temperature, ValueRank),
        ])
        .await
        .unwrap();
    let [value, absent, ty, rank, repeated] = mixed.as_slice() else {
        panic!("one result per attribute was expected");
    };
    assert_eq!(Sample::<f64>::from_raw(value).unwrap().value, Some(22.0));
    assert_eq!(absent.status, Some(ua::StatusCode::BadNodeIdUnknown));
    assert!(matches!(ty.value, Some(ua::Variant::NodeId(_))));
    for raw in [rank, repeated] {
        assert_eq!(Sample::<i32>::from_raw(raw).unwrap().value, Some(-1));
    }
    if partial {
        for (name, malformed) in [("DeniedRank", false), ("MalformedRank", true)] {
            let definition = client.read_definition(&node(name)).await.unwrap();
            assert_eq!(definition.data_type.unwrap().value.as_ref(), Some(&custom));
            if malformed {
                assert!(matches!(
                    definition.value_rank,
                    Err(ReadError::ScalarTypeMismatch { expected: "Int32" })
                ));
            } else {
                let rank = definition.value_rank.unwrap();
                assert_eq!((rank.status, rank.value), (0x801F_0000, None));
            }
        }
    }
}

// 013-read-limits/SR-001 013-read-limits/SR-002
async fn verify_limited_reads(client: &Client, change_limit: bool) {
    let meter = node("GridImportWh");
    let unknown = NodeId::new("urn:fixture:absent", "s=missing").unwrap();
    let invalid = [meter.clone(), meter.clone(), unknown];
    assert!(matches!(
        client.read_scalars::<u64>(&invalid).await,
        Err(ReadError::UnknownNamespace { index: 2 })
    ));

    let nodes = [
        meter.clone(),
        node("absent"),
        node("Temperature"),
        meter.clone(),
        meter.clone(),
    ];
    let rows = client.read_scalars::<u64>(&nodes).await.unwrap();
    let [first, missing, wrong_type, repeated, last] = rows.as_slice() else {
        panic!("expected one outcome per requested node");
    };
    for read in [first, repeated, last] {
        let sample = read.as_ref().unwrap();
        assert_eq!(sample.status, 0);
        assert_eq!(sample.value, Some((1 << 53) + 1));
        assert!(sample.source_timestamp.is_some());
    }
    assert_eq!(missing.as_ref().unwrap().status, 0x8034_0000);
    assert_eq!(missing.as_ref().unwrap().value, None);
    assert!(matches!(
        wrong_type,
        Err(ReadError::ScalarTypeMismatch { expected: "UInt64" })
    ));

    if change_limit {
        // A new server limit takes effect on the second chunk. A caller must
        // receive the service failure even though the first chunk succeeded.
        let interrupted = [
            meter.clone(),
            meter.clone(),
            node("LowerLimit"),
            meter.clone(),
            meter.clone(),
        ];
        assert!(matches!(
            client.read_scalars::<u64>(&interrupted).await,
            Err(ReadError::Service(error)) if error == ua::StatusCode::BadTooManyOperations
        ));
        assert!(matches!(
            client.read(&meter).await,
            Err(ReadError::SessionInterrupted)
        ));
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<_> = env::args().collect();
    let [_, folder, endpoint, pin, expected, additional @ ..] = args.as_slice() else {
        panic!("expected fixture folder, endpoint, server pin and expected outcome");
    };
    let folder = Path::new(folder);
    let server_cert = fs::read(folder.join(format!("{pin}.der"))).unwrap();
    let client_cert = fs::read(folder.join("client.der")).unwrap();
    let client_key = fs::read(folder.join("client-key.der")).unwrap();
    let connect = |endpoint: &str| {
        Client::connect(ConnectionConfig {
            endpoint,
            server_application_uri: "urn:fixture:server",
            server_certificate_der: &server_cert,
            client_application_uri: "urn:fixture:client",
            client_certificate_der: &client_cert,
            client_private_key_der: &client_key,
            timeout: Duration::from_secs(5),
        })
    };
    let result = connect(endpoint);
    if expected == "reject" {
        assert!(result.is_err(), "untrusted server accepted");
        return;
    }

    let client = result.expect("connect to pinned peer");
    if expected.starts_with("navigation-") {
        navigation::exercise(&client, expected == "navigation-python").await;
        client.disconnect().await;
        return;
    }
    #[cfg(feature = "commissioning")]
    if expected == "snapshot" {
        use opcua_kit::commissioning::{parse_contract, parse_snapshot};
        let contract = parse_contract(&fs::read(folder.join("contract.json")).unwrap()).unwrap();
        let snapshot = client.read_snapshot(&contract).await;
        client.disconnect().await;
        match snapshot {
            Ok(snapshot) => {
                let document = serde_json::to_string(&snapshot).unwrap();
                parse_snapshot(document.as_bytes()).unwrap();
                println!("{document}");
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        return;
    }
    #[cfg(feature = "commissioning")]
    if expected == "meter-project" {
        use opcua_kit::commissioning::{
            meter::{MeterProjector, MeterWindow},
            parse_contract,
        };
        use time::{Duration, OffsetDateTime};

        let [next_endpoint, close_register] = additional else {
            panic!("expected second meter endpoint and independently commissioned close register");
        };
        let contract = parse_contract(&fs::read(folder.join("contract.json")).unwrap()).unwrap();
        let start = OffsetDateTime::from_unix_timestamp(1_603_586_700).unwrap();
        let mut projector = MeterProjector::new(
            &contract,
            MeterWindow {
                device: "ahu",
                application_uri: "urn:fixture:server",
                node: &node(close_register),
                start,
                end: start + Duration::minutes(15),
                tolerance_wh: 1,
            },
        )
        .unwrap();
        for source in [client, connect(next_endpoint).unwrap()] {
            let reading = source.read_meter(&contract).await.unwrap();
            projector.push(&reading).unwrap();
            source.disconnect().await;
        }
        let result = projector.finish(&[(start, 284_999)]).unwrap();
        let counters = [
            result.skipped_status,
            result.skipped_source_time,
            result.skipped_precision,
            result.outside_window,
            result.duplicate_readings,
        ];
        println!(
            "{}",
            serde_json::json!({"trace": result.trace, "counters": counters})
        );
        return;
    }
    assert!(additional.is_empty());
    #[cfg(feature = "commissioning")]
    if expected == "meter" || expected == "meter-repeat" {
        use opcua_kit::commissioning::{meter::parse_meter_reading, parse_contract};
        let contract = parse_contract(&fs::read(folder.join("contract.json")).unwrap()).unwrap();
        if expected == "meter-repeat" {
            client
                .read_meter(&contract)
                .await
                .expect("first read qualifies");
        }
        let result = client.read_meter(&contract).await;
        client.disconnect().await;
        match result {
            Ok(reading) => {
                let document = serde_json::to_string(&reading).unwrap();
                parse_meter_reading(&contract, document.as_bytes()).unwrap();
                println!("{document}");
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        return;
    }
    if expected.starts_with("units-") {
        verify_engineering_units(&client, expected).await;
        client.disconnect().await;
        return;
    }
    if matches!(expected.as_str(), "attributes" | "asyncua") {
        verify_attributes(&client, expected == "asyncua").await;
        client.disconnect().await;
        return;
    }
    if matches!(expected.as_str(), "limit1" | "limit2") {
        verify_limited_reads(&client, expected == "limit2").await;
        client.disconnect().await;
        return;
    }
    assert!(client.read_many(&[]).await.unwrap().is_empty());
    let excessive = vec![node("GridImportWh"); opcua_kit::MAX_READ_NODES + 1];
    assert!(matches!(
        client.read_many(&excessive).await,
        Err(ReadError::TooManyNodes)
    ));
    let unknown = NodeId::new("urn:fixture:absent", "s=GridImportWh").unwrap();
    assert!(matches!(
        client.read(&unknown).await,
        Err(ReadError::UnknownNamespace { index: 0 })
    ));
    let register = client
        .read_scalar::<u64>(&node("GridImportWh"))
        .await
        .expect("read meter");
    let expected = expected.parse::<u64>().unwrap();
    assert_eq!(register.status, 0);
    assert_eq!(register.value, Some(expected));
    let at = register.source_timestamp.unwrap().to_datetime().unwrap();
    let fixture_time = if expected == (1 << 53) + 1 {
        1_603_586_700
    } else {
        1_603_587_600
    };
    assert_eq!(at.unix_timestamp(), fixture_time);
    assert!(register.server_timestamp.is_some());

    let mixed = client
        .read_many(&[
            node("absent"),
            node("GridImportWh"),
            node("Temperature"),
            node("Sensor"),
        ])
        .await
        .expect("read mixed statuses");
    assert_eq!(mixed.len(), 4);
    assert_eq!(mixed[0].status, Some(ua::StatusCode::BadNodeIdUnknown));
    let missing = Sample::<u64>::from_raw(&mixed[0]).unwrap();
    assert_eq!(missing.status, 0x8034_0000);
    assert_eq!(missing.value, None);
    assert_eq!(
        Sample::<u64>::from_raw(&mixed[1]).unwrap().value,
        Some(expected)
    );
    assert!(matches!(
        Sample::<f64>::from_raw(&mixed[1]),
        Err(ReadError::ScalarTypeMismatch { .. })
    ));
    assert_eq!(
        Sample::<f64>::from_raw(&mixed[2]).unwrap().value,
        Some(22.0)
    );
    assert!(
        Sample::<String>::from_raw(&mixed[3])
            .unwrap()
            .value
            .is_some()
    );
    client.disconnect().await;
}
