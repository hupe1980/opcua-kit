use opcua_kit::commissioning::meter::{
    MeterProjector, MeterWindow, parse_meter_reading, project_meter_trace,
};
use opcua_kit::commissioning::parse_contract;
use std::{env, fs, path::PathBuf};
use time::{Duration, OffsetDateTime, UtcOffset};

fn main() {
    let fixture = PathBuf::from(env::args_os().nth(1).unwrap());
    let contract = parse_contract(&fs::read(fixture.join("contract.json")).unwrap()).unwrap();
    let unit: &opcua_kit::EngineeringUnit =
        contract.signals()[0].engineering_units.as_ref().unwrap();
    assert!(unit.is_watt_hour());
    let rows = fs::read_to_string(fixture.join("readings.ndjson")).unwrap();
    let window = fs::read(fixture.join("window.json")).unwrap();
    let reading = parse_meter_reading(&contract, rows.lines().next().unwrap().as_bytes()).unwrap();
    let source: OffsetDateTime = reading.source_at().unwrap();
    let server: OffsetDateTime = reading.server_at().unwrap();
    let received: OffsetDateTime = reading.received_at();
    assert_eq!(source.offset(), UtcOffset::UTC);
    assert_eq!(server - source, Duration::milliseconds(100));
    assert_eq!(received - source, Duration::milliseconds(200));

    let trace = project_meter_trace(&contract, rows.as_bytes(), &window)
        .unwrap()
        .trace;
    let register: OffsetDateTime = trace.register[0].at();
    assert_eq!(register, source);
    assert_eq!(Some(trace.register[0].wh), reading.value());
    assert_eq!(trace.closed[0].at(), source);

    let end = source + Duration::minutes(30);
    let mut projector = MeterProjector::new(
        &contract,
        MeterWindow {
            device: "example-grid-incomer",
            application_uri: "urn:example:grid-meter",
            node: &opcua_kit::NodeId::new("urn:example:meter", "s=GridImportWh").unwrap(),
            start: source,
            end,
            tolerance_wh: 1,
        },
    )
    .unwrap();
    for line in rows.lines() {
        let evidence = parse_meter_reading(&contract, line.as_bytes()).unwrap();
        let available = projector.remaining_input_bytes();
        let charge = evidence.compact_line_bytes();
        assert!(charge <= available);
        projector.push(&evidence).unwrap();
        assert_eq!(projector.remaining_input_bytes(), available - charge);
    }
    let result = projector
        .finish(&[(source, 285_000), (source + Duration::minutes(15), 274_999)])
        .unwrap();
    assert_eq!(result.trace.start(), source);
    assert_eq!(result.trace.end(), end);
    assert_eq!(result.trace.tolerance_wh(), 1);
    assert!(
        result
            .trace
            .register
            .iter()
            .map(|p| (p.at(), p.wh))
            .eq(trace.register.iter().map(|p| (p.at(), p.wh)))
    );
    assert!(
        result
            .trace
            .closed
            .iter()
            .map(|p| (p.at(), p.wh))
            .eq(trace.closed.iter().map(|p| (p.at(), p.wh)))
    );
}
