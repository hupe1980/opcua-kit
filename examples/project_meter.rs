//! Project the packaged two-quarter example with the offline Rust API.
use opcua_kit::NodeId;
use opcua_kit::commissioning::{
    meter::{MeterProjector, MeterWindow, OffsetDateTime, parse_meter_reading},
    parse_contract,
};
use std::{
    error::Error,
    io::{self, Write},
};
use time::{Duration, format_description::well_known::Rfc3339};

fn main() -> Result<(), Box<dyn Error>> {
    let contract = parse_contract(include_bytes!("../fixtures/meter/contract.json"))?;

    // The independent close feed supplies the meter identity and the UTC quarter starts.
    let register = NodeId::new("urn:example:meter", "s=GridImportWh")?;
    let start = OffsetDateTime::parse("2026-10-25T00:45:00Z", &Rfc3339)?;
    let window = MeterWindow {
        device: "example-grid-incomer",
        application_uri: "urn:example:grid-meter",
        node: &register,
        start,
        end: start + Duration::minutes(30),
        tolerance_wh: 1,
    };
    let mut projector = MeterProjector::new(&contract, window)?;

    // In a live driver, push the MeterReading returned by client.read_meter(&contract).
    for line in include_str!("../fixtures/meter/readings.ndjson").lines() {
        let reading = parse_meter_reading(&contract, line.as_bytes())?;
        projector.push(&reading)?;
    }

    let closes = [(start, 285_000), (start + Duration::minutes(15), 274_999)];
    let result = projector.finish(&closes)?;
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &result.trace)?;
    writeln!(output)?;
    Ok(())
}
