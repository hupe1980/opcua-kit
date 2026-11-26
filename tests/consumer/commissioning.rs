use opcua_kit::commissioning::{Outcome, assess, parse_contract, parse_snapshot};
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = PathBuf::from(env::args_os().nth(1).expect("fixture directory"));
    let contract = parse_contract(&fs::read(fixtures.join("contract.json"))?)?;
    let snapshot = parse_snapshot(&fs::read(fixtures.join("before.json"))?)?;
    assert_eq!(assess(&contract, &snapshot)?.decision, Outcome::Matched);
    Ok(())
}
