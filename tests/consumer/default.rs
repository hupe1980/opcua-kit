//! Consumer compiled and run against the default features of the packaged crate.
use opcua_kit::{Client, NodeId, ReadAttribute, ReadError, ReadOperand, Sample};

async fn poll(
    client: &Client,
    nodes: &[NodeId],
) -> Result<Vec<Result<Sample<u64>, ReadError>>, ReadError> {
    client.read_scalars(nodes).await
}

async fn inspect(client: &Client, node: &NodeId) -> Result<Option<NodeId>, ReadError> {
    let operands = [ReadOperand::new(node, ReadAttribute::ValueRank)];
    let ranks = client.read_attributes(&operands).await?;
    assert_eq!(ranks.len(), 1);
    Ok(client.read_definition(node).await?.data_type?.value)
}

async fn identified_unit(
    client: &Client,
    node: &NodeId,
) -> Result<Option<opcua_kit::EngineeringUnit>, ReadError> {
    let evidence = client.read_engineering_units(node).await?;
    if evidence.sample.status != 0 {
        return Ok(None);
    }
    Ok(evidence
        .sample
        .value
        .filter(opcua_kit::EngineeringUnit::is_identified))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let node = NodeId::new("urn:plant:line-1", "i=00042")?;
    assert_eq!(node.identifier(), "i=42");
    assert_eq!(node.namespace(), "urn:plant:line-1");
    let _api = (poll, inspect, identified_unit);
    Ok(())
}
