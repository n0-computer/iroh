use anyhow::{anyhow, Result};
use iroh_net::NodeId;

pub mod discovery;
pub mod packet;
pub mod publish;
pub mod resolve;

pub fn to_z32(node_id: &NodeId) -> String {
    z32::encode(node_id.as_bytes())
}

pub fn from_z32(s: &str) -> Result<NodeId> {
    let bytes = z32::decode(s.as_bytes()).map_err(|_| anyhow!("invalid z32"))?;
    let bytes: &[u8; 32] = &bytes.try_into().map_err(|_| anyhow!("not 32 bytes long"))?;
    let node_id = NodeId::from_bytes(bytes)?;
    Ok(node_id)
}
