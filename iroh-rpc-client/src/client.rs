use anyhow::Result;

use crate::network::P2pClient;

#[derive(Debug, Clone)]
pub struct Client {
    pub p2p: P2pClient,
}

impl Client {
    pub async fn new(p2p_addr: &str) -> Result<Self> {
        let p2p = P2pClient::new(p2p_addr).await?;

        Ok(Client { p2p })
    }
}
