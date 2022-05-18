use anyhow::Result;

use crate::network::P2pClient;
use crate::store::StoreClient;

#[derive(Debug, Clone)]
pub struct Client {
    pub p2p: P2pClient,
    pub store: StoreClient,
}

impl Client {
    pub async fn new(cfg: &RpcClientConfig) -> Result<Self> {
        let p2p = P2pClient::new(&cfg.p2p_addr).await?;
        let store = StoreClient::new(&cfg.store_addr).await?;

        Ok(Client { p2p, store })
    }
}

#[derive(Debug, Clone)]
// Config for the rpc Client
pub struct RpcClientConfig {
    // gateway rpc address
    pub gateway_addr: String,
    // p2p rpc address
    pub p2p_addr: String,
    // store rpc address
    pub store_addr: String,
}

impl Default for RpcClientConfig {
    fn default() -> Self {
        Self {
            gateway_addr: "http://localhost:4400".into(),
            p2p_addr: "http://localhost:4401".into(),
            store_addr: "http:://localhost:4402".into(),
        }
    }
}
