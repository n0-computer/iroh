use std::net::SocketAddr;

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
        let p2p = P2pClient::new(cfg.p2p_addr).await?;
        let store = StoreClient::new(cfg.store_addr).await?;

        Ok(Client { p2p, store })
    }
}

#[derive(Debug, Clone)]
// Config for the rpc Client
pub struct RpcClientConfig {
    // gateway rpc address
    pub gateway_addr: SocketAddr,
    // p2p rpc address
    pub p2p_addr: SocketAddr,
    // store rpc address
    pub store_addr: SocketAddr,
}

impl Default for RpcClientConfig {
    fn default() -> Self {
        Self {
            gateway_addr: "0.0.0.0:4400".parse().unwrap(),
            p2p_addr: "0.0.0.0:4401".parse().unwrap(),
            store_addr: "0.0.0.0:4402".parse().unwrap(),
        }
    }
}
