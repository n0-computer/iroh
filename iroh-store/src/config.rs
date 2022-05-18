use std::net::SocketAddr;
use std::path::PathBuf;

use iroh_rpc_client::RpcClientConfig;

/// The configuration for the store.
#[derive(Debug, Clone)]
pub struct Config {
    /// The location of the content database.
    pub path: PathBuf,
    pub rpc: RpcConfig,
}

impl Config {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            rpc: RpcConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub listen_addr: SocketAddr,
    pub client_config: RpcClientConfig,
}

impl Default for RpcConfig {
    fn default() -> Self {
        let client_config = RpcClientConfig::default();
        Self {
            listen_addr: client_config.store_addr.parse().unwrap(),
            client_config,
        }
    }
}
