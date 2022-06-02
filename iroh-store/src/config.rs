use std::path::PathBuf;

use iroh_rpc_client::RpcClientConfig;
use serde::{Deserialize, Serialize};

/// The configuration for the store.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// The location of the content database.
    pub path: PathBuf,
    pub rpc: RpcClientConfig,
}

impl Config {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            rpc: RpcClientConfig::default(),
        }
    }
}
