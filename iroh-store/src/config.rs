use std::path::PathBuf;

use config::{ConfigError, Map, Source, Value};
use iroh_rpc_client::Config as RpcClientConfig;
use serde::{Deserialize, Serialize};

// pub const CONFIG: &str = "store.config.toml";

/// The configuration for the store.
#[derive(PartialEq, Debug, Clone, Deserialize, Serialize)]
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

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }
    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let rpc = self.rpc.collect()?;
        let mut map: Map<String, Value> = Map::new();
        map.insert("rpc".to_string(), Value::new(None, rpc));
        let path = self.path.clone();
        map.insert(
            "path".to_string(),
            Value::new(None, path.into_os_string().into_string().unwrap()),
        );
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_collect() {
        let path = PathBuf::new().join("test");
        let default = Config::new(path.clone());
        let mut rpc_client_expect: Map<String, Value> = Map::new();
        rpc_client_expect.insert(
            "gateway_addr".to_string(),
            Value::new(None, default.rpc.gateway_addr.to_string()),
        );
        rpc_client_expect.insert(
            "p2p_addr".to_string(),
            Value::new(None, default.rpc.p2p_addr.to_string()),
        );
        rpc_client_expect.insert(
            "store_addr".to_string(),
            Value::new(None, default.rpc.store_addr.to_string()),
        );

        let mut expect: Map<String, Value> = Map::new();
        expect.insert("rpc".to_string(), Value::new(None, rpc_client_expect));
        expect.insert(
            "path".to_string(),
            Value::new(None, default.path.into_os_string().into_string().unwrap()),
        );

        let got = Config::new(path).collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
    }

    #[test]
    fn test_build_config_from_struct() {
        let path = PathBuf::new().join("test");
        let expect = Config::new(path.clone());
        let got: Config = ConfigBuilder::builder()
            .add_source(Config::new(path))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }
}
