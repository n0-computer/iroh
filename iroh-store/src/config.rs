use std::net::SocketAddr;
use std::path::PathBuf;

use config::{ConfigError, Map, Source, Value};
use iroh_rpc_client::Config as RpcClientConfig;
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "store.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
/// For example, `IROH_STORE_PATH=/path/to/config` would set the value of the `Config.path` field
pub const ENV_PREFIX: &str = "IROH_STORE";

/// The configuration for the store.
#[derive(PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// The location of the content database.
    pub path: PathBuf,
    pub rpc_addr: SocketAddr,
    pub rpc_client: RpcClientConfig,
}

impl Config {
    pub fn new(path: PathBuf) -> Self {
        let rpc_client = RpcClientConfig::default();
        Self {
            path,
            rpc_addr: rpc_client.store_addr,
            rpc_client,
        }
    }
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }
    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let rpc_client = self.rpc_client.collect()?;
        let mut map: Map<String, Value> = Map::new();
        let path = self
            .path
            .to_str()
            .ok_or_else(|| ConfigError::Foreign("No `path` set. Path is required.".into()))?;
        insert_into_config_map(&mut map, "path", path);
        insert_into_config_map(&mut map, "rpc_addr", self.rpc_addr.to_string());
        insert_into_config_map(&mut map, "rpc_client", rpc_client);

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
        let rpc_client_expect = default.rpc_client.collect().unwrap();

        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "rpc_addr".to_string(),
            Value::new(None, default.rpc_addr.to_string()),
        );
        expect.insert(
            "rpc_client".to_string(),
            Value::new(None, rpc_client_expect),
        );
        expect.insert(
            "path".to_string(),
            Value::new(None, default.path.to_str().unwrap()),
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
