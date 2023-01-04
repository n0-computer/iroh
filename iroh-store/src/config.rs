use anyhow::{anyhow, Result};
use config::{ConfigError, Map, Source, Value};
use iroh_metrics::config::Config as MetricsConfig;
use iroh_rpc_client::Config as RpcClientConfig;
use iroh_rpc_types::store::StoreAddr;
use iroh_util::{insert_into_config_map, iroh_data_path};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "store.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
/// For example, `IROH_STORE_PATH=/path/to/config` would set the value of the `Config.path` field
pub const ENV_PREFIX: &str = "IROH_STORE";

/// the path to data directory. If arg_path is `None`, the default iroh_data_path()/store is used
/// iroh_data_path() returns an operating system-specific directory
pub fn config_data_path(arg_path: Option<PathBuf>) -> Result<PathBuf> {
    match arg_path {
        Some(p) => Ok(p),
        None => iroh_data_path("store").map_err(|e| anyhow!("{}", e)),
    }
}

/// The configuration for the store server.
///
/// This is the configuration which the store server binary needs to run.  This is a
/// superset from the configuration needed by the store service, which can also run
/// integrated into another binary like in iroh-one, iroh-share or iroh-embed.
#[derive(PartialEq, Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    /// Configuration of the store service.
    pub store: Config,
    /// Configuration for metrics export.
    pub metrics: MetricsConfig,
}

impl ServerConfig {
    pub fn new(path: PathBuf) -> Self {
        let addr = "irpc://0.0.0.0:4402".parse().unwrap();
        Self {
            store: Config::with_rpc_addr(path, addr),
            metrics: Default::default(),
        }
    }
}

impl Source for ServerConfig {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();
        insert_into_config_map(&mut map, "store", self.store.collect()?);
        insert_into_config_map(&mut map, "metrics", self.metrics.collect()?);
        Ok(map)
    }
}

/// The configuration for the store service.
///
/// As opposed to the [`ServerConfig`] this is only the configuration needed to run the
/// store service.  It can still be deserialised from a file, which is e.g. used by
/// iroh-one.
#[derive(PartialEq, Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// The location of the content database.
    pub path: PathBuf,
    /// The iRPC configuration.
    ///
    /// Only used to extract the listening address from the `store_addr` field.
    // TODO: split off listening address from RpcClientConfig.
    pub rpc_client: RpcClientConfig,
}

impl From<ServerConfig> for Config {
    fn from(source: ServerConfig) -> Self {
        source.store
    }
}

impl Config {
    /// Creates a new store config.
    ///
    /// This config will not have any RpcClientConfig, but that is fine because it is mostly
    /// unused: `iroh_rpc::rpc::new` which is used takes the RPC address as a separate
    /// argument.  Once #672 is merged we can probably remove the `rpc_client` field.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            rpc_client: Default::default(),
        }
    }

    /// Creates a new store config with the given RPC listen address.
    pub fn with_rpc_addr(path: PathBuf, addr: StoreAddr) -> Self {
        Self {
            path,
            rpc_client: RpcClientConfig {
                store_addr: Some(addr),
                ..Default::default()
            },
        }
    }

    pub fn rpc_addr(&self) -> Option<StoreAddr> {
        self.rpc_client.store_addr.clone()
    }
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();
        let path = self
            .path
            .to_str()
            .ok_or_else(|| ConfigError::Foreign("No `path` set. Path is required.".into()))?;
        insert_into_config_map(&mut map, "path", path);
        insert_into_config_map(&mut map, "rpc_client", self.rpc_client.collect()?);
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn test_collect() {
        let path = PathBuf::new().join("test");
        let default = ServerConfig::new(path);

        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "store".to_string(),
            Value::new(None, default.store.collect().unwrap()),
        );
        expect.insert(
            "metrics".to_string(),
            Value::new(None, default.metrics.collect().unwrap()),
        );

        let got = default.collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_build_config_from_struct() {
        let path = PathBuf::new().join("test");
        let expect = ServerConfig::new(path);
        let got: ServerConfig = config::Config::builder()
            .add_source(expect.clone())
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }

    #[test]
    fn test_config_data_path() {
        let path = PathBuf::new().join("arg_path");
        let path_given = config_data_path(Some(path.clone())).expect("config data path error");
        assert_eq!(path_given.display().to_string(), path.display().to_string());

        let no_path_given = config_data_path(None)
            .expect("config data path error")
            .display()
            .to_string();
        assert!(no_path_given.ends_with("store"));
    }
}
