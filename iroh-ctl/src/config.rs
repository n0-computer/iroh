use config::{ConfigError, Map, Source, Value};
use iroh_rpc_client::Config as RpcClientConfig;
use serde::{Deserialize, Serialize};

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "ctl.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
pub const ENV_PREFIX: &str = "IROH_CTL";

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub rpc_client: RpcClientConfig,
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }
    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let rpc_client = self.rpc_client.collect()?;
        let mut map: Map<String, Value> = Map::new();
        map.insert("rpc_client".to_string(), Value::new(None, rpc_client));
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_collect() {
        let rpc_client_default = RpcClientConfig::default();
        let mut rpc_client_expect: Map<String, Value> = Map::new();
        rpc_client_expect.insert(
            "gateway_addr".to_string(),
            Value::new(None, rpc_client_default.gateway_addr.to_string()),
        );
        rpc_client_expect.insert(
            "p2p_addr".to_string(),
            Value::new(None, rpc_client_default.p2p_addr.to_string()),
        );
        rpc_client_expect.insert(
            "store_addr".to_string(),
            Value::new(None, rpc_client_default.store_addr.to_string()),
        );
        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "rpc_client".to_string(),
            Value::new(None, rpc_client_expect),
        );
        let got = Config::default().collect().unwrap();
        assert_eq!(expect, got);
    }

    #[test]
    fn test_build_config_from_struct() {
        let expect = Config::default();
        let got: Config = ConfigBuilder::builder()
            .add_source(Config::default())
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }
}
