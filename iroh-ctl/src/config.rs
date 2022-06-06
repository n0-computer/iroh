use config::{ConfigError, Map, Source, Value};
use iroh_rpc_client::Config as RpcClientConfig;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct Config {
    rpc_client: RpcClientConfig,
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
