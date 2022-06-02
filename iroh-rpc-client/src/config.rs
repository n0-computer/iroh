use std::net::SocketAddr;

use config::{ConfigError, Map, Source, Value};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
// Config for the rpc Client
pub struct Config {
    // gateway rpc address
    pub gateway_addr: SocketAddr,
    // p2p rpc address
    pub p2p_addr: SocketAddr,
    // store rpc address
    pub store_addr: SocketAddr,
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();
        map.insert(
            "gateway_addr".into(),
            Value::new(Some(&"struct".to_string()), self.gateway_addr.to_string()),
        );
        map.insert(
            "p2p_addr".into(),
            Value::new(Some(&"struct".to_string()), self.p2p_addr.to_string()),
        );
        map.insert(
            "store_addr".into(),
            Value::new(Some(&"struct".to_string()), self.store_addr.to_string()),
        );
        Ok(map)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            gateway_addr: "0.0.0.0:4400".parse().unwrap(),
            p2p_addr: "0.0.0.0:4401".parse().unwrap(),
            store_addr: "0.0.0.0:4402".parse().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_collect() {
        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "gateway_addr".to_string(),
            Value::new(Some(&"struct".to_string()), "0.0.0.0:4400"),
        );
        expect.insert(
            "p2p_addr".to_string(),
            Value::new(Some(&"struct".to_string()), "0.0.0.0:4401"),
        );
        expect.insert(
            "store_addr".to_string(),
            Value::new(Some(&"struct".to_string()), "0.0.0.0:4402"),
        );
        let got = Config::default().collect().unwrap();
        assert_eq!(expect, got);
    }

    #[test]
    fn test_config() {
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
