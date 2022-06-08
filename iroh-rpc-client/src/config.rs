use std::net::SocketAddr;

use config::{ConfigError, Map, Source, Value};
use iroh_util::insert_into_config_map;
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
        insert_into_config_map(&mut map, "gateway_addr", self.gateway_addr.to_string());
        insert_into_config_map(&mut map, "p2p_addr", self.p2p_addr.to_string());
        insert_into_config_map(&mut map, "store_addr", self.store_addr.to_string());
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
        let default = Config::default();
        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "gateway_addr".to_string(),
            Value::new(None, default.gateway_addr.to_string()),
        );
        expect.insert(
            "p2p_addr".to_string(),
            Value::new(None, default.p2p_addr.to_string()),
        );
        expect.insert(
            "store_addr".to_string(),
            Value::new(None, default.store_addr.to_string()),
        );
        let got = Config::default().collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
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
