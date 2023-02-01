use config::{ConfigError, Map, Source, Value};
use iroh_rpc_types::{gateway::GatewayAddr, p2p::P2pAddr, store::StoreAddr};
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
/// Config for the rpc Client.
pub struct Config {
    /// Gateway rpc address.
    pub gateway_addr: Option<GatewayAddr>,
    /// P2p rpc address.
    pub p2p_addr: Option<P2pAddr>,
    /// Store rpc address.
    pub store_addr: Option<StoreAddr>,
    /// Number of concurent channels.
    ///
    /// If `None` defaults to `1`, not used for in-memory addresses.
    // TODO: Consider changing this to NonZeroUsize instead of Option<usize>.
    pub channels: Option<usize>,
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();
        if let Some(addr) = &self.gateway_addr {
            insert_into_config_map(&mut map, "gateway_addr", addr.to_string());
        }
        if let Some(addr) = &self.p2p_addr {
            insert_into_config_map(&mut map, "p2p_addr", addr.to_string());
        }
        if let Some(addr) = &self.store_addr {
            insert_into_config_map(&mut map, "store_addr", addr.to_string());
        }
        if let Some(channels) = &self.channels {
            insert_into_config_map(&mut map, "channels", channels.to_string());
        }
        Ok(map)
    }
}

impl Config {
    pub fn default_network() -> Self {
        Self {
            gateway_addr: Some("irpc://127.0.0.1:4400".parse().unwrap()),
            p2p_addr: Some("irpc://127.0.0.1:4401".parse().unwrap()),
            store_addr: Some("irpc://127.0.0.1:4402".parse().unwrap()),
            /// disable load balancing by default by just having 1 channel
            channels: Some(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_collect() {
        let default = Config::default_network();
        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "gateway_addr".to_string(),
            Value::new(None, default.gateway_addr.unwrap().to_string()),
        );
        expect.insert(
            "p2p_addr".to_string(),
            Value::new(None, default.p2p_addr.unwrap().to_string()),
        );
        expect.insert(
            "store_addr".to_string(),
            Value::new(None, default.store_addr.unwrap().to_string()),
        );
        expect.insert(
            "channels".to_string(),
            Value::new(None, default.channels.unwrap().to_string()),
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
