use config::{ConfigError, Map, Source, Value};
use iroh_rpc_types::{gateway::GatewayClientAddr, p2p::P2pClientAddr, store::StoreClientAddr};
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
// Config for the rpc Client
pub struct Config {
    // gateway rpc address
    pub gateway_addr: Option<GatewayClientAddr>,
    // p2p rpc address
    pub p2p_addr: Option<P2pClientAddr>,
    // store rpc address
    pub store_addr: Option<StoreClientAddr>,
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
        Ok(map)
    }
}

impl Config {
    pub fn default_grpc() -> Self {
        Self {
            gateway_addr: Some("grpc://0.0.0.0:4400".parse().unwrap()),
            p2p_addr: Some("grpc://0.0.0.0:4401".parse().unwrap()),
            store_addr: Some("grpc://0.0.0.0:4402".parse().unwrap()),
        }
    }

    // When running in ipfsd mode, the resolver will use memory channels to
    // communicate with the p2p and store modules.
    // The gateway itself is exposing a UDS rpc endpoint to be also usable
    // as a single entry point for other system services.
    pub fn default_ipfsd() -> Self {
        use iroh_rpc_types::Addr;
        let path = {
            #[cfg(target_os = "android")]
            "/dev/socket/ipfsd".into();

            #[cfg(not(target_os = "android"))]
            {
                let path = format!("{}", std::env::temp_dir().join("ipfsd.gateway").display());
                path.into()
            }
        };

        Self {
            gateway_addr: Some(Addr::GrpcUds(path)),
            p2p_addr: None,
            store_addr: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_collect() {
        let default = Config::default_grpc();
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
