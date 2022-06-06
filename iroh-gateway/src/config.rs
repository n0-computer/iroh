use std::net::SocketAddr;

use crate::constants::*;
use axum::http::{header::*, Method};
use config::{ConfigError, Map, Source, Value, ValueKind};
use headers::{
    AccessControlAllowHeaders, AccessControlAllowMethods, AccessControlAllowOrigin, HeaderMapExt,
};
use iroh_rpc_client::Config as RpcClientConfig;
use serde::{Deserialize, Serialize};

pub const CONFIG: &str = "gateway.config.toml";
pub const DEFAULT_PORT: u16 = 9050;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Config {
    /// flag to toggle whether the gateway allows writing/pushing data
    pub writeable: bool,
    /// flag to toggle whether the gateway allows fetching data from other nodes or is local only
    pub fetch: bool,
    /// flag to toggle whether the gateway enables/utilizes caching
    pub cache: bool,
    /// set of user provided headers to attach to all responses
    #[serde(with = "http_serde::header_map")]
    pub headers: HeaderMap,
    /// default port to listen on
    pub port: u16,
    pub rpc: RpcConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RpcConfig {
    /// Address on which to listen,
    pub listen_addr: SocketAddr,
    pub client_config: RpcClientConfig,
}

impl Default for RpcConfig {
    fn default() -> Self {
        let client_config = RpcClientConfig::default();
        RpcConfig {
            listen_addr: client_config.gateway_addr,
            client_config,
        }
    }
}

impl Source for RpcConfig {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }
    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let client_config = self.client_config.collect()?;
        let mut map: Map<String, Value> = Map::new();
        map.insert("client_config".to_string(), Value::new(None, client_config));
        map.insert(
            "listen_addr".to_string(),
            Value::new(None, self.listen_addr.to_string()),
        );
        Ok(map)
    }
}

impl Config {
    pub fn new(writeable: bool, fetch: bool, cache: bool, port: u16, rpc: RpcConfig) -> Self {
        Self {
            writeable,
            fetch,
            cache,
            headers: HeaderMap::new(),
            port,
            rpc,
        }
    }

    pub fn set_default_headers(&mut self) {
        let mut headers = HeaderMap::new();
        headers.typed_insert(AccessControlAllowOrigin::ANY);
        headers.typed_insert(
            [
                Method::GET,
                Method::PUT,
                Method::POST,
                Method::DELETE,
                Method::HEAD,
                Method::OPTIONS,
            ]
            .into_iter()
            .collect::<AccessControlAllowMethods>(),
        );
        headers.typed_insert(
            [
                CONTENT_TYPE,
                CONTENT_DISPOSITION,
                LAST_MODIFIED,
                CACHE_CONTROL,
                ACCEPT_RANGES,
                ETAG,
                HEADER_SERVICE_WORKER.clone(),
                HEADER_X_IPFS_GATEWAY_PREFIX.clone(),
                HEADER_X_TRACE_ID.clone(),
                HEADER_X_CONTENT_TYPE_OPTIONS.clone(),
                HEADER_X_IPFS_PATH.clone(),
                HEADER_X_IPFS_ROOTS.clone(),
            ]
            .into_iter()
            .collect::<AccessControlAllowHeaders>(),
        );
        // todo(arqu): remove these once propperly implmented
        headers.insert(CACHE_CONTROL, VALUE_NO_CACHE_NO_TRANSFORM.clone());
        headers.insert(ACCEPT_RANGES, VALUE_NONE.clone());
        self.headers = headers;
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut t = Self {
            writeable: false,
            fetch: false,
            cache: false,
            headers: HeaderMap::new(),
            port: DEFAULT_PORT,
            rpc: Default::default(),
        };
        t.set_default_headers();
        t
    }
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let rpc = self.rpc.collect()?;
        let mut map: Map<String, Value> = Map::new();
        insert_into_config_map(&mut map, "writeable", self.writeable);
        insert_into_config_map(&mut map, "fetch", self.fetch);
        insert_into_config_map(&mut map, "cache", self.cache);
        // TODO: add headers
        // insert_into_config_map(&mut map, "headers", self.headers);
        // Some issue between deserializing u64 & u16, converting this to
        // an signed int fixes the issue
        insert_into_config_map(&mut map, "port", self.port as i64);
        insert_into_config_map(&mut map, "rpc", rpc);
        Ok(map)
    }
}

fn insert_into_config_map<I: Into<String>, V: Into<ValueKind>>(
    map: &mut Map<String, Value>,
    field: I,
    val: V,
) {
    map.insert(field.into(), Value::new(None, val));
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn default_headers() {
        let mut config = Config::new(false, false, false, 9050, Default::default());
        config.set_default_headers();
        assert_eq!(config.headers.len(), 5);
        let h = config.headers.get(&ACCESS_CONTROL_ALLOW_ORIGIN).unwrap();
        assert_eq!(h, "*");
    }

    #[test]
    fn default_config() {
        let config = Config::default();
        assert!(!config.writeable);
        assert!(!config.fetch);
        assert!(!config.cache);
        assert_eq!(config.port, DEFAULT_PORT);
    }

    #[test]
    fn test_collect_rpc_config() {
        let default = RpcConfig::default();
        let mut rpc_client_expect: Map<String, Value> = Map::new();
        rpc_client_expect.insert(
            "gateway_addr".to_string(),
            Value::new(None, default.client_config.gateway_addr.to_string()),
        );
        rpc_client_expect.insert(
            "p2p_addr".to_string(),
            Value::new(None, default.client_config.p2p_addr.to_string()),
        );
        rpc_client_expect.insert(
            "store_addr".to_string(),
            Value::new(None, default.client_config.store_addr.to_string()),
        );

        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "client_config".to_string(),
            Value::new(None, rpc_client_expect),
        );
        expect.insert(
            "listen_addr".to_string(),
            Value::new(None, default.listen_addr.to_string()),
        );

        let got = RpcConfig::default().collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
    }

    #[test]
    fn test_build_rpc_config_from_struct() {
        let expect = RpcConfig::default();
        let got: RpcConfig = ConfigBuilder::builder()
            .add_source(RpcConfig::default())
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }

    #[test]
    fn test_collect() {
        let rpc = RpcConfig::default().collect().unwrap();
        let default = Config::default();
        let mut expect: Map<String, Value> = Map::new();
        expect.insert("writeable".to_string(), Value::new(None, default.writeable));
        expect.insert("fetch".to_string(), Value::new(None, default.fetch));
        expect.insert("cache".to_string(), Value::new(None, default.cache));
        expect.insert("port".to_string(), Value::new(None, default.port as i64));
        expect.insert("rpc".to_string(), Value::new(None, rpc));
        let got = Config::default().collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap_or_else(|| panic!("{}", key));
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
    }

    //     #[test]
    //     fn test_build_config_from_struct() {
    //         let expect = Config::default();
    //         let got: Config = ConfigBuilder::builder()
    //             .add_source(Config::default())
    //             .build()
    //             .unwrap()
    //             .try_deserialize()
    //             .unwrap();

    //         assert_eq!(expect, got);
    //     }

    // #[test]
    // fn test_write_file() {
    //     let c = Config::default().set_default_headers();
    //     let r = toml::to_string(&c).unwrap();
    //     println!("{}", r);
    //     std::fs::write(CONFIG, r).unwrap();
    //     assert_eq!(1, 1);
    // }
}
