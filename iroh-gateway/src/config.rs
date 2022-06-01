use std::net::SocketAddr;

use crate::constants::*;
use axum::http::{header::*, Method};
use headers::{
    AccessControlAllowHeaders, AccessControlAllowMethods, AccessControlAllowOrigin, HeaderMapExt,
};
use iroh_rpc_client::RpcClientConfig;

pub const DEFAULT_PORT: u16 = 9050;

#[derive(Debug, Clone)]
pub struct Config {
    /// flag to toggle whether the gateway allows writing/pushing data
    pub writeable: bool,
    /// flag to toggle whether the gateway allows fetching data from other nodes or is local only
    pub fetch: bool,
    /// flag to toggle whether the gateway enables/utilizes caching
    pub cache: bool,
    /// set of user provided headers to attach to all responses
    pub headers: HeaderMap,
    /// default port to listen on
    pub port: u16,
    pub rpc: RpcConfig,
}

#[derive(Debug, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
