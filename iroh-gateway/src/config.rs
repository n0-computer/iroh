use crate::constants::*;
use anyhow::Result;
use axum::http::{header::*, Method};
use config::{ConfigError, Map, Source, Value};
use headers::{
    AcceptRanges, AccessControlAllowHeaders, AccessControlAllowMethods, AccessControlAllowOrigin,
    AccessControlExposeHeaders, HeaderMapExt,
};
use iroh_metrics::config::Config as MetricsConfig;
use iroh_resolver::dns_resolver::Config as DnsResolverConfig;
use iroh_rpc_client::Config as RpcClientConfig;
use iroh_rpc_types::gateway::GatewayAddr;
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "gateway.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
/// For example, `IROH_GATEWAY_PORT=1000` would set the value of the `Config.port` field
pub const ENV_PREFIX: &str = "IROH_GATEWAY";
pub const DEFAULT_PORT: u16 = 9050;

/// The configuration for the gateway server.
///
/// This is the configuration which the gateway server binary needs to run.  This is a
/// superset from the configuration needed by the gateway service, which can also run
/// integrated into another binary like iroh-one, iroh-share or iroh-embed.
// NOTE: If this was moved into main.rs it would not need to be public.  Our binary is build
// as being outside of the lib crate, hence here it needs to be public.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Configuration of the gateway service.
    pub gateway: Config,
    /// Metrics configuration.
    pub metrics: MetricsConfig,
}

impl ServerConfig {
    pub fn new(port: u16, rpc_client: RpcClientConfig) -> Self {
        Self {
            gateway: Config::new(port, rpc_client),
            metrics: MetricsConfig::default(),
        }
    }
}

impl Source for ServerConfig {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();
        insert_into_config_map(&mut map, "gateway", self.gateway.collect()?);
        insert_into_config_map(&mut map, "metrics", self.metrics.collect()?);
        Ok(map)
    }
}

/// Configuration for [`iroh-gateway`].
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Config {
    /// Pretty URL to redirect to
    #[serde(default = "String::new")]
    pub public_url_base: String,
    /// default port to listen on
    pub port: u16,
    /// flag to toggle whether the gateway should use denylist on requests
    pub use_denylist: bool,
    /// URL of gateways to be used by the racing resolver.
    /// Strings can either be urls or subdomain gateway roots
    /// values without https:// prefix are treated as subdomain gateways (eg: dweb.link)
    /// values with are treated as IPFS path gateways (eg: <https://ipfs.io>)
    pub http_resolvers: Option<Vec<String>>,
    /// Separate resolvers for particular TLDs
    #[serde(default = "DnsResolverConfig::default")]
    pub dns_resolver: DnsResolverConfig,
    /// Indexer node to use.
    pub indexer_endpoint: Option<String>,
    /// rpc addresses for the gateway & addresses for the rpc client to dial
    pub rpc_client: RpcClientConfig,
    // NOTE: for toml to serialize properly, the "table" values must be serialized at the end, and
    // so much come at the end of the `Config` struct
    /// set of user provided headers to attach to all responses
    #[serde(with = "http_serde::header_map")]
    pub headers: HeaderMap,
    /// Redirects to subdomains for path requests
    #[serde(default)]
    pub redirect_to_subdomain: bool,
}

impl Config {
    pub fn new(port: u16, rpc_client: RpcClientConfig) -> Self {
        Self {
            public_url_base: String::new(),
            headers: HeaderMap::new(),
            port,
            rpc_client,
            http_resolvers: None,
            dns_resolver: DnsResolverConfig::default(),
            indexer_endpoint: None,
            use_denylist: false,
            redirect_to_subdomain: false,
        }
    }

    pub fn set_default_headers(&mut self) {
        self.headers = default_headers();
    }

    pub fn rpc_addr(&self) -> Option<GatewayAddr> {
        self.rpc_client.gateway_addr.clone()
    }
}

impl From<ServerConfig> for Config {
    fn from(source: ServerConfig) -> Self {
        source.gateway
    }
}

fn default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.typed_insert(AccessControlAllowOrigin::ANY);
    headers.typed_insert(AcceptRanges::bytes());
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
            IF_NONE_MATCH,
            ACCEPT,
            CACHE_CONTROL,
            RANGE,
            CONTENT_TYPE,
            HEADER_SERVICE_WORKER.clone(),
            HEADER_X_REQUESTED_WITH.clone(),
            USER_AGENT,
        ]
        .into_iter()
        .collect::<AccessControlAllowHeaders>(),
    );
    headers.typed_insert(
        [
            CONTENT_LENGTH,
            CONTENT_RANGE,
            HEADER_X_IPFS_PATH.clone(),
            HEADER_X_IPFS_ROOTS.clone(),
            HEADER_X_CHUNKED_OUTPUT.clone(),
            HEADER_X_STREAM_OUTPUT.clone(),
        ]
        .into_iter()
        .collect::<AccessControlExposeHeaders>(),
    );
    headers
}

impl Default for Config {
    fn default() -> Self {
        let rpc_client = RpcClientConfig::default_network();
        let mut t = Self {
            public_url_base: String::new(),
            headers: HeaderMap::new(),
            port: DEFAULT_PORT,
            rpc_client,
            http_resolvers: None,
            dns_resolver: DnsResolverConfig::default(),
            indexer_endpoint: None,
            use_denylist: false,
            redirect_to_subdomain: false,
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
        let rpc_client = self.rpc_client.collect()?;
        let mut map: Map<String, Value> = Map::new();
        insert_into_config_map(&mut map, "public_url_base", self.public_url_base.clone());
        insert_into_config_map(&mut map, "use_denylist", self.use_denylist);
        // Some issue between deserializing u64 & u16, converting this to
        // an signed int fixes the issue
        insert_into_config_map(&mut map, "port", self.port as i32);
        insert_into_config_map(&mut map, "headers", collect_headers(&self.headers)?);
        insert_into_config_map(&mut map, "rpc_client", rpc_client);

        if let Some(http_resolvers) = &self.http_resolvers {
            insert_into_config_map(&mut map, "http_resolvers", http_resolvers.clone());
        }
        if let Some(indexer_endpoint) = &self.indexer_endpoint {
            insert_into_config_map(&mut map, "indexer_endpoint", indexer_endpoint.clone());
        }
        Ok(map)
    }
}

impl crate::handlers::StateConfig for Config {
    fn rpc_client(&self) -> &iroh_rpc_client::Config {
        &self.rpc_client
    }

    fn public_url_base(&self) -> &str {
        &self.public_url_base
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn user_headers(&self) -> &HeaderMap<HeaderValue> {
        &self.headers
    }

    fn redirect_to_subdomain(&self) -> bool {
        self.redirect_to_subdomain
    }
}

fn collect_headers(headers: &HeaderMap) -> Result<Map<String, Value>, ConfigError> {
    let mut map = Map::new();
    for (key, value) in headers.iter() {
        insert_into_config_map(
            &mut map,
            key.as_str(),
            value.to_str().map_err(|e| ConfigError::Foreign(e.into()))?,
        );
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use testdir::testdir;

    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_default_headers() {
        let headers = default_headers();
        assert_eq!(headers.len(), 5);
        let h = headers.get(&ACCESS_CONTROL_ALLOW_ORIGIN).unwrap();
        assert_eq!(h, "*");
    }

    #[test]
    fn default_config() {
        let config = Config::default();
        assert_eq!(config.port, DEFAULT_PORT);
    }

    #[test]
    fn test_collect() {
        let default = ServerConfig::default();
        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "rpc_client".to_string(),
            Value::new(None, default.gateway.collect().unwrap()),
        );
        expect.insert(
            "metrics".to_string(),
            Value::new(None, default.metrics.collect().unwrap()),
        );

        let got = default.collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap_or_else(|| panic!("{}", key));
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
    }

    #[test]
    fn test_collect_headers() {
        let mut expect = Map::new();
        expect.insert(
            "access-control-allow-origin".to_string(),
            Value::new(None, "*"),
        );
        expect.insert("accept-ranges".to_string(), Value::new(None, "bytes"));
        expect.insert(
            "access-control-allow-methods".to_string(),
            Value::new(None, "GET, PUT, POST, DELETE, HEAD, OPTIONS"),
        );
        expect.insert(
            "access-control-allow-headers".to_string(),
            Value::new(
                None,
                "if-none-match, accept, cache-control, range, content-type, service-worker, x-requested-with, user-agent",
            ),
        );
        expect.insert(
            "access-control-expose-headers".to_string(),
            Value::new(None, "content-length, content-range, x-ipfs-path, x-ipfs-roots, x-chunked-output, x-stream-output"),
        );
        let got = collect_headers(&default_headers()).unwrap();
        assert_eq!(expect, got);
    }

    #[test]
    fn test_build_config_from_struct() {
        let mut expect = Config::default();
        expect.set_default_headers();
        let source = expect.clone();
        let got: Config = ConfigBuilder::builder()
            .add_source(source)
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }

    #[test]
    fn test_toml_file() {
        let dir = testdir!();
        let cfg_file = dir.join("config.toml");
        std::fs::write(
            &cfg_file,
            r#"
            [gateway]
            public_url_base = "http://example.com/base/"
            port = 2001
            [gateway.rpc_client]
            gateway_addr = "irpc://127.0.0.42:1234"
            "#,
        )
        .unwrap();
        let sources = [Some(cfg_file.as_path())];
        let cfg = iroh_util::make_config(
            ServerConfig::default(),
            &sources,
            ENV_PREFIX,
            HashMap::<&str, String>::new(),
        )
        .unwrap();
        dbg!(&cfg);

        assert_eq!(cfg.gateway.public_url_base, "http://example.com/base/");
        assert_eq!(cfg.gateway.port, 2001);
        assert_eq!(
            cfg.gateway.rpc_client.gateway_addr.unwrap(),
            "irpc://127.0.0.42:1234".parse().unwrap(),
        );
    }
}
