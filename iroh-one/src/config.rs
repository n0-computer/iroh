use anyhow::Result;
use axum::http::header::*;
use config::{ConfigError, Map, Source, Value};

use iroh_metrics::config::Config as MetricsConfig;
use iroh_p2p::Libp2pConfig;
use iroh_rpc_client::Config as RpcClientConfig;
use iroh_rpc_types::Addr;
use iroh_store::config::config_data_path;
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tempdir::TempDir;

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "one.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
/// For example, `IROH_ONE_PORT=1000` would set the value of the `Config.port` field
pub const ENV_PREFIX: &str = "IROH_ONE";
pub const DEFAULT_PORT: u16 = 9050;

/// The configuration includes gateway, store and p2p specific items
/// as well as the common rpc & metrics ones.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Config {
    /// Path for the UDS socket for the gateway.
    #[cfg(feature = "uds-gateway")]
    pub gateway_uds_path: Option<PathBuf>,
    /// URL of the gateway used by the racing resolver.
    pub resolver_gateway: Option<String>,
    /// Gateway specific configuration.
    pub gateway: iroh_gateway::config::Config,
    /// Store specific configuration.
    pub store: iroh_store::config::Config,
    /// P2P specific configuration.
    pub p2p: iroh_p2p::config::Config,
    /// rpc addresses for the gateway & addresses for the rpc client to dial
    pub rpc_client: RpcClientConfig,
    /// metrics configuration
    pub metrics: MetricsConfig,
}

impl Config {
    pub fn new(
        gateway: iroh_gateway::config::Config,
        store: iroh_store::config::Config,
        p2p: iroh_p2p::config::Config,
        rpc_client: RpcClientConfig,
        #[cfg(feature = "uds-gateway")] gateway_uds_path: Option<PathBuf>,
        resolver_gateway: Option<String>,
    ) -> Self {
        Self {
            gateway,
            store,
            p2p,
            rpc_client,
            metrics: MetricsConfig::default(),
            #[cfg(feature = "uds-gateway")]
            gateway_uds_path,
            resolver_gateway,
        }
    }

    /// When running in single binary mode, the resolver will use memory channels to
    /// communicate with the p2p and store modules.
    /// The gateway itself is exposing a UDS rpc endpoint to be also usable
    /// as a single entry point for other system services if feature enabled.
    pub fn default_rpc_config() -> RpcClientConfig {
        let path: PathBuf = TempDir::new("iroh").unwrap().path().join("ipfsd.http");

        RpcClientConfig {
            gateway_addr: Some(Addr::GrpcUds(path)),
            p2p_addr: None,
            store_addr: None,
        }
    }

    // synchronize the top level configs across subsystems
    pub fn synchronize_subconfigs(&mut self) {
        self.gateway.rpc_client = self.rpc_client.clone();
        self.p2p.rpc_client = self.rpc_client.clone();
        self.store.rpc_client = self.rpc_client.clone();
        self.gateway.metrics = self.metrics.clone();
        self.p2p.metrics = self.metrics.clone();
        self.store.metrics = self.metrics.clone();
    }
}

impl Default for Config {
    fn default() -> Self {
        #[cfg(feature = "uds-gateway")]
        let gateway_uds_path: PathBuf = TempDir::new("iroh").unwrap().path().join("ipfsd.http");
        let rpc_client = Self::default_rpc_config();
        let metrics_config = MetricsConfig::default();
        let store_config =
            default_store_config(None, rpc_client.clone(), metrics_config.clone()).unwrap();
        let key_store_path = iroh_util::iroh_data_root().unwrap();
        Self {
            rpc_client: rpc_client.clone(),
            metrics: metrics_config.clone(),
            gateway: iroh_gateway::config::Config::default(),
            store: store_config,
            p2p: default_p2p_config(rpc_client, metrics_config, key_store_path),
            #[cfg(feature = "uds-gateway")]
            gateway_uds_path: Some(gateway_uds_path),
            resolver_gateway: None,
        }
    }
}

fn default_store_config(
    store_path: Option<PathBuf>,
    ipfsd: RpcClientConfig,
    metrics: iroh_metrics::config::Config,
) -> Result<iroh_store::config::Config> {
    let path = config_data_path(store_path)?;
    Ok(iroh_store::config::Config {
        path,
        rpc_client: ipfsd,
        metrics,
    })
}

fn default_p2p_config(
    ipfsd: RpcClientConfig,
    metrics: iroh_metrics::config::Config,
    key_store_path: PathBuf,
) -> iroh_p2p::config::Config {
    iroh_p2p::config::Config {
        libp2p: Libp2pConfig::default(),
        rpc_client: ipfsd,
        metrics,
        key_store_path,
    }
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();

        insert_into_config_map(&mut map, "gateway", self.gateway.collect()?);
        insert_into_config_map(&mut map, "store", self.store.collect()?);
        insert_into_config_map(&mut map, "p2p", self.p2p.collect()?);
        insert_into_config_map(&mut map, "rpc_client", self.rpc_client.collect()?);
        insert_into_config_map(&mut map, "metrics", self.metrics.collect()?);
        #[cfg(feature = "uds-gateway")]
        if let Some(uds_path) = self.gateway_uds_path.as_ref() {
            insert_into_config_map(
                &mut map,
                "gateway_uds_path",
                uds_path.to_str().unwrap().to_string(),
            );
        }
        if let Some(resolver_gateway) = &self.resolver_gateway {
            insert_into_config_map(&mut map, "resolver_gateway", resolver_gateway.clone());
        }

        Ok(map)
    }
}

impl iroh_gateway::handlers::StateConfig for Config {
    fn rpc_client(&self) -> &iroh_rpc_client::Config {
        &self.rpc_client
    }

    fn public_url_base(&self) -> &str {
        &self.gateway.public_url_base
    }

    fn port(&self) -> u16 {
        self.gateway.port
    }

    fn user_headers(&self) -> &HeaderMap<HeaderValue> {
        &self.gateway.headers
    }
}
