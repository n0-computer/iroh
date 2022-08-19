use anyhow::{bail, Result};
use axum::http::{header::*};
use config::{ConfigError, Map, Source, Value};

use iroh_metrics::config::Config as MetricsConfig;
use iroh_p2p::{Libp2pConfig};
use iroh_rpc_client::Config as RpcClientConfig;
use iroh_rpc_types::{gateway::GatewayServerAddr, Addr};
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    // Gateway specific configuration.
    pub gateway: iroh_gateway::config::Config,
    // Store specific configuration.
    pub store: iroh_store::config::Config,
    // P2P specific configuration.
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
    ) -> Self {
        Self {
            gateway,
            store,
            p2p,
            rpc_client,
            metrics: MetricsConfig::default(),
        }
    }

    /// Derive server addr for non memory addrs.
    pub fn server_rpc_addr(&self) -> Result<Option<GatewayServerAddr>> {
        self.rpc_client
            .gateway_addr
            .as_ref()
            .map(|addr| {
                #[allow(unreachable_patterns)]
                match addr {
                    #[cfg(feature = "rpc-grpc")]
                    Addr::GrpcHttp2(addr) => Ok(Addr::GrpcHttp2(*addr)),
                    #[cfg(all(feature = "rpc-grpc", unix))]
                    Addr::GrpcUds(path) => Ok(Addr::GrpcUds(path.clone())),
                    #[cfg(feature = "rpc-mem")]
                    Addr::Mem(_) => bail!("can not derive rpc_addr for mem addr"),
                    _ => bail!("invalid rpc_addr"),
                }
            })
            .transpose()
    }

    // When running in ipfsd mode, the resolver will use memory channels to
    // communicate with the p2p and store modules.
    // The gateway itself is exposing a UDS rpc endpoint to be also usable
    // as a single entry point for other system services.
    pub fn default_ipfsd() -> RpcClientConfig {
        let path = {
            #[cfg(target_os = "android")]
            {
                "/dev/socket/ipfsd".into()
            }

            #[cfg(not(target_os = "android"))]
            {
                let path = format!("{}", std::env::temp_dir().join("ipfsd.gateway").display());
                path.into()
            }
        };

        RpcClientConfig {
            gateway_addr: Some(Addr::GrpcUds(path)),
            p2p_addr: None,
            store_addr: None,
            raw_gateway: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let ipfsd = Self::default_ipfsd();
        let metrics_config = MetricsConfig::default();
        Self {
            rpc_client: ipfsd.clone(),
            metrics: metrics_config.clone(),
            gateway: iroh_gateway::config::Config::default(),
            store: default_store_config(ipfsd.clone(), metrics_config.clone()),
            p2p: default_p2p_config(ipfsd, metrics_config),
        }
    }
}

fn default_store_config(
    ipfsd: RpcClientConfig,
    metrics: iroh_metrics::config::Config,
) -> iroh_store::config::Config {
    iroh_store::config::Config {
        path: PathBuf::new(),
        rpc_client: ipfsd,
        metrics,
    }
}

fn default_p2p_config(
    ipfsd: RpcClientConfig,
    metrics: iroh_metrics::config::Config,
) -> iroh_p2p::config::Config {
    iroh_p2p::config::Config {
        libp2p: Libp2pConfig::default(),
        rpc_client: ipfsd,
        metrics,
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
        Ok(map)
    }
}

impl iroh_gateway::handlers::StateConfig for Config {
    fn rpc_client(&self) -> iroh_rpc_client::Config {
        self.rpc_client.clone()
    }

    fn port(&self) -> u16 {
        self.gateway.port
    }

    fn user_headers(&self) -> HeaderMap<HeaderValue> {
        self.gateway.headers.clone()
    }
}
