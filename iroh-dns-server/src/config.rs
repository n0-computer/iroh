//! Configuration for the server

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use crate::{
    dns::DnsConfig,
    http::{CertMode, HttpConfig, HttpsConfig},
};

const DEFAULT_METRICS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9117);

/// Server configuration
///
/// The config is usually loaded from a file with [`Self::load`].
///
/// The struct also implements [`Default`] which creates a config suitable for local development
/// and testing.
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Config for the HTTP server
    ///
    /// If set to `None` no HTTP server will be started.
    pub http: Option<HttpConfig>,
    /// Config for the HTTPS server
    ///
    /// If set to `None` no HTTPS server will be started.
    pub https: Option<HttpsConfig>,
    /// Config for the DNS server.
    pub dns: DnsConfig,
    /// Config for the metrics server.
    ///
    /// The metrics server is started by default. To disable the metrics server, set to
    /// `Some(MetricsConfig::disabled())`.
    pub metrics: Option<MetricsConfig>,
}

/// The config for the metrics server.
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Set to true to disable the metrics server.
    pub disabled: bool,
    /// Optionally set a custom address to bind to.
    pub bind_addr: Option<SocketAddr>,
}

impl MetricsConfig {
    /// Disable the metrics server.
    pub fn disabled() -> Self {
        Self {
            disabled: true,
            bind_addr: None,
        }
    }
}

impl Config {
    /// Load the config from a file.
    pub async fn load(path: impl AsRef<Path>) -> Result<Config> {
        let s = tokio::fs::read_to_string(path.as_ref())
            .await
            .with_context(|| format!("failed to read {}", path.as_ref().to_string_lossy()))?;
        let config: Config = toml::from_str(&s)?;
        Ok(config)
    }

    /// Get the data directory.
    pub fn data_dir() -> Result<PathBuf> {
        let dir = if let Some(val) = env::var_os("IROH_DNS_DATA_DIR") {
            PathBuf::from(val)
        } else {
            let path = dirs_next::data_dir().ok_or_else(|| {
                anyhow!("operating environment provides no directory for application data")
            })?;
            path.join("iroh-dns")
        };
        Ok(dir)
    }

    /// Get the path to the store database file.
    pub fn signed_packet_store_path() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("signed-packets-1.db"))
    }

    /// Get the address where the metrics server should be bound, if set.
    pub(crate) fn metrics_addr(&self) -> Option<SocketAddr> {
        match &self.metrics {
            None => Some(DEFAULT_METRICS_ADDR),
            Some(conf) => match conf.disabled {
                true => None,
                false => Some(conf.bind_addr.unwrap_or(DEFAULT_METRICS_ADDR)),
            },
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http: Some(HttpConfig {
                port: 8080,
                bind_addr: None,
            }),
            https: Some(HttpsConfig {
                port: 8443,
                bind_addr: None,
                domains: vec!["localhost".to_string()],
                cert_mode: CertMode::SelfSigned,
                letsencrypt_contact: None,
                letsencrypt_prod: None,
            }),
            dns: DnsConfig {
                port: 5300,
                bind_addr: None,
                origins: vec!["irohdns.example.".to_string(), ".".to_string()],

                default_soa: "irohdns.example hostmaster.irohdns.example 0 10800 3600 604800 3600"
                    .to_string(),
                default_ttl: 900,

                rr_a: Some(Ipv4Addr::LOCALHOST),
                rr_aaaa: None,
                rr_ns: Some("ns1.irohdns.example.".to_string()),
            },
            metrics: None,
        }
    }
}
