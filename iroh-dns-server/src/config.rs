//! Configuration for the server

use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use n0_snafu::{Result, ResultExt};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    dns::DnsConfig,
    http::{CertMode, HttpConfig, HttpsConfig, RateLimitConfig},
    store::ZoneStoreOptions,
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

    /// Config for the mainline lookup.
    pub mainline: Option<MainlineConfig>,

    /// Config for the zone store.
    pub zone_store: Option<StoreConfig>,

    /// Config for pkarr rate limit
    #[serde(default)]
    pub pkarr_put_rate_limit: RateLimitConfig,
}

/// The config for the store.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoreConfig {
    /// Maximum number of packets to process in a single write transaction.
    max_batch_size: usize,

    /// Maximum time to keep a write transaction open.
    #[serde(with = "humantime_serde")]
    max_batch_time: Duration,

    /// Time to keep packets in the store before eviction.
    #[serde(with = "humantime_serde")]
    eviction: Duration,

    /// Pause between eviction checks.
    #[serde(with = "humantime_serde")]
    eviction_interval: Duration,
}

impl Default for StoreConfig {
    fn default() -> Self {
        ZoneStoreOptions::default().into()
    }
}

impl From<ZoneStoreOptions> for StoreConfig {
    fn from(value: ZoneStoreOptions) -> Self {
        Self {
            max_batch_size: value.max_batch_size,
            max_batch_time: value.max_batch_time,
            eviction: value.eviction,
            eviction_interval: value.eviction_interval,
        }
    }
}

impl From<StoreConfig> for ZoneStoreOptions {
    fn from(value: StoreConfig) -> Self {
        Self {
            max_batch_size: value.max_batch_size,
            max_batch_time: value.max_batch_time,
            eviction: value.eviction,
            eviction_interval: value.eviction_interval,
        }
    }
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

/// The config for the metrics server.
#[derive(Debug, Serialize, Deserialize)]
pub struct MainlineConfig {
    /// Set to true to enable the mainline lookup.
    pub enabled: bool,
    /// Set custom bootstrap nodes.
    ///
    /// Addresses can either be `domain:port` or `ipv4:port`.
    ///
    /// If empty this will use the default bittorrent mainline bootstrap nodes as defined by pkarr.
    pub bootstrap: Option<Vec<String>>,
}

/// Configure the bootstrap servers for mainline DHT resolution.
#[derive(Debug, Serialize, Deserialize, Default)]
pub enum BootstrapOption {
    /// Use the default bootstrap servers.
    #[default]
    Default,
    /// Use custom bootstrap servers.
    Custom(Vec<String>),
}

#[allow(clippy::derivable_impls)]
impl Default for MainlineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bootstrap: None,
        }
    }
}

impl Config {
    /// Load the config from a file.
    pub async fn load(path: impl AsRef<Path>) -> Result<Config> {
        info!(
            "loading config file from {}",
            path.as_ref().to_string_lossy()
        );
        let s = tokio::fs::read_to_string(path.as_ref())
            .await
            .with_context(|| format!("failed to read {}", path.as_ref().to_string_lossy()))?;
        let config: Config = toml::from_str(&s).e()?;
        Ok(config)
    }

    /// Get the data directory.
    pub fn data_dir() -> Result<PathBuf> {
        let dir = if let Some(val) = env::var_os("IROH_DNS_DATA_DIR") {
            PathBuf::from(val)
        } else {
            let path = dirs_next::data_dir()
                .context("operating environment provides no directory for application data")?;

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

    pub(crate) fn mainline_enabled(&self) -> Option<BootstrapOption> {
        match self.mainline.as_ref() {
            None => None,
            Some(MainlineConfig { enabled: false, .. }) => None,
            Some(MainlineConfig {
                bootstrap: Some(bootstrap),
                ..
            }) => Some(BootstrapOption::Custom(bootstrap.clone())),
            Some(MainlineConfig {
                bootstrap: None, ..
            }) => Some(BootstrapOption::Default),
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
            zone_store: None,
            metrics: None,
            mainline: None,
            pkarr_put_rate_limit: RateLimitConfig::default(),
        }
    }
}
