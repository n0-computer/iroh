//! Configuration for the [`Server`].
//!
//! The top-level [`Config`] struct composes all sub-configs that the server needs.
//! It is typically deserialized from a TOML file with [`Config::load`], but can also
//! be constructed in code (for tests or embedding).
//!
//! [`Server`]: crate::Server

use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use n0_error::{Result, StdResultExt};
use serde::{Deserialize, Serialize};
use tracing::info;

pub use crate::{
    dns::DnsConfig,
    http::{CertMode, HttpConfig, HttpsConfig, RateLimitConfig},
    store::ZoneStoreConfig,
};

const DEFAULT_METRICS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9117);

/// Top-level configuration for the server.
///
/// Groups all sub-configs needed to run the server: DNS listener, HTTP(S)
/// listeners, metrics endpoint, signed-packet store, mainline DHT fallback, and
/// data directory.
///
/// Typically loaded from a TOML file with [`Self::load`]. The [`Default`] impl
/// produces a config suitable for local development and testing: self-signed TLS
/// on `localhost`, DNS on port 5300, HTTP on 8080, and HTTPS on 8443.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Config {
    /// Configuration for the HTTP listener.
    ///
    /// When `None`, no HTTP listener is started.
    pub http: Option<HttpConfig>,
    /// Configuration for the HTTPS listener.
    ///
    /// When `None`, no HTTPS listener is started.
    pub https: Option<HttpsConfig>,
    /// Configuration for the DNS listener.
    pub dns: DnsConfig,
    /// Configuration for the metrics server.
    ///
    /// The metrics server exposes [Prometheus]-format counters for all
    /// [`Metrics`](crate::Metrics) fields (DNS requests, pkarr publishes, store
    /// inserts and evictions, HTTP request counts and latencies) over a plain
    /// HTTP endpoint, intended to be scraped by a Prometheus-compatible collector.
    ///
    /// When `None`, the metrics server binds to the default address
    /// `127.0.0.1:9117`. To disable the metrics server entirely, set this to
    /// `Some(MetricsConfig::disabled())`.
    ///
    /// [Prometheus]: https://prometheus.io/docs/instrumenting/exposition_formats/
    pub metrics: Option<MetricsConfig>,

    /// Configuration for the mainline DHT fallback.
    ///
    /// When `None` or disabled, packets that are not present in the local store
    /// are not looked up on the mainline DHT.
    pub mainline: Option<MainlineConfig>,

    /// Configuration for the signed-packet zone store.
    ///
    /// Controls write-batching and eviction; see [`ZoneStoreConfig`]. When
    /// `None`, the defaults are used.
    pub zone_store: Option<ZoneStoreConfig>,

    /// Rate limit applied to `PUT /pkarr` requests.
    #[serde(default)]
    pub pkarr_put_rate_limit: RateLimitConfig,

    /// Location where the server stores all its data.
    ///
    /// Consumed by [`Self::data_dir`], which also falls back to the
    /// `IROH_DNS_DATA_DIR` environment variable and the platform's standard data
    /// directory when this field is unset.
    pub data_dir: Option<PathBuf>,
}

/// Configuration for the metrics server.
///
/// The metrics server exposes [Prometheus]-format counters for the server's
/// [`Metrics`](crate::Metrics) over a plain HTTP endpoint. It is intended to be
/// scraped by a Prometheus-compatible collector and carries no authentication,
/// so the bind address should be kept on a trusted network. The default address
/// binds to loopback.
///
/// [Prometheus]: https://prometheus.io/docs/instrumenting/exposition_formats/
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Disables the metrics server when set to `true`.
    pub disabled: bool,
    /// Address to bind the metrics server to.
    ///
    /// When `None` and the server is enabled, binds to `127.0.0.1:9117`.
    pub bind_addr: Option<SocketAddr>,
}

impl MetricsConfig {
    /// Returns a [`MetricsConfig`] with the metrics server disabled.
    pub fn disabled() -> Self {
        Self {
            disabled: true,
            bind_addr: None,
        }
    }
}

/// Configuration for the mainline DHT fallback.
///
/// When enabled, the server looks up signed packets on the BitTorrent mainline
/// DHT for keys that are not present in the local store.
#[derive(Debug, Serialize, Deserialize)]
pub struct MainlineConfig {
    /// Enables the mainline DHT fallback when set to `true`.
    pub enabled: bool,
    /// Custom bootstrap nodes for the mainline DHT.
    ///
    /// Addresses must be formatted as `domain:port` or `ipv4:port`. When `None`
    /// or empty, the default BitTorrent mainline bootstrap nodes defined by
    /// pkarr are used.
    pub bootstrap: Option<Vec<String>>,
}

/// Selects the bootstrap nodes used for mainline DHT resolution.
///
/// Typically derived from [`MainlineConfig`] rather than constructed directly.
#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) enum BootstrapOption {
    /// Uses the default bootstrap nodes defined by pkarr.
    #[default]
    Default,
    /// Uses a custom set of bootstrap addresses (`domain:port` or `ipv4:port`).
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
    /// Loads a [`Config`] from a TOML file at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, or if its contents do not
    /// parse as TOML matching the [`Config`] schema.
    pub async fn load(path: impl AsRef<Path>) -> Result<Config> {
        info!(
            "loading config file from {}",
            path.as_ref().to_string_lossy()
        );
        let s = tokio::fs::read_to_string(path.as_ref())
            .await
            .with_std_context(|_| format!("failed to read {}", path.as_ref().to_string_lossy()))?;
        let config: Config = toml::from_str(&s).anyerr()?;
        Ok(config)
    }

    /// Returns the data directory where the server stores its state.
    ///
    /// Resolution order:
    /// 1. The [`Self::data_dir`] field, if set.
    /// 2. The `IROH_DNS_DATA_DIR` environment variable.
    /// 3. An `iroh-dns` subdirectory of the platform's standard data directory,
    ///    as reported by `dirs_next::data_dir`.
    ///
    /// # Errors
    ///
    /// Returns an error only when falling back to the platform data directory and
    /// the platform does not expose one.
    pub fn data_dir(&self) -> Result<PathBuf> {
        let dir = if let Some(dir) = &self.data_dir {
            dir.clone()
        } else if let Some(val) = env::var_os("IROH_DNS_DATA_DIR") {
            PathBuf::from(val)
        } else {
            let path = dirs_next::data_dir()
                .std_context("operating environment provides no directory for application data")?;

            path.join("iroh-dns")
        };
        Ok(dir)
    }

    /// Returns the path to the signed-packet store database file.
    ///
    /// The path is `<data_dir>/signed-packets-1.db`, where `<data_dir>` is
    /// resolved by [`Self::data_dir`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::data_dir`].
    pub fn signed_packet_store_path(&self) -> Result<PathBuf> {
        Ok(self.data_dir()?.join("signed-packets-1.db"))
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
            data_dir: None,
        }
    }
}
