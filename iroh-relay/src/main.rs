//! The relay server for iroh.
//!
//! This handles only the CLI and config file loading, the server implementation lives in
//! [`iroh::relay::server`].

use std::{
    net::{Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context as _, Result};
use clap::Parser;
use iroh_base::NodeId;
use iroh_relay::{
    defaults::{
        DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT, DEFAULT_METRICS_PORT, DEFAULT_RELAY_QUIC_PORT,
        DEFAULT_STUN_PORT,
    },
    server::{self as relay, ClientRateLimit, QuicConfig},
};
use serde::{Deserialize, Serialize};
use tokio_rustls_acme::{caches::DirCache, AcmeConfig};
use tracing::debug;
use tracing_subscriber::{prelude::*, EnvFilter};

/// The default `http_bind_port` when using `--dev`.
const DEV_MODE_HTTP_PORT: u16 = 3340;

/// A relay server for iroh.
#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    /// Run in localhost development mode over plain HTTP.
    ///
    /// Defaults to running the relay server on port 3340.
    ///
    /// Running in dev mode will ignore any config file fields pertaining to TLS.
    #[clap(long, default_value_t = false)]
    dev: bool,
    /// Run in localhost development mode over plain HTTP and the QUIC endpoint for QUIC address discovery.
    ///
    /// Defaults to running the relay server on port 3340 and the QUIC endpoint over 7842.
    ///
    /// Running in dev-quic mode requires tls configuration for the QUIC endpoint. It will ignore
    /// any tls configuration for the relay.
    #[clap(long, default_value_t = false)]
    dev_quic: bool,
    /// Path to the configuration file.
    ///
    /// If provided and no configuration file exists the default configuration will be
    /// written to the file.
    #[clap(long, short)]
    config_path: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CertMode {
    Manual,
    LetsEncrypt,
    #[cfg(feature = "server")]
    Reloading,
}

fn load_certs(
    filename: impl AsRef<Path>,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let certfile = std::fs::File::open(filename).context("cannot open certificate file")?;
    let mut reader = std::io::BufReader::new(certfile);

    let certs: Result<Vec<_>, std::io::Error> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs?;

    Ok(certs)
}

fn load_secret_key(
    filename: impl AsRef<Path>,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let filename = filename.as_ref();
    let keyfile = std::fs::File::open(filename)
        .with_context(|| format!("cannot open secret key file {}", filename.display()))?;
    let mut reader = std::io::BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).context("cannot parse secret key .pem file")? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
            }
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Sec1(key));
            }
            None => break,
            _ => {}
        }
    }

    bail!(
        "no keys found in {} (encrypted keys not supported)",
        filename.display()
    );
}

/// Configuration for the relay-server.
///
/// This is (de)serialised to/from a TOML config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    /// Whether to enable the Relay server.
    ///
    /// Defaults to `true`.
    ///
    /// Disabling will leave only the STUN server.  The `http_bind_addr` and `tls`
    /// configuration options will be ignored.
    #[serde(default = "cfg_defaults::enable_relay")]
    enable_relay: bool,
    /// The socket address to bind the Relay HTTP server on.
    ///
    /// Defaults to `[::]:80`.
    ///
    /// When running with `--dev` defaults to `[::]:3340`.  If specified overrides these
    /// defaults.
    ///
    /// The Relay server always starts an HTTP server, this specifies the socket this will
    /// be bound on.  If there is no `tls` configuration set all the HTTP relay services
    /// will be bound on this socket.  Otherwise most Relay HTTP services will run on the
    /// `https_bind_addr` of the `tls` configuration section and only the captive portal
    /// will be served from the HTTP socket.
    http_bind_addr: Option<SocketAddr>,
    /// TLS specific configuration.
    ///
    /// TLS is disabled if not present and the Relay server will serve all services over
    /// plain HTTP.
    ///
    /// If disabled all services will run on plain HTTP.
    ///
    /// Must exist if `enable_quic_addr_discovery` is `true`.
    tls: Option<TlsConfig>,
    /// Whether to run a STUN server. It will bind to the same IP as the `addr` field.
    ///
    /// Defaults to `true`.
    #[serde(default = "cfg_defaults::enable_stun")]
    enable_stun: bool,
    /// The socket address to bind the STUN server on.
    ///
    /// Defaults to using the `http_bind_addr` with the port set to [`DEFAULT_STUN_PORT`].
    stun_bind_addr: Option<SocketAddr>,
    /// Whether to allow QUIC connections for QUIC address discovery
    ///
    /// If no `tls` is set, this will error.
    ///
    /// Defaults to `false`
    #[serde(default = "cfg_defaults::enable_quic_addr_discovery")]
    enable_quic_addr_discovery: bool,
    /// Rate limiting configuration.
    ///
    /// Disabled if not present.
    limits: Option<Limits>,
    /// Whether to run the metrics server.
    ///
    /// Defaults to `true`, when the metrics feature is enabled.
    #[serde(default = "cfg_defaults::enable_metrics")]
    enable_metrics: bool,
    /// Metrics serve address.
    ///
    /// Defaults to `http_bind_addr` with the port set to [`DEFAULT_METRICS_PORT`]
    /// (`[::]:9090` when `http_bind_addr` is set to the default).
    metrics_bind_addr: Option<SocketAddr>,
    /// The capacity of the key cache.
    key_cache_capacity: Option<usize>,
    /// Access control
    #[serde(default)]
    access: AccessConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
enum AccessConfig {
    /// Allows everyone
    #[serde(rename = "everyone")]
    #[default]
    Everyone,
    /// Allows only these nodes.
    #[serde(rename = "allowlist")]
    Allowlist(Vec<NodeId>),
    /// Allows everyone, except these nodes.
    #[serde(rename = "denylist")]
    Denylist(Vec<NodeId>),
}

impl From<AccessConfig> for iroh_relay::server::AccessConfig {
    fn from(cfg: AccessConfig) -> Self {
        match cfg {
            AccessConfig::Everyone => iroh_relay::server::AccessConfig::Everyone,
            AccessConfig::Allowlist(allow_list) => {
                iroh_relay::server::AccessConfig::Restricted(Box::new(move |node_id| {
                    if allow_list.contains(&node_id) {
                        iroh_relay::server::Access::Allow
                    } else {
                        iroh_relay::server::Access::Deny
                    }
                }))
            }
            AccessConfig::Denylist(deny_list) => {
                iroh_relay::server::AccessConfig::Restricted(Box::new(move |node_id| {
                    if deny_list.contains(&node_id) {
                        iroh_relay::server::Access::Deny
                    } else {
                        iroh_relay::server::Access::Allow
                    }
                }))
            }
        }
    }
}

impl Config {
    fn http_bind_addr(&self) -> SocketAddr {
        self.http_bind_addr
            .unwrap_or((Ipv6Addr::UNSPECIFIED, DEFAULT_HTTP_PORT).into())
    }

    fn stun_bind_addr(&self) -> SocketAddr {
        self.stun_bind_addr
            .unwrap_or_else(|| SocketAddr::new(self.http_bind_addr().ip(), DEFAULT_STUN_PORT))
    }

    fn metrics_bind_addr(&self) -> SocketAddr {
        self.metrics_bind_addr
            .unwrap_or_else(|| SocketAddr::new(self.http_bind_addr().ip(), DEFAULT_METRICS_PORT))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_relay: cfg_defaults::enable_relay(),
            http_bind_addr: None,
            tls: None,
            enable_stun: cfg_defaults::enable_stun(),
            stun_bind_addr: None,
            enable_quic_addr_discovery: cfg_defaults::enable_quic_addr_discovery(),
            limits: None,
            enable_metrics: cfg_defaults::enable_metrics(),
            metrics_bind_addr: None,
            key_cache_capacity: Default::default(),
            access: AccessConfig::Everyone,
        }
    }
}

/// Defaults for fields from [`Config`] [`TlsConfig`].
///
/// These are the defaults that serde will fill in.  Other defaults depends on each other
/// and can not immediately be substituted by serde.
mod cfg_defaults {
    pub(crate) fn enable_relay() -> bool {
        true
    }

    pub(crate) fn enable_stun() -> bool {
        true
    }

    pub(crate) fn enable_quic_addr_discovery() -> bool {
        false
    }

    pub(crate) fn enable_metrics() -> bool {
        true
    }

    pub(crate) mod tls_config {
        pub(crate) fn prod_tls() -> bool {
            true
        }

        pub(crate) fn dangerous_http_only() -> bool {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsConfig {
    /// The socket address to bind the Relay HTTPS server on.
    ///
    /// Defaults to the `http_bind_addr` with the port set to `443`.
    https_bind_addr: Option<SocketAddr>,
    /// The socket address to bind the QUIC server one.
    ///
    /// Defaults to the `https_bind_addr` with the port set to [`iroh_relay::defaults::DEFAULT_RELAY_QUIC_PORT`].
    ///
    /// If `https_bind_addr` is not set, defaults to `http_bind_addr` with the
    /// port set to [`iroh_relay::defaults::DEFAULT_RELAY_QUIC_PORT`]
    quic_bind_addr: Option<SocketAddr>,
    /// Certificate hostname when using LetsEncrypt.
    hostname: Option<String>,
    /// Mode for getting a cert.
    ///
    /// Possible options: 'Manual', 'LetsEncrypt'.
    cert_mode: CertMode,
    /// Directory to store LetsEncrypt certs or read manual certificates from.
    ///
    /// Defaults to the servers' current working directory.
    cert_dir: Option<PathBuf>,
    /// Path of where to read the certificate from for the `Manual` `cert_mode`.
    ///
    /// Defaults to `<cert_dir>/default.crt`.
    ///
    /// Only used when `cert_mode` is `Manual`.
    manual_cert_path: Option<PathBuf>,
    /// Path of where to read the private key from for the `Manual` `cert_mode`.
    ///
    /// Defaults to `<cert_dir>/default.key`.
    ///
    /// Only used when `cert_mode` is `Manual`.
    manual_key_path: Option<PathBuf>,
    /// Whether to use the LetsEncrypt production or staging server.
    ///
    /// Default is `true`.
    ///
    /// Only used when `cert_mode` is `LetsEncrypt`.
    ///
    /// While in development, LetsEncrypt prefers you to use the staging server. However,
    /// the staging server seems to only use `ECDSA` keys. In their current set up, you can
    /// only get intermediate certificates for `ECDSA` keys if you are on their
    /// "allowlist". The production server uses `RSA` keys, which allow for issuing
    /// intermediate certificates in all normal circumstances.  So, to have valid
    /// certificates, we must use the LetsEncrypt production server.  Read more here:
    /// <https://letsencrypt.org/certificates/#intermediate-certificates>.
    #[serde(default = "cfg_defaults::tls_config::prod_tls")]
    prod_tls: bool,
    /// The contact email for the tls certificate.
    ///
    /// Used when `cert_mode` is `LetsEncrypt`.
    contact: Option<String>,
    /// **This field should never be manually set**
    ///
    /// When `true`, it will force the relay to ignore binding to https. It is only
    /// ever used internally when the `--dev` flag is used on the CLI.
    ///
    /// Default is `false`.
    #[serde(default = "cfg_defaults::tls_config::dangerous_http_only")]
    dangerous_http_only: bool,
}

impl TlsConfig {
    fn https_bind_addr(&self, cfg: &Config) -> SocketAddr {
        self.https_bind_addr
            .unwrap_or_else(|| SocketAddr::new(cfg.http_bind_addr().ip(), DEFAULT_HTTPS_PORT))
    }

    fn quic_bind_addr(&self, cfg: &Config) -> SocketAddr {
        self.quic_bind_addr.unwrap_or_else(|| {
            SocketAddr::new(self.https_bind_addr(cfg).ip(), DEFAULT_RELAY_QUIC_PORT)
        })
    }

    fn cert_dir(&self) -> PathBuf {
        self.cert_dir.clone().unwrap_or_else(|| PathBuf::from("."))
    }

    fn cert_path(&self) -> PathBuf {
        self.manual_cert_path
            .clone()
            .unwrap_or_else(|| self.cert_dir().join("default.crt"))
    }

    fn key_path(&self) -> PathBuf {
        self.manual_key_path
            .clone()
            .unwrap_or_else(|| self.cert_dir().join("default.key"))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Limits {
    /// Rate limit for accepting new connection. Unlimited if not set.
    accept_conn_limit: Option<f64>,
    /// Burst limit for accepting new connection. Unlimited if not set.
    accept_conn_burst: Option<usize>,
    /// Rate limiting configuration per client.
    client: Option<PerClientRateLimitConfig>,
}

/// Rate limit configuration for each connected client.
///
/// The rate limiting uses a token-bucket style algorithm:
///
/// - The base rate limit uses a steady-stream rate of bytes allowed.
/// - Additionally a burst quota allows sending bytes over this steady-stream rate
///   limit, as long as the maximum burst quota is not exceeded.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PerClientRateLimitConfig {
    /// Rate limit configuration for the incoming data from the client.
    rx: Option<RateLimitConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RateLimitConfig {
    /// Maximum number of bytes per second.
    bytes_per_second: Option<u32>,
    /// Maximum number of bytes to read in a single burst.
    max_burst_bytes: Option<u32>,
}

impl Config {
    async fn load(opts: &Cli) -> Result<Self> {
        let config_path = if let Some(config_path) = &opts.config_path {
            config_path
        } else {
            return Ok(Config::default());
        };

        if config_path.exists() {
            Self::read_from_file(&config_path).await
        } else {
            Ok(Config::default())
        }
    }

    fn from_str(config: &str) -> Result<Self> {
        toml::from_str(config).context("config must be valid toml")
    }

    async fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        if !path.as_ref().is_file() {
            bail!("config-path must be a file");
        }
        let config_ser = tokio::fs::read_to_string(&path)
            .await
            .context("unable to read config")?;
        Self::from_str(&config_ser)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let mut cfg = Config::load(&cli).await?;
    if cfg.enable_quic_addr_discovery && cfg.tls.is_none() {
        bail!("TLS must be configured in order to spawn a QUIC endpoint");
    }
    if cli.dev {
        // When in `--dev` mode, do not use https, even when tls is configured.
        if let Some(ref mut tls) = cfg.tls {
            tls.dangerous_http_only = true;
        }
        if cfg.http_bind_addr.is_none() {
            cfg.http_bind_addr = Some((Ipv6Addr::UNSPECIFIED, DEV_MODE_HTTP_PORT).into());
        }
    }
    if cfg.tls.is_none() && cfg.enable_quic_addr_discovery {
        bail!("If QUIC address discovery is enabled, TLS must also be configured");
    };
    let relay_config = build_relay_config(cfg).await?;
    debug!("{relay_config:#?}");

    let mut relay = relay::Server::spawn(relay_config).await?;

    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => (),
        _ = relay.task_handle() => (),
    }

    relay.shutdown().await
}

async fn maybe_load_tls(
    cfg: &Config,
) -> Result<Option<relay::TlsConfig<std::io::Error, std::io::Error>>> {
    let Some(ref tls) = cfg.tls else {
        return Ok(None);
    };
    let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocols supported by ring")
    .with_no_client_auth();
    let (cert_config, server_config) = match tls.cert_mode {
        CertMode::Manual => {
            let cert_path = tls.cert_path();
            let key_path = tls.key_path();
            // Could probably just do this blocking, we're only starting up.
            let (private_key, certs) = tokio::task::spawn_blocking(move || {
                let key = load_secret_key(key_path)?;
                let certs = load_certs(cert_path)?;
                anyhow::Ok((key, certs))
            })
            .await??;
            let server_config = server_config.with_single_cert(certs.clone(), private_key)?;
            (relay::CertConfig::Manual { certs }, server_config)
        }
        CertMode::LetsEncrypt => {
            let hostname = tls
                .hostname
                .clone()
                .context("LetsEncrypt needs a hostname")?;
            let contact = tls
                .contact
                .clone()
                .context("LetsEncrypt needs a contact email")?;
            let config = AcmeConfig::new(vec![hostname.clone()])
                .contact([format!("mailto:{}", contact)])
                .cache_option(Some(DirCache::new(tls.cert_dir())))
                .directory_lets_encrypt(tls.prod_tls);
            let state = config.state();
            let resolver = state.resolver().clone();
            let server_config = server_config.with_cert_resolver(resolver);
            (relay::CertConfig::LetsEncrypt { state }, server_config)
        }
        #[cfg(feature = "server")]
        CertMode::Reloading => {
            use rustls_cert_file_reader::FileReader;
            use rustls_cert_reloadable_resolver::{key_provider::Dyn, CertifiedKeyLoader};
            use webpki::types::{CertificateDer, PrivateKeyDer};

            let cert_path = tls.cert_path();
            let key_path = tls.key_path();
            let interval = relay::DEFAULT_CERT_RELOAD_INTERVAL;

            let key_reader = rustls_cert_file_reader::FileReader::new(
                key_path,
                rustls_cert_file_reader::Format::DER,
            );
            let certs_reader = rustls_cert_file_reader::FileReader::new(
                cert_path,
                rustls_cert_file_reader::Format::DER,
            );

            let loader: CertifiedKeyLoader<
                Dyn,
                FileReader<PrivateKeyDer<'_>>,
                FileReader<Vec<CertificateDer<'_>>>,
            > = CertifiedKeyLoader {
                key_provider: Dyn(server_config.crypto_provider().key_provider),
                key_reader,
                certs_reader,
            };

            let resolver = Arc::new(relay::ReloadingResolver::init(loader, interval).await?);
            let server_config = server_config.with_cert_resolver(resolver);
            (relay::CertConfig::Reloading, server_config)
        }
    };
    Ok(Some(relay::TlsConfig {
        https_bind_addr: tls.https_bind_addr(cfg),
        cert: cert_config,
        server_config,
        quic_bind_addr: tls.quic_bind_addr(cfg),
    }))
}

/// Convert the TOML-loaded config to the [`relay::RelayConfig`] format.
async fn build_relay_config(cfg: Config) -> Result<relay::ServerConfig<std::io::Error>> {
    // Don't bind to https, even if tls configuration is available.
    // Is really only relevant if we are in `--dev` mode & we also have TLS configuration
    // enabled to use QUIC address discovery locally.
    let dangerous_http_only = cfg.tls.as_ref().is_some_and(|tls| tls.dangerous_http_only);
    let relay_tls = maybe_load_tls(&cfg).await?;

    let mut quic_config = None;
    if cfg.enable_quic_addr_discovery {
        if let Some(ref tls) = relay_tls {
            quic_config = Some(QuicConfig {
                server_config: tls.server_config.clone(),
                bind_addr: tls.quic_bind_addr,
            });
        } else {
            bail!("Must have a valid TLS configuration to enable a QUIC server for QUIC address discovery")
        }
    };
    let limits = match cfg.limits {
        Some(ref limits) => {
            let client_rx = match &limits.client {
                Some(PerClientRateLimitConfig { rx: Some(rx) }) => {
                    if rx.bytes_per_second.is_none() && rx.max_burst_bytes.is_some() {
                        bail!("bytes_per_seconds must be specified to enable the rate-limiter");
                    }
                    match rx.bytes_per_second {
                        Some(bps) => Some(ClientRateLimit {
                            bytes_per_second: bps
                                .try_into()
                                .context("bytes_per_second must be non-zero u32")?,
                            max_burst_bytes: rx
                                .max_burst_bytes
                                .map(|v| {
                                    v.try_into().context("max_burst_bytes must be non-zero u32")
                                })
                                .transpose()?,
                        }),
                        None => None,
                    }
                }
                Some(PerClientRateLimitConfig { rx: None }) | None => None,
            };
            relay::Limits {
                accept_conn_limit: limits.accept_conn_limit,
                accept_conn_burst: limits.accept_conn_burst,
                client_rx,
            }
        }
        None => Default::default(),
    };

    let relay_config = relay::RelayConfig {
        http_bind_addr: cfg.http_bind_addr(),
        // if `dangerous_http_only` is set, do not pass in any tls configuration
        tls: relay_tls.and_then(|tls| if dangerous_http_only { None } else { Some(tls) }),
        limits,
        key_cache_capacity: cfg.key_cache_capacity,
        access: cfg.access.clone().into(),
    };

    let stun_config = relay::StunConfig {
        bind_addr: cfg.stun_bind_addr(),
    };
    Ok(relay::ServerConfig {
        relay: Some(relay_config),
        stun: Some(stun_config).filter(|_| cfg.enable_stun),
        quic: quic_config,
        #[cfg(feature = "metrics")]
        metrics_addr: Some(cfg.metrics_bind_addr()).filter(|_| cfg.enable_metrics),
    })
}

mod metrics {
    use iroh_metrics::{
        core::{Counter, Metric},
        struct_iterable::Iterable,
    };

    /// StunMetrics tracked for the relay server
    #[allow(missing_docs)]
    #[derive(Debug, Clone, Iterable)]
    pub struct StunMetrics {
        /*
         * Metrics about STUN requests over ipv6
         */
        /// Number of stun requests made
        pub requests: Counter,
        /// Number of successful requests over ipv4
        pub ipv4_success: Counter,
        /// Number of successful requests over ipv6
        pub ipv6_success: Counter,

        /// Number of bad requests, either non-stun packets or incorrect binding request
        pub bad_requests: Counter,
        /// Number of failures
        pub failures: Counter,
    }

    impl Default for StunMetrics {
        fn default() -> Self {
            Self {
                /*
                 * Metrics about STUN requests
                 */
                requests: Counter::new("Number of STUN requests made to the server."),
                ipv4_success: Counter::new("Number of successful ipv4 STUN requests served."),
                ipv6_success: Counter::new("Number of successful ipv6 STUN requests served."),
                bad_requests: Counter::new("Number of bad requests made to the STUN endpoint."),
                failures: Counter::new("Number of STUN requests that end in failure."),
            }
        }
    }

    impl Metric for StunMetrics {
        fn name() -> &'static str {
            "stun"
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use testresult::TestResult;

    use super::*;

    #[tokio::test]
    async fn test_rate_limit_config() -> TestResult {
        let config = "
            [limits.client.rx]
            bytes_per_second = 400
            max_burst_bytes = 800
        ";
        let config = Config::from_str(config)?;
        let relay_config = build_relay_config(config).await?;

        let relay = relay_config.relay.expect("no relay config");
        assert_eq!(
            relay.limits.client_rx.expect("ratelimit").bytes_per_second,
            NonZeroU32::try_from(400).unwrap()
        );
        assert_eq!(
            relay.limits.client_rx.expect("ratelimit").max_burst_bytes,
            Some(NonZeroU32::try_from(800).unwrap())
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limit_default() -> TestResult {
        let config = Config::from_str("")?;
        let relay_config = build_relay_config(config).await?;

        let relay = relay_config.relay.expect("no relay config");
        assert!(relay.limits.client_rx.is_none());

        Ok(())
    }
}
