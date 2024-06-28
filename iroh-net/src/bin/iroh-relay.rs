//! A simple relay server for iroh-net.
//!
//! This handles only the CLI and config file loading, the server implementation lives in
//! [`iroh_net::relay::iroh_relay`].

use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::Parser;
use iroh_net::defaults::{
    DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT, DEFAULT_METRICS_PORT, DEFAULT_STUN_PORT,
};
use iroh_net::key::SecretKey;
use iroh_net::relay::iroh_relay;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use tokio_rustls_acme::{caches::DirCache, AcmeConfig};
use tracing::{debug, info};
use tracing_subscriber::{prelude::*, EnvFilter};

/// The default `http_bind_port` when using `--dev`.
const DEV_MODE_HTTP_PORT: u16 = 3340;

/// A relay server for iroh-net.
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
}

fn load_certs(filename: impl AsRef<Path>) -> Result<Vec<rustls::Certificate>> {
    let certfile = std::fs::File::open(filename).context("cannot open certificate file")?;
    let mut reader = std::io::BufReader::new(certfile);

    let certs = rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();

    Ok(certs)
}

fn load_secret_key(filename: impl AsRef<Path>) -> Result<rustls::PrivateKey> {
    let keyfile = std::fs::File::open(filename.as_ref()).context("cannot open secret key file")?;
    let mut reader = std::io::BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).context("cannot parse secret key .pem file")? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    bail!(
        "no keys found in {} (encrypted keys not supported)",
        filename.as_ref().display()
    );
}

/// Configuration for the relay-server.
///
/// This is (de)serialised to/from a TOML config file.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    /// The iroh [`SecretKey`] for this relay server.
    ///
    /// If not specified a new key will be generated and the config file will be re-written
    /// using it.
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "SecretKey::generate")]
    secret_key: SecretKey,
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
    /// When running with `--dev` defaults to [::]:3340`.  If specified overrides these
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
    /// If disabled all services will run on plain HTTP.  The `--dev` option disables this,
    /// regardless of what is in the configuration file.
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
            secret_key: SecretKey::generate(),
            enable_relay: true,
            http_bind_addr: None,
            tls: None,
            enable_stun: true,
            stun_bind_addr: None,
            limits: None,
            enable_metrics: true,
            metrics_bind_addr: None,
        }
    }
}

/// Defaults for fields from [`Config`].
///
/// These are the defaults that serde will fill in.  Other defaults depends on each other
/// and can not immediately be substituded by serde.
mod cfg_defaults {
    pub(crate) fn enable_relay() -> bool {
        true
    }

    pub(crate) fn enable_stun() -> bool {
        true
    }

    pub(crate) fn enable_metrics() -> bool {
        true
    }

    pub(crate) mod tls_config {
        pub(crate) fn prod_tls() -> bool {
            true
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsConfig {
    /// The socket address to bind the Relay HTTPS server on.
    ///
    /// Defaults to the `http_bind_addr` with the port set to `443`.
    https_bind_addr: Option<SocketAddr>,
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
}

impl TlsConfig {
    fn https_bind_addr(&self, cfg: &Config) -> SocketAddr {
        self.https_bind_addr
            .unwrap_or_else(|| SocketAddr::new(cfg.http_bind_addr().ip(), DEFAULT_HTTPS_PORT))
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
            let config = Config::default();
            config.write_to_file(&config_path).await?;

            Ok(config)
        }
    }

    async fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        if !path.as_ref().is_file() {
            bail!("config-path must be a file");
        }
        let config_ser = tokio::fs::read_to_string(&path)
            .await
            .context("unable to read config")?;
        let config: Self = toml::from_str(&config_ser).context("config file must be valid toml")?;
        if !config_ser.contains("secret_key") {
            info!("generating new secret key and updating config file");
            config.write_to_file(path).await?;
        }

        Ok(config)
    }

    /// Write the content of this configuration to the provided path.
    async fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let p = path
            .as_ref()
            .parent()
            .ok_or_else(|| anyhow!("invalid config file path, no parent"))?;
        // TODO: correct permissions (0777 for dir, 0600 for file)
        tokio::fs::create_dir_all(p)
            .await
            .with_context(|| format!("unable to create config-path dir: {}", p.display()))?;
        let config_ser = toml::to_string(self).context("unable to serialize configuration")?;
        tokio::fs::write(path, config_ser)
            .await
            .context("unable to write config file")?;

        Ok(())
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
    if cli.dev {
        cfg.tls = None;
        if cfg.http_bind_addr.is_none() {
            cfg.http_bind_addr = Some((Ipv6Addr::UNSPECIFIED, DEV_MODE_HTTP_PORT).into());
        }
    }
    let relay_config = build_relay_config(cfg).await?;
    debug!("{relay_config:#?}");

    let mut relay = iroh_relay::Server::spawn(relay_config).await?;

    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => (),
        _ = relay.task_handle() => (),
    }

    relay.shutdown().await
}

/// Convert the TOML-loaded config to the [`iroh_relay::RelayConfig`] format.
async fn build_relay_config(cfg: Config) -> Result<iroh_relay::ServerConfig<std::io::Error>> {
    let tls = match cfg.tls {
        Some(ref tls) => {
            let cert_config = match tls.cert_mode {
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
                    iroh_relay::CertConfig::Manual { private_key, certs }
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
                    iroh_relay::CertConfig::LetsEncrypt { config }
                }
            };
            Some(iroh_relay::TlsConfig {
                https_bind_addr: tls.https_bind_addr(&cfg),
                cert: cert_config,
            })
        }
        None => None,
    };
    let limits = iroh_relay::Limits {
        accept_conn_limit: cfg
            .limits
            .as_ref()
            .map(|l| l.accept_conn_limit)
            .unwrap_or_default(),
        accept_conn_burst: cfg
            .limits
            .as_ref()
            .map(|l| l.accept_conn_burst)
            .unwrap_or_default(),
    };
    let relay_config = iroh_relay::RelayConfig {
        secret_key: cfg.secret_key.clone(),
        http_bind_addr: cfg.http_bind_addr(),
        tls,
        limits,
    };
    let stun_config = iroh_relay::StunConfig {
        bind_addr: cfg.stun_bind_addr(),
    };
    Ok(iroh_relay::ServerConfig {
        relay: Some(relay_config),
        stun: Some(stun_config),
        #[cfg(feature = "metrics")]
        metrics_addr: if cfg.enable_metrics {
            Some(cfg.metrics_bind_addr())
        } else {
            None
        },
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
