//! A simple relay server for iroh-net.
//!
//! Based on /tailscale/cmd/derper.

use std::{
    borrow::Cow,
    fmt,
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::Parser;
use futures_lite::StreamExt;
use http::{response::Builder as ResponseBuilder, HeaderMap};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use iroh_metrics::inc;
use iroh_net::defaults::{
    DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT, DEFAULT_METRICS_PORT, DEFAULT_STUN_PORT,
    NA_RELAY_HOSTNAME,
};
use iroh_net::key::SecretKey;
use iroh_net::relay::http::{
    ServerBuilder as RelayServerBuilder, TlsAcceptor, TlsConfig as RelayTlsConfig,
};
use iroh_net::relay::{self, iroh_relay};
use iroh_net::stun;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};
use tokio_rustls_acme::{caches::DirCache, AcmeConfig};
use tracing::{debug, debug_span, error, info, info_span, trace, warn, Instrument};
use tracing_subscriber::{prelude::*, EnvFilter};

use metrics::StunMetrics;

type BytesBody = http_body_util::Full<hyper::body::Bytes>;
type HyperError = Box<dyn std::error::Error + Send + Sync>;
type HyperResult<T> = std::result::Result<T, HyperError>;

/// The default `http_bind_port` when using `--dev`.
const DEV_MODE_HTTP_PORT: u16 = 3340;

/// Creates a new [`BytesBody`] with no content.
fn body_empty() -> BytesBody {
    http_body_util::Full::new(hyper::body::Bytes::new())
}

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

impl CertMode {
    async fn gen_server_config(
        &self,
        hostname: String,
        contact: String,
        is_production: bool,
        dir: PathBuf,
    ) -> Result<(Arc<rustls::ServerConfig>, TlsAcceptor)> {
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth();

        match self {
            CertMode::LetsEncrypt => {
                let mut state = AcmeConfig::new(vec![hostname])
                    .contact([format!("mailto:{contact}")])
                    .cache_option(Some(DirCache::new(dir)))
                    .directory_lets_encrypt(is_production)
                    .state();

                let config = config.with_cert_resolver(state.resolver());
                let acceptor = state.acceptor();

                tokio::spawn(
                    async move {
                        while let Some(event) = state.next().await {
                            match event {
                                Ok(ok) => debug!("acme event: {:?}", ok),
                                Err(err) => error!("error: {:?}", err),
                            }
                        }
                        debug!("event stream finished");
                    }
                    .instrument(info_span!("acme")),
                );

                Ok((Arc::new(config), TlsAcceptor::LetsEncrypt(acceptor)))
            }
            CertMode::Manual => {
                // load certificates manually
                let keyname = escape_hostname(&hostname);
                let cert_path = dir.join(format!("{keyname}.crt"));
                let key_path = dir.join(format!("{keyname}.key"));

                let (certs, secret_key) = tokio::task::spawn_blocking(move || {
                    let certs = load_certs(cert_path)?;
                    let key = load_secret_key(key_path)?;
                    anyhow::Ok((certs, key))
                })
                .await??;

                let config = config.with_single_cert(certs, secret_key)?;
                let config = Arc::new(config);
                let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());

                Ok((config, TlsAcceptor::Manual(acceptor)))
            }
        }
    }
}

fn escape_hostname(hostname: &str) -> Cow<'_, str> {
    let unsafe_hostname_characters =
        regex::Regex::new(r"[^a-zA-Z0-9-\.]").expect("regex manually checked");
    unsafe_hostname_characters.replace_all(hostname, "")
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
    /// Defaults to using the `http_bind_addr` with the port set to
    /// [`DEFAULT_RELAY_STUN_PORT`].
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
    use super::*;

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
        use super::*;

        pub(crate) fn hostname() -> String {
            NA_RELAY_HOSTNAME.to_string()
        }

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
    /// Certificate hostname.
    ///
    /// Defaults to [`NA_RELAY_HOSTNAME`].
    #[serde(default = "cfg_defaults::tls_config::hostname")]
    hostname: String,
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
    /// Defaults to `<cert_dir>/<hostname>.crt`, with `<hostname>` being the escaped
    /// hostname.
    ///
    /// Only used when `cert_mode` is `Manual`.
    manual_cert_path: Option<PathBuf>,
    /// Path of where to read the private key from for the `Manual` `cert_mode`.
    ///
    /// Defaults to `<cert_dir>/<hostname>.key` with `<hostname>` being the escaped
    /// hostname.
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
    contact: String,
}

impl TlsConfig {
    fn https_bind_addr(&self, cfg: &Config) -> SocketAddr {
        self.https_bind_addr
            .unwrap_or_else(|| SocketAddr::new(cfg.http_bind_addr().ip(), DEFAULT_HTTPS_PORT))
    }

    fn cert_dir(&self) -> PathBuf {
        self.cert_dir
            .as_ref()
            .map(|d| d.clone())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    fn cert_path(&self) -> PathBuf {
        let name = escape_hostname(&self.hostname);
        self.cert_dir().join(format!("{name}.crt"))
    }

    fn key_path(&self) -> PathBuf {
        let name = escape_hostname(&self.hostname);
        self.cert_dir().join(format!("{name}.key"))
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
            bail!("config-path must be a valid file");
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
                    let config = AcmeConfig::new(vec![tls.hostname.clone()])
                        .contact([format!("mailto:{}", tls.contact)])
                        .cache_option(Some(DirCache::new(tls.cert_dir())))
                        .directory_lets_encrypt(tls.prod_tls);
                    iroh_relay::CertConfig::LetsEncrypt { config }
                }
            };
            Some(iroh_relay::TlsConfig {
                https_bind_addr: tls.https_bind_addr(&cfg),
                hostname: tls.hostname.clone(),
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

// async fn run(
//     dev_mode: bool,
//     cfg: Config,
//     addr_sender: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
// ) -> Result<()> {
//     let (addr, tls_config) = if dev_mode {
//         let port = if cfg.addr.port() != 443 {
//             cfg.addr.port()
//         } else {
//             DEV_PORT
//         };

//         let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
//         info!(%addr, "Running in dev mode.");
//         (addr, None)
//     } else {
//         (cfg.addr, cfg.tls)
//     };

//     if let Some(tls_config) = &tls_config {
//         if let Some(captive_portal_port) = tls_config.captive_portal_port {
//             if addr.port() == captive_portal_port {
//                 bail!("The main listening address {addr:?} and the `captive_portal_port` have the same port number.");
//             }
//         }
//     } else if addr.port() == 443 {
//         // no tls config, but the port is 443
//         warn!("The address port is 443, which is typically the expected tls port, but you have not supplied any tls configuration.\nIf you meant to run the relay server with tls enabled, adjust the config file to include tls configuration.");
//     }

//     // set up relay configuration details
//     let secret_key = if cfg.enable_relay {
//         Some(cfg.secret_key)
//     } else {
//         None
//     };

//     // run stun
//     let stun_task = if cfg.enable_stun {
//         Some(tokio::task::spawn(async move {
//             serve_stun(addr.ip(), cfg.stun_port).await
//         }))
//     } else {
//         None
//     };

//     // set up tls configuration details
//     let (tls_config, headers, captive_portal_port) = if let Some(tls_config) = tls_config {
//         let contact = tls_config.contact;
//         let is_production = tls_config.prod_tls;
//         let (config, acceptor) = tls_config
//             .cert_mode
//             .gen_server_config(
//                 cfg.hostname.clone(),
//                 contact,
//                 is_production,
//                 tls_config.cert_dir.unwrap_or_else(|| PathBuf::from(".")),
//             )
//             .await?;
//         let mut headers = HeaderMap::new();
//         for (name, value) in TLS_HEADERS.iter() {
//             headers.insert(*name, value.parse()?);
//         }
//         (
//             Some(RelayTlsConfig { config, acceptor }),
//             headers,
//             tls_config
//                 .captive_portal_port
//                 .unwrap_or(DEFAULT_CAPTIVE_PORTAL_PORT),
//         )
//     } else {
//         (None, HeaderMap::new(), 0)
//     };

//     let mut builder = RelayServerBuilder::new(addr)
//         .secret_key(secret_key.map(Into::into))
//         .headers(headers)
//         .tls_config(tls_config.clone())
//         .relay_override(Box::new(relay_disabled_handler))
//         .request_handler(Method::GET, "/", Box::new(root_handler))
//         .request_handler(Method::GET, "/index.html", Box::new(root_handler))
//         .request_handler(Method::GET, "/derp/probe", Box::new(probe_handler))
//         .request_handler(Method::GET, "/robots.txt", Box::new(robots_handler));
//     // if tls is enabled, we need to serve this endpoint from a non-tls connection
//     // which we check for below
//     if tls_config.is_none() {
//         builder = builder.request_handler(
//             Method::GET,
//             "/generate_204",
//             Box::new(serve_no_content_handler),
//         );
//     }
//     let relay_server = builder.spawn().await?;

//     // captive portal detections must be served over HTTP
//     let captive_portal_task = if tls_config.is_some() {
//         let http_addr = SocketAddr::new(addr.ip(), captive_portal_port);
//         let task = serve_captive_portal_service(http_addr).await?;
//         Some(task)
//     } else {
//         None
//     };

//     if let Some(addr_sender) = addr_sender {
//         if let Err(e) = addr_sender.send(relay_server.addr()) {
//             bail!("Unable to send the local SocketAddr, the Sender was dropped - {e:?}");
//         }
//     }

//     tokio::signal::ctrl_c().await?;
//     // Shutdown all tasks
//     if let Some(task) = stun_task {
//         task.abort();
//     }
//     if let Some(task) = captive_portal_task {
//         task.abort()
//     }
//     relay_server.shutdown().await;

//     Ok(())
// }

// const NO_CONTENT_CHALLENGE_HEADER: &str = "X-Tailscale-Challenge";
// const NO_CONTENT_RESPONSE_HEADER: &str = "X-Tailscale-Response";

// const NOTFOUND: &[u8] = b"Not Found";
// const RELAY_DISABLED: &[u8] = b"relay server disabled";
// const ROBOTS_TXT: &[u8] = b"User-agent: *\nDisallow: /\n";
// const INDEX: &[u8] = br#"<html><body>
// <h1>RELAY</h1>
// <p>
//   This is an
//   <a href="https://iroh.computer/">Iroh</a> Relay
//   server.
// </p>
// "#;

// const TLS_HEADERS: [(&str, &str); 2] = [
//     ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
//     ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'self'; block-all-mixed-content; plugin-types 'none'")
// ];

// async fn serve_captive_portal_service(addr: SocketAddr) -> Result<tokio::task::JoinHandle<()>> {
//     let http_listener = TcpListener::bind(&addr)
//         .await
//         .context("failed to bind http")?;
//     let http_addr = http_listener.local_addr()?;
//     info!("[CaptivePortalService]: serving on {}", http_addr);

//     let task = tokio::spawn(
//         async move {
//             loop {
//                 match http_listener.accept().await {
//                     Ok((stream, peer_addr)) => {
//                         debug!(
//                             "[CaptivePortalService] Connection opened from {}",
//                             peer_addr
//                         );
//                         let handler = CaptivePortalService;

//                         tokio::task::spawn(async move {
//                             let stream = relay::MaybeTlsStreamServer::Plain(stream);
//                             let stream = hyper_util::rt::TokioIo::new(stream);
//                             if let Err(err) = hyper::server::conn::http1::Builder::new()
//                                 .serve_connection(stream, handler)
//                                 .with_upgrades()
//                                 .await
//                             {
//                                 error!(
//                                     "[CaptivePortalService] Failed to serve connection: {:?}",
//                                     err
//                                 );
//                             }
//                         });
//                     }
//                     Err(err) => {
//                         error!(
//                             "[CaptivePortalService] failed to accept connection: {:#?}",
//                             err
//                         );
//                     }
//                 }
//             }
//         }
//         .instrument(info_span!("captive-portal.service")),
//     );
//     Ok(task)
// }

// #[derive(Clone)]
// struct CaptivePortalService;

// impl hyper::service::Service<Request<Incoming>> for CaptivePortalService {
//     type Response = Response<BytesBody>;
//     type Error = HyperError;
//     type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

//     fn call(&self, req: Request<Incoming>) -> Self::Future {
//         match (req.method(), req.uri().path()) {
//             // Captive Portal checker
//             (&Method::GET, "/generate_204") => {
//                 Box::pin(async move { serve_no_content_handler(req, Response::builder()) })
//             }
//             _ => {
//                 // Return 404 not found response.
//                 let r = Response::builder()
//                     .status(StatusCode::NOT_FOUND)
//                     .body(NOTFOUND.into())
//                     .map_err(|err| Box::new(err) as HyperError);
//                 Box::pin(async move { r })
//             }
//         }
//     }
// }

// fn relay_disabled_handler(
//     _r: Request<Incoming>,
//     response: ResponseBuilder,
// ) -> HyperResult<Response<BytesBody>> {
//     response
//         .status(StatusCode::NOT_FOUND)
//         .body(RELAY_DISABLED.into())
//         .map_err(|err| Box::new(err) as HyperError)
// }

// fn root_handler(
//     _r: Request<Incoming>,
//     response: ResponseBuilder,
// ) -> HyperResult<Response<BytesBody>> {
//     response
//         .status(StatusCode::OK)
//         .header("Content-Type", "text/html; charset=utf-8")
//         .body(INDEX.into())
//         .map_err(|err| Box::new(err) as HyperError)
// }

// /// HTTP latency queries
// fn probe_handler(
//     _r: Request<Incoming>,
//     response: ResponseBuilder,
// ) -> HyperResult<Response<BytesBody>> {
//     response
//         .status(StatusCode::OK)
//         .header("Access-Control-Allow-Origin", "*")
//         .body(body_empty())
//         .map_err(|err| Box::new(err) as HyperError)
// }

// fn robots_handler(
//     _r: Request<Incoming>,
//     response: ResponseBuilder,
// ) -> HyperResult<Response<BytesBody>> {
//     response
//         .status(StatusCode::OK)
//         .body(ROBOTS_TXT.into())
//         .map_err(|err| Box::new(err) as HyperError)
// }

// /// For captive portal detection.
// fn serve_no_content_handler<B: hyper::body::Body>(
//     r: Request<B>,
//     mut response: ResponseBuilder,
// ) -> HyperResult<Response<BytesBody>> {
//     if let Some(challenge) = r.headers().get(NO_CONTENT_CHALLENGE_HEADER) {
//         if !challenge.is_empty()
//             && challenge.len() < 64
//             && challenge
//                 .as_bytes()
//                 .iter()
//                 .all(|c| is_challenge_char(*c as char))
//         {
//             response = response.header(
//                 NO_CONTENT_RESPONSE_HEADER,
//                 format!("response {}", challenge.to_str()?),
//             );
//         }
//     }

//     response
//         .status(StatusCode::NO_CONTENT)
//         .body(body_empty())
//         .map_err(|err| Box::new(err) as HyperError)
// }

// fn is_challenge_char(c: char) -> bool {
//     // Semi-randomly chosen as a limited set of valid characters
//     c.is_ascii_lowercase()
//         || c.is_ascii_uppercase()
//         || c.is_ascii_digit()
//         || c == '.'
//         || c == '-'
//         || c == '_'
// }

// async fn serve_stun(host: IpAddr, port: u16) {
//     match UdpSocket::bind((host, port)).await {
//         Ok(sock) => {
//             let addr = sock.local_addr().expect("socket just bound");
//             info!(%addr, "running STUN server");
//             server_stun_listener(sock)
//                 .instrument(debug_span!("stun_server", %addr))
//                 .await;
//         }
//         Err(err) => {
//             error!(
//                 "failed to open STUN listener at host {host} and port {port}: {:#?}",
//                 err
//             );
//         }
//     }
// }

// async fn server_stun_listener(sock: UdpSocket) {
//     let sock = Arc::new(sock);
//     let mut buffer = vec![0u8; 64 << 10];
//     loop {
//         match sock.recv_from(&mut buffer).await {
//             Ok((n, src_addr)) => {
//                 inc!(StunMetrics, requests);
//                 let pkt = buffer[..n].to_vec();
//                 let sock = sock.clone();
//                 tokio::task::spawn(async move {
//                     if !stun::is(&pkt) {
//                         debug!(%src_addr, "STUN: ignoring non stun packet");
//                         inc!(StunMetrics, bad_requests);
//                         return;
//                     }
//                     match tokio::task::spawn_blocking(move || stun::parse_binding_request(&pkt))
//                         .await
//                     {
//                         Ok(Ok(txid)) => {
//                             debug!(%src_addr, %txid, "STUN: received binding request");
//                             let res = match tokio::task::spawn_blocking(move || {
//                                 stun::response(txid, src_addr)
//                             })
//                             .await
//                             {
//                                 Ok(res) => res,
//                                 Err(err) => {
//                                     error!("JoinError: {err:#}");
//                                     return;
//                                 }
//                             };
//                             match sock.send_to(&res, src_addr).await {
//                                 Ok(len) => {
//                                     if len != res.len() {
//                                         warn!(%src_addr, %txid, "STUN: failed to write response sent: {}, but expected {}", len, res.len());
//                                     }
//                                     match src_addr {
//                                         SocketAddr::V4(_) => {
//                                             inc!(StunMetrics, ipv4_success);
//                                         }
//                                         SocketAddr::V6(_) => {
//                                             inc!(StunMetrics, ipv6_success);
//                                         }
//                                     }
//                                     trace!(%src_addr, %txid, "STUN: sent {} bytes", len);
//                                 }
//                                 Err(err) => {
//                                     inc!(StunMetrics, failures);
//                                     warn!(%src_addr, %txid, "STUN: failed to write response: {:?}", err);
//                                 }
//                             }
//                         }
//                         Ok(Err(err)) => {
//                             inc!(StunMetrics, bad_requests);
//                             warn!(%src_addr, "STUN: invalid binding request: {:?}", err);
//                         }
//                         Err(err) => error!("JoinError parsing STUN binding: {err:#}"),
//                     }
//                 });
//             }
//             Err(err) => {
//                 inc!(StunMetrics, failures);
//                 warn!("STUN: failed to recv: {:?}", err);
//             }
//         }
//     }
// }

// // var validProdHostname = regexp.MustCompile(`^relay([^.]*)\.tailscale\.com\.?$`)

// // func prodAutocertHostPolicy(_ context.Context, host string) error {
// // 	if validProdHostname.MatchString(host) {
// // 		return nil
// // 	}
// // 	return errors.New("invalid hostname")
// // }

// // func rateLimitedListenAndServeTLS(srv *http.Server) error {
// // 	addr := srv.Addr
// // 	if addr == "" {
// // 		addr = ":https"
// // 	}
// // 	ln, err := net.Listen("tcp", addr)
// // 	if err != nil {
// // 		return err
// // 	}
// // 	rln := newRateLimitedListener(ln, rate.Limit(*acceptConnLimit), *acceptConnBurst)
// // 	expvar.Publish("tls_listener", rln.ExpVar())
// // 	defer rln.Close()
// // 	return srv.ServeTLS(rln, "", "")
// // }

// // type rateLimitedListener struct {
// // 	// These are at the start of the struct to ensure 64-bit alignment
// // 	// on 32-bit architecture regardless of what other fields may exist
// // 	// in this package.
// // 	numAccepts expvar.Int // does not include number of rejects
// // 	numRejects expvar.Int

// // 	net.Listener

// // 	lim *rate.Limiter
// // }

// // func newRateLimitedListener(ln net.Listener, limit rate.Limit, burst int) *rateLimitedListener {
// // 	return &rateLimitedListener{Listener: ln, lim: rate.NewLimiter(limit, burst)}
// // }

// // func (l *rateLimitedListener) ExpVar() expvar.Var {
// // 	m := new(metrics.Set)
// // 	m.Set("counter_accepted_connections", &l.numAccepts)
// // 	m.Set("counter_rejected_connections", &l.numRejects)
// // 	return m
// // }

// // var errLimitedConn = errors.New("cannot accept connection; rate limited")

// // func (l *rateLimitedListener) Accept() (net.Conn, error) {
// // 	// Even under a rate limited situation, we accept the connection immediately
// // 	// and close it, rather than being slow at accepting new connections.
// // 	// This provides two benefits: 1) it signals to the client that something
// // 	// is going on on the server, and 2) it prevents new connections from
// // 	// piling up and occupying resources in the OS kernel.
// // 	// The client will retry as needing (with backoffs in place).
// // 	cn, err := l.Listener.Accept()
// // 	if err != nil {
// // 		return nil, err
// // 	}
// // 	if !l.lim.Allow() {
// // 		l.numRejects.Add(1)
// // 		cn.Close()
// // 		return nil, errLimitedConn
// // 	}
// // 	l.numAccepts.Add(1)
// // 	return cn, nil
// // }
// //
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

// #[cfg(test)]
// mod tests {
//     use super::*;

//     use std::net::Ipv4Addr;
//     use std::time::Duration;

//     use bytes::Bytes;
//     use http_body_util::BodyExt;
//     use iroh_base::node_addr::RelayUrl;
//     use iroh_net::relay::http::ClientBuilder;
//     use iroh_net::relay::ReceivedMessage;
//     use tokio::task::JoinHandle;

//     #[tokio::test]
//     async fn test_serve_no_content_handler() {
//         let challenge = "123az__.";
//         let req = Request::builder()
//             .header(NO_CONTENT_CHALLENGE_HEADER, challenge)
//             .body(body_empty())
//             .unwrap();

//         let res = serve_no_content_handler(req, Response::builder()).unwrap();
//         assert_eq!(res.status(), StatusCode::NO_CONTENT);

//         let header = res
//             .headers()
//             .get(NO_CONTENT_RESPONSE_HEADER)
//             .unwrap()
//             .to_str()
//             .unwrap();
//         assert_eq!(header, format!("response {challenge}"));
//         assert!(res
//             .into_body()
//             .collect()
//             .await
//             .unwrap()
//             .to_bytes()
//             .is_empty());
//     }

//     #[test]
//     fn test_escape_hostname() {
//         assert_eq!(
//             escape_hostname("hello.host.name_foo-bar%baz"),
//             "hello.host.namefoo-barbaz"
//         );
//     }

//     struct DropServer {
//         server_task: JoinHandle<()>,
//     }

//     impl Drop for DropServer {
//         fn drop(&mut self) {
//             self.server_task.abort();
//         }
//     }

//     #[tokio::test]
//     async fn test_relay_server_basic() -> Result<()> {
//         tracing_subscriber::registry()
//             .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
//             .with(EnvFilter::from_default_env())
//             .try_init()
//             .ok();
//         // Binding to LOCALHOST to satisfy issues when binding to UNSPECIFIED in Windows for tests
//         // Binding to Ipv4 because, when binding to `IPv6::UNSPECIFIED`, it will also listen for
//         // IPv4 connections, but will not automatically do the same for `LOCALHOST`. In order to
//         // test STUN, which only listens on Ipv4, we must bind the whole relay server to Ipv4::LOCALHOST.
//         let cfg = Config {
//             addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
//             ..Default::default()
//         };
//         let (addr_send, addr_recv) = tokio::sync::oneshot::channel();
//         let relay_server_task = tokio::spawn(
//             async move {
//                 // dev mode will bind to IPv6::UNSPECIFIED, so setting it `false`
//                 let res = run(false, cfg, Some(addr_send)).await;
//                 if let Err(e) = res {
//                     eprintln!("error starting relay server {e}");
//                 }
//             }
//             .instrument(debug_span!("relay server")),
//         );
//         let _drop_server = DropServer {
//             server_task: relay_server_task,
//         };

//         let relay_server_addr = addr_recv.await?;
//         let relay_server_str_url = format!("http://{}", relay_server_addr);
//         let relay_server_url: RelayUrl = relay_server_str_url.parse().unwrap();

//         // set up clients
//         let a_secret_key = SecretKey::generate();
//         let a_key = a_secret_key.public();
//         let resolver = iroh_net::dns::default_resolver().clone();
//         let (client_a, mut client_a_receiver) =
//             ClientBuilder::new(relay_server_url.clone()).build(a_secret_key, resolver);
//         let connect_client = client_a.clone();

//         // give the relay server some time to set up
//         if let Err(e) = tokio::time::timeout(Duration::from_secs(10), async move {
//             loop {
//                 match connect_client.connect().await {
//                     Ok(_) => break,
//                     Err(e) => {
//                         tracing::warn!("client a unable to connect to relay server: {e:?}. Attempting to dial again in 10ms");
//                         tokio::time::sleep(Duration::from_millis(100)).await
//                     }
//                 }
//             }
//         })
//         .await
//         {
//             bail!("error connecting client a to relay server: {e:?}");
//         }

//         let b_secret_key = SecretKey::generate();
//         let b_key = b_secret_key.public();
//         let resolver = iroh_net::dns::default_resolver().clone();
//         let (client_b, mut client_b_receiver) =
//             ClientBuilder::new(relay_server_url.clone()).build(b_secret_key, resolver);
//         client_b.connect().await?;

//         let msg = Bytes::from("hello, b");
//         client_a.send(b_key, msg.clone()).await?;

//         let (res, _) = client_b_receiver.recv().await.unwrap()?;
//         if let ReceivedMessage::ReceivedPacket { source, data } = res {
//             assert_eq!(a_key, source);
//             assert_eq!(msg, data);
//         } else {
//             bail!("client_b received unexpected message {res:?}");
//         }

//         let msg = Bytes::from("howdy, a");
//         client_b.send(a_key, msg.clone()).await?;

//         let (res, _) = client_a_receiver.recv().await.unwrap()?;
//         if let ReceivedMessage::ReceivedPacket { source, data } = res {
//             assert_eq!(b_key, source);
//             assert_eq!(msg, data);
//         } else {
//             bail!("client_a received unexpected message {res:?}");
//         }

//         // run stun check
//         let stun_addr: SocketAddr =
//             SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3478);

//         let txid = stun::TransactionId::default();
//         let req = stun::request(txid);
//         let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

//         let server_socket = socket.clone();
//         let server_task = tokio::task::spawn(async move {
//             let mut buf = vec![0u8; 64000];
//             let len = server_socket.recv(&mut buf).await.unwrap();
//             dbg!(len);
//             buf.truncate(len);
//             buf
//         });

//         tracing::info!("sending stun request to {stun_addr}");
//         if let Err(e) = socket.send_to(&req, stun_addr).await {
//             bail!("socket.send_to error: {e:?}");
//         }

//         let response = server_task.await.unwrap();
//         let (txid_back, response_addr) = stun::parse_response(&response).unwrap();
//         assert_eq!(txid, txid_back);
//         tracing::info!("got {response_addr}");

//         // get 200 home page response
//         tracing::info!("send request for homepage");
//         let res = reqwest::get(relay_server_str_url).await?;
//         assert!(res.status().is_success());
//         tracing::info!("got OK");

//         // test captive portal
//         tracing::info!("test captive portal response");

//         let url = relay_server_url.join("/generate_204")?;
//         let challenge = "123az__.";
//         let client = reqwest::Client::new();
//         let res = client
//             .get(url)
//             .header(NO_CONTENT_CHALLENGE_HEADER, challenge)
//             .send()
//             .await?;
//         assert_eq!(StatusCode::NO_CONTENT.as_u16(), res.status().as_u16());
//         let header = res.headers().get(NO_CONTENT_RESPONSE_HEADER).unwrap();
//         assert_eq!(header.to_str().unwrap(), format!("response {challenge}"));
//         let body = res.bytes().await?;
//         assert!(body.is_empty());

//         tracing::info!("got successful captive portal response");

//         Ok(())
//     }
// }
