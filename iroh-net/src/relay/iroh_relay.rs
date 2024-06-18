//! A full-fledged iroh-relay server.
//!
//! This module provides an API to run a full fledged iroh-relay server.  It is primarily
//! used by the `iroh-relay` binary in this crate.  It can be used to run a relay server in
//! other locations however.
//!
//! This code is fully written in a form of structured-concurrency: every spawned task is
//! always attached to a handle and when the handle is dropped the tasks abort.  So tasks
//! can not outlive their handle.  It is also always possible to await for completion of a
//! task.  Some tasks additionally have a method to do graceful shutdown.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use futures_lite::StreamExt;
use http::response::Builder as ResponseBuilder;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use iroh_metrics::inc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tracing::{debug, error, info, info_span, instrument, trace, warn, Instrument};

use crate::key::SecretKey;
use crate::relay;
use crate::relay::http::{ServerBuilder as RelayServerBuilder, TlsAcceptor};
use crate::stun;
use crate::util::AbortingJoinHandle;

// Module defined in this file.
use metrics::StunMetrics;

const NO_CONTENT_CHALLENGE_HEADER: &str = "X-Tailscale-Challenge";
const NO_CONTENT_RESPONSE_HEADER: &str = "X-Tailscale-Response";
const NOTFOUND: &[u8] = b"Not Found";
const RELAY_DISABLED: &[u8] = b"relay server disabled";
const ROBOTS_TXT: &[u8] = b"User-agent: *\nDisallow: /\n";
const INDEX: &[u8] = br#"<html><body>
<h1>Iroh Relay</h1>
<p>
  This is an <a href="https://iroh.computer/">Iroh</a> Relay server.
</p>
"#;
const TLS_HEADERS: [(&str, &str); 2] = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'self'; block-all-mixed-content; plugin-types 'none'")
];

type BytesBody = http_body_util::Full<hyper::body::Bytes>;
type HyperError = Box<dyn std::error::Error + Send + Sync>;
type HyperResult<T> = std::result::Result<T, HyperError>;

/// Creates a new [`BytesBody`] with no content.
fn body_empty() -> BytesBody {
    http_body_util::Full::new(hyper::body::Bytes::new())
}

/// Configuration for the full Relay & STUN server.
///
/// Be aware the generic parameters are for when using the Let's Encrypt TLS configuration.
/// If not used dummy ones need to be provided, e.g. `ServerConfig::<(), ()>::default()`.
#[derive(Debug, Default)]
pub struct ServerConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// Configuration for the Relay server, disabled if `None`.
    pub relay: Option<RelayConfig<EC, EA>>,
    /// Configuration for the STUN server, disabled if `None`.
    pub stun: Option<StunConfig>,
    /// Socket to serve metrics on.
    #[cfg(feature = "metrics")]
    pub metrics_addr: Option<SocketAddr>,
}

/// Configuration for the Relay HTTP and HTTPS server.
///
/// This includes the HTTP services hosted by the Relay server, the Relay `/derp` HTTP
/// endpoint is only one of the services served.
#[derive(Debug)]
pub struct RelayConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// The iroh secret key of the Relay server.
    pub secret_key: SecretKey,
    /// The socket address on which the Relay HTTP server should bind.
    ///
    /// Normally you'd choose port `80`.  The bind address for the HTTPS server is
    /// configured in [`RelayConfig::tls`].
    ///
    /// If [`RelayConfig::tls`] is `None` then this serves all the HTTP services without
    /// TLS.
    pub http_bind_addr: SocketAddr,
    /// TLS configuration for the HTTPS server.
    ///
    /// If *None* all the HTTP services that would be served here are served from
    /// [`RelayConfig::http_bind_addr`].
    pub tls: Option<TlsConfig<EC, EA>>,
    /// Rate limits.
    pub limits: Limits,
}

/// Configuration for the STUN server.
#[derive(Debug)]
pub struct StunConfig {
    /// The socket address on which the STUN server should bind.
    ///
    /// Normally you'd chose port `3478`, see [`crate::defaults::DEFAULT_STUN_PORT`].
    pub bind_addr: SocketAddr,
}

/// TLS configuration for Relay server.
///
/// Normally the Relay server accepts connections on both HTTPS and HTTP.
#[derive(Debug)]
pub struct TlsConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// The socket address on which to serve the HTTPS server.
    ///
    /// Since the captive portal probe has to run over plain text HTTP and TLS is used for
    /// the main relay server this has to be on a different port.  When TLS is not enabled
    /// this is served on the [`RelayConfig::http_bind_addr`] socket address.
    ///
    /// Normally you'd choose port `80`.
    pub https_bind_addr: SocketAddr,
    /// Mode for getting a cert.
    pub cert: CertConfig<EC, EA>,
}

/// Rate limits.
#[derive(Debug, Default)]
pub struct Limits {
    /// Rate limit for accepting new connection. Unlimited if not set.
    pub accept_conn_limit: Option<f64>,
    /// Burst limit for accepting new connection. Unlimited if not set.
    pub accept_conn_burst: Option<usize>,
}

/// TLS certificate configuration.
#[derive(derive_more::Debug)]
pub enum CertConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// Use Let's Encrypt.
    LetsEncrypt {
        /// Configuration for Let's Encrypt certificates.
        #[debug("AcmeConfig")]
        config: tokio_rustls_acme::AcmeConfig<EC, EA>,
    },
    /// Use a static TLS key and certificate chain.
    Manual {
        /// The TLS private key.
        private_key: rustls::PrivateKey,
        /// The TLS certificate chain.
        certs: Vec<rustls::Certificate>,
    },
}

/// A running Relay + STUN server.
///
/// This is a full Relay server, including STUN, Relay and various associated HTTP services.
///
/// Dropping this will stop the server.
#[derive(Debug)]
pub struct Server {
    /// The address of the HTTP server, if configured.
    http_addr: Option<SocketAddr>,
    /// The address of the STUN server, if configured.
    stun_addr: Option<SocketAddr>,
    /// The address of the HTTPS server, if the relay server is using TLS.
    ///
    /// If the Relay server is not using TLS then it is served from the
    /// [`Server::http_addr`].
    https_addr: Option<SocketAddr>,
    /// Handle to the relay server.
    relay_handle: Option<relay::http::ServerHandle>,
    /// The main task running the server.
    supervisor: AbortingJoinHandle<Result<()>>,
}

impl Server {
    /// Starts the server.
    pub async fn spawn<EC, EA>(config: ServerConfig<EC, EA>) -> Result<Self>
    where
        EC: fmt::Debug + 'static,
        EA: fmt::Debug + 'static,
    {
        let mut tasks = JoinSet::new();

        #[cfg(feature = "metrics")]
        if let Some(addr) = config.metrics_addr {
            debug!("Starting metrics server");
            use iroh_metrics::core::Metric;

            iroh_metrics::core::Core::init(|reg, metrics| {
                metrics.insert(crate::metrics::RelayMetrics::new(reg));
                metrics.insert(StunMetrics::new(reg));
            });
            tasks.spawn(
                iroh_metrics::metrics::start_metrics_server(addr)
                    .instrument(info_span!("metrics-server")),
            );
        }

        // Start the STUN server.
        let stun_addr = match config.stun {
            Some(stun) => {
                debug!("Starting STUN server");
                match UdpSocket::bind(stun.bind_addr).await {
                    Ok(sock) => {
                        let addr = sock.local_addr()?;
                        info!("STUN server bound on {addr}");
                        tasks.spawn(
                            server_stun_listener(sock).instrument(info_span!("stun-server", %addr)),
                        );
                        Some(addr)
                    }
                    Err(err) => bail!("failed to bind STUN listener: {err:#?}"),
                }
            }
            None => None,
        };

        // Start the Relay server.
        let (relay_server, http_addr) = match config.relay {
            Some(relay_config) => {
                debug!("Starting Relay server");
                let mut headers = HeaderMap::new();
                for (name, value) in TLS_HEADERS.iter() {
                    headers.insert(*name, value.parse()?);
                }
                let relay_bind_addr = match relay_config.tls {
                    Some(ref tls) => tls.https_bind_addr,
                    None => relay_config.http_bind_addr,
                };
                let mut builder = RelayServerBuilder::new(relay_bind_addr)
                    .secret_key(Some(relay_config.secret_key))
                    .headers(headers)
                    .relay_override(Box::new(relay_disabled_handler))
                    .request_handler(Method::GET, "/", Box::new(root_handler))
                    .request_handler(Method::GET, "/index.html", Box::new(root_handler))
                    .request_handler(Method::GET, "/derp/probe", Box::new(probe_handler))
                    .request_handler(Method::GET, "/robots.txt", Box::new(robots_handler));
                let http_addr = match relay_config.tls {
                    Some(tls_config) => {
                        let server_config = rustls::ServerConfig::builder()
                            .with_safe_defaults()
                            .with_no_client_auth();
                        let server_tls_config = match tls_config.cert {
                            CertConfig::LetsEncrypt { config } => {
                                let mut state = config.state();
                                let server_config =
                                    server_config.with_cert_resolver(state.resolver());
                                let acceptor = TlsAcceptor::LetsEncrypt(state.acceptor());
                                tasks.spawn(
                                    async move {
                                        while let Some(event) = state.next().await {
                                            match event {
                                                Ok(ok) => debug!("acme event: {ok:?}"),
                                                Err(err) => error!("error: {err:?}"),
                                            }
                                        }
                                        Err(anyhow!("acme event stream finished"))
                                    }
                                    .instrument(info_span!("acme")),
                                );
                                Some(relay::http::TlsConfig {
                                    config: Arc::new(server_config),
                                    acceptor,
                                })
                            }
                            CertConfig::Manual { private_key, certs } => {
                                let server_config = server_config
                                    .with_single_cert(certs.clone(), private_key.clone())?;
                                let server_config = Arc::new(server_config);
                                let acceptor =
                                    tokio_rustls::TlsAcceptor::from(server_config.clone());
                                let acceptor = TlsAcceptor::Manual(acceptor);
                                Some(relay::http::TlsConfig {
                                    config: server_config,
                                    acceptor,
                                })
                            }
                        };
                        builder = builder.tls_config(server_tls_config);

                        // Some services always need to be served over HTTP without TLS.  Run
                        // these standalone.
                        let http_listener = TcpListener::bind(&relay_config.http_bind_addr)
                            .await
                            .context("failed to bind http")?;
                        let http_addr = http_listener.local_addr()?;
                        tasks.spawn(
                            run_captive_portal_service(http_listener)
                                .instrument(info_span!("http-service", addr = %http_addr)),
                        );
                        Some(http_addr)
                    }
                    None => {
                        // If running Relay without TLS add the plain HTTP server directly
                        // to the Relay server.
                        builder = builder.request_handler(
                            Method::GET,
                            "/generate_204",
                            Box::new(serve_no_content_handler),
                        );
                        None
                    }
                };
                let relay_server = builder.spawn().await?;
                (Some(relay_server), http_addr)
            }
            None => (None, None),
        };
        // If http_addr is Some then relay_server is serving HTTPS.  If http_addr is None
        // relay_server is serving HTTP, including the /generate_204 service.
        let relay_addr = relay_server.as_ref().map(|srv| srv.addr());
        let relay_handle = relay_server.as_ref().map(|srv| srv.handle());
        let relay_server = relay_server.map(RelayHttpServerGuard);
        let task = tokio::spawn(relay_supervisor(tasks, relay_server));
        Ok(Self {
            http_addr: http_addr.or(relay_addr),
            stun_addr,
            https_addr: http_addr.and(relay_addr),
            relay_handle,
            supervisor: AbortingJoinHandle::from(task),
        })
    }

    /// Requests graceful shutdown.
    ///
    /// Returns once all server tasks have stopped.
    pub async fn shutdown(self) -> Result<()> {
        // Only the Relay server needs shutting down, the supervisor will abort the tasks in
        // the JoinSet when the server terminates.
        if let Some(handle) = self.relay_handle {
            handle.shutdown();
        }
        self.supervisor.await?
    }

    /// Returns the handle for the task.
    ///
    /// This allows waiting for the server's supervisor task to finish.  Can be useful in
    /// case there is an error in the server before it is shut down.
    pub fn task_handle(&mut self) -> &mut AbortingJoinHandle<Result<()>> {
        &mut self.supervisor
    }

    /// The socket address the HTTPS server is listening on.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https_addr
    }

    /// The socket address the HTTP server is listening on.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// The socket address the STUN server is listening on.
    pub fn stun_addr(&self) -> Option<SocketAddr> {
        self.stun_addr
    }
}

/// Horrible hack to make [`relay::http::Server`] behave somewhat.
///
/// We need this server to abort on drop to achieve structured concurrency.
// TODO: could consider building this directly into the relay::http::Server
#[derive(Debug)]
struct RelayHttpServerGuard(relay::http::Server);

impl Drop for RelayHttpServerGuard {
    fn drop(&mut self) {
        self.0.task_handle().abort();
    }
}

/// Supervisor for the relay server tasks.
///
/// As soon as one of the tasks exits, all other tasks are stopped and the server stops.
/// The supervisor finishes once all tasks are finished.
#[instrument(skip_all)]
async fn relay_supervisor(
    mut tasks: JoinSet<Result<()>>,
    mut relay_http_server: Option<RelayHttpServerGuard>,
) -> Result<()> {
    let res = match (relay_http_server.as_mut(), tasks.len()) {
        (None, _) => tasks
            .join_next()
            .await
            .unwrap_or_else(|| Ok(Err(anyhow!("Nothing to supervise")))),
        (Some(relay), 0) => relay.0.task_handle().await.map(anyhow::Ok),
        (Some(relay), _) => {
            tokio::select! {
                biased;
                Some(ret) = tasks.join_next() => ret,
                ret = relay.0.task_handle() => ret.map(anyhow::Ok),
                else => Ok(Err(anyhow!("Empty JoinSet (unreachable)"))),
            }
        }
    };
    let ret = match res {
        Ok(Ok(())) => {
            debug!("Task exited");
            Ok(())
        }
        Ok(Err(err)) => {
            error!(%err, "Task failed");
            Err(err.context("task failed"))
        }
        Err(err) => {
            if let Ok(panic) = err.try_into_panic() {
                error!("Task panicked");
                std::panic::resume_unwind(panic);
            }
            debug!("Task cancelled");
            Err(anyhow!("task cancelled"))
        }
    };

    // Ensure the HTTP server terminated, there is no harm in calling this after it is
    // already shut down.  The JoinSet is aborted on drop.
    if let Some(server) = relay_http_server {
        server.0.shutdown();
    }

    tasks.shutdown().await;

    ret
}

/// Runs a STUN server.
///
/// When the future is dropped, the server stops.
async fn server_stun_listener(sock: UdpSocket) -> Result<()> {
    info!(addr = ?sock.local_addr().ok(), "running STUN server");
    let sock = Arc::new(sock);
    let mut buffer = vec![0u8; 64 << 10];
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = tasks.join_next(), if !tasks.is_empty() => (),
            res = sock.recv_from(&mut buffer) => {
                match res {
                    Ok((n, src_addr)) => {
                        inc!(StunMetrics, requests);
                        let pkt = &buffer[..n];
                        if !stun::is(pkt) {
                            debug!(%src_addr, "STUN: ignoring non stun packet");
                            inc!(StunMetrics, bad_requests);
                            continue;
                        }
                        let pkt = pkt.to_vec();
                        tasks.spawn(handle_stun_request(src_addr, pkt, sock.clone()));
                    }
                    Err(err) => {
                        inc!(StunMetrics, failures);
                        warn!("failed to recv: {err:#}");
                    }
                }
            }
        }
    }
}

/// Handles a single STUN request, doing all logging required.
async fn handle_stun_request(src_addr: SocketAddr, pkt: Vec<u8>, sock: Arc<UdpSocket>) {
    let handle = AbortingJoinHandle::from(tokio::task::spawn_blocking(move || {
        match stun::parse_binding_request(&pkt) {
            Ok(txid) => {
                debug!(%src_addr, %txid, "STUN: received binding request");
                Some((txid, stun::response(txid, src_addr)))
            }
            Err(err) => {
                inc!(StunMetrics, bad_requests);
                warn!(%src_addr, "STUN: invalid binding request: {:?}", err);
                None
            }
        }
    }));
    let (txid, response) = match handle.await {
        Ok(Some(val)) => val,
        Ok(None) => return,
        Err(err) => {
            error!("{err:#}");
            return;
        }
    };
    match sock.send_to(&response, src_addr).await {
        Ok(len) => {
            if len != response.len() {
                warn!(
                    %src_addr,
                    %txid,
                    "failed to write response, {len}/{} bytes sent",
                    response.len()
                );
            } else {
                match src_addr {
                    SocketAddr::V4(_) => inc!(StunMetrics, ipv4_success),
                    SocketAddr::V6(_) => inc!(StunMetrics, ipv6_success),
                }
            }
            trace!(%src_addr, %txid, "sent {len} bytes");
        }
        Err(err) => {
            inc!(StunMetrics, failures);
            warn!(%src_addr, %txid, "failed to write response: {err:#}");
        }
    }
}

fn relay_disabled_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    response
        .status(StatusCode::NOT_FOUND)
        .body(RELAY_DISABLED.into())
        .map_err(|err| Box::new(err) as HyperError)
}

fn root_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    response
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(INDEX.into())
        .map_err(|err| Box::new(err) as HyperError)
}

/// HTTP latency queries
fn probe_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    response
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .body(body_empty())
        .map_err(|err| Box::new(err) as HyperError)
}

fn robots_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    response
        .status(StatusCode::OK)
        .body(ROBOTS_TXT.into())
        .map_err(|err| Box::new(err) as HyperError)
}

/// For captive portal detection.
fn serve_no_content_handler<B: hyper::body::Body>(
    r: Request<B>,
    mut response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    if let Some(challenge) = r.headers().get(NO_CONTENT_CHALLENGE_HEADER) {
        if !challenge.is_empty()
            && challenge.len() < 64
            && challenge
                .as_bytes()
                .iter()
                .all(|c| is_challenge_char(*c as char))
        {
            response = response.header(
                NO_CONTENT_RESPONSE_HEADER,
                format!("response {}", challenge.to_str()?),
            );
        }
    }

    response
        .status(StatusCode::NO_CONTENT)
        .body(body_empty())
        .map_err(|err| Box::new(err) as HyperError)
}

fn is_challenge_char(c: char) -> bool {
    // Semi-randomly chosen as a limited set of valid characters
    c.is_ascii_lowercase()
        || c.is_ascii_uppercase()
        || c.is_ascii_digit()
        || c == '.'
        || c == '-'
        || c == '_'
}

/// This is a future that never returns, drop it to cancel/abort.
async fn run_captive_portal_service(http_listener: TcpListener) -> Result<()> {
    info!("serving");

    // If this future is cancelled, this is dropped and all tasks are aborted.
    let mut tasks = JoinSet::new();

    loop {
        match http_listener.accept().await {
            Ok((stream, peer_addr)) => {
                debug!(%peer_addr, "Connection opened",);
                let handler = CaptivePortalService;

                tasks.spawn(async move {
                    let stream = relay::MaybeTlsStreamServer::Plain(stream);
                    let stream = hyper_util::rt::TokioIo::new(stream);
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(stream, handler)
                        .with_upgrades()
                        .await
                    {
                        error!("Failed to serve connection: {err:?}");
                    }
                });
            }
            Err(err) => {
                error!(
                    "[CaptivePortalService] failed to accept connection: {:#?}",
                    err
                );
            }
        }
    }
}

#[derive(Clone)]
struct CaptivePortalService;

impl hyper::service::Service<Request<Incoming>> for CaptivePortalService {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        match (req.method(), req.uri().path()) {
            // Captive Portal checker
            (&Method::GET, "/generate_204") => {
                Box::pin(async move { serve_no_content_handler(req, Response::builder()) })
            }
            _ => {
                // Return 404 not found response.
                let r = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(NOTFOUND.into())
                    .map_err(|err| Box::new(err) as HyperError);
                Box::pin(async move { r })
            }
        }
    }
}

mod metrics {
    use iroh_metrics::{
        core::{Counter, Metric},
        struct_iterable::Iterable,
    };

    /// StunMetrics tracked for the DERPER
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
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use bytes::Bytes;
    use iroh_base::node_addr::RelayUrl;

    use crate::relay::http::ClientBuilder;

    use self::relay::ReceivedMessage;

    use super::*;

    #[tokio::test]
    async fn test_no_services() {
        let _guard = iroh_test::logging::setup();
        let mut server = Server::spawn(ServerConfig::<(), ()>::default())
            .await
            .unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), server.task_handle())
            .await
            .expect("timeout, server not finished")
            .expect("server task JoinError");
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_conflicting_bind() {
        let _guard = iroh_test::logging::setup();
        let mut server = Server::spawn(ServerConfig::<(), ()> {
            relay: Some(RelayConfig {
                secret_key: SecretKey::generate(),
                http_bind_addr: (Ipv4Addr::LOCALHOST, 1234).into(),
                tls: None,
                limits: Default::default(),
            }),
            stun: None,
            metrics_addr: Some((Ipv4Addr::LOCALHOST, 1234).into()),
        })
        .await
        .unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), server.task_handle())
            .await
            .expect("timeout, server not finished")
            .expect("server task JoinError");
        assert!(res.is_err()); // AddrInUse
    }

    #[tokio::test]
    async fn test_root_handler() {
        let _guard = iroh_test::logging::setup();
        let server = Server::spawn(ServerConfig::<(), ()> {
            relay: Some(RelayConfig {
                secret_key: SecretKey::generate(),
                http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                tls: None,
                limits: Default::default(),
            }),
            stun: None,
            metrics_addr: None,
        })
        .await
        .unwrap();
        let url = format!("http://{}", server.http_addr().unwrap());

        let response = reqwest::get(&url).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        assert!(body.contains("iroh.computer"));
    }

    #[tokio::test]
    async fn test_captive_portal_service() {
        let _guard = iroh_test::logging::setup();
        let server = Server::spawn(ServerConfig::<(), ()> {
            relay: Some(RelayConfig {
                secret_key: SecretKey::generate(),
                http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                tls: None,
                limits: Default::default(),
            }),
            stun: None,
            metrics_addr: None,
        })
        .await
        .unwrap();
        let url = format!("http://{}/generate_204", server.http_addr().unwrap());
        let challenge = "123az__.";

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header(NO_CONTENT_CHALLENGE_HEADER, challenge)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let header = response.headers().get(NO_CONTENT_RESPONSE_HEADER).unwrap();
        assert_eq!(header.to_str().unwrap(), format!("response {challenge}"));
        let body = response.text().await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_relay_clients() {
        let _guard = iroh_test::logging::setup();
        let server = Server::spawn(ServerConfig::<(), ()> {
            relay: Some(RelayConfig {
                secret_key: SecretKey::generate(),
                http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                tls: None,
                limits: Default::default(),
            }),
            stun: None,
            metrics_addr: None,
        })
        .await
        .unwrap();
        let relay_url = format!("http://{}", server.http_addr().unwrap());
        let relay_url: RelayUrl = relay_url.parse().unwrap();

        // set up client a
        let a_secret_key = SecretKey::generate();
        let a_key = a_secret_key.public();
        let resolver = crate::dns::default_resolver().clone();
        let (client_a, mut client_a_receiver) =
            ClientBuilder::new(relay_url.clone()).build(a_secret_key, resolver);
        let connect_client = client_a.clone();

        // give the relay server some time to accept connections
        if let Err(err) = tokio::time::timeout(Duration::from_secs(10), async move {
            loop {
                match connect_client.connect().await {
                    Ok(_) => break,
                    Err(err) => {
                        warn!("client unable to connect to relay server: {err:#}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        })
        .await
        {
            panic!("error connecting to relay server: {err:#}");
        }

        // set up client b
        let b_secret_key = SecretKey::generate();
        let b_key = b_secret_key.public();
        let resolver = crate::dns::default_resolver().clone();
        let (client_b, mut client_b_receiver) =
            ClientBuilder::new(relay_url.clone()).build(b_secret_key, resolver);
        client_b.connect().await.unwrap();

        // send message from a to b
        let msg = Bytes::from("hello, b");
        client_a.send(b_key, msg.clone()).await.unwrap();

        let (res, _) = client_b_receiver.recv().await.unwrap().unwrap();
        if let ReceivedMessage::ReceivedPacket { source, data } = res {
            assert_eq!(a_key, source);
            assert_eq!(msg, data);
        } else {
            panic!("client_b received unexpected message {res:?}");
        }

        // send message from b to a
        let msg = Bytes::from("howdy, a");
        client_b.send(a_key, msg.clone()).await.unwrap();

        let (res, _) = client_a_receiver.recv().await.unwrap().unwrap();
        if let ReceivedMessage::ReceivedPacket { source, data } = res {
            assert_eq!(b_key, source);
            assert_eq!(msg, data);
        } else {
            panic!("client_a received unexpected message {res:?}");
        }
    }

    #[tokio::test]
    async fn test_stun() {
        let _guard = iroh_test::logging::setup();
        let server = Server::spawn(ServerConfig::<(), ()> {
            relay: None,
            stun: Some(StunConfig {
                bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
            }),
            metrics_addr: None,
        })
        .await
        .unwrap();

        let txid = stun::TransactionId::default();
        let req = stun::request(txid);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&req, server.stun_addr().unwrap())
            .await
            .unwrap();

        // get response
        let mut buf = vec![0u8; 64000];
        let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(addr, server.stun_addr().unwrap());
        buf.truncate(len);
        let (txid_back, response_addr) = stun::parse_response(&buf).unwrap();
        assert_eq!(txid, txid_back);
        assert_eq!(response_addr, socket.local_addr().unwrap());
    }
}
