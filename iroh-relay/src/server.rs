//! A fully-fledged iroh-relay server over HTTP or HTTPS.
//!
//! This module provides an API to run a full fledged iroh-relay server.  It is primarily
//! used by the `iroh-relay` binary in this crate.  It can be used to run a relay server in
//! other locations however.
//!
//! This code is fully written in a form of structured-concurrency: every spawned task is
//! always attached to a handle and when the handle is dropped the tasks abort.  So tasks
//! can not outlive their handle.  It is also always possible to await for completion of a
//! task.  Some tasks additionally have a method to do graceful shutdown.
//!
//! The relay server hosts the following services:
//!
//! - HTTPS `/relay`: The main URL endpoint to which clients connect and sends traffic over.
//! - HTTPS `/ping`: Used for net_report probes.
//! - HTTPS `/generate_204`: Used for net_report probes.

use std::{fmt, future::Future, net::SocketAddr, num::NonZeroU32, pin::Pin, sync::Arc};

use derive_more::Debug;
use http::{
    header::InvalidHeaderValue, response::Builder as ResponseBuilder, HeaderMap, Method, Request,
    Response, StatusCode,
};
use hyper::body::Incoming;
use iroh_base::NodeId;
#[cfg(feature = "test-utils")]
use iroh_base::RelayUrl;
use n0_future::{future::Boxed, StreamExt};
use nested_enum_utils::common_fields;
use snafu::{Backtrace, ResultExt, Snafu};
use tokio::{
    net::TcpListener,
    task::{JoinError, JoinSet},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, error, info, info_span, instrument, Instrument};

use crate::{
    defaults::DEFAULT_KEY_CACHE_CAPACITY,
    http::RELAY_PROBE_PATH,
    quic::server::{QuicServer, QuicSpawnError, ServerHandle as QuicServerHandle},
};

mod client;
mod clients;
mod http_server;
mod metrics;
pub(crate) mod resolver;
pub(crate) mod streams;
#[cfg(feature = "test-utils")]
pub mod testing;

pub use self::{
    metrics::{Metrics, RelayMetrics},
    resolver::{ReloadingResolver, DEFAULT_CERT_RELOAD_INTERVAL},
};

const NO_CONTENT_CHALLENGE_HEADER: &str = "X-Tailscale-Challenge";
const NO_CONTENT_RESPONSE_HEADER: &str = "X-Tailscale-Response";
const NOTFOUND: &[u8] = b"Not Found";
const ROBOTS_TXT: &[u8] = b"User-agent: *\nDisallow: /\n";
const INDEX: &[u8] = br#"<html><body>
<h1>Iroh Relay</h1>
<p>
  This is an <a href="https://iroh.computer/">Iroh</a> Relay server.
</p>
"#;
const TLS_HEADERS: [(&str, &str); 2] = [
    (
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    ),
    (
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'self'; block-all-mixed-content; plugin-types 'none'",
    ),
];

type BytesBody = http_body_util::Full<hyper::body::Bytes>;
type HyperError = Box<dyn std::error::Error + Send + Sync>;
type HyperResult<T> = std::result::Result<T, HyperError>;

/// Creates a new [`BytesBody`] with no content.
fn body_empty() -> BytesBody {
    http_body_util::Full::new(hyper::body::Bytes::new())
}

/// Configuration for the full Relay.
///
/// Be aware the generic parameters are for when using the Let's Encrypt TLS configuration.
/// If not used dummy ones need to be provided, e.g. `ServerConfig::<(), ()>::default()`.
#[derive(Debug, Default)]
pub struct ServerConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// Configuration for the Relay server, disabled if `None`.
    pub relay: Option<RelayConfig<EC, EA>>,
    /// Configuration for the QUIC server, disabled if `None`.
    pub quic: Option<QuicConfig>,
    /// Socket to serve metrics on.
    #[cfg(feature = "metrics")]
    pub metrics_addr: Option<SocketAddr>,
}

/// Configuration for the Relay HTTP and HTTPS server.
///
/// This includes the HTTP services hosted by the Relay server, the Relay `/relay` HTTP
/// endpoint is only one of the services served.
#[derive(Debug)]
pub struct RelayConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
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
    /// Key cache capacity.
    pub key_cache_capacity: Option<usize>,
    /// Access configuration.
    pub access: AccessConfig,
}

/// Controls which nodes are allowed to use the relay.
#[derive(derive_more::Debug)]
pub enum AccessConfig {
    /// Everyone
    Everyone,
    /// Only nodes for which the function returns `Access::Allow`.
    #[debug("restricted")]
    Restricted(Box<dyn Fn(NodeId) -> Boxed<Access> + Send + Sync + 'static>),
}

impl AccessConfig {
    /// Is this node allowed?
    pub async fn is_allowed(&self, node: NodeId) -> bool {
        match self {
            Self::Everyone => true,
            Self::Restricted(check) => {
                let res = check(node).await;
                matches!(res, Access::Allow)
            }
        }
    }
}

/// Access restriction for a node.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Access {
    /// Access is allowed.
    Allow,
    /// Access is denied.
    Deny,
}

/// Configuration for the QUIC server.
#[derive(Debug)]
pub struct QuicConfig {
    /// The socket address on which the QUIC server should bind.
    ///
    /// Normally you'd chose port `7842`, see [`crate::defaults::DEFAULT_RELAY_QUIC_PORT`].
    pub bind_addr: SocketAddr,
    /// The TLS server configuration for the QUIC server.
    ///
    /// If this [`rustls::ServerConfig`] does not support TLS 1.3, the QUIC server will fail
    /// to spawn.
    pub server_config: rustls::ServerConfig,
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
    /// The socket address on which to server the QUIC server is QUIC is enabled.
    pub quic_bind_addr: SocketAddr,
    /// Mode for getting a cert.
    pub cert: CertConfig<EC, EA>,
    /// The server configuration.
    pub server_config: rustls::ServerConfig,
}

/// Rate limits.
// TODO: accept_conn_limit and accept_conn_burst are not currently implemented.
#[derive(Debug, Default)]
pub struct Limits {
    /// Rate limit for accepting new connection. Unlimited if not set.
    pub accept_conn_limit: Option<f64>,
    /// Burst limit for accepting new connection. Unlimited if not set.
    pub accept_conn_burst: Option<usize>,
    /// Rate limits for incoming traffic from a client connection.
    pub client_rx: Option<ClientRateLimit>,
}

/// Per-client rate limit configuration.
#[derive(Debug, Copy, Clone)]
pub struct ClientRateLimit {
    /// Max number of bytes per second to read from the client connection.
    pub bytes_per_second: NonZeroU32,
    /// Max number of bytes to read in a single burst.
    pub max_burst_bytes: Option<NonZeroU32>,
}

/// TLS certificate configuration.
#[derive(derive_more::Debug)]
pub enum CertConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// Use Let's Encrypt.
    LetsEncrypt {
        /// State for Let's Encrypt certificates.
        #[debug("AcmeConfig")]
        state: tokio_rustls_acme::AcmeState<EC, EA>,
    },
    /// Use a static TLS key and certificate chain.
    Manual {
        /// The TLS certificate chain.
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    },
    /// Use a TLS key and certificate chain that can be reloaded.
    Reloading,
}

/// A running Relay + QAD server.
///
/// This is a full Relay server, including QAD, Relay and various associated HTTP services.
///
/// Dropping this will stop the server.
#[derive(Debug)]
pub struct Server {
    /// The address of the HTTP server, if configured.
    http_addr: Option<SocketAddr>,
    /// The address of the HTTPS server, if the relay server is using TLS.
    ///
    /// If the Relay server is not using TLS then it is served from the
    /// [`Server::http_addr`].
    https_addr: Option<SocketAddr>,
    /// The address of the QUIC server, if configured.
    quic_addr: Option<SocketAddr>,
    /// Handle to the relay server.
    relay_handle: Option<http_server::ServerHandle>,
    /// Handle to the quic server.
    quic_handle: Option<QuicServerHandle>,
    /// The main task running the server.
    supervisor: AbortOnDropHandle<Result<(), SupervisorError>>,
    /// The certificate for the server.
    ///
    /// If the server has manual certificates configured the certificate chain will be
    /// available here, this can be used by a client to authenticate the server.
    certificates: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
    metrics: RelayMetrics,
}

/// Server spawn errors
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SpawnError {
    #[snafu(display("Unable to get local address"))]
    LocalAddr { source: std::io::Error },
    #[snafu(display("Failed to bind QAD listener"))]
    QuicSpawn { source: QuicSpawnError },
    #[snafu(display("Failed to parse TLS header"))]
    TlsHeaderParse { source: InvalidHeaderValue },
    #[snafu(display("Failed to bind TcpListener"))]
    BindTlsListener { source: std::io::Error },
    #[snafu(display("No local address"))]
    NoLocalAddr { source: std::io::Error },
    #[snafu(display("Failed to bind server socket to {addr}"))]
    BindTcpListener { addr: SocketAddr },
}

/// Server task errors
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SupervisorError {
    #[snafu(display("Error starting metrics server"))]
    Metrics { source: std::io::Error },
    #[snafu(display("Acme event stream finished"))]
    AcmeEventStreamFinished {},
    #[snafu(transparent)]
    JoinError { source: JoinError },
    #[snafu(display("No relay services are enabled"))]
    NoRelayServicesEnabled {},
    #[snafu(display("Task cancelled"))]
    TaskCancelled {},
}

impl Server {
    /// Starts the server.
    pub async fn spawn<EC, EA>(config: ServerConfig<EC, EA>) -> Result<Self, SpawnError>
    where
        EC: fmt::Debug + 'static,
        EA: fmt::Debug + 'static,
    {
        let mut tasks = JoinSet::new();

        let metrics = RelayMetrics::default();

        #[cfg(feature = "metrics")]
        if let Some(addr) = config.metrics_addr {
            debug!("Starting metrics server");
            let mut registry = iroh_metrics::Registry::default();
            registry.register_all(&metrics);
            tasks.spawn(
                async move {
                    iroh_metrics::service::start_metrics_server(addr, Arc::new(registry))
                        .await
                        .context(MetricsSnafu)
                }
                .instrument(info_span!("metrics-server")),
            );
        }

        // Start the Relay server, but first clone the certs out.
        let certificates = config.relay.as_ref().and_then(|relay| {
            relay.tls.as_ref().and_then(|tls| match tls.cert {
                CertConfig::LetsEncrypt { .. } => None,
                CertConfig::Manual { ref certs, .. } => Some(certs.clone()),
                CertConfig::Reloading => None,
            })
        });

        let quic_server = match config.quic {
            Some(quic_config) => {
                debug!("Starting QUIC server {}", quic_config.bind_addr);
                Some(QuicServer::spawn(quic_config).context(QuicSpawnSnafu)?)
            }
            None => None,
        };
        let quic_addr = quic_server.as_ref().map(|srv| srv.bind_addr());
        let quic_handle = quic_server.as_ref().map(|srv| srv.handle());

        let (relay_server, http_addr) = match config.relay {
            Some(relay_config) => {
                debug!("Starting Relay server");
                let mut headers = HeaderMap::new();
                for (name, value) in TLS_HEADERS.iter() {
                    headers.insert(*name, value.parse().context(TlsHeaderParseSnafu)?);
                }
                let relay_bind_addr = match relay_config.tls {
                    Some(ref tls) => tls.https_bind_addr,
                    None => relay_config.http_bind_addr,
                };
                let key_cache_capacity = relay_config
                    .key_cache_capacity
                    .unwrap_or(DEFAULT_KEY_CACHE_CAPACITY);
                let mut builder = http_server::ServerBuilder::new(relay_bind_addr)
                    .metrics(metrics.server.clone())
                    .headers(headers)
                    .key_cache_capacity(key_cache_capacity)
                    .access(relay_config.access)
                    .request_handler(Method::GET, "/", Box::new(root_handler))
                    .request_handler(Method::GET, "/index.html", Box::new(root_handler))
                    .request_handler(Method::GET, RELAY_PROBE_PATH, Box::new(probe_handler))
                    .request_handler(Method::GET, "/robots.txt", Box::new(robots_handler));
                if let Some(cfg) = relay_config.limits.client_rx {
                    builder = builder.client_rx_ratelimit(cfg);
                }
                let http_addr = match relay_config.tls {
                    Some(tls_config) => {
                        let server_tls_config = match tls_config.cert {
                            CertConfig::LetsEncrypt { mut state } => {
                                let acceptor =
                                    http_server::TlsAcceptor::LetsEncrypt(state.acceptor());
                                tasks.spawn(
                                    async move {
                                        while let Some(event) = state.next().await {
                                            match event {
                                                Ok(ok) => debug!("acme event: {ok:?}"),
                                                Err(err) => error!("error: {err:?}"),
                                            }
                                        }
                                        Err(AcmeEventStreamFinishedSnafu.build())
                                    }
                                    .instrument(info_span!("acme")),
                                );
                                Some(http_server::TlsConfig {
                                    config: Arc::new(tls_config.server_config),
                                    acceptor,
                                })
                            }
                            CertConfig::Manual { .. } | CertConfig::Reloading => {
                                let server_config = Arc::new(tls_config.server_config);
                                let acceptor =
                                    tokio_rustls::TlsAcceptor::from(server_config.clone());
                                let acceptor = http_server::TlsAcceptor::Manual(acceptor);
                                Some(http_server::TlsConfig {
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
                            .context(BindTlsListenerSnafu)?;
                        let http_addr = http_listener.local_addr().context(NoLocalAddrSnafu)?;
                        tasks.spawn(
                            async move {
                                run_captive_portal_service(http_listener).await;
                                Ok(())
                            }
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
        let task = tokio::spawn(relay_supervisor(tasks, relay_server, quic_server));

        Ok(Self {
            http_addr: http_addr.or(relay_addr),
            https_addr: http_addr.and(relay_addr),
            quic_addr,
            relay_handle,
            quic_handle,
            supervisor: AbortOnDropHandle::new(task),
            certificates,
            metrics,
        })
    }

    /// Requests graceful shutdown.
    ///
    /// Returns once all server tasks have stopped.
    pub async fn shutdown(self) -> Result<(), SupervisorError> {
        // Only the Relay server and QUIC server need shutting down, the supervisor will abort the tasks in
        // the JoinSet when the server terminates.
        if let Some(handle) = self.relay_handle {
            handle.shutdown();
        }
        if let Some(handle) = self.quic_handle {
            handle.shutdown();
        }
        self.supervisor.await?
    }

    /// Returns the handle for the task.
    ///
    /// This allows waiting for the server's supervisor task to finish.  Can be useful in
    /// case there is an error in the server before it is shut down.
    pub fn task_handle(&mut self) -> &mut AbortOnDropHandle<Result<(), SupervisorError>> {
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

    /// The socket address the QUIC server is listening on.
    pub fn quic_addr(&self) -> Option<SocketAddr> {
        self.quic_addr
    }

    /// The certificates chain if configured with manual TLS certificates.
    pub fn certificates(&self) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        self.certificates.clone()
    }

    /// Get the server's https [`RelayUrl`].
    ///
    /// This uses [`Self::https_addr`] so it's mostly useful for local development.
    #[cfg(feature = "test-utils")]
    pub fn https_url(&self) -> Option<RelayUrl> {
        self.https_addr.map(|addr| {
            url::Url::parse(&format!("https://{addr}"))
                .expect("valid url")
                .into()
        })
    }

    /// Get the server's http [`RelayUrl`].
    ///
    /// This uses [`Self::http_addr`] so it's mostly useful for local development.
    #[cfg(feature = "test-utils")]
    pub fn http_url(&self) -> Option<RelayUrl> {
        self.http_addr.map(|addr| {
            url::Url::parse(&format!("http://{addr}"))
                .expect("valid url")
                .into()
        })
    }

    /// Returns the metrics collected in the relay server.
    pub fn metrics(&self) -> &RelayMetrics {
        &self.metrics
    }
}

/// Supervisor for the relay server tasks.
///
/// As soon as one of the tasks exits, all other tasks are stopped and the server stops.
/// The supervisor finishes once all tasks are finished.
#[instrument(skip_all)]
async fn relay_supervisor(
    mut tasks: JoinSet<Result<(), SupervisorError>>,
    mut relay_http_server: Option<http_server::Server>,
    mut quic_server: Option<QuicServer>,
) -> Result<(), SupervisorError> {
    let quic_enabled = quic_server.is_some();
    let mut quic_fut = match quic_server {
        Some(ref mut server) => n0_future::Either::Left(server.task_handle()),
        None => n0_future::Either::Right(n0_future::future::pending()),
    };
    let relay_enabled = relay_http_server.is_some();
    let mut relay_fut = match relay_http_server {
        Some(ref mut server) => n0_future::Either::Left(server.task_handle()),
        None => n0_future::Either::Right(n0_future::future::pending()),
    };
    let res = tokio::select! {
        biased;
        Some(ret) = tasks.join_next() => ret,
        ret = &mut quic_fut, if quic_enabled => ret.map(Ok),
        ret = &mut relay_fut, if relay_enabled => ret.map(Ok),
        else => Ok(Err(NoRelayServicesEnabledSnafu.build())),
    };
    let ret = match res {
        Ok(Ok(())) => {
            debug!("Task exited");
            Ok(())
        }
        Ok(Err(err)) => {
            error!(%err, "Task failed");
            Err(err)
        }
        Err(err) => {
            if let Ok(panic) = err.try_into_panic() {
                error!("Task panicked");
                std::panic::resume_unwind(panic);
            }
            debug!("Task cancelled");
            Err(TaskCancelledSnafu.build())
        }
    };

    // Ensure the HTTP server terminated, there is no harm in calling this after it is
    // already shut down.
    if let Some(server) = relay_http_server {
        server.shutdown();
    }

    // Ensure the QUIC server is closed
    if let Some(server) = quic_server {
        server.shutdown().await;
    }

    // Stop all remaining tasks
    tasks.shutdown().await;

    ret
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
async fn run_captive_portal_service(http_listener: TcpListener) {
    info!("serving");

    // If this future is cancelled, this is dropped and all tasks are aborted.
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;

            Some(res) = tasks.join_next() => {
                if let Err(err) = res {
                    if err.is_panic() {
                        panic!("task panicked: {err:#?}");
                    }
                }
            }

            res = http_listener.accept() => {
                match res {
                    Ok((stream, peer_addr)) => {
                        debug!(%peer_addr, "Connection opened",);
                        let handler = CaptivePortalService;

                        tasks.spawn(async move {
                            let stream = crate::server::streams::MaybeTlsStream::Plain(stream);
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

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use bytes::Bytes;
    use http::StatusCode;
    use iroh_base::{NodeId, RelayUrl, SecretKey};
    use n0_future::{FutureExt, SinkExt, StreamExt};
    use n0_snafu::Result;
    use tracing::{info, instrument};
    use tracing_test::traced_test;

    use super::{
        Access, AccessConfig, RelayConfig, Server, ServerConfig, SpawnError,
        NO_CONTENT_CHALLENGE_HEADER, NO_CONTENT_RESPONSE_HEADER,
    };
    use crate::{
        client::{ClientBuilder, ConnectError},
        dns::DnsResolver,
        protos::{
            handshake,
            relay::{ClientToRelayMsg, RelayToClientMsg},
        },
    };

    async fn spawn_local_relay() -> std::result::Result<Server, SpawnError> {
        Server::spawn(ServerConfig::<(), ()> {
            relay: Some(RelayConfig::<(), ()> {
                http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                tls: None,
                limits: Default::default(),
                key_cache_capacity: Some(1024),
                access: AccessConfig::Everyone,
            }),
            quic: None,
            metrics_addr: None,
        })
        .await
    }

    #[instrument]
    async fn try_send_recv(
        client_a: &mut crate::client::Client,
        client_b: &mut crate::client::Client,
        b_key: NodeId,
        msg: Bytes,
    ) -> Result<RelayToClientMsg> {
        // try resend 10 times
        for _ in 0..10 {
            client_a
                .send(ClientToRelayMsg::SendPacket {
                    dst_key: b_key,
                    packet: msg.clone(),
                })
                .await?;
            let Ok(res) = tokio::time::timeout(Duration::from_millis(500), client_b.next()).await
            else {
                continue;
            };
            let res = res.expect("stream finished")?;
            return Ok(res);
        }
        panic!("failed to send and recv message");
    }

    fn dns_resolver() -> DnsResolver {
        DnsResolver::new()
    }

    #[tokio::test]
    #[traced_test]
    async fn test_no_services() {
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
    #[traced_test]
    async fn test_conflicting_bind() {
        let mut server = Server::spawn(ServerConfig::<(), ()> {
            relay: Some(RelayConfig {
                http_bind_addr: (Ipv4Addr::LOCALHOST, 1234).into(),
                tls: None,
                limits: Default::default(),
                key_cache_capacity: Some(1024),
                access: AccessConfig::Everyone,
            }),
            quic: None,
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
    #[traced_test]
    async fn test_root_handler() {
        let server = spawn_local_relay().await.unwrap();
        let url = format!("http://{}", server.http_addr().unwrap());

        let response = reqwest::get(&url).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        assert!(body.contains("iroh.computer"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_captive_portal_service() {
        let server = spawn_local_relay().await.unwrap();
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
    #[traced_test]
    async fn test_relay_clients() -> Result<()> {
        let server = spawn_local_relay().await?;

        let relay_url = format!("http://{}", server.http_addr().unwrap());
        let relay_url: RelayUrl = relay_url.parse()?;

        // set up client a
        let a_secret_key = SecretKey::generate(rand::thread_rng());
        let a_key = a_secret_key.public();
        let resolver = dns_resolver();
        info!("client a build & connect");
        let mut client_a = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver.clone())
            .connect()
            .await?;

        // set up client b
        let b_secret_key = SecretKey::generate(rand::thread_rng());
        let b_key = b_secret_key.public();
        info!("client b build & connect");
        let mut client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver.clone())
            .connect()
            .await?;

        info!("sending a -> b");

        // send message from a to b
        let msg = Bytes::from_static(b"hello, b");
        let res = try_send_recv(&mut client_a, &mut client_b, b_key, msg.clone()).await?;
        let RelayToClientMsg::ReceivedPacket { src_key, content } = res else {
            panic!("client_b received unexpected message {res:?}");
        };

        assert_eq!(a_key, src_key);
        assert_eq!(msg, content);

        info!("sending b -> a");
        // send message from b to a
        let msg = Bytes::from_static(b"howdy, a");
        let res = try_send_recv(&mut client_b, &mut client_a, a_key, msg.clone()).await?;

        let RelayToClientMsg::ReceivedPacket { src_key, content } = res else {
            panic!("client_a received unexpected message {res:?}");
        };

        assert_eq!(b_key, src_key);
        assert_eq!(msg, content);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_relay_access_control() -> Result<()> {
        let current_span = tracing::info_span!("this is a test");
        let _guard = current_span.enter();

        let a_secret_key = SecretKey::generate(rand::thread_rng());
        let a_key = a_secret_key.public();

        let server = Server::spawn(ServerConfig::<(), ()> {
            relay: Some(RelayConfig::<(), ()> {
                http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                tls: None,
                limits: Default::default(),
                key_cache_capacity: Some(1024),
                access: AccessConfig::Restricted(Box::new(move |node_id| {
                    async move {
                        info!("checking {}", node_id);
                        // reject node a
                        if node_id == a_key {
                            Access::Deny
                        } else {
                            Access::Allow
                        }
                    }
                    .boxed()
                })),
            }),
            quic: None,
            metrics_addr: None,
        })
        .await?;

        let relay_url = format!("http://{}", server.http_addr().unwrap());
        let relay_url: RelayUrl = relay_url.parse()?;

        // set up client a
        let resolver = dns_resolver();
        let result = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver)
            .connect()
            .await;

        assert!(
            matches!(result, Err(ConnectError::Handshake { source: handshake::Error::ServerDeniedAuth { reason, .. }, .. }) if reason == "not authorized")
        );

        // test that another client has access

        // set up client b
        let b_secret_key = SecretKey::generate(rand::thread_rng());
        let b_key = b_secret_key.public();

        let resolver = dns_resolver();
        let mut client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver)
            .connect()
            .await?;

        // set up client c
        let c_secret_key = SecretKey::generate(rand::thread_rng());
        let c_key = c_secret_key.public();

        let resolver = dns_resolver();
        let mut client_c = ClientBuilder::new(relay_url.clone(), c_secret_key, resolver)
            .connect()
            .await?;

        // send message from b to c
        let msg = Bytes::from_static(b"hello, c");
        let res = try_send_recv(&mut client_b, &mut client_c, c_key, msg.clone()).await?;

        if let RelayToClientMsg::ReceivedPacket { src_key, content } = res {
            assert_eq!(b_key, src_key);
            assert_eq!(msg, content);
        } else {
            panic!("client_c received unexpected message {res:?}");
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_relay_clients_full() -> Result<()> {
        let server = spawn_local_relay().await.unwrap();
        let relay_url = format!("http://{}", server.http_addr().unwrap());
        let relay_url: RelayUrl = relay_url.parse().unwrap();

        // set up client a
        let a_secret_key = SecretKey::generate(rand::thread_rng());
        let resolver = dns_resolver();
        let mut client_a = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver.clone())
            .connect()
            .await?;

        // set up client b
        let b_secret_key = SecretKey::generate(rand::thread_rng());
        let b_key = b_secret_key.public();
        let _client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver.clone())
            .connect()
            .await?;

        // send messages from a to b, without b receiving anything.
        // we should still keep succeeding to send, even if the packet won't be forwarded
        // by the relay server because the server's send queue for b fills up.
        let msg = Bytes::from_static(b"hello, b");
        for _i in 0..1000 {
            client_a
                .send(ClientToRelayMsg::SendPacket {
                    dst_key: b_key,
                    packet: msg.clone(),
                })
                .await?;
        }
        Ok(())
    }
}
