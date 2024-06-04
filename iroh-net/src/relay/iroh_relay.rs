//! A full-fledged iroh-relay server.
//!
//! This module provides an API to create a full fledged iroh-relay server.  It is primarily
//! used by the `iroh-relay` binary in this crate.

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
use crate::relay::http::{ServerBuilder as DerpServerBuilder, TlsAcceptor};
use crate::stun;
use crate::util::AbortingJoinHandle;

// Module defined in this file.
use metrics::StunMetrics;

const NO_CONTENT_CHALLENGE_HEADER: &str = "X-Tailscale-Challenge";
const NO_CONTENT_RESPONSE_HEADER: &str = "X-Tailscale-Response";
const NOTFOUND: &[u8] = b"Not Found";
const RELAY_DISABLED: &[u8] = b"derp server disabled";
const ROBOTS_TXT: &[u8] = b"User-agent: *\nDisallow: /\n";
const INDEX: &[u8] = br#"<html><body>
<h1>DERP</h1>
<p>
  This is an
  <a href="https://iroh.computer/">Iroh</a> DERP
  server.
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
#[derive(Debug)]
#[non_exhaustive]
pub struct ServerConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// Configuration for the DERP server, disabled if `None`.
    pub relay: Option<RelayConfig<EC, EA>>,
    /// Configuration for the STUN server, disabled if `None`.
    pub stun: Option<StunConfig>,
    /// Socket to serve metrics on.
    pub metrics_addr: Option<SocketAddr>,
}

impl<EC: fmt::Debug, EA: fmt::Debug> ServerConfig<EC, EA> {
    /// Creates a new config.
    pub fn new() -> Self {
        Self {
            relay: None,
            stun: None,
            metrics_addr: None,
        }
    }

    /// Validates the config for internal consistency.
    pub fn validate(&self) -> Result<()> {
        // todo: check all bind addrs are different.  Though if done correctly the server
        // will just fail to start and show an approriate error, so maybe we shouldn't be
        // validating at all.
        if self.relay.is_none() && self.stun.is_none() {
            bail!("neither DERP nor STUN server configured");
        }
        if let Some(derp) = &self.relay {
            if let Some(tls) = &derp.tls {
                if derp.bind_addr == tls.http_bind_addr {
                    bail!("derp port conflicts with captive portal port");
                }
            }
        }
        Ok(())
    }
}

/// Configuration for the Relay server.
///
/// This includes the HTTP services hosted by the Relay server, the Relay HTTP endpoint is
/// only one of the services served.
#[derive(Debug)]
#[non_exhaustive]
pub struct RelayConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// The socket address on which the relay server should bind.
    ///
    /// Normally you'd choose port `80` if configured without TLS and port `443` when
    /// configured with TLS since the DERP server is an HTTP server.
    pub bind_addr: SocketAddr,
    /// The iroh secret key of the Relay server.
    pub secret_key: SecretKey,
    /// TLS configuration, no TLS is used if `None`.
    pub tls: Option<TlsConfig<EC, EA>>,
    /// Rate limits, if enabled.
    pub limits: Option<Limits>,
}

/// Configuration for the STUN server.
#[derive(Debug)]
#[non_exhaustive]
pub struct StunConfig {
    /// The socket address on which the STUN server should bind.
    ///
    /// Normally you'd chose port `3478`, see [`crate::defaults::DEFAULT_DERP_STUN_SERVER`].
    pub bind_addr: SocketAddr,
}

/// TLS configuration for DERP server.
///
/// Normally the DERP server accepts connections on HTTPS.
#[derive(Debug)]
#[non_exhaustive]
pub struct TlsConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// Mode for getting a cert.
    pub cert: CertConfig<EC, EA>,
    /// Hostname to use for the certificate, must match the certificate.
    pub hostname: String,
    /// The socket address on which to serve plain text HTTP requests.
    ///
    /// Since the captive portal probe has to run over plain text HTTP and TLS is used for
    /// the main relay server this has to be on a different port.  When TLS is not enabled
    /// this is served on the [`RelayConfig::bind_addr`] socket address.
    ///
    /// Normally you'd choose port `80`.
    pub http_bind_addr: SocketAddr,
}

/// Rate limits.
#[derive(Debug)]
#[non_exhaustive]
pub struct Limits {
    /// Rate limit for accepting new connection. Unlimited if not set.
    pub accept_conn_limit: Option<f64>,
    /// Burst limit for accepting new connection. Unlimited if not set.
    pub accept_conn_burst: Option<usize>,
}

/// TLS certificate configuration.
#[derive(derive_more::Debug)]
#[non_exhaustive]
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
    _supervisor: AbortingJoinHandle<Result<()>>,
}

impl Server {
    /// Starts the server.
    pub async fn spawn<EC, EA>(config: ServerConfig<EC, EA>) -> Result<Self>
    where
        EC: fmt::Debug + 'static,
        EA: fmt::Debug + 'static,
    {
        config.validate()?;
        let mut tasks = JoinSet::new();

        // Start the STUN server.
        let stun_addr = match config.stun {
            Some(stun) => match UdpSocket::bind(stun.bind_addr).await {
                Ok(sock) => {
                    let addr = sock.local_addr()?;
                    tasks.spawn(
                        server_stun_listener(sock).instrument(info_span!("stun-server", %addr)),
                    );
                    Some(addr)
                }
                Err(err) => bail!("failed to bind STUN listener: {err:#?}"),
            },
            None => None,
        };

        // Start the Relay server.
        let (relay_server, http_addr) = match config.relay {
            Some(relay_config) => {
                let mut headers = HeaderMap::new();
                for (name, value) in TLS_HEADERS.iter() {
                    headers.insert(*name, value.parse()?);
                }
                let mut builder = DerpServerBuilder::new(relay_config.bind_addr)
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
                        let http_listener = TcpListener::bind(&tls_config.http_bind_addr)
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
                        // If running DERP without TLS add the plain HTTP server directly to the
                        // DERP server.
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
            https_addr: http_addr.and_then(|_| relay_addr),
            relay_handle,
            _supervisor: AbortingJoinHandle::from(task),
        })
    }

    /// Graceful shutdown.
    pub async fn shutdown(self) {
        // Only the Relay server needs shutting down, all other services only abort on drop.
        if let Some(handle) = self.relay_handle {
            handle.shutdown();
        }
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
#[instrument(skip_all)]
async fn relay_supervisor(
    mut tasks: JoinSet<Result<()>>,
    mut relay_http_server: Option<RelayHttpServerGuard>,
) -> Result<()> {
    let res = tokio::select! {
        biased;
        Some(ret) = tasks.join_next() => ret,
        ret = relay_http_server.as_mut().expect("protected by if branch").0.task_handle(),
            if relay_http_server.is_some()
            => ret.map(|res| Ok(res)),
        else => Ok(Err(anyhow!("Empty JoinSet"))),
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
    relay_http_server.map(|server| server.0.shutdown());

    ret
}

// /// Supervisor for a set of fallible tasks.
// ///
// /// As soon as one of the tasks fails, the supervisor will exit with a failure.  Thus
// /// dropping the [`JoinSet`] and aborting all remaining tasks.
// async fn supervisor(mut tasks: JoinSet<Result<()>>) -> Result<()> {
//     while let Some(res) = tasks.join_next().await {
//         match res {
//             Ok(_) => continue,
//             Err(err) => bail!("Task failed: {err:#}"),
//         }
//     }
//     Ok(())
// }

// /// An actor which supervises other tasks, with no restarting and one-for-all strategy.
// ///
// /// The supervisor itself does no restarting of tasks.  It only terminates all other tasks
// /// when one fails.  It is essentially a one-for-all supervisor strategy with a max-restarts
// /// count of 0.
// #[derive(Debug)]
// struct TaskSupervisor {
//     addr_tx: mpsc::Sender<SupervisorMessage>,
//     addr_rx: mpsc::Receiver<SupervisorMessage>,
//     tasks: FuturesUnordered<JoinHandle<Result<()>>>,
// }

// impl TaskSupervisor {
//     fn new() -> Self {
//         let (addr_tx, addr_rx) = mpsc::channel(16);
//         Self {
//             addr_tx,
//             addr_rx,
//             tasks: FuturesUnordered::new(),
//         }
//     }

//     async fn run(&mut self) {
//         // Note this can never fail!
//         loop {
//             tokio::select! {
//                 biased;
//                 res = self.addr_rx.recv() => {
//                     match res {
//                         Some(msg) => self.handle_msg(msg),
//                         None => {
//                             error!("All senders closed, impossible");
//                             break;
//                         }
//                     }
//                 }
//                 item = self.tasks.next() => {
//                     match item {
//                         Some(res) => {
//                             self.handle_task_finished(res);
//                             if self.tasks.is_terminated() {
//                                 break;
//                             }
//                         }
//                         None => break,
//                     }
//                 }
//             }
//         }
//         debug!("Supervisor finished");
//     }

//     fn handle_msg(&mut self, msg: SupervisorMessage) {
//         match msg {
//             SupervisorMessage::AddTask(task) => {
//                 self.tasks.push(task);
//             }
//             SupervisorMessage::Abort => {
//                 for task in self.tasks.iter() {
//                     task.abort();
//                 }
//             }
//         }
//     }

//     fn handle_task_finished(&mut self, res: Result<Result<()>, JoinError>) {
//         match res {
//             Ok(Ok(())) => info!("Supervised task gracefully finished, aborting others"),
//             Ok(Err(err)) => error!("Supervised task failed, aborting others.  err: {err}"),
//             Err(err) => {
//                 if err.is_cancelled() {
//                     info!("Supervised task cancelled, aborting others");
//                 }
//                 if err.is_panic() {
//                     // TODO: We just swallow the panic.  Unfortunately we can only resume
//                     // it, which is not (yet?) what we want?  Or maybe it is.
//                     error!("Supervised task paniced, aborting others");
//                 }
//             }
//         }
//         for task in self.tasks.iter() {
//             task.abort();
//         }
//     }

//     fn addr(&self) -> SupervisorAddr {
//         SupervisorAddr {
//             tx: self.addr_tx.clone(),
//         }
//     }
// }

// #[derive(Debug)]
// enum SupervisorMessage {
//     AddTask(JoinHandle<Result<()>>),
//     Abort,
// }

// #[derive(Debug)]
// struct SupervisorAddr {
//     tx: mpsc::Sender<SupervisorMessage>,
// }

// impl SupervisorAddr {
//     fn add_task(
//         &self,
//         task: JoinHandle<Result<()>>,
//     ) -> Result<(), mpsc::error::TrySendError<SupervisorMessage>> {
//         self.tx.try_send(SupervisorMessage::AddTask(task))
//     }

//     fn shutdown(&self) -> Result<(), mpsc::error::TrySendError<SupervisorMessage>> {
//         self.tx.try_send(SupervisorMessage::Abort)
//     }
// }

/// Runs a STUN server.
///
/// When the future is dropped, the server stops.
async fn server_stun_listener(sock: UdpSocket) -> Result<()> {
    info!("running STUN server");
    // TODO: re-write this as structured-concurrency and returning errors

    // let mut buffer = vec![0u8; 64 << 10];
    // let mut tasks = JoinSet::new();
    // loop {
    //     // TODO: tokio::select!() on tasks.join_next()
    //     match sock.recv_from(&mut buffer).await {
    //         Ok((n, src_addr)) => {
    //             inc!(StunMetrics, requests);
    //             let pkt = buffer[..n];
    //             if !stun::is(&pkt) {
    //                 debug!(%src_addr, "STUN: ignoring non stun packet");
    //                 inc!(StunMetrics, bad_requests);
    //                 continue;
    //             }
    //             let pkt = pkt.to_vec();
    //             tasks.spawn(async {
    //                 // This task handles the entire request-response.
    //                 let handle = AbortingJoinHandle::from(tokio::spawn_blocking(|| {
    //                     match stun::parse_binding_request(&pkt) {
    //                         Ok(txid) => {
    //                             debug!(%src_addr, %txid, "STUN: received binding request");
    //                             Some(stun::response(txid, src_addr))
    //                         }
    //                         Err(err) => {
    //                             inc!(StunMetrics, bad_requests);
    //                             warn!(%src_addr, "STUN: invalid binding request: {:?}", err);
    //                             None
    //                         }
    //                     }
    //                 }));
    //                 let response = handle.await?;
    //                 let t: () = response;
    //                 Ok(())
    //             })
    //         }
    //     }
    // }

    let sock = Arc::new(sock);
    let mut buffer = vec![0u8; 64 << 10];
    let mut tasks = JoinSet::new();
    loop {
        match sock.recv_from(&mut buffer).await {
            Ok((n, src_addr)) => {
                inc!(StunMetrics, requests);
                let pkt = buffer[..n].to_vec();
                let sock = sock.clone();
                tasks.spawn(async move {
                    if !stun::is(&pkt) {
                        debug!(%src_addr, "STUN: ignoring non stun packet");
                        inc!(StunMetrics, bad_requests);
                        return;
                    }
                    match tokio::task::spawn_blocking(move || stun::parse_binding_request(&pkt))
                        .await
                        .unwrap()
                    {
                        Ok(txid) => {
                            debug!(%src_addr, %txid, "STUN: received binding request");
                            let res =
                                tokio::task::spawn_blocking(move || stun::response(txid, src_addr))
                                    .await
                                    .unwrap();
                            match sock.send_to(&res, src_addr).await {
                                Ok(len) => {
                                    if len != res.len() {
                                        warn!(%src_addr, %txid, "STUN: failed to write response sent: {}, but expected {}", len, res.len());
                                    }
                                    match src_addr {
                                        SocketAddr::V4(_) => {
                                            inc!(StunMetrics, ipv4_success);
                                        }
                                        SocketAddr::V6(_) => {
                                            inc!(StunMetrics, ipv6_success);
                                        }
                                    }
                                    trace!(%src_addr, %txid, "STUN: sent {} bytes", len);
                                }
                                Err(err) => {
                                    inc!(StunMetrics, failures);
                                    warn!(%src_addr, %txid, "STUN: failed to write response: {:#}", err);
                                }
                            }
                        }
                        Err(err) => {
                            inc!(StunMetrics, bad_requests);
                            warn!(%src_addr, "STUN: invalid binding request: {:?}", err);
                        }
                    }
                });
            }
            Err(err) => {
                inc!(StunMetrics, failures);
                warn!("STUN: failed to recv: {:?}", err);
            }
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
