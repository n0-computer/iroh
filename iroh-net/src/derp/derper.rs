//! A full-fledged DERP and STUN server.
//!
//! This module provides an API to create a full fledged DERP server.  It is primarily used
//! by the `derper` binary in this crate.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use anyhow::{anyhow, bail, Context, Result};
use futures::stream::{FusedStream, FuturesUnordered};
use futures::StreamExt;
use http::response::Builder as ResponseBuilder;
use http::{Method, Request, Response, StatusCode};
use hyper::Body;
use iroh_metrics::inc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};
use url::Url;

use crate::derp::http::{ServerBuilder as DerpServerBuilder, TlsAcceptor};
use crate::derp::{self, MeshKey};
use crate::key::SecretKey;
use crate::stun;

// Module defined in this file.
use metrics::StunMetrics;

use super::http::MeshAddrs;

const NO_CONTENT_CHALLENGE_HEADER: &str = "X-Tailscale-Challenge";
const NO_CONTENT_RESPONSE_HEADER: &str = "X-Tailscale-Response";
const NOTFOUND: &[u8] = b"Not Found";
const DERP_DISABLED: &[u8] = b"derp server disabled";
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

type HyperError = Box<dyn std::error::Error + Send + Sync>;
type HyperResult<T> = std::result::Result<T, HyperError>;

/// Configuration for the full DERP & STUN server.
#[derive(Debug)]
#[non_exhaustive]
pub struct ServerConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// Main listen address.
    pub addr: IpAddr,
    /// Configuration for the DERP server, disabled if `None`.
    pub derp: Option<DerpConfig<EC, EA>>,
    /// Configuration for the STUN server, disabled if `None`.
    pub stun: Option<StunConfig>,
    /// Socket to serve metrics on.
    pub metrics_addr: Option<SocketAddr>,
}

impl<EC: fmt::Debug, EA: fmt::Debug> ServerConfig<EC, EA> {
    /// Creates a new config.
    pub fn new() -> Self {
        Self {
            addr: Ipv6Addr::UNSPECIFIED.into(),
            derp: None,
            stun: None,
            metrics_addr: None,
        }
    }

    /// Validates the config for internal consistency.
    pub fn validate(&self) -> Result<()> {
        if self.derp.is_none() && self.stun.is_none() {
            bail!("neither DERP nor STUN server configured");
        }
        if let Some(derp) = &self.derp {
            if let Some(tls) = &derp.tls {
                if derp.port == tls.http_port {
                    bail!("derp port conflicts with captive portal port");
                }
            }
        }
        if let Some(sock) = self.metrics_addr {
            if sock.ip() == self.addr {
                bail!("Metrics address conflicts with server address");
            }
        }
        Ok(())
    }
}

/// Configuration for the DERP server.
///
/// This includes the HTTP services hosted by the DERP server.
#[derive(Debug)]
#[non_exhaustive]
pub struct DerpConfig<EC: fmt::Debug, EA: fmt::Debug = EC> {
    /// The port on which the server should listen.
    ///
    /// Normally you'd choose `80` if configured without TLS and `443` when configured with
    /// TLS since the DERP server is an HTTP server.
    pub port: u16,
    /// The secret key of the DERP server.
    pub secret_key: SecretKey,
    /// TLS configuration, no TLS is used if `None`.
    pub tls: Option<TlsConfig<EC, EA>>,
    /// Rate limits, if enabled.
    pub limits: Option<Limits>,
    /// Optional DERP mesh configuration.
    pub mesh: Option<MeshConfig>,
}

/// Configuration for the STUN server.
#[derive(Debug)]
#[non_exhaustive]
pub struct StunConfig {
    /// The port on which to listen.
    ///
    /// Normally you'd chose `3478`, see [`crate::defaults::DEFAULT_DERP_STUN_SERVER`].
    pub port: u16,
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
    /// The port on which to serve plain text HTTP requests.
    ///
    /// Since the captive portal probe has to run over plain text HTTP and TLS is used for
    /// the main derper this has to be a different port.  Normally you'd choose `80`.
    pub http_port: u16,
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
        // /// Whether to use the LetsEncrypt production or staging server.
        // ///
        // /// While in developement, LetsEncrypt prefers you to use the staging
        // /// server. However, the staging server seems to only use `ECDSA` keys. In their
        // /// current set up, you can only get intermediate certificates for `ECDSA` keys if
        // /// you are on their "allowlist". The production server uses `RSA` keys, which allow
        // /// for issuing intermediate certificates in all normal circumstances.  So, to have
        // /// valid certificates, we must use the LetsEncrypt production server.  Read more
        // /// here: <https://letsencrypt.org/certificates/#intermediate-certificates> Default
        // /// is true. This field is ignored if we are not using `cert_mode:
        // /// CertMode::LetsEncrypt`.
        // prod: bool,
        // /// The contact email for the tls certificate.
        // contact: String,
    },
    /// Use a static TLS key and certificate chain.
    Manual {
        /// The TLS private key.
        private_key: rustls::PrivateKey,
        /// The TLS certificate chain.
        certs: Vec<rustls::Certificate>,
    },
}

/// DERP mesh config.
#[derive(Debug)]
#[non_exhaustive]
pub struct MeshConfig {
    /// The PSK mesh key.
    key: MeshKey,
    /// The other DERP servers to mesh with.
    peers: Vec<Url>,
}

/// A running STUN + DERP server.
///
/// This is a full DERP server, including STUN, DERP and various associated HTTP services.
///
/// Dropping this will stop the server.
#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Server {
    /// Starts the server.
    pub async fn spawn<EC, EA>(config: ServerConfig<EC, EA>) -> Result<Self>
    where
        EC: fmt::Debug + 'static,
        EA: fmt::Debug + 'static,
    {
        config.validate()?;
        let supervisor = TaskSupervisor::new();
        let supervisor_addr = supervisor.addr();
        let supervisor_task = tokio::spawn(
            async move {
                let mut supervisor = supervisor;
                supervisor.run().await
            }
            .instrument(info_span!("supervisor")),
        );
        if let Some(stun) = config.stun {
            let task = tokio::spawn(
                async move {
                    serve_stun(config.addr, stun.port).await;
                    Ok(())
                }
                .instrument(info_span!("stun-server", addr = %config.addr, port = stun.port)),
            );
            supervisor_addr.add_task(task)?;
        }
        if let Some(derp_config) = config.derp {
            let headers: Vec<(&str, &str)> = TLS_HEADERS.into();
            let mesh_key = derp_config.mesh.as_ref().map(|cfg| cfg.key);
            let mesh_addrs = derp_config
                .mesh
                .map(|mesh_config| MeshAddrs::Addrs(mesh_config.peers));
            let addr = SocketAddr::new(config.addr, derp_config.port);
            let mut builder = DerpServerBuilder::new(addr)
                .secret_key(Some(derp_config.secret_key))
                .headers(headers)
                .derp_override(Box::new(derp_disabled_handler))
                .mesh_key(mesh_key)
                .mesh_derpers(mesh_addrs)
                .request_handler(Method::GET, "/", Box::new(root_handler))
                .request_handler(Method::GET, "/index.html", Box::new(root_handler))
                .request_handler(Method::GET, "/derp/probe", Box::new(probe_handler))
                .request_handler(Method::GET, "/robots.txt", Box::new(robots_handler));
            match derp_config.tls {
                Some(tls_config) => {
                    let server_config = rustls::ServerConfig::builder()
                        .with_safe_defaults()
                        .with_no_client_auth();
                    let server_tls_config = match tls_config.cert {
                        CertConfig::LetsEncrypt { config } => {
                            let mut state = config.state();
                            let server_config = server_config.with_cert_resolver(state.resolver());
                            let acceptor = TlsAcceptor::LetsEncrypt(state.acceptor());
                            let task = tokio::spawn(
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
                            supervisor_addr.add_task(task)?;
                            Some(derp::http::TlsConfig {
                                config: Arc::new(server_config),
                                acceptor,
                            })
                        }
                        CertConfig::Manual { private_key, certs } => {
                            let server_config = server_config
                                .with_single_cert(certs.clone(), private_key.clone())?;
                            let server_config = Arc::new(server_config);
                            let acceptor = tokio_rustls::TlsAcceptor::from(server_config.clone());
                            let acceptor = TlsAcceptor::Manual(acceptor);
                            Some(derp::http::TlsConfig {
                                config: server_config,
                                acceptor,
                            })
                        }
                    };
                    builder = builder.tls_config(server_tls_config);

                    // Some services always need to be served over HTTP without TLS.  Run
                    // these standalone.
                    let http_addr = SocketAddr::new(config.addr, tls_config.http_port);
                    let task = serve_captive_portal_service(http_addr).await?;
                    supervisor_addr.add_task(task)?;
                }
                None => {
                    // If running DERP without TLS add the plain HTTP server directly to the
                    // DERP server.
                    builder = builder.request_handler(
                        Method::GET,
                        "/generate_204",
                        Box::new(serve_no_content_handler),
                    );
                }
            };
            let derp_server = builder.spawn().await?;
        }
        Ok(Self {
            addr: todo!(),
            task: supervisor_task,
        })
    }
}

/// An actor which supervises other tasks, with no restarting and one-for-all strategy.
///
/// The supervisor itself does no restarting of tasks.  It only terminates all other tasks
/// when one fails.  It is essentially a one-for-all supervisor strategy with a max-restarts
/// count of 0.
#[derive(Debug)]
struct TaskSupervisor {
    addr_tx: mpsc::Sender<SupervisorMessage>,
    addr_rx: mpsc::Receiver<SupervisorMessage>,
    tasks: FuturesUnordered<JoinHandle<Result<()>>>,
}

impl TaskSupervisor {
    fn new() -> Self {
        let (addr_tx, addr_rx) = mpsc::channel(16);
        Self {
            addr_tx,
            addr_rx,
            tasks: FuturesUnordered::new(),
        }
    }

    async fn run(&mut self) {
        // Note this can never fail!
        loop {
            tokio::select! {
                biased;
                res = self.addr_rx.recv() => {
                    match res {
                        Some(msg) => self.handle_msg(msg),
                        None => {
                            error!("All senders closed, impossible");
                            break;
                        }
                    }
                }
                item = self.tasks.next() => {
                    match item {
                        Some(res) => {
                            self.handle_task_finished(res);
                            if self.tasks.is_terminated() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        debug!("Supervisor finished");
    }

    fn handle_msg(&mut self, msg: SupervisorMessage) {
        match msg {
            SupervisorMessage::AddTask(task) => {
                self.tasks.push(task);
            }
            SupervisorMessage::Abort => {
                for task in self.tasks.iter() {
                    task.abort();
                }
            }
        }
    }

    fn handle_task_finished(&mut self, res: Result<Result<()>, JoinError>) {
        match res {
            Ok(Ok(())) => info!("Supervised task gracefully finished, aborting others"),
            Ok(Err(err)) => error!("Supervised task failed, aborting others.  err: {err}"),
            Err(err) => {
                if err.is_cancelled() {
                    info!("Supervised task cancelled, aborting others");
                }
                if err.is_panic() {
                    // TODO: We just swallow the panic.  Unfortunately we can only resume
                    // it, which is not (yet?) what we want?  Or maybe it is.
                    error!("Supervised task paniced, aborting others");
                }
            }
        }
        for task in self.tasks.iter() {
            task.abort();
        }
    }

    fn addr(&self) -> SupervisorAddr {
        SupervisorAddr {
            tx: self.addr_tx.clone(),
        }
    }
}

#[derive(Debug)]
enum SupervisorMessage {
    AddTask(JoinHandle<Result<()>>),
    Abort,
}

#[derive(Debug)]
struct SupervisorAddr {
    tx: mpsc::Sender<SupervisorMessage>,
}

impl SupervisorAddr {
    fn add_task(
        &self,
        task: JoinHandle<Result<()>>,
    ) -> Result<(), mpsc::error::TrySendError<SupervisorMessage>> {
        self.tx.try_send(SupervisorMessage::AddTask(task))
    }

    fn shutdown(&self) -> Result<(), mpsc::error::TrySendError<SupervisorMessage>> {
        self.tx.try_send(SupervisorMessage::Abort)
    }
}

async fn serve_stun(host: IpAddr, port: u16) {
    match UdpSocket::bind((host, port)).await {
        Ok(sock) => {
            let addr = sock.local_addr().expect("socket just bound");
            info!(%addr, "running STUN server");
            server_stun_listener(sock).await;
        }
        Err(err) => {
            error!("failed to open STUN listener: {:#?}", err);
        }
    }
}

async fn server_stun_listener(sock: UdpSocket) {
    let sock = Arc::new(sock);
    let mut buffer = vec![0u8; 64 << 10];
    loop {
        match sock.recv_from(&mut buffer).await {
            Ok((n, src_addr)) => {
                inc!(StunMetrics, requests);
                let pkt = buffer[..n].to_vec();
                let sock = sock.clone();
                tokio::spawn(async move {
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

fn derp_disabled_handler(
    _r: Request<Body>,
    response: ResponseBuilder,
) -> HyperResult<Response<Body>> {
    Ok(response
        .status(StatusCode::NOT_FOUND)
        .body(DERP_DISABLED.into())
        .unwrap())
}

fn root_handler(_r: Request<Body>, response: ResponseBuilder) -> HyperResult<Response<Body>> {
    let response = response
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(INDEX.into())
        .unwrap();

    Ok(response)
}

/// HTTP latency queries
fn probe_handler(_r: Request<Body>, response: ResponseBuilder) -> HyperResult<Response<Body>> {
    let response = response
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::empty())
        .unwrap();

    Ok(response)
}

fn robots_handler(_r: Request<Body>, response: ResponseBuilder) -> HyperResult<Response<Body>> {
    Ok(response
        .status(StatusCode::OK)
        .body(ROBOTS_TXT.into())
        .unwrap())
}

/// For captive portal detection.
fn serve_no_content_handler(
    r: Request<Body>,
    mut response: ResponseBuilder,
) -> HyperResult<Response<Body>> {
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

    Ok(response
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
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

async fn serve_captive_portal_service(addr: SocketAddr) -> Result<JoinHandle<Result<()>>> {
    let http_listener = TcpListener::bind(&addr)
        .await
        .context("failed to bind http")?;
    let http_addr = http_listener.local_addr()?;
    info!("[CaptivePortalService]: serving on {}", http_addr);

    let task = tokio::spawn(
        async move {
            loop {
                match http_listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        debug!(
                            "[CaptivePortalService] Connection opened from {}",
                            peer_addr
                        );
                        let handler = CaptivePortalService;

                        tokio::task::spawn(async move {
                            if let Err(err) = hyper::server::conn::Http::new()
                                .serve_connection(
                                    derp::MaybeTlsStreamServer::Plain(stream),
                                    handler,
                                )
                                .with_upgrades()
                                .await
                            {
                                error!(
                                    "[CaptivePortalService] Failed to serve connection: {:?}",
                                    err
                                );
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
        .instrument(info_span!("captive-portal.service")),
    );
    Ok(task)
}

#[derive(Clone)]
struct CaptivePortalService;

impl hyper::service::Service<Request<Body>> for CaptivePortalService {
    type Response = Response<Body>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
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
                    .unwrap();
                Box::pin(async move { Ok(r) })
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
