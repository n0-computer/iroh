//! A full-fledged DERP and STUN server.
//!
//! This module provides an API to create a full fledged DERP server.  It is primarily used
//! by the `derper` binary in this crate.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Result};
use futures::stream::{FusedStream, FuturesUnordered};
use futures::StreamExt;
use iroh_metrics::inc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};
use url::Url;

use crate::derp::MeshKey;
use crate::key::SecretKey;
use crate::stun;

// Module defined in this file.
use metrics::StunMetrics;

use super::http::TlsAcceptor;

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
        /// Whether to use the LetsEncrypt production or staging server.
        ///
        /// While in developement, LetsEncrypt prefers you to use the staging
        /// server. However, the staging server seems to only use `ECDSA` keys. In their
        /// current set up, you can only get intermediate certificates for `ECDSA` keys if
        /// you are on their "allowlist". The production server uses `RSA` keys, which allow
        /// for issuing intermediate certificates in all normal circumstances.  So, to have
        /// valid certificates, we must use the LetsEncrypt production server.  Read more
        /// here: <https://letsencrypt.org/certificates/#intermediate-certificates> Default
        /// is true. This field is ignored if we are not using `cert_mode:
        /// CertMode::LetsEncrypt`.
        prod: bool,
        /// The contact email for the tls certificate.
        contact: String,
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
        EC: fmt::Debug,
        EA: fmt::Debug,
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
        if let Some(derp) = config.derp {
            let (tls_config, headers, captive_portal_port) = if let Some(tls_config) = derp.tls {
                match tls_config.cert {
                    CertConfig::LetsEncrypt {
                        config,
                        prod,
                        contact,
                    } => todo!(),
                    CertConfig::Manual { private_key, certs } => todo!(),
                }
                let config: rustls::ServerConfig = todo!();
                let acceptor: TlsAcceptor = todo!();
            };
            //     let contact = tls_config.contact;
            //     let is_production = tls_config.prod_tls;
            //     let (config, acceptor) = tls_config
            //         .cert
            //         .gen_server_config(
            //             cfg.hostname.clone(),
            //             contact,
            //             is_production,
            //             tls_config.cert_dir.unwrap_or_else(|| PathBuf::from(".")),
            //         )
            //         .await?;
            //     let headers: Vec<(&str, &str)> = TLS_HEADERS.into();
            //     (
            //         Some(DerpTlsConfig { config, acceptor }),
            //         headers,
            //         tls_config
            //             .captive_portal_port
            //             .unwrap_or(DEFAULT_CAPTIVE_PORTAL_PORT),
            //     )
            // } else {
            //     (None, Vec::new(), 0)
            // };
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
/// when one fails.
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
