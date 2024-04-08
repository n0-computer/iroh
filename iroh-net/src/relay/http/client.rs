//! Based on tailscale/derp/derphttp/derphttp_client.go

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use bytes::Bytes;
use futures::future::BoxFuture;
use hyper::body::Incoming;
use hyper::header::UPGRADE;
use hyper::upgrade::{Parts, Upgraded};
use hyper::Request;
use rand::Rng;
use rustls::client::Resumption;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{debug, error, info_span, trace, warn, Instrument};
use url::Url;

use crate::dns::{lookup_ipv4_ipv6, DnsResolver};
use crate::key::{PublicKey, SecretKey};
use crate::relay::RelayUrl;
use crate::relay::{
    client::Client as RelayClient, client::ClientBuilder as RelayClientBuilder,
    client::ClientReceiver as RelayClientReceiver, ReceivedMessage,
};
use crate::util::AbortingJoinHandle;

const DIAL_NODE_TIMEOUT: Duration = Duration::from_millis(1500);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(1);

/// Possible connection errors on the [`Client`]
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The client is closed
    #[error("client is closed")]
    Closed,
    /// There no underlying relay [`super::client::Client`] client exists for this http relay [`Client`]
    #[error("no relay client")]
    NoClient,
    /// There was an error sending a packet
    #[error("error sending a packet")]
    Send,
    /// There was an error receiving a packet
    #[error("error receiving a packet: {0:?}")]
    Receive(anyhow::Error),
    /// There was a connection timeout error
    #[error("connect timeout")]
    ConnectTimeout,
    /// No relay nodes are available
    #[error("Relay node is not available")]
    RelayNodeNotAvail,
    /// No relay nodes are available with that name
    #[error("no nodes available for {0}")]
    NoNodeForTarget(String),
    /// The relay node specified only allows STUN requests
    #[error("no relay nodes found for {0}, only are stun_only nodes")]
    StunOnlyNodesFound(String),
    /// There was an error dialing
    #[error("dial error")]
    DialIO(#[from] std::io::Error),
    /// There was an error from the task doing the dialing
    #[error("dial error")]
    DialTask(#[from] tokio::task::JoinError),
    /// Both IPv4 and IPv6 are disabled for this relay node
    #[error("both IPv4 and IPv6 are explicitly disabled for this node")]
    IPDisabled,
    /// No local addresses exist
    #[error("no local addr: {0}")]
    NoLocalAddr(String),
    /// There was http server [`hyper::Error`]
    #[error("http connection error")]
    Hyper(#[from] hyper::Error),
    /// There was an http error [`http::Error`].
    #[error("http error")]
    Http(#[from] http::Error),
    /// There was an unexpected status code
    #[error("unexpected status code: expected {0}, got {1}")]
    UnexpectedStatusCode(hyper::StatusCode, hyper::StatusCode),
    /// The connection failed to upgrade
    #[error("failed to upgrade connection: {0}")]
    Upgrade(String),
    /// The relay [`super::client::Client`] failed to build
    #[error("failed to build relay client: {0}")]
    Build(String),
    /// The ping request timed out
    #[error("ping timeout")]
    PingTimeout,
    /// The ping request was aborted
    #[error("ping aborted")]
    PingAborted,
    /// This [`Client`] cannot acknowledge pings
    #[error("cannot acknowledge pings")]
    CannotAckPings,
    /// The given [`Url`] is invalid
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// There was an error with DNS resolution
    #[error("dns: {0:?}")]
    Dns(Option<anyhow::Error>),
    /// There was a timeout resolving DNS.
    #[error("dns timeout")]
    DnsTimeout,
    /// The inner actor is gone, likely means things are shutdown.
    #[error("actor gone")]
    ActorGone,
}

/// An HTTP Relay client.
///
/// Cheaply clonable.
#[derive(Clone, Debug)]
pub struct Client {
    inner: mpsc::Sender<ActorMessage>,
    public_key: PublicKey,
    #[allow(dead_code)]
    recv_loop: Arc<AbortingJoinHandle<()>>,
}

#[derive(Debug)]
enum ActorMessage {
    Connect(oneshot::Sender<Result<(RelayClient, usize), ClientError>>),
    NotePreferred(bool),
    LocalAddr(oneshot::Sender<Result<Option<SocketAddr>, ClientError>>),
    Ping(oneshot::Sender<Result<Duration, ClientError>>),
    Pong([u8; 8], oneshot::Sender<Result<(), ClientError>>),
    Send(PublicKey, Bytes, oneshot::Sender<Result<(), ClientError>>),
    Close(oneshot::Sender<Result<(), ClientError>>),
    CloseForReconnect(oneshot::Sender<Result<(), ClientError>>),
    IsConnected(oneshot::Sender<Result<bool, ClientError>>),
}

/// Receiving end of a [`Client`].
#[derive(Debug)]
pub struct ClientReceiver {
    msg_receiver: mpsc::Receiver<Result<(ReceivedMessage, usize), ClientError>>,
}

#[derive(derive_more::Debug)]
struct Actor {
    secret_key: SecretKey,
    can_ack_pings: bool,
    is_preferred: bool,
    relay_client: Option<(RelayClient, RelayClientReceiver)>,
    is_closed: bool,
    #[debug("address family selector callback")]
    address_family_selector:
        Option<Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>>,
    conn_gen: usize,
    is_prober: bool,
    server_public_key: Option<PublicKey>,
    url: RelayUrl,
    #[debug("TlsConnector")]
    tls_connector: tokio_rustls::TlsConnector,
    pings: PingTracker,
    ping_tasks: JoinSet<()>,
    dns_resolver: DnsResolver,
}

#[derive(Default, Debug)]
struct PingTracker(HashMap<[u8; 8], oneshot::Sender<()>>);

impl PingTracker {
    /// Note that we have sent a ping, and store the [`oneshot::Sender`] we
    /// must notify when the pong returns
    fn register(&mut self) -> ([u8; 8], oneshot::Receiver<()>) {
        let data = rand::thread_rng().gen::<[u8; 8]>();
        let (send, recv) = oneshot::channel();
        self.0.insert(data, send);
        (data, recv)
    }

    /// Remove the associated [`oneshot::Sender`] for `data` & return it.
    ///
    /// If there is no [`oneshot::Sender`] in the tracker, return `None`.
    fn unregister(&mut self, data: [u8; 8], why: &'static str) -> Option<oneshot::Sender<()>> {
        trace!("removing ping {}: {}", hex::encode(data), why);
        self.0.remove(&data)
    }
}

/// Build a Client.
pub struct ClientBuilder {
    /// Default is false
    can_ack_pings: bool,
    /// Default is false
    is_preferred: bool,
    /// Default is None
    address_family_selector:
        Option<Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>>,
    /// Default is false
    is_prober: bool,
    /// Expected PublicKey of the server
    server_public_key: Option<PublicKey>,
    /// Server url.
    url: RelayUrl,
    /// Allow self-signed certificates from relay servers
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_cert_verify: bool,
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let address_family_selector_txt = match self.address_family_selector {
            Some(_) => "Some(Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>)",
            None => "None",
        };
        write!(f, "ClientBuilder {{ can_ack_pings: {}, is_preferred: {}, address_family_selector: {address_family_selector_txt} }}", self.can_ack_pings, self.is_preferred)
    }
}

impl ClientBuilder {
    /// Create a new [`ClientBuilder`]
    pub fn new(url: impl Into<RelayUrl>) -> Self {
        ClientBuilder {
            can_ack_pings: false,
            is_preferred: false,
            address_family_selector: None,
            is_prober: false,
            server_public_key: None,
            url: url.into(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify: false,
        }
    }

    /// Sets the server url
    pub fn server_url(mut self, url: impl Into<RelayUrl>) -> Self {
        self.url = url.into();
        self
    }

    /// Returns if we should prefer ipv6
    /// it replaces the relayhttp.AddressFamilySelector we pass
    /// It provides the hint as to whether in an IPv4-vs-IPv6 race that
    /// IPv4 should be held back a bit to give IPv6 a better-than-50/50
    /// chance of winning. We only return true when we believe IPv6 will
    /// work anyway, so we don't artificially delay the connection speed.
    pub fn address_family_selector<S>(mut self, selector: S) -> Self
    where
        S: Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static,
    {
        self.address_family_selector = Some(Box::new(selector));
        self
    }

    /// Enable this [`Client`] to acknowledge pings.
    pub fn can_ack_pings(mut self, can: bool) -> Self {
        self.can_ack_pings = can;
        self
    }

    /// Indicate this client is the preferred way to communicate
    /// to the peer with this client's [`PublicKey`]
    pub fn is_preferred(mut self, is: bool) -> Self {
        self.is_preferred = is;
        self
    }

    /// Indicates this client is a prober
    pub fn is_prober(mut self, is: bool) -> Self {
        self.is_prober = is;
        self
    }

    /// Skip the verification of the relay server's SSL certificates.
    ///
    /// May only be used in tests.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn insecure_skip_cert_verify(mut self, skip: bool) -> Self {
        self.insecure_skip_cert_verify = skip;
        self
    }

    /// Build the [`Client`]
    pub fn build(self, key: SecretKey, dns_resolver: DnsResolver) -> (Client, ClientReceiver) {
        // TODO: review TLS config
        let mut roots = rustls::RootCertStore::empty();
        roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let mut config = rustls::client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        #[cfg(any(test, feature = "test-utils"))]
        if self.insecure_skip_cert_verify {
            warn!("Insecure config: SSL certificates from relay servers will be trusted without verification");
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertVerifier));
        }

        config.resumption = Resumption::default();

        let tls_connector: tokio_rustls::TlsConnector = Arc::new(config).into();
        let public_key = key.public();

        let inner = Actor {
            secret_key: key,
            can_ack_pings: self.can_ack_pings,
            is_preferred: self.is_preferred,
            relay_client: None,
            is_closed: false,
            address_family_selector: self.address_family_selector,
            conn_gen: 0,
            pings: PingTracker::default(),
            ping_tasks: Default::default(),
            is_prober: self.is_prober,
            server_public_key: self.server_public_key,
            url: self.url,
            tls_connector,
            dns_resolver,
        };

        let (msg_sender, inbox) = mpsc::channel(64);
        let (s, r) = mpsc::channel(64);
        let recv_loop = tokio::task::spawn(
            async move { inner.run(inbox, s).await }.instrument(info_span!("client")),
        );

        (
            Client {
                public_key,
                inner: msg_sender,
                recv_loop: Arc::new(recv_loop.into()),
            },
            ClientReceiver { msg_receiver: r },
        )
    }

    /// The expected [`PublicKey`] of the [`super::server::Server`] we are connecting to.
    pub fn server_public_key(mut self, server_public_key: PublicKey) -> Self {
        self.server_public_key = Some(server_public_key);
        self
    }
}

impl ClientReceiver {
    /// Reads a message from the server. Returns the message and the `conn_get`, or the number of
    /// re-connections this Client has ever made
    pub async fn recv(&mut self) -> Option<Result<(ReceivedMessage, usize), ClientError>> {
        self.msg_receiver.recv().await
    }
}

impl Client {
    /// The public key for this client
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    async fn send_actor<F, T>(&self, msg_create: F) -> Result<T, ClientError>
    where
        F: FnOnce(oneshot::Sender<Result<T, ClientError>>) -> ActorMessage,
    {
        let (s, r) = oneshot::channel();
        let msg = msg_create(s);
        match self.inner.send(msg).await {
            Ok(_) => {
                let res = r.await.map_err(|_| ClientError::ActorGone)??;
                Ok(res)
            }
            Err(_) => Err(ClientError::ActorGone),
        }
    }

    /// Connect to a relay Server and returns the underlying relay Client.
    ///
    /// Returns [`ClientError::Closed`] if the [`Client`] is closed.
    ///
    /// If there is already an active relay connection, returns the already
    /// connected [`crate::relay::client::Client`].
    pub async fn connect(&self) -> Result<(RelayClient, usize), ClientError> {
        self.send_actor(ActorMessage::Connect).await
    }

    /// Let the server know that this client is the preferred client
    pub async fn note_preferred(&self, is_preferred: bool) {
        self.inner
            .send(ActorMessage::NotePreferred(is_preferred))
            .await
            .ok();
    }

    /// Get the local addr of the connection. If there is no current underlying relay connection
    /// or the [`Client`] is closed, returns `None`.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        self.send_actor(ActorMessage::LocalAddr)
            .await
            .ok()
            .flatten()
    }

    /// Send a ping to the server. Return once we get an expected pong.
    ///
    /// There must be a task polling `recv_detail` to process the `pong` response.
    pub async fn ping(&self) -> Result<Duration, ClientError> {
        self.send_actor(ActorMessage::Ping).await
    }

    /// Send a pong back to the server.
    ///
    /// If there is no underlying active relay connection, it creates one before attempting to
    /// send the pong message.
    ///
    /// If there is an error sending pong, it closes the underlying relay connection before
    /// returning.
    pub async fn send_pong(&self, data: [u8; 8]) -> Result<(), ClientError> {
        self.send_actor(|s| ActorMessage::Pong(data, s)).await
    }

    /// Send a packet to the server.
    ///
    /// If there is no underlying active relay connection, it creates one before attempting to
    /// send the message.
    ///
    /// If there is an error sending the packet, it closes the underlying relay connection before
    /// returning.
    pub async fn send(&self, dst_key: PublicKey, b: Bytes) -> Result<(), ClientError> {
        self.send_actor(|s| ActorMessage::Send(dst_key, b, s)).await
    }

    /// Close the http relay connection.
    pub async fn close(self) -> Result<(), ClientError> {
        self.send_actor(ActorMessage::Close).await
    }

    /// Disconnect the http relay connection.
    pub async fn close_for_reconnect(&self) -> Result<(), ClientError> {
        self.send_actor(ActorMessage::CloseForReconnect).await
    }

    /// Returns `true` if the underlying relay connection is established.
    pub async fn is_connected(&self) -> Result<bool, ClientError> {
        self.send_actor(ActorMessage::IsConnected).await
    }
}

impl Actor {
    async fn run(
        mut self,
        mut inbox: mpsc::Receiver<ActorMessage>,
        msg_sender: mpsc::Sender<Result<(ReceivedMessage, usize), ClientError>>,
    ) {
        // Add an initial connection attempt.
        if let Err(err) = self.connect("initial connect").await {
            msg_sender.send(Err(err)).await.ok();
        }

        loop {
            tokio::select! {
                res = self.recv_detail() => {
                    if let Ok((ReceivedMessage::Pong(ping), _)) = res {
                        match self.pings.unregister(ping, "pong") {
                            Some(chan) => {
                                if chan.send(()).is_err() {
                                    warn!("pong received for ping {ping:?}, but the receiving channel was closed");
                                }
                            }
                            None => {
                                warn!("pong received for ping {ping:?}, but not registered");
                            }
                        }
                        continue;
                    }
                    msg_sender.send(res).await.ok();
                }
                Some(msg) = inbox.recv() => {
                    match msg {
                        ActorMessage::Connect(s) => {
                            let res = self.connect("actor msg").await.map(|(client, _, count)| (client, count));
                            s.send(res).ok();
                        },
                        ActorMessage::NotePreferred(is_preferred) => {
                            self.note_preferred(is_preferred).await;
                        },
                        ActorMessage::LocalAddr(s) => {
                            let res = self.local_addr();
                            s.send(Ok(res)).ok();
                        },
                        ActorMessage::Ping(s) => {
                            self.ping(s).await;
                        },
                        ActorMessage::Pong(data, s) => {
                            let res = self.send_pong(data).await;
                            s.send(res).ok();
                        },
                        ActorMessage::Send(key, data, s) => {
                            let res = self.send(key, data).await;
                            s.send(res).ok();
                        },
                        ActorMessage::Close(s) => {
                            let res = self.close().await;
                            s.send(Ok(res)).ok();
                            // shutting down
                            break;
                        },
                        ActorMessage::CloseForReconnect(s) => {
                            let res = self.close_for_reconnect().await;
                            s.send(Ok(res)).ok();
                        },
                        ActorMessage::IsConnected(s) => {
                            let res = self.is_connected();
                            s.send(Ok(res)).ok();
                        },
                    }
                }
                else => {
                    // Shutting down
                    self.close().await;
                    break;
                }
            }
        }
    }

    async fn connect(
        &mut self,
        why: &'static str,
    ) -> Result<(RelayClient, &'_ mut RelayClientReceiver, usize), ClientError> {
        debug!(
            "connect: {}, current client {}",
            why,
            self.relay_client.is_some()
        );

        if self.is_closed {
            return Err(ClientError::Closed);
        }
        async move {
            if self.relay_client.is_none() {
                trace!("no connection, trying to connect");
                let (relay_client, receiver) =
                    tokio::time::timeout(CONNECT_TIMEOUT, self.connect_0())
                        .await
                        .map_err(|_| ClientError::ConnectTimeout)??;

                self.relay_client = Some((relay_client.clone(), receiver));
                self.next_conn();
            } else {
                trace!("already had connection");
            }
            let count = self.current_conn();
            let (relay_client, receiver) = self
                .relay_client
                .as_mut()
                .map(|(c, r)| (c.clone(), r))
                .expect("just checked");

            Ok((relay_client, receiver, count))
        }
        .instrument(info_span!("connect"))
        .await
    }

    async fn connect_0(&self) -> Result<(RelayClient, RelayClientReceiver), ClientError> {
        let tcp_stream = self.dial_url().await?;

        let local_addr = tcp_stream
            .local_addr()
            .map_err(|e| ClientError::NoLocalAddr(e.to_string()))?;

        debug!(server_addr = ?tcp_stream.peer_addr(), %local_addr, "TCP stream connected");

        let response = if self.use_https() {
            debug!("Starting TLS handshake");
            let hostname = self
                .tls_servername()
                .ok_or_else(|| ClientError::InvalidUrl("No tls servername".into()))?;
            let tls_stream = self.tls_connector.connect(hostname, tcp_stream).await?;
            debug!("tls_connector connect success");
            Self::start_upgrade(tls_stream).await?
        } else {
            debug!("Starting handshake");
            Self::start_upgrade(tcp_stream).await?
        };

        if response.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
            error!(
                "expected status 101 SWITCHING_PROTOCOLS, got: {}",
                response.status()
            );
            return Err(ClientError::UnexpectedStatusCode(
                hyper::StatusCode::SWITCHING_PROTOCOLS,
                response.status(),
            ));
        }

        debug!("starting upgrade");
        let upgraded = match hyper::upgrade::on(response).await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                warn!("upgrade failed: {:#}", err);
                return Err(ClientError::Hyper(err));
            }
        };

        debug!("connection upgraded");
        let (reader, writer) =
            downcast_upgrade(upgraded).map_err(|e| ClientError::Upgrade(e.to_string()))?;

        let (relay_client, receiver) =
            RelayClientBuilder::new(self.secret_key.clone(), local_addr, reader, writer)
                .can_ack_pings(self.can_ack_pings)
                .prober(self.is_prober)
                .server_public_key(self.server_public_key)
                .build()
                .await
                .map_err(|e| ClientError::Build(e.to_string()))?;

        if self.is_preferred && relay_client.note_preferred(true).await.is_err() {
            relay_client.close().await;
            return Err(ClientError::Send);
        }

        trace!("connect_0 done");
        Ok((relay_client, receiver))
    }

    /// Sends the HTTP upgrade request to the relay server.
    async fn start_upgrade<T>(io: T) -> Result<hyper::Response<Incoming>, ClientError>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(io);
        let (mut request_sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(io)
            .await?;
        tokio::spawn(
            // This task drives the HTTP exchange, completes once connection is upgraded.
            async move {
                debug!("HTTP upgrade driver started");
                if let Err(err) = connection.with_upgrades().await {
                    error!("HTTP upgrade error: {err:#}");
                }
                debug!("HTTP upgrade driver finished");
            }
            .instrument(info_span!("http-driver")),
        );
        debug!("Sending upgrade request");
        let req = Request::builder()
            .uri("/derp")
            .header(UPGRADE, super::HTTP_UPGRADE_PROTOCOL)
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
        request_sender.send_request(req).await.map_err(From::from)
    }

    async fn note_preferred(&mut self, is_preferred: bool) {
        let old = &mut self.is_preferred;
        if *old == is_preferred {
            return;
        }
        *old = is_preferred;

        // only send the preference if we already have a connection
        let res = {
            if let Some((ref client, _)) = self.relay_client {
                client.note_preferred(is_preferred).await
            } else {
                return;
            }
        };
        // need to do this outside the above closure because they rely on the same lock
        // if there was an error sending, close the underlying relay connection
        if res.is_err() {
            self.close_for_reconnect().await;
        }
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        if self.is_closed {
            return None;
        }
        if let Some((ref client, _)) = self.relay_client {
            match client.local_addr() {
                Ok(addr) => return Some(addr),
                _ => return None,
            }
        }
        None
    }

    async fn ping(&mut self, s: oneshot::Sender<Result<Duration, ClientError>>) {
        let connect_res = self.connect("ping").await.map(|(c, _, _)| c);
        let (ping, recv) = self.pings.register();
        trace!("ping: {}", hex::encode(ping));

        self.ping_tasks.spawn(async move {
            let res = match connect_res {
                Ok(client) => {
                    let start = Instant::now();
                    if let Err(err) = client.send_ping(ping).await {
                        warn!("failed to send ping: {:?}", err);
                        Err(ClientError::Send)
                    } else {
                        match tokio::time::timeout(PING_TIMEOUT, recv).await {
                            Ok(Ok(())) => Ok(start.elapsed()),
                            Err(_) => Err(ClientError::PingTimeout),
                            Ok(Err(_)) => Err(ClientError::PingAborted),
                        }
                    }
                }
                Err(err) => Err(err),
            };
            s.send(res).ok();
        });
    }

    async fn send(&mut self, dst_key: PublicKey, b: Bytes) -> Result<(), ClientError> {
        trace!(dst = %dst_key.fmt_short(), len = b.len(), "send");
        let (client, _, _) = self.connect("send").await?;
        if client.send(dst_key, b).await.is_err() {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    async fn send_pong(&mut self, data: [u8; 8]) -> Result<(), ClientError> {
        debug!("send_pong");
        if self.can_ack_pings {
            let (client, _, _) = self.connect("send_pong").await?;
            if client.send_pong(data).await.is_err() {
                self.close_for_reconnect().await;
                return Err(ClientError::Send);
            }
            Ok(())
        } else {
            Err(ClientError::CannotAckPings)
        }
    }

    async fn close(mut self) {
        if !self.is_closed {
            self.is_closed = true;
            self.close_for_reconnect().await;
        }
    }

    fn is_connected(&self) -> bool {
        if self.is_closed {
            return false;
        }
        self.relay_client.is_some()
    }

    fn current_conn(&self) -> usize {
        self.conn_gen
    }

    fn next_conn(&mut self) -> usize {
        self.conn_gen = self.conn_gen.wrapping_add(1);
        self.conn_gen
    }

    fn tls_servername(&self) -> Option<rustls::ServerName> {
        self.url
            .host_str()
            .and_then(|s| rustls::ServerName::try_from(s).ok())
    }

    fn url_port(&self) -> Option<u16> {
        if let Some(port) = self.url.port() {
            return Some(port);
        }

        match self.url.scheme() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        }
    }

    fn use_https(&self) -> bool {
        // only disable https if we are explicitly dialing a http url
        if self.url.scheme() == "http" {
            return false;
        }
        true
    }

    async fn dial_url(&self) -> Result<TcpStream, ClientError> {
        debug!(%self.url, "dial url");

        let prefer_ipv6 = self.prefer_ipv6().await;
        let dst_ip = resolve_host(&self.dns_resolver, &self.url, prefer_ipv6).await?;

        let port = self
            .url_port()
            .ok_or_else(|| ClientError::InvalidUrl("missing url port".into()))?;
        let addr = SocketAddr::new(dst_ip, port);

        debug!("connecting to {}", addr);
        let tcp_stream =
            tokio::time::timeout(
                DIAL_NODE_TIMEOUT,
                async move { TcpStream::connect(addr).await },
            )
            .await
            .map_err(|_| ClientError::ConnectTimeout)?
            .map_err(ClientError::DialIO)?;

        Ok(tcp_stream)
    }

    /// Reports whether IPv4 dials should be slightly
    /// delayed to give IPv6 a better chance of winning dial races.
    /// Implementations should only return true if IPv6 is expected
    /// to succeed. (otherwise delaying IPv4 will delay the connection
    /// overall)
    async fn prefer_ipv6(&self) -> bool {
        match self.address_family_selector {
            Some(ref selector) => selector().await,
            None => false,
        }
    }

    async fn recv_detail(&mut self) -> Result<(ReceivedMessage, usize), ClientError> {
        if let Some((_client, client_receiver)) = self.relay_client.as_mut() {
            trace!("recv_detail tick");
            match client_receiver.recv().await {
                Ok(msg) => {
                    let current_gen = self.current_conn();
                    return Ok((msg, current_gen));
                }
                Err(e) => {
                    self.close_for_reconnect().await;
                    if self.is_closed {
                        return Err(ClientError::Closed);
                    }
                    // TODO(ramfox): more specific error?
                    return Err(ClientError::Receive(e));
                }
            }
        }
        std::future::pending().await
    }

    /// Close the underlying relay connection. The next time the client takes some action that
    /// requires a connection, it will call `connect`.
    async fn close_for_reconnect(&mut self) {
        debug!("close for reconnect");
        if let Some((client, _)) = self.relay_client.take() {
            client.close().await
        }
    }
}

async fn resolve_host(
    resolver: &DnsResolver,
    url: &Url,
    prefer_ipv6: bool,
) -> Result<IpAddr, ClientError> {
    let host = url
        .host()
        .ok_or_else(|| ClientError::InvalidUrl("missing host".into()))?;
    match host {
        url::Host::Domain(domain) => {
            // Need to do a DNS lookup
            let addrs = lookup_ipv4_ipv6(resolver, domain, DNS_TIMEOUT)
                .await
                .map_err(|e| ClientError::Dns(Some(e)))?;

            if prefer_ipv6 {
                if let Some(addr) = addrs.iter().find(|addr| addr.is_ipv6()) {
                    return Ok(*addr);
                }
            }
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| ClientError::Dns(None))
        }
        url::Host::Ipv4(ip) => Ok(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => Ok(IpAddr::V6(ip)),
    }
}

fn downcast_upgrade(
    upgraded: Upgraded,
) -> anyhow::Result<(
    Box<dyn AsyncRead + Unpin + Send + Sync + 'static>,
    Box<dyn AsyncWrite + Unpin + Send + Sync + 'static>,
)> {
    match upgraded.downcast::<hyper_util::rt::TokioIo<tokio::net::TcpStream>>() {
        Ok(Parts { read_buf, io, .. }) => {
            let (reader, writer) = tokio::io::split(io.into_inner());
            // Prepend data to the reader to avoid data loss
            let reader = std::io::Cursor::new(read_buf).chain(reader);

            Ok((Box::new(reader), Box::new(writer)))
        }
        Err(upgraded) => {
            if let Ok(Parts { read_buf, io, .. }) =
                upgraded.downcast::<hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>()
            {
                let (reader, writer) = tokio::io::split(io.into_inner());
                // Prepend data to the reader to avoid data loss
                let reader = std::io::Cursor::new(read_buf).chain(reader);

                return Ok((Box::new(reader), Box::new(writer)));
            }

            bail!(
                "could not downcast the upgraded connection to a TcpStream or client::TlsStream<TcpStream>"
            )
        }
    }
}

/// Used to allow self signed certificates in tests
#[cfg(any(test, feature = "test-utils"))]
struct NoCertVerifier;

#[cfg(any(test, feature = "test-utils"))]
impl rustls::client::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::dns::default_resolver;

    use super::*;

    #[tokio::test]
    async fn test_recv_detail_connect_error() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let key = SecretKey::generate();
        let bad_url: Url = "https://bad.url".parse().unwrap();
        let dns_resolver = default_resolver();

        let (_client, mut client_receiver) =
            ClientBuilder::new(bad_url).build(key.clone(), dns_resolver.clone());

        // ensure that the client will bubble up any connection error & not
        // just loop ad infinitum attempting to connect
        if client_receiver.recv().await.and_then(|s| s.ok()).is_some() {
            bail!("expected client with bad relay node detail to return with an error");
        }
        Ok(())
    }
}
