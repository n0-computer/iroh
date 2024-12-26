//! Exposes [`Client`], which allows to establish connections to a relay server.
//!
//! Based on tailscale/derp/derphttp/derphttp_client.go

use std::{
    collections::HashMap,
    future::{self, Future},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use bytes::Bytes;
use conn::Conn;
use futures_util::StreamExt;
use hickory_resolver::TokioResolver as DnsResolver;
use http_body_util::Empty;
use hyper::{
    body::Incoming,
    header::{HOST, UPGRADE},
    upgrade::Parts,
    Request,
};
use hyper_util::rt::TokioIo;
use iroh_base::{NodeId, PublicKey, RelayUrl, SecretKey};
use rand::Rng;
use rustls::client::Resumption;
use streams::{downcast_upgrade, MaybeTlsStream, ProxyStream};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::oneshot,
    time::Instant,
};
use tracing::{debug, error, event, info_span, trace, warn, Instrument, Level};
use url::Url;

pub use self::conn::ReceivedMessage;
use crate::{
    defaults::timeouts::*,
    http::{Protocol, RELAY_PATH},
    KeyCache,
};

pub(crate) mod conn;
pub(crate) mod streams;
mod util;

/// Possible connection errors on the [`Client`]
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// There was an error sending a packet
    #[error("error sending a packet")]
    Send,
    /// There was a connection timeout error
    #[error("connect timeout")]
    ConnectTimeout,
    /// There was an error dialing
    #[error("dial error")]
    DialIO(#[from] std::io::Error),
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
    /// The connection failed to proxy
    #[error("failed to proxy connection: {0}")]
    Proxy(String),
    /// The relay [`super::client::Client`] failed to build
    #[error("failed to build relay client: {0}")]
    Build(String),
    /// The ping request timed out
    #[error("ping timeout")]
    PingTimeout,
    /// The ping request was aborted
    #[error("ping aborted")]
    PingAborted,
    /// The given [`Url`] is invalid
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// There was an error with DNS resolution
    #[error("dns: {0:?}")]
    Dns(Option<anyhow::Error>),
    /// An error related to websockets, either errors with parsing ws messages or the handshake
    #[error("websocket error: {0}")]
    WebsocketError(#[from] tokio_tungstenite_wasm::Error),
}

/// An HTTP Relay client.
///
/// Cheaply clonable.
#[derive(derive_more::Debug)]
pub struct Client {
    secret_key: SecretKey,
    is_preferred: bool,
    relay_conn: Option<(Conn, Option<SocketAddr>)>,
    #[debug("address family selector callback")]
    address_family_selector: Option<Box<dyn Fn() -> bool + Send + Sync>>,
    url: RelayUrl,
    protocol: Protocol,
    #[debug("TlsConnector")]
    tls_connector: tokio_rustls::TlsConnector,
    pings: PingTracker,
    dns_resolver: DnsResolver,
    proxy_url: Option<Url>,
    key_cache: KeyCache,
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
    fn unregister(&mut self, data: &[u8; 8]) -> Option<oneshot::Sender<()>> {
        trace!("removing ping {}", data_encoding::HEXLOWER.encode(data),);
        self.0.remove(data)
    }
}

/// Build a Client.
#[derive(derive_more::Debug)]
pub struct ClientBuilder {
    /// Default is None
    #[debug("address family selector callback")]
    address_family_selector: Option<Box<dyn Fn() -> bool + Send + Sync>>,
    /// Default is false
    is_prober: bool,
    /// Expected PublicKey of the server
    server_public_key: Option<PublicKey>,
    /// Server url.
    url: RelayUrl,
    /// Relay protocol
    protocol: Protocol,
    /// Allow self-signed certificates from relay servers
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_cert_verify: bool,
    /// HTTP Proxy
    proxy_url: Option<Url>,
    /// Capacity of the key cache
    key_cache_capacity: usize,
}

impl ClientBuilder {
    /// Create a new [`ClientBuilder`]
    pub fn new(url: impl Into<RelayUrl>) -> Self {
        ClientBuilder {
            address_family_selector: None,
            is_prober: false,
            server_public_key: None,
            url: url.into(),
            protocol: Protocol::Relay,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify: false,
            proxy_url: None,
            key_cache_capacity: 128,
        }
    }

    /// Sets the server url
    pub fn server_url(mut self, url: impl Into<RelayUrl>) -> Self {
        self.url = url.into();
        self
    }

    /// Sets whether to connect to the relay via websockets or not.
    /// Set to use non-websocket, normal relaying by default.
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
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
        S: Fn() -> bool + Send + Sync + 'static,
    {
        self.address_family_selector = Some(Box::new(selector));
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

    /// Set an explicit proxy url to proxy all HTTP(S) traffic through.
    pub fn proxy_url(mut self, url: Url) -> Self {
        self.proxy_url.replace(url);
        self
    }

    /// Set the capacity of the cache for public keys.
    pub fn key_cache_capacity(mut self, capacity: usize) -> Self {
        self.key_cache_capacity = capacity;
        self
    }

    /// Build the [`Client`]
    pub fn build(self, key: SecretKey, dns_resolver: DnsResolver) -> Client {
        // TODO: review TLS config
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut config = rustls::client::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocols supported by ring")
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

        Client {
            secret_key: key,
            is_preferred: false,
            relay_conn: None,
            address_family_selector: self.address_family_selector,
            pings: PingTracker::default(),
            url: self.url,
            protocol: self.protocol,
            tls_connector,
            dns_resolver,
            proxy_url: self.proxy_url,
            key_cache: KeyCache::new(self.key_cache_capacity),
        }
    }

    /// The expected [`PublicKey`] of the relay server we are connecting to.
    pub fn server_public_key(mut self, server_public_key: PublicKey) -> Self {
        self.server_public_key = Some(server_public_key);
        self
    }
}

#[cfg(any(test, feature = "test-utils"))]
/// Creates a client config that trusts any servers without verifying their TLS certificate.
///
/// Should be used for testing local relay setups only.
pub fn make_dangerous_client_config() -> rustls::ClientConfig {
    warn!(
        "Insecure config: SSL certificates from relay servers will be trusted without verification"
    );
    rustls::client::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("protocols supported by ring")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
    .with_no_client_auth()
}

impl Client {
    /// Reads a message from the server.
    ///
    /// Any [`ReceivedMessage::Pong`] messages which are in response to a pong we sent will
    /// wake up the future returned by [`Client::send_ping`] and not be returned here.  Any
    /// unknown ping messages are returned.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe.  If the future is dropped before completion it is
    /// guaranteed that no message is lost.
    pub async fn recv(
        &mut self,
    ) -> Result<Option<anyhow::Result<ReceivedMessage>>, tokio::time::error::Elapsed> {
        if let Some((conn, _)) = self.relay_conn.as_mut() {
            loop {
                let res = tokio::time::timeout(CLIENT_RECV_TIMEOUT, conn.next()).await;
                if let Ok(Some(Ok(ReceivedMessage::Pong(ref data)))) = res {
                    match self.pings.unregister(data) {
                        Some(chan) => {
                            chan.send(()).ok();
                            continue;
                        }
                        None => {
                            warn!(ping = ?data, "Unknown pong received.");
                        }
                    }
                }
                return res;
            }
        } else {
            future::pending().await
        }
    }

    /// Connects to a relay Server.
    ///
    /// If there already is a connection it is returned rather than re-establishing it.
    pub async fn connect(&mut self) -> Result<(), ClientError> {
        self.connect_inner("public api").await?;
        Ok(())
    }

    async fn connect_inner(
        &mut self,
        why: &'static str,
    ) -> Result<(&'_ mut Conn, Option<SocketAddr>), ClientError> {
        debug!(url = %self.url, %why, "connecting");

        if self.relay_conn.is_none() {
            trace!("no connection, trying to connect");
            let (conn, local_addr) = tokio::time::timeout(CONNECT_TIMEOUT, self.connect_0())
                .await
                .map_err(|_| ClientError::ConnectTimeout)??;

            self.relay_conn = Some((conn, local_addr));
        } else {
            trace!("already had connection");
        }

        let (conn, addr) = self.relay_conn.as_mut().expect("just checked");

        Ok((conn, *addr))
    }

    async fn connect_0(&self) -> Result<(Conn, Option<SocketAddr>), ClientError> {
        let (mut conn, local_addr) = match self.protocol {
            Protocol::Websocket => {
                let conn = self.connect_ws().await?;
                let local_addr = None;
                (conn, local_addr)
            }
            Protocol::Relay => {
                let (conn, local_addr) = self.connect_relay().await?;
                (conn, Some(local_addr))
            }
        };

        if self.is_preferred {
            if let Err(err) = conn.note_preferred(true).await {
                warn!("failed to note preferred connection: {:?}", err);
                conn.close().await;
                return Err(ClientError::Send);
            }
        }

        event!(
            target: "events.net.relay.connected",
            Level::DEBUG,
            home = self.is_preferred,
            url = %self.url,
        );

        trace!("connect_0 done");
        Ok((conn, local_addr))
    }

    async fn connect_ws(&self) -> Result<Conn, ClientError> {
        let mut dial_url = (*self.url).clone();
        dial_url.set_path(RELAY_PATH);
        // The relay URL is exchanged with the http(s) scheme in tickets and similar.
        // We need to use the ws:// or wss:// schemes when connecting with websockets, though.
        dial_url
            .set_scheme(if self.use_tls() { "wss" } else { "ws" })
            .map_err(|()| ClientError::InvalidUrl(self.url.to_string()))?;

        debug!(%dial_url, "Dialing relay by websocket");

        let conn = tokio_tungstenite_wasm::connect(dial_url).await?;
        let conn = Conn::new_ws(conn, self.key_cache.clone(), &self.secret_key)
            .await
            .map_err(|e| ClientError::Build(e.to_string()))?;
        Ok(conn)
    }

    async fn connect_relay(&self) -> Result<(Conn, SocketAddr), ClientError> {
        let url = self.url.clone();
        let tcp_stream = self.dial_url().await?;

        let local_addr = tcp_stream
            .local_addr()
            .map_err(|e| ClientError::NoLocalAddr(e.to_string()))?;

        debug!(server_addr = ?tcp_stream.peer_addr(), %local_addr, "TCP stream connected");

        let response = if self.use_tls() {
            debug!("Starting TLS handshake");
            let hostname = self
                .tls_servername()
                .ok_or_else(|| ClientError::InvalidUrl("No tls servername".into()))?;
            let hostname = hostname.to_owned();
            let tls_stream = self.tls_connector.connect(hostname, tcp_stream).await?;
            debug!("tls_connector connect success");
            Self::start_upgrade(tls_stream, url).await?
        } else {
            debug!("Starting handshake");
            Self::start_upgrade(tcp_stream, url).await?
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
        let conn = downcast_upgrade(upgraded).map_err(|e| ClientError::Upgrade(e.to_string()))?;

        let conn = Conn::new_relay(conn, self.key_cache.clone(), &self.secret_key)
            .await
            .map_err(|e| ClientError::Build(e.to_string()))?;

        Ok((conn, local_addr))
    }

    /// Sends the HTTP upgrade request to the relay server.
    async fn start_upgrade<T>(
        io: T,
        relay_url: RelayUrl,
    ) -> Result<hyper::Response<Incoming>, ClientError>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let host_header_value = host_header_value(relay_url)?;

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
            .uri(RELAY_PATH)
            .header(UPGRADE, Protocol::Relay.upgrade_header())
            // https://datatracker.ietf.org/doc/html/rfc2616#section-14.23
            // > A client MUST include a Host header field in all HTTP/1.1 request messages.
            // This header value helps reverse proxies identify how to forward requests.
            .header(HOST, host_header_value)
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
        request_sender.send_request(req).await.map_err(From::from)
    }

    /// Let the server know that this client is the preferred client
    pub async fn note_preferred(&mut self, is_preferred: bool) {
        let old = &mut self.is_preferred;
        if *old == is_preferred {
            return;
        }
        *old = is_preferred;

        // only send the preference if we already have a connection
        let res = {
            if let Some((ref mut conn, _)) = self.relay_conn {
                conn.note_preferred(is_preferred).await
            } else {
                return;
            }
        };
        // need to do this outside the above closure because they rely on the same lock
        // if there was an error sending, close the underlying relay connection
        if res.is_err() {
            self.close().await;
        }
    }

    /// Returns the local addr of the connection.
    ///
    /// If there is no current underlying relay connection, `None` is returned.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.relay_conn.as_ref().and_then(|(_, addr)| *addr)
    }

    /// Send a ping to the server.
    ///
    /// The returned future will complete once we get an expected pong.
    ///
    /// [`Client::recv`] must be called for any reads to occur and thus to process the pong
    /// reply.
    ///
    /// This has a built-in timeout `crate::defaults::timeouts::PING_TIMEOUT`.
    pub async fn send_ping(
        &mut self,
    ) -> Result<
        impl Future<Output = Result<Duration, ClientError>> + Send + Sync + 'static,
        ClientError,
    > {
        let (ping, recv) = self.pings.register();
        let conn = self.connect_inner("ping").await.map(|(c, _)| c)?;
        trace!("ping: {}", data_encoding::HEXLOWER.encode(&ping));

        let start = Instant::now();
        if let Err(err) = conn.send_ping(ping).await {
            warn!("failed to send ping: {:?}", err);
            Err(ClientError::Send)
        } else {
            Ok(async move {
                match tokio::time::timeout(PING_TIMEOUT, recv).await {
                    Ok(Ok(())) => Ok(start.elapsed()),
                    Err(_) => Err(ClientError::PingTimeout),
                    Ok(Err(_)) => Err(ClientError::PingAborted),
                }
            })
        }
    }

    /// Sends a packet for a remote node to the server.
    ///
    /// If there is no underlying active relay connection, it creates one before attempting
    /// to send the message.
    ///
    /// If there is an error sending the packet, it closes the underlying relay connection
    /// before returning.
    pub async fn send(&mut self, remote_node: NodeId, payload: Bytes) -> Result<(), ClientError> {
        trace!(remote_node = %remote_node.fmt_short(), len = payload.len(), "send");
        let (conn, _) = self.connect_inner("send").await?;
        if conn.send(remote_node, payload).await.is_err() {
            self.close().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Send a pong back to the server.
    ///
    /// If there is no underlying active relay connection, it creates one before attempting to
    /// send the pong message.
    ///
    /// If there is an error sending pong, it closes the underlying relay connection before
    /// returning.
    pub async fn send_pong(&mut self, data: [u8; 8]) -> Result<(), ClientError> {
        debug!("send_pong");
        let (conn, _) = self.connect_inner("send_pong").await?;
        if conn.send_pong(data).await.is_err() {
            self.close().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Disconnects the http relay connection.
    ///
    /// Closes the underlying relay connection. The next time the client takes some action
    /// that requires a connection, it will call [`Client::connect`].
    pub async fn close(&mut self) {
        if let Some((ref mut conn, _)) = self.relay_conn.take() {
            debug!("Closing connection");
            conn.close().await
        }
    }

    /// Returns `true` if the underlying relay connection is established.
    pub fn is_connected(&self) -> bool {
        self.relay_conn.is_some()
    }

    fn tls_servername(&self) -> Option<rustls::pki_types::ServerName> {
        self.url
            .host_str()
            .and_then(|s| rustls::pki_types::ServerName::try_from(s).ok())
    }

    fn use_tls(&self) -> bool {
        // only disable tls if we are explicitly dialing a http url
        #[allow(clippy::match_like_matches_macro)]
        match self.url.scheme() {
            "http" => false,
            "ws" => false,
            _ => true,
        }
    }

    async fn dial_url(&self) -> Result<ProxyStream, ClientError> {
        if let Some(ref proxy) = self.proxy_url {
            let stream = self.dial_url_proxy(proxy.clone()).await?;
            Ok(ProxyStream::Proxied(stream))
        } else {
            let stream = self.dial_url_direct().await?;
            Ok(ProxyStream::Raw(stream))
        }
    }

    async fn dial_url_direct(&self) -> Result<TcpStream, ClientError> {
        debug!(%self.url, "dial url");
        let prefer_ipv6 = self.prefer_ipv6();
        let dst_ip = self
            .dns_resolver
            .resolve_host(&self.url, prefer_ipv6)
            .await?;

        let port = url_port(&self.url)
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

        tcp_stream.set_nodelay(true)?;

        Ok(tcp_stream)
    }

    async fn dial_url_proxy(
        &self,
        proxy_url: Url,
    ) -> Result<util::Chain<std::io::Cursor<Bytes>, MaybeTlsStream>, ClientError> {
        debug!(%self.url, %proxy_url, "dial url via proxy");

        // Resolve proxy DNS
        let prefer_ipv6 = self.prefer_ipv6();
        let proxy_ip = self
            .dns_resolver
            .resolve_host(&proxy_url, prefer_ipv6)
            .await?;

        let proxy_port = url_port(&proxy_url)
            .ok_or_else(|| ClientError::Proxy("missing proxy url port".into()))?;
        let proxy_addr = SocketAddr::new(proxy_ip, proxy_port);

        debug!(%proxy_addr, "connecting to proxy");

        let tcp_stream = tokio::time::timeout(DIAL_NODE_TIMEOUT, async move {
            TcpStream::connect(proxy_addr).await
        })
        .await
        .map_err(|_| ClientError::ConnectTimeout)?
        .map_err(ClientError::DialIO)?;

        tcp_stream.set_nodelay(true)?;

        // Setup TLS if necessary
        let io = if proxy_url.scheme() == "http" {
            MaybeTlsStream::Raw(tcp_stream)
        } else {
            let hostname = proxy_url
                .host_str()
                .and_then(|s| rustls::pki_types::ServerName::try_from(s.to_string()).ok())
                .ok_or_else(|| ClientError::InvalidUrl("No tls servername for proxy url".into()))?;
            let tls_stream = self.tls_connector.connect(hostname, tcp_stream).await?;
            MaybeTlsStream::Tls(tls_stream)
        };
        let io = TokioIo::new(io);

        let target_host = self
            .url
            .host_str()
            .ok_or_else(|| ClientError::Proxy("missing proxy host".into()))?;

        let port =
            url_port(&self.url).ok_or_else(|| ClientError::Proxy("invalid target port".into()))?;

        // Establish Proxy Tunnel
        let mut req_builder = Request::builder()
            .uri(format!("{}:{}", target_host, port))
            .method("CONNECT")
            .header("Host", target_host)
            .header("Proxy-Connection", "Keep-Alive");
        if !proxy_url.username().is_empty() {
            // Passthrough authorization
            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization
            debug!(
                "setting proxy-authorization: username={}",
                proxy_url.username()
            );
            let to_encode = format!(
                "{}:{}",
                proxy_url.username(),
                proxy_url.password().unwrap_or_default()
            );
            let encoded = URL_SAFE.encode(to_encode);
            req_builder = req_builder.header("Proxy-Authorization", format!("Basic {}", encoded));
        }
        let req = req_builder.body(Empty::<Bytes>::new())?;

        debug!("Sending proxy request: {:?}", req);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                error!("Proxy connection failed: {:?}", err);
            }
        });

        let res = sender.send_request(req).await?;
        if !res.status().is_success() {
            return Err(ClientError::Proxy(format!(
                "failed to connect to proxy: {}",
                res.status(),
            )));
        }

        let upgraded = hyper::upgrade::on(res).await?;
        let Ok(Parts { io, read_buf, .. }) = upgraded.downcast::<TokioIo<MaybeTlsStream>>() else {
            return Err(ClientError::Proxy("invalid upgrade".to_string()));
        };

        let res = util::chain(std::io::Cursor::new(read_buf), io.into_inner());

        Ok(res)
    }

    /// Reports whether IPv4 dials should be slightly
    /// delayed to give IPv6 a better chance of winning dial races.
    /// Implementations should only return true if IPv6 is expected
    /// to succeed. (otherwise delaying IPv4 will delay the connection
    /// overall)
    fn prefer_ipv6(&self) -> bool {
        match self.address_family_selector {
            Some(ref selector) => selector(),
            None => false,
        }
    }
}

fn host_header_value(relay_url: RelayUrl) -> Result<String, ClientError> {
    // grab the host, turns e.g. https://example.com:8080/xyz -> example.com.
    let relay_url_host = relay_url
        .host_str()
        .ok_or_else(|| ClientError::InvalidUrl(relay_url.to_string()))?;
    // strip the trailing dot, if present: example.com. -> example.com
    let relay_url_host = relay_url_host.strip_suffix('.').unwrap_or(relay_url_host);
    // build the host header value (reserve up to 6 chars for the ":" and port digits):
    let mut host_header_value = String::with_capacity(relay_url_host.len() + 6);
    host_header_value += relay_url_host;
    if let Some(port) = relay_url.port() {
        host_header_value += ":";
        host_header_value += &port.to_string();
    }
    Ok(host_header_value)
}

trait DnsExt {
    fn lookup_ipv4<N: hickory_resolver::IntoName>(
        &self,
        host: N,
    ) -> impl future::Future<Output = anyhow::Result<Option<IpAddr>>>;

    fn lookup_ipv6<N: hickory_resolver::IntoName>(
        &self,
        host: N,
    ) -> impl future::Future<Output = anyhow::Result<Option<IpAddr>>>;

    fn resolve_host(
        &self,
        url: &Url,
        prefer_ipv6: bool,
    ) -> impl future::Future<Output = Result<IpAddr, ClientError>>;
}

impl DnsExt for DnsResolver {
    async fn lookup_ipv4<N: hickory_resolver::IntoName>(
        &self,
        host: N,
    ) -> anyhow::Result<Option<IpAddr>> {
        let addrs = tokio::time::timeout(DNS_TIMEOUT, self.ipv4_lookup(host)).await??;
        Ok(addrs.into_iter().next().map(|ip| IpAddr::V4(ip.0)))
    }

    async fn lookup_ipv6<N: hickory_resolver::IntoName>(
        &self,
        host: N,
    ) -> anyhow::Result<Option<IpAddr>> {
        let addrs = tokio::time::timeout(DNS_TIMEOUT, self.ipv6_lookup(host)).await??;
        Ok(addrs.into_iter().next().map(|ip| IpAddr::V6(ip.0)))
    }

    async fn resolve_host(&self, url: &Url, prefer_ipv6: bool) -> Result<IpAddr, ClientError> {
        let host = url
            .host()
            .ok_or_else(|| ClientError::InvalidUrl("missing host".into()))?;
        match host {
            url::Host::Domain(domain) => {
                // Need to do a DNS lookup
                let lookup = tokio::join!(self.lookup_ipv4(domain), self.lookup_ipv6(domain));
                let (v4, v6) = match lookup {
                    (Err(ipv4_err), Err(ipv6_err)) => {
                        let err = anyhow::anyhow!("Ipv4: {:?}, Ipv6: {:?}", ipv4_err, ipv6_err);
                        return Err(ClientError::Dns(Some(err)));
                    }
                    (Err(_), Ok(v6)) => (None, v6),
                    (Ok(v4), Err(_)) => (v4, None),
                    (Ok(v4), Ok(v6)) => (v4, v6),
                };
                if prefer_ipv6 { v6.or(v4) } else { v4.or(v6) }
                    .ok_or_else(|| ClientError::Dns(None))
            }
            url::Host::Ipv4(ip) => Ok(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Ok(IpAddr::V6(ip)),
        }
    }
}

/// Used to allow self signed certificates in tests
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug)]
struct NoCertVerifier;

#[cfg(any(test, feature = "test-utils"))]
impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn url_port(url: &Url) -> Option<u16> {
    if let Some(port) = url.port() {
        return Some(port);
    }

    match url.scheme() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::Result;

    use super::*;

    #[test]
    fn test_host_header_value() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let cases = [
            (
                "https://euw1-1.relay.iroh.network.",
                "euw1-1.relay.iroh.network",
            ),
            ("http://localhost:8080", "localhost:8080"),
        ];

        for (url, expected_host) in cases {
            let relay_url = RelayUrl::from_str(url)?;
            let host = host_header_value(relay_url)?;
            assert_eq!(host, expected_host);
        }

        Ok(())
    }
}
