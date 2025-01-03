//! Exposes [`Client`], which allows to establish connections to a relay server.
//!
//! Based on tailscale/derp/derphttp/derphttp_client.go

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use conn::Conn;
use data_encoding::BASE64URL;
use futures_lite::Stream;
use futures_util::{
    stream::{SplitSink, SplitStream},
    Sink, StreamExt,
};
use hickory_resolver::TokioResolver as DnsResolver;
use http_body_util::Empty;
use hyper::{
    body::Incoming,
    header::{HOST, UPGRADE},
    upgrade::Parts,
    Request,
};
use hyper_util::rt::TokioIo;
use iroh_base::{RelayUrl, SecretKey};
use rustls::client::Resumption;
use streams::{downcast_upgrade, MaybeTlsStream, ProxyStream};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
#[cfg(any(test, feature = "test-utils"))]
use tracing::warn;
use tracing::{debug, error, event, info_span, trace, Instrument, Level};
use url::Url;

pub use self::conn::{ConnSendError, ReceivedMessage, SendMessage};
use crate::{
    defaults::timeouts::*,
    http::{Protocol, RELAY_PATH},
    KeyCache,
};

pub(crate) mod conn;
pub(crate) mod streams;
mod util;

/// Build a Client.
#[derive(derive_more::Debug, Clone)]
pub struct ClientBuilder {
    /// Default is None
    #[debug("address family selector callback")]
    address_family_selector: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// Default is false
    is_prober: bool,
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
    /// The secret key of this client.
    secret_key: SecretKey,
    /// The DNS resolver to use.
    dns_resolver: DnsResolver,
}

impl ClientBuilder {
    /// Create a new [`ClientBuilder`]
    pub fn new(url: impl Into<RelayUrl>, secret_key: SecretKey, dns_resolver: DnsResolver) -> Self {
        ClientBuilder {
            address_family_selector: None,
            is_prober: false,
            url: url.into(),
            protocol: Protocol::Relay,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify: false,
            proxy_url: None,
            key_cache_capacity: 128,
            secret_key,
            dns_resolver,
        }
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
        self.address_family_selector = Some(Arc::new(selector));
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

    /// Establishes a new connection to the relay server.
    pub async fn connect(&self) -> Result<Client> {
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
            warn!("Insecure config: SSL certificates from relay servers not verified");
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertVerifier));
        }

        config.resumption = Resumption::default();

        let tls_connector: tokio_rustls::TlsConnector = Arc::new(config).into();

        let builder = ConnectionBuilder {
            secret_key: self.secret_key.clone(),
            address_family_selector: self.address_family_selector.clone(),
            url: self.url.clone(),
            protocol: self.protocol,
            tls_connector,
            dns_resolver: self.dns_resolver.clone(),
            proxy_url: self.proxy_url.clone(),
            key_cache: KeyCache::new(self.key_cache_capacity),
        };
        let (conn, local_addr) = builder.connect_0().await?;

        Ok(Client { conn, local_addr })
    }
}

/// A relay client.
#[derive(Debug)]
pub struct Client {
    conn: Conn,
    local_addr: Option<SocketAddr>,
}

impl Client {
    /// Splits the client into a sink and a stream.
    pub fn split(self) -> (ClientStream, ClientSink) {
        let (sink, stream) = self.conn.split();
        (
            ClientStream {
                stream,
                local_addr: self.local_addr,
            },
            ClientSink { sink },
        )
    }
}

impl Stream for Client {
    type Item = Result<ReceivedMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.conn).poll_next(cx)
    }
}

impl Sink<SendMessage> for Client {
    type Error = ConnSendError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        <Conn as Sink<SendMessage>>::poll_ready(Pin::new(&mut self.conn), cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: SendMessage) -> Result<(), Self::Error> {
        Pin::new(&mut self.conn).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        <Conn as Sink<SendMessage>>::poll_flush(Pin::new(&mut self.conn), cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        <Conn as Sink<SendMessage>>::poll_close(Pin::new(&mut self.conn), cx)
    }
}

/// The send half of a relay client.
#[derive(Debug)]
pub struct ClientSink {
    sink: SplitSink<Conn, SendMessage>,
}

impl Sink<SendMessage> for ClientSink {
    type Error = ConnSendError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: SendMessage) -> Result<(), Self::Error> {
        Pin::new(&mut self.sink).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_close(cx)
    }
}

/// The receive half of a relay client.
#[derive(Debug)]
pub struct ClientStream {
    stream: SplitStream<Conn>,
    local_addr: Option<SocketAddr>,
}

impl ClientStream {
    /// Returns the local address of the client.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

impl Stream for ClientStream {
    type Item = Result<ReceivedMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
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

/// Some state to build a new connection.
///
/// Not because this necessarily the best way to structure this code, but because it was
/// easy to migrate existing code.
#[derive(derive_more::Debug)]
struct ConnectionBuilder {
    secret_key: SecretKey,
    #[debug("address family selector callback")]
    address_family_selector: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    url: RelayUrl,
    protocol: Protocol,
    #[debug("TlsConnector")]
    tls_connector: tokio_rustls::TlsConnector,
    dns_resolver: DnsResolver,
    proxy_url: Option<Url>,
    key_cache: KeyCache,
}

impl ConnectionBuilder {
    async fn connect_0(&self) -> Result<(Conn, Option<SocketAddr>)> {
        let (conn, local_addr) = match self.protocol {
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

        event!(
            target: "events.net.relay.connected",
            Level::DEBUG,
            url = %self.url,
            protocol = ?self.protocol,
        );

        trace!("connect_0 done");
        Ok((conn, local_addr))
    }

    async fn connect_ws(&self) -> Result<Conn> {
        let mut dial_url = (*self.url).clone();
        dial_url.set_path(RELAY_PATH);
        // The relay URL is exchanged with the http(s) scheme in tickets and similar.
        // We need to use the ws:// or wss:// schemes when connecting with websockets, though.
        dial_url
            .set_scheme(if self.use_tls() { "wss" } else { "ws" })
            .map_err(|()| anyhow!("Invalid URL"))?;

        debug!(%dial_url, "Dialing relay by websocket");

        let conn = tokio_tungstenite_wasm::connect(dial_url).await?;
        let conn = Conn::new_ws(conn, self.key_cache.clone(), &self.secret_key).await?;
        Ok(conn)
    }

    async fn connect_relay(&self) -> Result<(Conn, SocketAddr)> {
        let url = self.url.clone();
        let tcp_stream = self.dial_url().await?;

        let local_addr = tcp_stream
            .local_addr()
            .context("No local addr for TCP stream")?;

        debug!(server_addr = ?tcp_stream.peer_addr(), %local_addr, "TCP stream connected");

        let response = if self.use_tls() {
            debug!("Starting TLS handshake");
            let hostname = self
                .tls_servername()
                .ok_or_else(|| anyhow!("No tls servername"))?;
            let hostname = hostname.to_owned();
            let tls_stream = self.tls_connector.connect(hostname, tcp_stream).await?;
            debug!("tls_connector connect success");
            Self::start_upgrade(tls_stream, url).await?
        } else {
            debug!("Starting handshake");
            Self::start_upgrade(tcp_stream, url).await?
        };

        if response.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
            bail!(
                "Unexpected status code: expected {}, actual: {}",
                hyper::StatusCode::SWITCHING_PROTOCOLS,
                response.status(),
            );
        }

        debug!("starting upgrade");
        let upgraded = hyper::upgrade::on(response)
            .await
            .context("Upgrade failed")?;

        debug!("connection upgraded");
        let conn = downcast_upgrade(upgraded)?;

        let conn = Conn::new_relay(conn, self.key_cache.clone(), &self.secret_key).await?;

        Ok((conn, local_addr))
    }

    /// Sends the HTTP upgrade request to the relay server.
    async fn start_upgrade<T>(io: T, relay_url: RelayUrl) -> Result<hyper::Response<Incoming>>
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

    async fn dial_url(&self) -> Result<ProxyStream> {
        if let Some(ref proxy) = self.proxy_url {
            let stream = self.dial_url_proxy(proxy.clone()).await?;
            Ok(ProxyStream::Proxied(stream))
        } else {
            let stream = self.dial_url_direct().await?;
            Ok(ProxyStream::Raw(stream))
        }
    }

    async fn dial_url_direct(&self) -> Result<TcpStream> {
        debug!(%self.url, "dial url");
        let prefer_ipv6 = self.prefer_ipv6();
        let dst_ip = self
            .dns_resolver
            .resolve_host(&self.url, prefer_ipv6)
            .await?;

        let port = url_port(&self.url).ok_or_else(|| anyhow!("Missing URL port"))?;
        let addr = SocketAddr::new(dst_ip, port);

        debug!("connecting to {}", addr);
        let tcp_stream =
            tokio::time::timeout(
                DIAL_NODE_TIMEOUT,
                async move { TcpStream::connect(addr).await },
            )
            .await
            .context("Timeout connecting")?
            .context("Failed connecting")?;
        tcp_stream.set_nodelay(true)?;

        Ok(tcp_stream)
    }

    async fn dial_url_proxy(
        &self,
        proxy_url: Url,
    ) -> Result<util::Chain<std::io::Cursor<Bytes>, MaybeTlsStream>> {
        debug!(%self.url, %proxy_url, "dial url via proxy");

        // Resolve proxy DNS
        let prefer_ipv6 = self.prefer_ipv6();
        let proxy_ip = self
            .dns_resolver
            .resolve_host(&proxy_url, prefer_ipv6)
            .await?;

        let proxy_port = url_port(&proxy_url).ok_or_else(|| anyhow!("Missing proxy url port"))?;
        let proxy_addr = SocketAddr::new(proxy_ip, proxy_port);

        debug!(%proxy_addr, "connecting to proxy");

        let tcp_stream = tokio::time::timeout(DIAL_NODE_TIMEOUT, async move {
            TcpStream::connect(proxy_addr).await
        })
        .await
        .context("Timeout connecting")?
        .context("Error connecting")?;

        tcp_stream.set_nodelay(true)?;

        // Setup TLS if necessary
        let io = if proxy_url.scheme() == "http" {
            MaybeTlsStream::Raw(tcp_stream)
        } else {
            let hostname = proxy_url.host_str().context("No hostname in proxy URL")?;
            let hostname = rustls::pki_types::ServerName::try_from(hostname.to_string())?;
            let tls_stream = self.tls_connector.connect(hostname, tcp_stream).await?;
            MaybeTlsStream::Tls(tls_stream)
        };
        let io = TokioIo::new(io);

        let target_host = self
            .url
            .host_str()
            .ok_or_else(|| anyhow!("Missing proxy host"))?;

        let port = url_port(&self.url).ok_or_else(|| anyhow!("invalid target port"))?;

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
            let encoded = BASE64URL.encode(to_encode.as_bytes());
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
            bail!("Failed to connect to proxy: {}", res.status());
        }

        let upgraded = hyper::upgrade::on(res).await?;
        let Ok(Parts { io, read_buf, .. }) = upgraded.downcast::<TokioIo<MaybeTlsStream>>() else {
            bail!("Invalid upgrade");
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

fn host_header_value(relay_url: RelayUrl) -> Result<String> {
    // grab the host, turns e.g. https://example.com:8080/xyz -> example.com.
    let relay_url_host = relay_url.host_str().context("Invalid URL")?;
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
    ) -> impl Future<Output = Result<Option<IpAddr>>>;

    fn lookup_ipv6<N: hickory_resolver::IntoName>(
        &self,
        host: N,
    ) -> impl Future<Output = Result<Option<IpAddr>>>;

    fn resolve_host(&self, url: &Url, prefer_ipv6: bool) -> impl Future<Output = Result<IpAddr>>;
}

impl DnsExt for DnsResolver {
    async fn lookup_ipv4<N: hickory_resolver::IntoName>(&self, host: N) -> Result<Option<IpAddr>> {
        let addrs = tokio::time::timeout(DNS_TIMEOUT, self.ipv4_lookup(host)).await??;
        Ok(addrs.into_iter().next().map(|ip| IpAddr::V4(ip.0)))
    }

    async fn lookup_ipv6<N: hickory_resolver::IntoName>(&self, host: N) -> Result<Option<IpAddr>> {
        let addrs = tokio::time::timeout(DNS_TIMEOUT, self.ipv6_lookup(host)).await??;
        Ok(addrs.into_iter().next().map(|ip| IpAddr::V6(ip.0)))
    }

    async fn resolve_host(&self, url: &Url, prefer_ipv6: bool) -> Result<IpAddr> {
        let host = url.host().context("Invalid URL")?;
        match host {
            url::Host::Domain(domain) => {
                // Need to do a DNS lookup
                let lookup = tokio::join!(self.lookup_ipv4(domain), self.lookup_ipv6(domain));
                let (v4, v6) = match lookup {
                    (Err(ipv4_err), Err(ipv6_err)) => {
                        bail!("Ipv4: {ipv4_err:?}, Ipv6: {ipv6_err:?}");
                    }
                    (Err(_), Ok(v6)) => (None, v6),
                    (Ok(v4), Err(_)) => (v4, None),
                    (Ok(v4), Ok(v6)) => (v4, v6),
                };
                if prefer_ipv6 { v6.or(v4) } else { v4.or(v6) }.context("No response")
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
