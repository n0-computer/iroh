//! Exposes [`Client`], which allows to establish connections to a relay server.
//!
//! Based on tailscale/derp/derphttp/derphttp_client.go

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use anyhow::{anyhow, bail, Result};
use conn::Conn;
#[cfg(not(wasm_browser))]
use hickory_resolver::TokioResolver as DnsResolver;
use iroh_base::{RelayUrl, SecretKey};
use n0_future::{
    split::{split, SplitSink, SplitStream},
    Sink, Stream,
};
#[cfg(any(test, feature = "test-utils"))]
use tracing::warn;
use tracing::{debug, event, trace, Level};
use url::Url;

pub use self::conn::{ConnSendError, ReceivedMessage, SendMessage};
use crate::{
    http::{Protocol, RELAY_PATH},
    KeyCache,
};

pub(crate) mod conn;
#[cfg(not(wasm_browser))]
mod connect_relay;
#[cfg(not(wasm_browser))]
pub(crate) mod streams;
#[cfg(not(wasm_browser))]
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
    /// The secret key of this client.
    secret_key: SecretKey,
    /// The DNS resolver to use.
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    /// Cache for public keys of remote nodes.
    key_cache: KeyCache,
}

impl ClientBuilder {
    /// Create a new [`ClientBuilder`]
    pub fn new(
        url: impl Into<RelayUrl>,
        secret_key: SecretKey,
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
    ) -> Self {
        ClientBuilder {
            address_family_selector: None,
            is_prober: false,
            url: url.into(),

            // Resolves to websockets in browsers and relay otherwise
            protocol: Protocol::default(),

            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify: false,

            proxy_url: None,
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            key_cache: KeyCache::new(128),
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
        self.key_cache = KeyCache::new(capacity);
        self
    }

    /// Establishes a new connection to the relay server.
    pub async fn connect(&self) -> Result<Client> {
        let (conn, local_addr) = match self.protocol {
            Protocol::Websocket => {
                let conn = self.connect_ws().await?;
                let local_addr = None;
                (conn, local_addr)
            }
            #[cfg(not(wasm_browser))]
            Protocol::Relay => {
                let (conn, local_addr) = self.connect_relay().await?;
                (conn, Some(local_addr))
            }
            #[cfg(wasm_browser)]
            Protocol::Relay => {
                bail!("Can only connect to relay using websockets in browsers.");
            }
        };

        event!(
            target: "events.net.relay.connected",
            Level::DEBUG,
            url = %self.url,
            protocol = ?self.protocol,
        );

        trace!("connect done");
        Ok(Client { conn, local_addr })
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

    fn use_tls(&self) -> bool {
        // only disable tls if we are explicitly dialing a http url
        #[allow(clippy::match_like_matches_macro)]
        match self.url.scheme() {
            "http" => false,
            "ws" => false,
            _ => true,
        }
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
        let (sink, stream) = split(self.conn);
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
