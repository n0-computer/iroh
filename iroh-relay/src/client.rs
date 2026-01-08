//! Exposes [`Client`], which allows to establish connections to a relay server.
//!
//! Based on tailscale/derp/derphttp/derphttp_client.go

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use conn::Conn;
use iroh_base::{RelayUrl, SecretKey};
use n0_error::{e, stack_error};
use n0_future::{
    Sink, Stream,
    split::{SplitSink, SplitStream, split},
    time,
};
#[cfg(any(test, feature = "test-utils"))]
use tracing::warn;
use tracing::{Level, debug, event, trace};
use url::Url;

pub use self::conn::{RecvError, SendError};
#[cfg(not(wasm_browser))]
use crate::dns::{DnsError, DnsResolver};
use crate::{
    KeyCache,
    http::RELAY_PATH,
    protos::{
        handshake,
        relay::{ClientToRelayMsg, RelayToClientMsg},
    },
};

pub(crate) mod conn;
#[cfg(not(wasm_browser))]
pub(crate) mod streams;
#[cfg(not(wasm_browser))]
mod tls;
#[cfg(not(wasm_browser))]
mod util;

/// Connection errors.
///
/// `ConnectError` contains `DialError`, errors that can occur while dialing the
/// relay, as well as errors that occur while creating or maintaining a connection.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ConnectError {
    #[error("Invalid URL for websocket: {url}")]
    InvalidWebsocketUrl { url: Url },
    #[error("Invalid relay URL: {url}")]
    InvalidRelayUrl { url: Url },
    #[error(transparent)]
    Websocket {
        #[cfg(not(wasm_browser))]
        #[error(std_err)]
        source: tokio_websockets::Error,
        #[cfg(wasm_browser)]
        #[error(std_err)]
        source: ws_stream_wasm::WsErr,
    },
    #[error(transparent)]
    Handshake {
        #[error(std_err)]
        source: handshake::Error,
    },
    #[error(transparent)]
    Dial { source: DialError },
    #[error("Unexpected status during upgrade: {code}")]
    UnexpectedUpgradeStatus { code: hyper::StatusCode },
    #[error("Failed to upgrade response")]
    Upgrade {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("Invalid TLS servername")]
    InvalidTlsServername {},
    #[error("No local address available")]
    NoLocalAddr {},
    #[error("tls connection failed")]
    Tls {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[cfg(wasm_browser)]
    #[error("The relay protocol is not available in browsers")]
    RelayProtoNotAvailable {},
}

/// Errors that can occur while dialing the relay server.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum DialError {
    #[error("Invalid target port")]
    InvalidTargetPort {},
    #[error(transparent)]
    #[cfg(not(wasm_browser))]
    Dns { source: DnsError },
    #[error(transparent)]
    Timeout {
        #[error(std_err)]
        source: time::Elapsed,
    },
    #[error(transparent)]
    Io {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("Invalid URL: {url}")]
    InvalidUrl { url: Url },
    #[error("Failed proxy connection: {status}")]
    ProxyConnectInvalidStatus { status: hyper::StatusCode },
    #[error("Invalid Proxy URL {proxy_url}")]
    ProxyInvalidUrl { proxy_url: Url },
    #[error("failed to establish proxy connection")]
    ProxyConnect {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("Invalid proxy TLS servername: {proxy_hostname}")]
    ProxyInvalidTlsServername { proxy_hostname: String },
    #[error("Invalid proxy target port")]
    ProxyInvalidTargetPort {},
}

/// Build a Client.
#[derive(derive_more::Debug, Clone)]
pub struct ClientBuilder {
    /// Default is None
    #[debug("address family selector callback")]
    address_family_selector: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// Server url.
    url: RelayUrl,
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
    /// Cache for public keys of remote endpoints.
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
            url: url.into(),

            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify: false,

            proxy_url: None,
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            key_cache: KeyCache::new(128),
        }
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
    #[cfg(not(wasm_browser))]
    pub async fn connect(&self) -> Result<Client, ConnectError> {
        use http::header::SEC_WEBSOCKET_PROTOCOL;
        use tls::MaybeTlsStreamBuilder;

        use crate::{
            http::{CLIENT_AUTH_HEADER, RELAY_PROTOCOL_VERSION},
            protos::{handshake::KeyMaterialClientAuth, relay::MAX_FRAME_SIZE},
        };

        let mut dial_url = (*self.url).clone();
        dial_url.set_path(RELAY_PATH);
        // The relay URL is exchanged with the http(s) scheme in tickets and similar.
        // We need to use the ws:// or wss:// schemes when connecting with websockets, though.
        dial_url
            .set_scheme(match self.url.scheme() {
                "http" => "ws",
                "ws" => "ws",
                _ => "wss",
            })
            .map_err(|_| {
                e!(ConnectError::InvalidWebsocketUrl {
                    url: dial_url.clone()
                })
            })?;

        debug!(%dial_url, "Dialing relay by websocket");

        #[allow(unused_mut)]
        let mut builder = MaybeTlsStreamBuilder::new(dial_url.clone(), self.dns_resolver.clone())
            .prefer_ipv6(self.prefer_ipv6())
            .proxy_url(self.proxy_url.clone());

        #[cfg(any(test, feature = "test-utils"))]
        if self.insecure_skip_cert_verify {
            builder = builder.insecure_skip_cert_verify(self.insecure_skip_cert_verify);
        }

        let stream = builder.connect().await?;
        let local_addr = stream
            .as_ref()
            .local_addr()
            .map_err(|_| e!(ConnectError::NoLocalAddr))?;
        let mut builder = tokio_websockets::ClientBuilder::new()
            .uri(dial_url.as_str())
            .map_err(|_| {
                e!(ConnectError::InvalidRelayUrl {
                    url: dial_url.clone()
                })
            })?
            .add_header(
                SEC_WEBSOCKET_PROTOCOL,
                http::HeaderValue::from_static(RELAY_PROTOCOL_VERSION),
            )
            .expect("valid header name and value")
            .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)))
            // We turn off automatic flushing after a threshold (the default would be after 8KB).
            // This means we need to flush manually, which we do by calling `Sink::send_all` or
            // `Sink::send` (which calls `Sink::flush`) in the `ActiveRelayActor`.
            .config(tokio_websockets::Config::default().flush_threshold(usize::MAX));
        if let Some(client_auth) = KeyMaterialClientAuth::new(&self.secret_key, &stream) {
            debug!("Using TLS key export for relay client authentication");
            builder = builder
                .add_header(CLIENT_AUTH_HEADER, client_auth.into_header_value())
                .expect(
                    "impossible: CLIENT_AUTH_HEADER isn't a disallowed header value for websockets",
                );
        }
        let (conn, response) = builder.connect_on(stream).await?;

        n0_error::ensure!(
            response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS,
            ConnectError::UnexpectedUpgradeStatus {
                code: response.status()
            }
        );

        let conn = Conn::new(conn, self.key_cache.clone(), &self.secret_key).await?;

        event!(
            target: "iroh::_events::net::relay::connected",
            Level::DEBUG,
            url = %self.url,
        );

        trace!("connect done");

        Ok(Client {
            conn,
            local_addr: Some(local_addr),
        })
    }

    /// Reports whether IPv4 dials should be slightly
    /// delayed to give IPv6 a better chance of winning dial races.
    /// Implementations should only return true if IPv6 is expected
    /// to succeed. (otherwise delaying IPv4 will delay the connection
    /// overall)
    #[cfg(not(wasm_browser))]
    fn prefer_ipv6(&self) -> bool {
        match self.address_family_selector {
            Some(ref selector) => selector(),
            None => false,
        }
    }

    /// Establishes a new connection to the relay server.
    #[cfg(wasm_browser)]
    pub async fn connect(&self) -> Result<Client, ConnectError> {
        use crate::http::RELAY_PROTOCOL_VERSION;

        let mut dial_url = (*self.url).clone();
        dial_url.set_path(RELAY_PATH);
        // The relay URL is exchanged with the http(s) scheme in tickets and similar.
        // We need to use the ws:// or wss:// schemes when connecting with websockets, though.
        dial_url
            .set_scheme(match self.url.scheme() {
                "http" => "ws",
                "ws" => "ws",
                _ => "wss",
            })
            .map_err(|_| {
                e!(ConnectError::InvalidWebsocketUrl {
                    url: dial_url.clone()
                })
            })?;

        debug!(%dial_url, "Dialing relay by websocket");

        let (_, ws_stream) =
            ws_stream_wasm::WsMeta::connect(dial_url.as_str(), Some(vec![RELAY_PROTOCOL_VERSION]))
                .await?;
        let conn = Conn::new(ws_stream, self.key_cache.clone(), &self.secret_key).await?;

        event!(
            target: "iroh::_events::net::relay::connected",
            Level::DEBUG,
            url = %self.url,
        );

        trace!("connect done");

        Ok(Client {
            conn,
            local_addr: None,
        })
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
    type Item = Result<RelayToClientMsg, RecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.conn).poll_next(cx)
    }
}

impl Sink<ClientToRelayMsg> for Client {
    type Error = SendError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: ClientToRelayMsg) -> Result<(), Self::Error> {
        Pin::new(&mut self.conn).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_close(cx)
    }
}

/// The send half of a relay client.
#[derive(Debug)]
pub struct ClientSink {
    sink: SplitSink<Conn, ClientToRelayMsg>,
}

impl Sink<ClientToRelayMsg> for ClientSink {
    type Error = SendError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: ClientToRelayMsg) -> Result<(), Self::Error> {
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
    type Item = Result<RelayToClientMsg, RecvError>;

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
