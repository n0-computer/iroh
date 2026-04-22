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
use n0_error::{AnyError, e, stack_error};
use n0_future::{
    Sink, Stream,
    split::{SplitSink, SplitStream, split},
    time,
};
use tracing::{Level, debug, event, trace};
use url::Url;

pub use self::conn::{RecvError, SendError};
#[cfg(not(wasm_browser))]
use crate::dns::{DnsError, DnsResolver};
use crate::{
    KeyCache,
    http::{ProtocolVersion, RELAY_PATH},
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
    Websocket { source: AnyError },
    #[error(
        "Server replied with invalid iroh-relay version header: {}",
        server_version.as_deref().unwrap_or("<empty>")
    )]
    BadVersionHeader { server_version: Option<String> },
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
    #[error(
        "No rustls crypto provider configured while both ring and aws-lc-rs feature flags are disabled"
    )]
    MissingCryptoProvider,
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
    /// TLS verification config.
    tls_config: Option<rustls::ClientConfig>,
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
            tls_config: None,
            proxy_url: None,
            secret_key,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            key_cache: KeyCache::new(128),
        }
    }

    /// Sets a custom TLS config.
    ///
    /// This is a required option.
    ///
    /// You can construct a [`rustls::ClientConfig`] by combining a [`rustls::crypto::CryptoProvider`]
    /// with a [`tls::CaRootsConfig`] using [`tls::CaRootsConfig::client_config`], for example:
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use iroh_relay::tls::CaRootsConfig;
    ///
    /// let crypto_provider: rustls::crypto::CryptoProvider = todo!();
    /// let client_config = CaRootsConfig::default().client_config(Arc::new(crypto_provider));
    /// ```
    ///
    /// If you enable the tls-ring or tls-aws-lc-rs feature, you can use the enabled crypto provider
    /// by using [`tls::default_provider`].
    ///
    /// [`tls::CaRootsConfig`]: crate::tls::CaRootsConfig
    /// [`tls::CaRootsConfig::client_config`]: crate::tls::CaRootsConfig::client_config
    /// [`tls::default_provider`]: crate::tls::default_provider
    pub fn tls_client_config(mut self, tls_config: rustls::ClientConfig) -> Self {
        self.tls_config = Some(tls_config);
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
        use n0_error::StdResultExt;
        use tls::MaybeTlsStreamBuilder;

        use crate::{
            http::CLIENT_AUTH_HEADER,
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

        let tls_config = self
            .tls_config
            .clone()
            .ok_or_else(|| e!(ConnectError::MissingCryptoProvider))?;

        #[allow(unused_mut)]
        let mut builder =
            MaybeTlsStreamBuilder::new(dial_url.clone(), self.dns_resolver.clone(), tls_config)
                .prefer_ipv6(self.prefer_ipv6())
                .proxy_url(self.proxy_url.clone());

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
                ProtocolVersion::all_as_header_value(),
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
        let (conn, response) = builder.connect_on(stream).await.anyerr()?;

        n0_error::ensure!(
            response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS,
            ConnectError::UnexpectedUpgradeStatus {
                code: response.status()
            }
        );

        let protocol_version_str = response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|s| s.to_str().ok());
        let protocol_version = protocol_version_str
            .and_then(ProtocolVersion::match_from_str)
            .ok_or_else(|| {
                e!(ConnectError::BadVersionHeader {
                    server_version: protocol_version_str.map(ToOwned::to_owned)
                })
            })?;

        let conn = Conn::new(
            conn,
            self.key_cache.clone(),
            &self.secret_key,
            protocol_version,
        )
        .await?;

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

        let (ws_meta, ws_stream) = ws_stream_wasm::WsMeta::connect(
            dial_url.as_str(),
            Some(ProtocolVersion::all().collect()),
        )
        .await?;

        let protocol_version =
            ProtocolVersion::match_from_str(&ws_meta.protocol()).ok_or_else(|| {
                e!(ConnectError::BadVersionHeader {
                    server_version: Some(ws_meta.protocol())
                })
            })?;

        let conn = Conn::new(
            ws_stream,
            self.key_cache.clone(),
            &self.secret_key,
            protocol_version,
        )
        .await?;

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
