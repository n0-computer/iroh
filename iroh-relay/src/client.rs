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
#[cfg(not(wasm_browser))]
use iroh_dns::dns::{DnsError, DnsResolver};
#[cfg(wasm_browser)]
use n0_error::StdResultExt;
use n0_error::{AnyError, e, stack_error};
#[cfg(all(not(wasm_browser), feature = "h3-transport"))]
use n0_future::Either;
use n0_future::{
    Sink, Stream,
    split::{SplitSink, SplitStream, split},
    time,
};
use tracing::{debug, trace};
use url::Url;

pub use self::conn::{RecvError, SendError, Transport};
#[cfg(feature = "h3-transport")]
use crate::relay_map::H3Opts;
use crate::{
    KeyCache,
    http::{ProtocolVersion, RELAY_PATH},
    protos::{
        handshake,
        relay::{ClientToRelayMsg, RelayToClientMsg},
    },
};

pub(crate) mod conn;
#[cfg(all(not(wasm_browser), feature = "h3-transport"))]
pub(crate) mod h3_conn;
#[cfg(all(wasm_browser, feature = "h3-transport"))]
pub(crate) mod h3_conn_wasm;
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
    /// Error returned from the underlying WebSocket stream while establishing the connection.
    ///
    /// The concrete error type is `tokio_websockets::Error` on native targets and
    /// `ws_stream_wasm::WsErr` on `wasm_browser` targets. Use [`AnyError::downcast_ref`] to
    /// recover it. Note that the concrete downcast type is not covered by any semver
    /// guarantees and may change between releases.
    #[error(transparent)]
    Websocket { source: AnyError },
    #[error(
        "Server replied with invalid iroh-relay version header: {}",
        server_version.as_deref().unwrap_or("<empty>")
    )]
    BadVersionHeader { server_version: Option<String> },
    #[error("Authorization token set to a string that is not a valid HTTP header value")]
    InvalidAuthToken,
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
    #[cfg(all(not(wasm_browser), feature = "h3-transport"))]
    #[error(transparent)]
    H3 {
        #[error(std_err)]
        source: h3_conn::H3ConnectError,
    },
    #[cfg(all(wasm_browser, feature = "h3-transport"))]
    #[error(transparent)]
    H3 {
        #[error(std_err)]
        source: h3_conn_wasm::H3ConnectError,
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
    /// TLS verification config.
    tls_config: Option<rustls::ClientConfig>,
    /// HTTP Proxy
    proxy_url: Option<Url>,
    /// The secret key of this client.
    secret_key: SecretKey,
    /// Optional authorization token.
    ///
    /// Sent as an `Authorization: Bearer` header on native targets and as
    /// a `?token=` query parameter under Wasm. See [`ClientBuilder::auth_token`].
    auth_token: Option<String>,
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    /// Cache for public keys of remote endpoints.
    key_cache: KeyCache,
    /// WebTransport (H3) transport options.
    ///
    /// `Some` enables H3: the client tries WebTransport first (racing WebSocket
    /// on native) and falls back to WebSocket on failure. Set via
    /// [`ClientBuilder::enable_h3`].
    #[cfg(feature = "h3-transport")]
    h3: Option<H3Opts>,
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
            auth_token: None,
            #[cfg(feature = "h3-transport")]
            h3: None,
        }
    }

    /// Sets a custom TLS config.
    ///
    /// This is a required option.
    ///
    /// You can construct a [`rustls::ClientConfig`] by combining a [`rustls::crypto::CryptoProvider`]
    /// with a [`tls::CaTlsConfig`] using [`tls::CaTlsConfig::client_config`], for example:
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use iroh_relay::tls::CaTlsConfig;
    ///
    /// let crypto_provider: rustls::crypto::CryptoProvider = todo!();
    /// let client_config = CaTlsConfig::default().client_config(Arc::new(crypto_provider));
    /// ```
    ///
    /// If you enable the tls-ring or tls-aws-lc-rs feature, you can use the enabled crypto provider
    /// by using [`tls::default_provider`].
    ///
    /// [`tls::CaTlsConfig`]: crate::tls::CaTlsConfig
    /// [`tls::CaTlsConfig::client_config`]: crate::tls::CaTlsConfig::client_config
    /// [`tls::default_provider`]: crate::tls::default_provider
    pub fn tls_client_config(mut self, tls_config: rustls::ClientConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Sets a callback hinting whether to prefer IPv6 when dialing the relay.
    ///
    /// The callback runs on each dial. When it returns `true`, IPv6 addresses
    /// are tried first and IPv4 dials are held back slightly, biasing the
    /// happy-eyeballs race towards IPv6; when it returns `false`, IPv4 is
    /// preferred. Only return `true` when IPv6 is expected to work, since
    /// otherwise the bias just delays the connection.
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

    /// Sets an authorization token.
    ///
    /// On native targets, the token is sent as an `Authorization: Bearer TOKEN`
    /// header on the WebSocket upgrade request that establishes the relay
    /// connection. The token must be a valid HTTP header field value, if not
    /// [`Self::connect`] will return [`ConnectError::InvalidAuthToken`].
    ///
    /// When compiled to WebAssembly the token is sent as a `?token=TOKEN`
    /// query parameter on the upgrade URL, since browsers don't allow setting
    /// headers on WebSocket requests.
    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Set the capacity of the cache for public keys.
    pub fn key_cache_capacity(mut self, capacity: usize) -> Self {
        self.key_cache = KeyCache::new(capacity);
        self
    }

    /// Enable the H3/WebTransport relay transport with the given [`H3Opts`].
    ///
    /// Pass `H3Opts::default()` for the defaults. On native targets, the client
    /// races WebTransport and WebSocket connections concurrently; the first
    /// transport to receive a server response wins and the other is aborted. In
    /// the browser, the client first attempts a WebTransport connection and
    /// falls back to WebSocket on any failure.
    ///
    /// # Building for the browser
    ///
    /// On `wasm32-unknown-unknown` the browser WebTransport client uses web-sys's
    /// unstable `WebTransport` bindings, so the crate must be built with
    /// `RUSTFLAGS="--cfg=web_sys_unstable_apis"` (for example via
    /// `.cargo/config.toml`). This rustflag is not inherited from a dependency,
    /// so any crate that builds `iroh-relay` for a browser target with the
    /// `h3-transport` feature (which is enabled by default) must set it itself.
    #[cfg(feature = "h3-transport")]
    pub fn enable_h3(mut self, opts: H3Opts) -> Self {
        self.h3 = Some(opts);
        self
    }

    /// Establishes a new connection to the relay server.
    ///
    /// When H3 is enabled via [`enable_h3`](Self::enable_h3), races WebTransport
    /// and WebSocket concurrently. The first to receive a server response wins.
    #[cfg(not(wasm_browser))]
    pub async fn connect(&self) -> Result<Client, ConnectError> {
        #[cfg(feature = "h3-transport")]
        if let Some(opts) = &self.h3 {
            return self.connect_race(opts).await;
        }

        self.connect_ws().await
    }

    /// Race WebTransport and WebSocket connections concurrently.
    ///
    /// DNS is resolved once, then both transports connect in parallel using
    /// the same IP. The first to complete wins; the loser is dropped.
    #[cfg(all(not(wasm_browser), feature = "h3-transport"))]
    async fn connect_race(&self, opts: &H3Opts) -> Result<Client, ConnectError> {
        let url = &*self.url;
        let host = url
            .host_str()
            .ok_or_else(|| e!(ConnectError::InvalidRelayUrl { url: url.clone() }))?;

        let tls_config = self
            .tls_config
            .clone()
            .ok_or_else(|| e!(ConnectError::MissingCryptoProvider))?;

        debug!(%url, "racing WT and WS connections");

        // Race the QUIC handshake against the full WS connect. The QUIC handshake is
        // 1 RTT; WS needs TCP + TLS + HTTP upgrade (3-4 RTTs). If QUIC succeeds first,
        // abort WS and complete the WT handshake uncontested. Both dials resolve the
        // relay URL and race addresses Happy Eyeballs style (RFC 8305).
        let quic_fut = self.quic_connect_happy_eyeballs(host, tls_config);
        let ws_fut = self.connect_ws();
        tokio::pin!(quic_fut);
        tokio::pin!(ws_fut);

        // Race QUIC handshake (1 RTT) against the full WS connect (3-4 RTTs).
        // The &mut borrows keep the loser alive for fallback.
        #[rustfmt::skip]
        let race = n0_future::future::race(
            async { Either::Left((&mut quic_fut).await) },
            async { Either::Right((&mut ws_fut).await) }
        )
        .await;

        match race {
            Either::Left(Ok(quic)) => {
                debug!("QUIC handshake won the race, completing WT handshake");
                match self.finish_wt(quic, host, opts.use_datagrams).await {
                    Ok(client) => Ok(client),
                    Err(err) => {
                        debug!("WT handshake failed ({err:#}), falling back to WS");
                        ws_fut.await
                    }
                }
            }
            Either::Left(Err(err)) => {
                debug!("QUIC failed ({err:#}), waiting for WS");
                ws_fut.await
            }
            Either::Right(Ok(client)) => {
                debug!("WS won the race");
                Ok(client)
            }
            Either::Right(Err(ws_err)) => {
                debug!("WS failed ({ws_err:#}), waiting for QUIC");
                match quic_fut.await {
                    Ok(quic) => self
                        .finish_wt(quic, host, opts.use_datagrams)
                        .await
                        .map_err(|_| ws_err),
                    Err(err) => {
                        debug!("QUIC also failed: {err:#}");
                        Err(ws_err)
                    }
                }
            }
        }
    }

    /// Completes the WebTransport handshake on a won QUIC connection and builds a
    /// [`Client`], emitting the relay-connected telemetry event.
    #[cfg(all(not(wasm_browser), feature = "h3-transport"))]
    async fn finish_wt(
        &self,
        quic: h3_conn::QuicConnected,
        host: &str,
        use_datagrams: bool,
    ) -> Result<Client, h3_conn::H3ConnectError> {
        use tracing::{Level, event};

        let (io, state, local_addr) =
            h3_conn::wt_handshake(quic, host, &self.secret_key, use_datagrams).await?;
        event!(
            target: "iroh::_events::net::relay::connected",
            Level::DEBUG,
            url = %self.url,
            transport = "h3",
        );
        let conn = Conn::from_wt(
            io,
            state,
            self.key_cache.clone(),
            ProtocolVersion::default(),
        );
        Ok(Client {
            conn,
            local_addr: Some(local_addr),
        })
    }

    /// Establishes a QUIC connection to the relay, racing the resolved addresses
    /// Happy Eyeballs style (RFC 8305), the same way the WebSocket path dials.
    #[cfg(all(not(wasm_browser), feature = "h3-transport"))]
    async fn quic_connect_happy_eyeballs(
        &self,
        server_name: &str,
        tls_config: rustls::ClientConfig,
    ) -> Result<h3_conn::QuicConnected, DialError> {
        tls::race_happy_eyeballs(
            &self.dns_resolver,
            &self.url,
            self.prefer_ipv6(),
            move |addr| {
                let tls_config = tls_config.clone();
                async move {
                    h3_conn::quic_connect(addr, server_name, tls_config)
                        .await
                        .map_err(|err| {
                            e!(DialError::Io {
                                source: std::io::Error::other(err)
                            })
                        })
                }
            },
        )
        .await
    }

    /// Connect via WebSocket.
    #[cfg(not(wasm_browser))]
    async fn connect_ws(&self) -> Result<Client, ConnectError> {
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

        let builder =
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

        if let Some(token) = self.auth_token.as_ref() {
            use http::{HeaderValue, header::AUTHORIZATION};

            let value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| e!(ConnectError::InvalidAuthToken))?;
            builder = builder
                .add_header(AUTHORIZATION, value)
                .expect("valid header name");
        }

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
    ///
    /// When H3 is enabled via [`enable_h3`](Self::enable_h3), first attempts a
    /// browser WebTransport connection and falls back to WebSocket on any
    /// failure. Otherwise connects over WebSocket directly.
    #[cfg(wasm_browser)]
    pub async fn connect(&self) -> Result<Client, ConnectError> {
        #[cfg(feature = "h3-transport")]
        if let Some(opts) = &self.h3 {
            match self.connect_h3_browser(opts).await {
                Ok(client) => return Ok(client),
                Err(err) => {
                    debug!("browser WebTransport connect failed ({err:#}), falling back to WS");
                }
            }
        }

        self.connect_ws().await
    }

    /// Connect over the browser's native WebTransport.
    #[cfg(all(wasm_browser, feature = "h3-transport"))]
    async fn connect_h3_browser(&self, opts: &H3Opts) -> Result<Client, ConnectError> {
        debug!(url = %self.url, "Dialing relay by browser WebTransport");
        let io =
            h3_conn_wasm::connect_h3(&self.url, opts.server_cert_hashes.clone(), &self.secret_key)
                .await
                .map_err(|source| e!(ConnectError::H3 { source }))?;

        let conn = Conn::from_wt_browser(io, self.key_cache.clone(), ProtocolVersion::default());

        trace!("browser WebTransport connect done");
        Ok(Client {
            conn,
            local_addr: None,
        })
    }

    /// Connect via WebSocket (browser).
    #[cfg(wasm_browser)]
    async fn connect_ws(&self) -> Result<Client, ConnectError> {
        use crate::http::AUTH_TOKEN_URL_QUERY_PARAM;

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

        if let Some(token) = self.auth_token.as_ref() {
            dial_url
                .query_pairs_mut()
                .append_pair(AUTH_TOKEN_URL_QUERY_PARAM, token);
        }

        debug!(%dial_url, "Dialing relay by websocket");

        let (ws_meta, ws_stream) = ws_stream_wasm::WsMeta::connect(
            dial_url.as_str(),
            Some(ProtocolVersion::all().collect()),
        )
        .await
        .anyerr()?;

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
    /// Creates a [`Client`] from a pre-established [`Conn`] and optional local address.
    #[cfg(all(feature = "h3-transport", test))]
    pub(crate) fn from_conn(conn: Conn, local_addr: Option<SocketAddr>) -> Self {
        Self { conn, local_addr }
    }

    /// Returns which transport protocol this connection uses.
    pub fn transport(&self) -> Transport {
        self.conn.transport()
    }

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
