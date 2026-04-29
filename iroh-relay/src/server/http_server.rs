//! Low-level HTTP server components for embedding the relay service.
//!
//! This module provides [`RelayService`] which can be used to embed relay functionality
//! into an existing HTTP server. It handles individual connections and provides
//! the core relay protocol implementation.
//!
//! For a complete relay server implementation, see the parent [`server`](super) module.

use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use derive_more::Debug;
use http::{
    header::{CONNECTION, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION},
    response::Builder as ResponseBuilder,
};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    body::Incoming,
    header::{HeaderValue, SEC_WEBSOCKET_ACCEPT, UPGRADE},
    service::Service,
    upgrade::Upgraded,
};
use n0_error::{e, ensure, stack_error};
use n0_future::MaybeFuture;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Notify,
};
use tokio_rustls_acme::AcmeAcceptor;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, error, info, info_span, trace, warn, warn_span};

use super::{
    AccessConfig, ClientRequest, SpawnError, clients::Clients, streams::InvalidBucketConfig,
};
use crate::{
    KeyCache,
    defaults::{DEFAULT_KEY_CACHE_CAPACITY, timeouts::SERVER_WRITE_TIMEOUT},
    http::{
        CLIENT_AUTH_HEADER, ProtocolVersion, RELAY_PATH, SUPPORTED_WEBSOCKET_VERSION,
        WEBSOCKET_UPGRADE_PROTOCOL,
    },
    protos::{
        handshake,
        relay::{MAX_FRAME_SIZE, PER_CLIENT_SEND_QUEUE_DEPTH},
        streams::WsBytesFramed,
    },
    server::{
        ClientRateLimit,
        client::Config,
        metrics::Metrics,
        streams::{MaybeTlsStream, RateLimited, RelayedStream},
    },
};

// type BytesBody = http_body_util::Full<hyper::body::Bytes>;
pub(super) type BytesBody = Box<
    dyn 'static + Send + Unpin + hyper::body::Body<Data = hyper::body::Bytes, Error = Infallible>,
>;
pub(super) type HyperError = Box<dyn std::error::Error + Send + Sync>;
pub(super) type HyperResult<T> = std::result::Result<T, HyperError>;
pub(super) type HyperHandler = Box<
    dyn Fn(Request<Incoming>, ResponseBuilder) -> HyperResult<Response<BytesBody>>
        + Send
        + Sync
        + 'static,
>;

/// WebSocket GUID needed for accepting websocket connections, see RFC 6455 (<https://www.rfc-editor.org/rfc/rfc6455>) section 1.3
const SEC_WEBSOCKET_ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Timeout for a connection to finish the TLS and WebSocket upgrade handshakes.
///
/// The connection is aborted if the connection does not complete the TLS handshake
/// and establishes relay protocol WebSocket stream within this timeout.
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// Derives the accept key for WebSocket handshake according to RFC 6455.
/// Takes the client's Sec-WebSocket-Key value and returns the calculated accept key.
fn derive_accept_key(client_key: &HeaderValue) -> String {
    use sha1::Digest;

    let mut sha1 = sha1::Sha1::new();
    sha1.update(client_key.as_bytes());
    sha1.update(SEC_WEBSOCKET_ACCEPT_GUID);
    data_encoding::BASE64.encode(&sha1.finalize())
}

/// Creates a new [`BytesBody`] with given content.
fn body_full(content: impl Into<hyper::body::Bytes>) -> BytesBody {
    Box::new(http_body_util::Full::new(content.into()))
}

#[allow(clippy::result_large_err)]
fn downcast_upgrade(upgraded: Upgraded) -> Result<(MaybeTlsStream, Bytes), ConnectionHandlerError> {
    match upgraded.downcast::<hyper_util::rt::TokioIo<MaybeTlsStream>>() {
        Ok(parts) => Ok((parts.io.into_inner(), parts.read_buf)),
        Err(_) => Err(e!(ConnectionHandlerError::DowncastUpgrade)),
    }
}

/// The Relay HTTP server.
///
/// A running HTTP server serving the relay endpoint and optionally a number of additional
/// HTTP services added with [`ServerBuilder::request_handler`].  If configured using
/// [`ServerBuilder::tls_config`] the server will handle TLS as well.
///
/// Created using [`ServerBuilder::spawn`].
#[derive(Debug)]
pub(super) struct Server {
    addr: SocketAddr,
    http_server_task: AbortOnDropHandle<()>,
    cancel_server_loop: CancellationToken,
}

impl Server {
    /// Returns a handle for this server.
    ///
    /// The server runs in the background as several async tasks.  This allows controlling
    /// the server, in particular it allows gracefully shutting down the server.
    pub(super) fn handle(&self) -> ServerHandle {
        ServerHandle {
            cancel_token: self.cancel_server_loop.clone(),
        }
    }

    /// Closes the underlying relay server and the HTTP(S) server tasks.
    pub(super) fn shutdown(&self) {
        self.cancel_server_loop.cancel();
    }

    /// Returns the [`AbortOnDropHandle`] for the supervisor task managing the server.
    ///
    /// This is the root of all the tasks for the server.  Aborting it will abort all the
    /// other tasks for the server.  Awaiting it will complete when all the server tasks are
    /// completed.
    pub(super) fn task_handle(&mut self) -> &mut AbortOnDropHandle<()> {
        &mut self.http_server_task
    }

    /// Returns the local address of this server.
    pub(super) fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// A handle for the [`Server`].
///
/// This does not allow access to the task but can communicate with it.
#[derive(Debug, Clone)]
pub(super) struct ServerHandle {
    cancel_token: CancellationToken,
}

impl ServerHandle {
    /// Gracefully shut down the server.
    pub(super) fn shutdown(&self) {
        self.cancel_token.cancel()
    }
}

/// Configuration to use for the TLS connection
///
/// This struct wraps a rustls server configuration and TLS acceptor for use with
/// [`RelayService::handle_connection`].
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use iroh_relay::server::http_server::TlsConfig;
/// use rustls::ServerConfig;
/// use webpki_types::{CertificateDer, PrivateKeyDer};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Set ring as the process-level default crypto provider
/// rustls::crypto::ring::default_provider()
///     .install_default()
///     .ok();
/// // Generate a self-signed certificate for testing
/// let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
/// let cert_der = cert.cert.der().to_vec();
/// let private_key_der = cert.signing_key.serialize_der();
///
/// // Create rustls types
/// let cert_chain = vec![CertificateDer::from(cert_der)];
/// let private_key = PrivateKeyDer::try_from(private_key_der)?;
///
/// // Create a rustls ServerConfig
/// let server_config = Arc::new(
///     ServerConfig::builder()
///         .with_no_client_auth()
///         .with_single_cert(cert_chain, private_key)?,
/// );
///
/// // Create TlsConfig for use with RelayService
/// let tls_config = TlsConfig::new(server_config);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// The server config
    pub(super) config: Arc<rustls::ServerConfig>,
    /// The kind
    pub(super) acceptor: TlsAcceptor,
}

impl TlsConfig {
    /// Creates a new `TlsConfig` from a rustls `ServerConfig`.
    ///
    /// This creates a manual TLS acceptor using the provided server configuration.
    /// The acceptor will handle TLS handshakes for incoming connections.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use iroh_relay::server::http_server::TlsConfig;
    /// use rustls::ServerConfig;
    /// use webpki_types::{CertificateDer, PrivateKeyDer};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Set ring as the process-level default crypto provider
    /// rustls::crypto::ring::default_provider()
    ///     .install_default()
    ///     .ok();
    /// // Generate a self-signed certificate for testing
    /// let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    /// let cert_der = cert.cert.der().to_vec();
    /// let private_key_der = cert.signing_key.serialize_der();
    ///
    /// // Create rustls types
    /// let cert_chain = vec![CertificateDer::from(cert_der)];
    /// let private_key = PrivateKeyDer::try_from(private_key_der)?;
    ///
    /// let server_config = Arc::new(
    ///     ServerConfig::builder()
    ///         .with_no_client_auth()
    ///         .with_single_cert(cert_chain, private_key)?,
    /// );
    ///
    /// let tls_config = TlsConfig::new(server_config);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: Arc<rustls::ServerConfig>) -> Self {
        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
        Self {
            config,
            acceptor: TlsAcceptor::Manual(acceptor),
        }
    }
}

/// Errors when attempting to upgrade and
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum ServeConnectionError {
    #[error("TLS[acme] handshake")]
    TlsHandshake {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("TLS[acme] serve connection")]
    ServeConnection {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("TLS[manual] accept")]
    ManualAccept {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("TLS[acme] accept")]
    LetsEncryptAccept {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("HTTPS connection")]
    Https {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("HTTP connection")]
    Http {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[error("Connection did not reach established state within timeout")]
    EstablishTimeout,
}

/// Server accept errors.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum AcceptError {
    #[error(transparent)]
    Handshake { source: handshake::Error },
    #[error("rate limiting misconfigured")]
    RateLimitingMisconfigured { source: InvalidBucketConfig },
}

/// Server connection errors, includes errors that can happen on `accept`.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum ConnectionHandlerError {
    #[error(transparent)]
    Accept { source: AcceptError },
    #[error("Could not downcast the upgraded connection to MaybeTlsStream")]
    DowncastUpgrade {},
    #[error("Cannot deal with buffered data yet: {buf:?}")]
    BufferNotEmpty { buf: Bytes },
}

/// Builder for the Relay HTTP Server.
///
/// Defaults to handling relay requests on the "/relay" (and "/derp" for backwards compatibility) endpoint.
/// Other HTTP endpoints can be added using [`ServerBuilder::request_handler`].
#[derive(derive_more::Debug)]
pub(super) struct ServerBuilder {
    /// The ip + port combination for this server.
    addr: SocketAddr,
    /// Optional tls configuration/TlsAcceptor combination.
    ///
    /// When `None`, the server will serve HTTP, otherwise it will serve HTTPS.
    tls_config: Option<TlsConfig>,
    /// A map of request handlers to routes.
    ///
    /// Used when certain routes in your server should be made available at the same port as
    /// the relay server, and so must be handled along side requests to the relay endpoint.
    handlers: Handlers,
    /// Headers to use for HTTP responses.
    headers: HeaderMap,
    /// Rate-limiting configuration for an individual client connection.
    ///
    /// Rate-limiting is enforced on received traffic from individual clients.  This
    /// configuration applies to a single client connection.
    client_rx_ratelimit: Option<ClientRateLimit>,
    /// The capacity of the key cache.
    key_cache_capacity: usize,
    /// Access config for endpoints.
    access: AccessConfig,
    metrics: Option<Arc<Metrics>>,
    establish_timeout: Duration,
}

impl ServerBuilder {
    /// Creates a new [ServerBuilder].
    pub(super) fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            tls_config: None,
            handlers: Default::default(),
            headers: HeaderMap::new(),
            client_rx_ratelimit: None,
            key_cache_capacity: DEFAULT_KEY_CACHE_CAPACITY,
            access: AccessConfig::Everyone,
            metrics: None,
            establish_timeout: ESTABLISH_TIMEOUT,
        }
    }

    /// Sets the metrics collector.
    pub(super) fn metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Set the access configuration.
    pub(super) fn access(mut self, access: AccessConfig) -> Self {
        self.access = access;
        self
    }

    /// Serves all requests content using TLS.
    pub(super) fn tls_config(mut self, config: Option<TlsConfig>) -> Self {
        self.tls_config = config;
        self
    }

    /// Sets the timeout after which connections are aborted if they don't become fully established.
    ///
    /// The timeout is started immediately after a TCP connection comes in, and cleared once
    /// the connection has finished the TLS handshake and fully processed the WebSocket request
    /// to initiate the relay protocol. If the timeout expires before being cleared, the
    /// connection is aborted.
    ///
    /// Defaults to 30s.
    #[cfg(test)]
    pub(super) fn establish_timeout(mut self, timeout: Duration) -> Self {
        self.establish_timeout = timeout;
        self
    }

    /// Sets the per-client rate-limit configuration for incoming data.
    ///
    /// On each client connection the incoming data is rate-limited.  By default
    /// no rate limit is enforced.
    pub(super) fn client_rx_ratelimit(mut self, config: ClientRateLimit) -> Self {
        self.client_rx_ratelimit = Some(config);
        self
    }

    /// Adds a custom handler for a specific Method & URI.
    pub(super) fn request_handler(
        mut self,
        method: Method,
        uri_path: &'static str,
        handler: HyperHandler,
    ) -> Self {
        self.handlers.insert((method, uri_path), handler);
        self
    }

    /// Adds HTTP headers to responses.
    pub(super) fn headers(mut self, headers: HeaderMap) -> Self {
        for (k, v) in headers.iter() {
            self.headers.insert(k.clone(), v.clone());
        }
        self
    }

    /// Set the capacity of the cache for public keys.
    pub(super) fn key_cache_capacity(mut self, capacity: usize) -> Self {
        self.key_cache_capacity = capacity;
        self
    }

    /// Builds and spawns an HTTP(S) Relay Server.
    pub(super) async fn spawn(self) -> Result<Server, SpawnError> {
        let cancel_token = CancellationToken::new();

        let service = RelayService::new(
            self.handlers,
            self.headers,
            self.client_rx_ratelimit,
            KeyCache::new(self.key_cache_capacity),
            self.access,
            self.metrics.unwrap_or_default(),
        );

        let addr = self.addr;
        let tls_config = self.tls_config;

        // Bind a TCP listener on `addr` and handles content using HTTPS.

        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|err| e!(super::SpawnError::BindTcpListener { addr }, err))?;

        let addr = listener
            .local_addr()
            .map_err(|err| e!(super::SpawnError::NoLocalAddr, err))?;
        let http_str = tls_config.as_ref().map_or("HTTP/WS", |_| "HTTPS/WSS");
        info!("[{http_str}] relay: serving on {addr}");

        let cancel = cancel_token.clone();
        let task = tokio::task::spawn(
            async move {
                // create a join set to track all our connection tasks
                let mut set = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {
                            break;
                        }
                        Some(res) = set.join_next() => {
                            if let Err(err) = res
                                && err.is_panic()
                            {
                                panic!("task panicked: {err:#?}");
                            }
                        }
                        res = listener.accept() => match res {
                            Ok((stream, peer_addr)) => {
                                debug!("connection opened from {peer_addr}");
                                let tls_config = tls_config.clone();
                                let service = service.clone();
                                // spawn a task to handle the connection
                                set.spawn(async move {
                                    service
                                        .handle_connection(stream, tls_config, self.establish_timeout)
                                        .await
                                }.instrument(info_span!("conn", peer = %peer_addr)));
                            }
                            Err(err) => {
                                error!("failed to accept connection: {err}");
                            }
                        }
                    }
                }
                service.shutdown().await;
                set.shutdown().await;
                debug!("server has been shutdown.");
            }
            .instrument(info_span!("relay-http-serve")),
        );

        Ok(Server {
            addr,
            http_server_task: AbortOnDropHandle::new(task),
            cancel_server_loop: cancel_token,
        })
    }
}

/// The hyper Service that serves the actual relay endpoints.
///
/// This service can be used standalone or embedded into an existing HTTP server.
#[derive(Clone, Debug)]
pub struct RelayService(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    handlers: Handlers,
    headers: HeaderMap,
    clients: Clients,
    write_timeout: Duration,
    rate_limit: Option<ClientRateLimit>,
    key_cache: KeyCache,
    access: AccessConfig,
    metrics: Arc<Metrics>,
}

#[stack_error(derive, add_meta)]
enum RelayUpgradeReqError {
    #[error("missing header: {header}")]
    MissingHeader { header: http::HeaderName },
    #[error("invalid header value for {header}: {details}")]
    InvalidHeader {
        header: http::HeaderName,
        details: String,
    },
    #[error(
        "invalid header value for {SEC_WEBSOCKET_VERSION}: unsupported websocket version, only supporting {SUPPORTED_WEBSOCKET_VERSION}"
    )]
    UnsupportedWebsocketVersion,
    #[error(
        "invalid header value for {SEC_WEBSOCKET_PROTOCOL}: unsupported relay version: we support {we_support} but you only provide {you_support}"
    )]
    UnsupportedRelayVersion {
        we_support: String,
        you_support: String,
    },
}

impl RelayServiceWithNotify {
    fn build_response(&self) -> http::response::Builder {
        let mut res = Response::builder();
        for (key, value) in self.service.0.headers.iter() {
            res = res.header(key, value);
        }
        res
    }

    /// Upgrades the HTTP connection to the relay protocol, runs relay client.
    fn handle_relay_ws_upgrade(
        &self,
        mut req: Request<Incoming>,
    ) -> Result<Response<BytesBody>, RelayUpgradeReqError> {
        fn expect_header(
            req: &Request<Incoming>,
            header: http::HeaderName,
        ) -> Result<&HeaderValue, RelayUpgradeReqError> {
            req.headers()
                .get(&header)
                .ok_or_else(|| e!(RelayUpgradeReqError::MissingHeader { header }))
        }

        let upgrade_header = expect_header(&req, UPGRADE)?;
        ensure!(
            upgrade_header == HeaderValue::from_static(WEBSOCKET_UPGRADE_PROTOCOL),
            RelayUpgradeReqError::InvalidHeader {
                header: UPGRADE,
                details: format!("value must be {WEBSOCKET_UPGRADE_PROTOCOL}")
            }
        );

        let key = expect_header(&req, SEC_WEBSOCKET_KEY)?.clone();
        let version = expect_header(&req, SEC_WEBSOCKET_VERSION)?.clone();

        ensure!(
            version.as_bytes() == SUPPORTED_WEBSOCKET_VERSION.as_bytes(),
            RelayUpgradeReqError::UnsupportedWebsocketVersion
        );

        let subprotocols = expect_header(&req, SEC_WEBSOCKET_PROTOCOL)?
            .to_str()
            .ok()
            .ok_or_else(|| {
                e!(RelayUpgradeReqError::InvalidHeader {
                    header: SEC_WEBSOCKET_PROTOCOL,
                    details: "header value is not ascii".to_string()
                })
            })?;
        let protocol_version = subprotocols
            .split(",")
            .map(|s| s.trim())
            .filter_map(ProtocolVersion::match_from_str)
            .max()
            .ok_or_else(|| {
                e!(RelayUpgradeReqError::UnsupportedRelayVersion {
                    we_support: ProtocolVersion::all_joined(),
                    you_support: subprotocols.to_string()
                })
            })?;

        // Setup a future that will eventually receive the upgraded
        // connection and talk a new protocol, and spawn the future
        // into the runtime.
        //
        // Note: This can't possibly be fulfilled until the 101 response
        // is returned below, so it's better to spawn this future instead
        // waiting for it to complete to then return a response.
        tokio::task::spawn({
            let this = self.clone();
            async move {
                match hyper::upgrade::on(&mut req).await {
                    Ok(upgraded) => {
                        let (parts, _) = req.into_parts();
                        if let Err(err) = this
                            .service
                            .0
                            .relay_connection_handler(upgraded, parts, protocol_version)
                            .await
                        {
                            warn!("error accepting upgraded connection: {err:#}",);
                        } else {
                            // We have passed the connection to the relay protocol handler,
                            // thus we trigger the on_establish notification so that timeouts
                            // on the upper layer will be cleared.
                            this.on_establish.notify_waiters();
                            debug!("upgraded connection completed");
                        };
                    }
                    Err(err) => warn!("upgrade error: {err:#}"),
                }
            }
            .instrument(warn_span!("handler"))
        });

        // Now return a 101 Response saying we agree to the upgrade to the
        // websocket upgrade protocol
        Ok(self
            .build_response()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(
                UPGRADE,
                HeaderValue::from_static(WEBSOCKET_UPGRADE_PROTOCOL),
            )
            .header(SEC_WEBSOCKET_ACCEPT, derive_accept_key(&key))
            .header(SEC_WEBSOCKET_PROTOCOL, protocol_version.to_header_value())
            .header(CONNECTION, "upgrade")
            .body(body_full("switching to websocket protocol"))
            .expect("valid body"))
    }
}

/// Combines [`RelayService`] with a notification token.
///
/// This struct implements [`Service`]. Note that the service has to be called with hyper's `io`
/// argument set to [`MaybeTlsStream`] wrapped by [`hyper_util::rt::TokioIo`], otherwise handling
/// WebSocket requests at `/relay` will fail at runtime with [`ConnectionHandlerError::DowncastUpgrade`].
///
/// The notification token is triggered once the relay connection is fully established. It can be used
/// to cancel a timeout aborting the TCP connection if no upgrade request is received in some time.
///
/// ## Example
///
/// ```no_run
/// # use std::sync::Arc;
/// # use http::HeaderMap;
/// # use hyper::server::conn::http1;
/// # use hyper_util::rt::TokioIo;
/// # use tokio::{net::TcpListener, sync::Notify};
/// # use iroh_relay::{
/// #     KeyCache,
/// #     server::{
/// #         AccessConfig, Metrics,
/// #         http_server::{Handlers, RelayService, RelayServiceWithNotify},
/// #         streams::MaybeTlsStream
/// #     },
/// # };
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let service = RelayService::new(
///     Handlers::default(),
///     HeaderMap::new(),
///     None,
///     KeyCache::new(1024),
///     AccessConfig::Everyone,
///     Arc::new(Metrics::default()),
/// );
/// let service = RelayServiceWithNotify::new(service, Arc::new(Notify::new()));
///
/// let listener = TcpListener::bind("127.0.0.1:0").await?;
/// let (stream, _peer) = listener.accept().await?;
/// // Wrap the TCP stream in `MaybeTlsStream`, otherwise the relay WebSocket handler will error at runtime
/// // for all WebSocket requests to `/relay`.
/// let stream = MaybeTlsStream::Plain(stream);
/// http1::Builder::new()
///     .serve_connection(TokioIo::new(stream), service)
///     .with_upgrades()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RelayServiceWithNotify {
    service: RelayService,
    on_establish: Arc<Notify>,
}

impl RelayServiceWithNotify {
    /// Creates a new service wrapper for a connection.
    ///
    /// The `on_establish` notification is triggered once the connection is passed to the
    /// relay protocol, i.e. after a WebSocket request on /relay is received and established.
    pub fn new(service: RelayService, on_establish: Arc<Notify>) -> Self {
        Self {
            service,
            on_establish,
        }
    }
}

impl Service<Request<Incoming>> for RelayServiceWithNotify {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        // Create a client if the request hits the relay endpoint.
        if matches!(
            (req.method(), req.uri().path()),
            (&hyper::Method::GET, RELAY_PATH)
        ) {
            let response = match self.handle_relay_ws_upgrade(req) {
                Ok(response) => Ok(response),
                // It's convention to send back the version(s) we *do* support
                Err(e @ RelayUpgradeReqError::UnsupportedWebsocketVersion { .. }) => self
                    .build_response()
                    .status(StatusCode::BAD_REQUEST)
                    .header(SEC_WEBSOCKET_VERSION, SUPPORTED_WEBSOCKET_VERSION)
                    .body(body_full(e.to_string())),
                Err(e) => self
                    .build_response()
                    .status(StatusCode::BAD_REQUEST)
                    .body(body_full(e.to_string())),
            }
            .map_err(Into::into);
            return std::future::ready(response);
        }
        // Otherwise handle the relay connection as normal.

        // Check all other possible endpoints.
        let uri = req.uri().clone();
        if let Some(handler) = self
            .service
            .0
            .handlers
            .get(&(req.method().clone(), uri.path()))
        {
            let response = handler(req, self.service.0.default_response());
            return std::future::ready(response);
        }

        // Otherwise return 404
        let response = self
            .service
            .0
            .not_found_fn(req, self.service.0.default_response());
        std::future::ready(response)
    }
}

impl Inner {
    fn default_response(&self) -> ResponseBuilder {
        let mut response = Response::builder();
        for (key, value) in self.headers.iter() {
            response = response.header(key.clone(), value.clone());
        }
        response
    }

    fn not_found_fn(
        &self,
        _req: Request<Incoming>,
        mut res: ResponseBuilder,
    ) -> HyperResult<Response<BytesBody>> {
        for (k, v) in self.headers.iter() {
            res = res.header(k.clone(), v.clone());
        }
        let body = body_full("Not Found");
        let r = res.status(StatusCode::NOT_FOUND).body(body)?;
        HyperResult::Ok(r)
    }

    /// The server HTTP handler to do HTTP upgrades.
    ///
    /// This handler runs while doing the connection upgrade handshake.  Once the connection
    /// is upgraded it sends the stream to the relay server which takes it over.  After
    /// having sent off the connection this handler returns.
    async fn relay_connection_handler(
        &self,
        upgraded: Upgraded,
        request_parts: http::request::Parts,
        protocol_version: ProtocolVersion,
    ) -> Result<(), ConnectionHandlerError> {
        debug!("relay_connection upgraded");
        let (io, read_buf) = downcast_upgrade(upgraded)?;
        if !read_buf.is_empty() {
            return Err(e!(ConnectionHandlerError::BufferNotEmpty { buf: read_buf }));
        }

        self.accept(io, request_parts, protocol_version).await?;
        Ok(())
    }

    /// Adds a new connection to the server and serves it.
    ///
    /// Will error if it takes too long (10 sec) to write or read to the connection, if there is
    /// some read or write error to the connection,  if the server is meant to verify clients,
    /// and is unable to verify this one, or if there is some issue communicating with the server.
    ///
    /// The provided [`AsyncRead`] and [`AsyncWrite`] must be already connected to the connection.
    ///
    /// [`AsyncRead`]: tokio::io::AsyncRead
    /// [`AsyncWrite`]: tokio::io::AsyncWrite
    async fn accept(
        &self,
        io: MaybeTlsStream,
        request_parts: http::request::Parts,
        protocol_version: ProtocolVersion,
    ) -> Result<(), AcceptError> {
        trace!("accept: start");

        // Set the socket to NO_DELAY.
        io.disable_nagle();

        let io = RateLimited::from_cfg(self.rate_limit, io, self.metrics.clone())
            .map_err(|err| e!(AcceptError::RateLimitingMisconfigured, err))?;

        // Create a server builder with default config
        let websocket = tokio_websockets::ServerBuilder::new()
            .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)))
            // Serve will create a WebSocketStream on an already upgraded connection
            .serve(io);

        let mut io = WsBytesFramed { io: websocket };

        let client_auth_header = request_parts.headers.get(CLIENT_AUTH_HEADER).cloned();
        let authentication = handshake::serverside(&mut io, client_auth_header).await?;

        trace!(?authentication.mechanism, "accept: verified authentication");

        let request = ClientRequest::new(authentication.client_key, request_parts);
        let is_authorized = self.access.is_allowed(&request).await;
        let client_key = authentication.authorize_if(is_authorized, &mut io).await?;

        trace!("accept: verified authorization");

        let io = RelayedStream {
            inner: io,
            key_cache: self.key_cache.clone(),
        };

        trace!("accept: build client conn");
        let client_conn_builder = Config {
            endpoint_id: client_key,
            stream: io,
            write_timeout: self.write_timeout,
            channel_capacity: PER_CLIENT_SEND_QUEUE_DEPTH,
            protocol_version,
        };
        trace!("accept: create client");
        let endpoint_id = client_conn_builder.endpoint_id;
        trace!(endpoint_id = %endpoint_id.fmt_short(), "create client");

        // build and register client, starting up read & write loops for the client
        // connection
        self.clients
            .register(client_conn_builder, self.metrics.clone());
        Ok(())
    }
}

/// TLS Certificate Authority acceptor.
#[derive(Clone, derive_more::Debug)]
pub(super) enum TlsAcceptor {
    /// Uses Let's Encrypt as the Certificate Authority. This is used in production.
    LetsEncrypt(#[debug("tokio_rustls_acme::AcmeAcceptor")] AcmeAcceptor),
    /// Manually added tls acceptor. Generally used for tests or for when we've passed in
    /// a certificate via a file.
    Manual(#[debug("tokio_rustls::TlsAcceptor")] tokio_rustls::TlsAcceptor),
}

impl RelayService {
    /// Creates a new RelayService.
    ///
    /// This allows embedding the relay service into an existing HTTP server.
    pub fn new(
        handlers: Handlers,
        headers: HeaderMap,
        rate_limit: Option<ClientRateLimit>,
        key_cache: KeyCache,
        access: AccessConfig,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self(Arc::new(Inner {
            handlers,
            headers,
            clients: Clients::default(),
            write_timeout: SERVER_WRITE_TIMEOUT,
            rate_limit,
            key_cache,
            access,
            metrics,
        }))
    }

    /// Shuts down the relay service, disconnecting all clients.
    pub async fn shutdown(&self) {
        self.0.clients.shutdown().await;
    }

    /// Handle the incoming connection.
    ///
    /// If a `tls_config` is given, will serve the connection using HTTPS, otherwise HTTP.
    ///
    /// If the connection did not fully upgrade to a relay WebSocket connection after
    /// `establish_timeout`, the connection is aborted.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::{sync::Arc, time::Duration};
    /// # use tokio::net::TcpStream;
    /// # use http::HeaderMap;
    /// # use iroh_relay::server::http_server::{Handlers, RelayService, TlsConfig};
    /// # use iroh_relay::{KeyCache, server::{AccessConfig, Metrics}};
    /// # use webpki_types::{CertificateDer, PrivateKeyDer};
    /// # async fn example(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    /// // Create a relay service
    /// let handlers = Handlers::default();
    /// let headers = HeaderMap::new();
    /// let key_cache = KeyCache::new(1024);
    /// let metrics = Arc::new(Metrics::default());
    /// let relay_service = RelayService::new(
    ///     handlers,
    ///     headers,
    ///     None, // No rate limiting
    ///     key_cache,
    ///     AccessConfig::Everyone,
    ///     metrics,
    /// );
    ///
    /// // Generate a self-signed certificate for HTTPS
    /// let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    /// let cert_der = cert.cert.der().to_vec();
    /// let private_key_der = cert.signing_key.serialize_der();
    /// let cert_chain = vec![CertificateDer::from(cert_der)];
    /// let private_key = PrivateKeyDer::try_from(private_key_der)?;
    ///
    /// // Serve with HTTPS
    /// let server_config = Arc::new(
    ///     rustls::ServerConfig::builder()
    ///         .with_no_client_auth()
    ///         .with_single_cert(cert_chain, private_key)?,
    /// );
    /// let tls_config = TlsConfig::new(server_config);
    /// relay_service
    ///     .clone()
    ///     .handle_connection(stream, Some(tls_config), Duration::from_secs(30))
    ///     .await;
    ///
    /// // Or serve with plain HTTP
    /// # let stream = TcpStream::connect("127.0.0.1:0").await?;
    /// relay_service
    ///     .handle_connection(stream, None, Duration::from_secs(30))
    ///     .await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn handle_connection(
        self,
        stream: TcpStream,
        tls_config: Option<TlsConfig>,
        establish_timeout: Duration,
    ) {
        let metrics = self.0.metrics.clone();
        metrics.http_connections.inc();
        // We create a notification token to be triggered once the connection is fully established
        // and passed to the relay server.
        let on_establish = Arc::new(Notify::new());
        let service = RelayServiceWithNotify::new(self, on_establish.clone());

        // This is the main connection future, driving the connection to completion.
        let serve_fut = async move {
            match tls_config {
                Some(tls_config) => {
                    debug!("HTTPS: serve connection");
                    service.tls_serve_connection(stream, tls_config).await
                }
                None => {
                    debug!("HTTP: serve connection");
                    let stream = MaybeTlsStream::Plain(stream);
                    service.serve_connection(stream).await
                }
            }
        };

        // We set a timeout for the connection to limit lingering connections during establishment.
        // The timeout is cleared once the connection has completed the TLS and WebSocket
        // handshakes and has been passed over to the relay protocol handler.
        // If the timeout expires before that happens, the connection is aborted.
        let res = clearable_timeout(establish_timeout, on_establish, serve_fut)
            .await
            .map_err(|_elapsed| e!(ServeConnectionError::EstablishTimeout))
            .flatten();

        metrics.http_connections_closed.inc();

        if let Err(error) = res {
            match error {
                ServeConnectionError::ManualAccept { source, .. }
                | ServeConnectionError::LetsEncryptAccept { source, .. }
                    if source.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    debug!(reason=?source, "peer disconnected");
                }
                // From hyper: <https://github.com/hyperium/hyper/commit/271bba16672ff54a44e043c5cc1ae6b9345bb172>
                // `hyper::Error::IncompleteMessage` is hyper's equivalent of UnexpectedEof
                ServeConnectionError::Https { source, .. }
                | ServeConnectionError::Http { source, .. }
                    if source.is_incomplete_message() =>
                {
                    debug!(reason=?source, "peer disconnected");
                }
                _ => {
                    metrics.http_connections_errored.inc();
                    error!(?error, "failed to handle connection");
                }
            }
        }
    }
}

impl RelayServiceWithNotify {
    /// Serves a TLS connection.
    async fn tls_serve_connection(
        self,
        stream: TcpStream,
        tls_config: TlsConfig,
    ) -> Result<(), ServeConnectionError> {
        let TlsConfig { acceptor, config } = tls_config;
        let stream = match acceptor {
            TlsAcceptor::LetsEncrypt(a) => {
                match a
                    .accept(stream)
                    .await
                    .map_err(|err| e!(ServeConnectionError::LetsEncryptAccept, err))?
                {
                    None => {
                        info!("TLS[acme]: received TLS-ALPN-01 validation request");
                        return Ok(());
                    }
                    Some(start_handshake) => {
                        debug!("TLS[acme]: start handshake");
                        let tls_stream = start_handshake
                            .into_stream(config)
                            .await
                            .map_err(|err| e!(ServeConnectionError::TlsHandshake, err))?;
                        MaybeTlsStream::Tls(tls_stream)
                    }
                }
            }
            TlsAcceptor::Manual(a) => {
                debug!("TLS[manual]: accept");
                let tls_stream = a
                    .accept(stream)
                    .await
                    .map_err(|err| e!(ServeConnectionError::ManualAccept, err))?;
                MaybeTlsStream::Tls(tls_stream)
            }
        };
        self.serve_connection(stream).await
    }

    /// Wrapper for the actual http connection (with upgrades)
    async fn serve_connection(self, io: MaybeTlsStream) -> Result<(), ServeConnectionError> {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(io), self)
            .with_upgrades()
            .await
            .map_err(|err| e!(ServeConnectionError::ServeConnection, err))
    }
}

/// A collection of HTTP request handlers for custom endpoints.
#[derive(Default)]
pub struct Handlers(HashMap<(Method, &'static str), HyperHandler>);

impl std::fmt::Debug for Handlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0.keys().fold(String::new(), |curr, next| {
            let (method, uri) = next;
            format!("{curr}\n({method},{uri}): Box<Fn(ResponseBuilder) -> Result<Response<Body>> + Send + Sync + 'static>")
        });
        write!(f, "HashMap<{s}>")
    }
}

impl std::ops::Deref for Handlers {
    type Target = HashMap<(Method, &'static str), HyperHandler>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Handlers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Requires a future to complete before the specified duration elapses, unless the timeout is cleared.
///
/// If the future completes before the duration has elapsed, then the completed value is returned.
/// Otherwise, an error is returned and the future is canceled.
///
/// If `clear_timeout` is triggered, the timeout is cleared and the future is always run to completion.
async fn clearable_timeout<F: Future>(
    timeout: Duration,
    clear_timeout: Arc<Notify>,
    fut: F,
) -> Result<F::Output, Elapsed> {
    tokio::pin!(fut);
    let timeout = MaybeFuture::Some(tokio::time::sleep(timeout));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            biased;
            res = &mut fut => {
                return Ok(res);
            }
            _ = clear_timeout.notified() => {
                timeout.as_mut().set_none();
            },
            _ = &mut timeout => {
                return Err(Elapsed);
            }
        }
    }
}

#[stack_error(derive)]
#[error("Timeout elapsed")]
struct Elapsed;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use iroh_base::{PublicKey, SecretKey};
    use iroh_dns::dns::DnsResolver;
    use n0_error::{Result, StdResultExt, bail_any};
    use n0_future::{SinkExt, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};
    use reqwest::Url;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::info;

    use super::*;
    use crate::{
        client::{Client, ClientBuilder, ConnectError, conn::Conn},
        protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
        tls::{CaRootsConfig, default_provider},
    };

    pub(crate) fn make_tls_config() -> TlsConfig {
        let subject_alt_names = vec!["localhost".to_string()];

        let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
        let rustls_certificate = cert.cert.der().clone();
        let rustls_key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocols supported by ring")
        .with_no_client_auth()
        .with_single_cert(vec![(rustls_certificate)], rustls_key.into())
        .expect("cert is right");

        TlsConfig::new(Arc::new(config))
    }

    #[tokio::test]
    #[traced_test]
    async fn test_http_clients_and_server() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let a_key = SecretKey::from_bytes(&rng.random());
        let b_key = SecretKey::from_bytes(&rng.random());

        // start server
        let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .spawn()
            .await?;

        let addr = server.addr();

        // get dial info
        let port = addr.port();
        let addr = if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
            ipv4_addr
        } else {
            bail_any!("cannot get ipv4 addr from socket addr {addr:?}");
        };

        info!("addr: {addr}:{port}");
        let relay_addr: Url = format!("http://{addr}:{port}").parse().unwrap();

        // create clients
        let (a_key, mut client_a) = create_test_client(a_key, relay_addr.clone()).await?;
        info!("created client {a_key:?}");
        let (b_key, mut client_b) = create_test_client(b_key, relay_addr).await?;
        info!("created client {b_key:?}");

        info!("ping a");
        client_a.send(ClientToRelayMsg::Ping([1u8; 8])).await?;
        let pong = client_a.next().await.expect("eos")?;
        assert!(matches!(pong, RelayToClientMsg::Pong { .. }));

        info!("ping b");
        client_b.send(ClientToRelayMsg::Ping([2u8; 8])).await?;
        let pong = client_b.next().await.expect("eos")?;
        assert!(matches!(pong, RelayToClientMsg::Pong { .. }));

        info!("sending message from a to b");
        let msg = Datagrams::from(b"hi there, client b!");
        client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: b_key,
                datagrams: msg.clone(),
            })
            .await?;
        info!("waiting for message from a on b");
        let (got_key, got_msg) =
            process_msg(client_b.next().await).expect("expected message from client_a");
        assert_eq!(a_key, got_key);
        assert_eq!(msg, got_msg);

        info!("sending message from b to a");
        let msg = Datagrams::from(b"right back at ya, client b!");
        client_b
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: a_key,
                datagrams: msg.clone(),
            })
            .await?;
        info!("waiting for message b on a");
        let (got_key, got_msg) =
            process_msg(client_a.next().await).expect("expected message from client_b");
        assert_eq!(b_key, got_key);
        assert_eq!(msg, got_msg);

        // Close before shutting down, otherwise we'll try to send close frames on broken pipes
        client_a.close().await?;
        client_b.close().await?;
        server.shutdown();

        Ok(())
    }

    async fn create_test_client(
        key: SecretKey,
        server_url: Url,
    ) -> Result<(PublicKey, Client), ConnectError> {
        let public_key = key.public();
        let client = ClientBuilder::new(server_url, key, DnsResolver::new()).tls_client_config(
            CaRootsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
        );
        let client = client.connect().await?;

        Ok((public_key, client))
    }

    fn process_msg(
        msg: Option<Result<RelayToClientMsg, crate::client::RecvError>>,
    ) -> Option<(PublicKey, Datagrams)> {
        match msg {
            Some(Err(e)) => {
                info!("client `recv` error {e}");
                None
            }
            Some(Ok(msg)) => {
                info!("got message on: {msg:?}");
                if let RelayToClientMsg::Datagrams {
                    remote_endpoint_id: source,
                    datagrams,
                } = msg
                {
                    Some((source, datagrams))
                } else {
                    None
                }
            }
            None => {
                info!("client end of stream");
                None
            }
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_subprotocol_negotiation_picks_latest() -> Result {
        let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .spawn()
            .await?;
        let addr = server.addr();

        for offered in [
            "iroh-relay-v2,iroh-relay-v1",
            "iroh-relay-v1,iroh-relay-v2",
            "baz, iroh-relay-v1, iroh-relay-v2, boo",
            "foo, iroh-relay-v2, bar",
        ] {
            let ws_uri = format!("ws://{addr}{RELAY_PATH}");
            let (_stream, response) = tokio_websockets::ClientBuilder::new()
                .uri(&ws_uri)
                .expect("valid websocket URI")
                .add_header(
                    SEC_WEBSOCKET_PROTOCOL,
                    HeaderValue::from_str(offered).expect("valid subprotocol header value"),
                )
                .expect("header accepted by websocket client")
                .connect()
                .await
                .expect("websocket upgrade succeeds");
            let negotiated = response
                .headers()
                .get(SEC_WEBSOCKET_PROTOCOL)
                .expect("Sec-WebSocket-Protocol response header is present");
            assert_eq!(negotiated, "iroh-relay-v2", "offered={offered}");
        }

        server.shutdown();
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_https_clients_and_server() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let a_key = SecretKey::from_bytes(&rng.random());
        let b_key = SecretKey::from_bytes(&rng.random());

        // create tls_config
        let tls_config = make_tls_config();

        // start server
        let mut server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .tls_config(Some(tls_config))
            .spawn()
            .await?;

        let addr = server.addr();

        // get dial info
        let port = addr.port();
        let addr = if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
            ipv4_addr
        } else {
            bail_any!("cannot get ipv4 addr from socket addr {addr:?}");
        };

        info!("Relay listening on: {addr}:{port}");

        let url: Url = format!("https://localhost:{port}").parse().unwrap();

        // create clients
        let (a_key, mut client_a) = create_test_client(a_key, url.clone()).await?;
        info!("created client {a_key:?}");
        let (b_key, mut client_b) = create_test_client(b_key, url).await?;
        info!("created client {b_key:?}");

        info!("ping a");
        client_a.send(ClientToRelayMsg::Ping([1u8; 8])).await?;
        let pong = client_a.next().await.expect("eos")?;
        assert!(matches!(pong, RelayToClientMsg::Pong { .. }));

        info!("ping b");
        client_b.send(ClientToRelayMsg::Ping([2u8; 8])).await?;
        let pong = client_b.next().await.expect("eos")?;
        assert!(matches!(pong, RelayToClientMsg::Pong { .. }));

        info!("sending message from a to b");
        let msg = Datagrams::from(b"hi there, client b!");
        client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: b_key,
                datagrams: msg.clone(),
            })
            .await?;
        info!("waiting for message from a on b");
        let (got_key, got_msg) =
            process_msg(client_b.next().await).expect("expected message from client_a");
        assert_eq!(a_key, got_key);
        assert_eq!(msg, got_msg);

        info!("sending message from b to a");
        let msg = Datagrams::from(b"right back at ya, client b!");
        client_b
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: a_key,
                datagrams: msg.clone(),
            })
            .await?;
        info!("waiting for message b on a");
        let (got_key, got_msg) =
            process_msg(client_a.next().await).expect("expected message from client_b");
        assert_eq!(b_key, got_key);
        assert_eq!(msg, got_msg);

        // Close before shutting down, otherwise we'll try to send close frames on broken pipes
        client_a.close().await?;
        client_b.close().await?;
        server.shutdown();
        server.task_handle().await.std_context("join")?;

        Ok(())
    }

    async fn make_test_client(client: tokio::io::DuplexStream, key: &SecretKey) -> Result<Conn> {
        let client = crate::client::streams::MaybeTlsStream::Test(client);
        let client = tokio_websockets::ClientBuilder::new().take_over(client);
        let client = Conn::new(client, KeyCache::test(), key, Default::default()).await?;
        Ok(client)
    }

    #[tokio::test]
    #[traced_test]
    async fn test_server_basic() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        info!("Create the server.");
        let metrics = Arc::new(Metrics::default());
        let service = RelayService::new(
            Default::default(),
            Default::default(),
            None,
            KeyCache::test(),
            AccessConfig::Everyone,
            metrics.clone(),
        );

        info!("Create client A and connect it to the server.");
        let key_a = SecretKey::from_bytes(&rng.random());
        let public_key_a = key_a.public();
        let (client_a, rw_a) = tokio::io::duplex(10);
        let s = service.clone();
        let handler_task = tokio::spawn(async move {
            s.0.accept(
                MaybeTlsStream::Test(rw_a),
                Request::new(()).into_parts().0,
                Default::default(),
            )
            .await
        });
        let mut client_a = make_test_client(client_a, &key_a).await?;
        handler_task.await.std_context("join")??;

        info!("Create client B and connect it to the server.");
        let key_b = SecretKey::from_bytes(&rng.random());
        let public_key_b = key_b.public();
        let (client_b, rw_b) = tokio::io::duplex(10);
        let s = service.clone();
        let handler_task = tokio::spawn(async move {
            s.0.accept(
                MaybeTlsStream::Test(rw_b),
                Request::new(()).into_parts().0,
                Default::default(),
            )
            .await
        });
        let mut client_b = make_test_client(client_b, &key_b).await?;
        handler_task.await.std_context("join")??;

        info!("Send message from A to B.");
        let msg = Datagrams::from(b"hello client b!!");
        client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: public_key_b,
                datagrams: msg.clone(),
            })
            .await?;
        match client_b.next().await.unwrap()? {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                assert_eq!(public_key_a, remote_endpoint_id);
                assert_eq!(msg, datagrams);
            }
            msg => {
                bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
            }
        }

        info!("Send message from B to A.");
        let msg = Datagrams::from(b"nice to meet you client a!!");
        client_b
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: public_key_a,
                datagrams: msg.clone(),
            })
            .await?;
        match client_a.next().await.unwrap()? {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                assert_eq!(public_key_b, remote_endpoint_id);
                assert_eq!(msg, datagrams);
            }
            msg => {
                bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
            }
        }

        info!("Close the server and clients");
        service.shutdown().await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        info!("Fail to send message from A to B.");
        let res = client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: public_key_b,
                datagrams: Datagrams::from(b"try to send"),
            })
            .await;
        assert!(res.is_err());
        assert!(client_b.next().await.is_none());

        drop(client_a);
        drop(client_b);

        service.shutdown().await;

        assert_eq!(metrics.accepts.get(), metrics.disconnects.get());

        Ok(())
    }

    #[tokio::test]
    async fn test_server_replace_client() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        info!("Create the server.");
        let service = RelayService::new(
            Default::default(),
            Default::default(),
            None,
            KeyCache::test(),
            AccessConfig::Everyone,
            Default::default(),
        );

        info!("Create client A and connect it to the server.");
        let key_a = SecretKey::from_bytes(&rng.random());
        let public_key_a = key_a.public();
        let (client_a, rw_a) = tokio::io::duplex(10);
        let s = service.clone();
        let handler_task = tokio::spawn(async move {
            s.0.accept(
                MaybeTlsStream::Test(rw_a),
                Request::new(()).into_parts().0,
                Default::default(),
            )
            .await
        });
        let mut client_a = make_test_client(client_a, &key_a).await?;
        handler_task.await.std_context("join")??;

        info!("Create client B and connect it to the server.");
        let key_b = SecretKey::from_bytes(&rng.random());
        let public_key_b = key_b.public();
        let (client_b, rw_b) = tokio::io::duplex(10);
        let s = service.clone();
        let handler_task = tokio::spawn(async move {
            s.0.accept(
                MaybeTlsStream::Test(rw_b),
                Request::new(()).into_parts().0,
                Default::default(),
            )
            .await
        });
        let mut client_b = make_test_client(client_b, &key_b).await?;
        handler_task.await.std_context("join")??;

        info!("Send message from A to B.");
        let msg = Datagrams::from(b"hello client b!!");
        client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: public_key_b,
                datagrams: msg.clone(),
            })
            .await?;
        match client_b.next().await.expect("eos")? {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                assert_eq!(public_key_a, remote_endpoint_id);
                assert_eq!(msg, datagrams);
            }
            msg => {
                bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
            }
        }

        info!("Send message from B to A.");
        let msg = Datagrams::from(b"nice to meet you client a!!");
        client_b
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: public_key_a,
                datagrams: msg.clone(),
            })
            .await?;
        match client_a.next().await.expect("eos")? {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                assert_eq!(public_key_b, remote_endpoint_id);
                assert_eq!(msg, datagrams);
            }
            msg => {
                bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
            }
        }

        info!("Create client B and connect it to the server");
        let (new_client_b, new_rw_b) = tokio::io::duplex(10);
        let s = service.clone();
        let handler_task = tokio::spawn(async move {
            s.0.accept(
                MaybeTlsStream::Test(new_rw_b),
                Request::new(()).into_parts().0,
                Default::default(),
            )
            .await
        });
        let mut new_client_b = make_test_client(new_client_b, &key_b).await?;
        handler_task.await.std_context("join")??;

        // assert!(client_b.recv().await.is_err());

        info!("Send message from A to B.");
        let msg = Datagrams::from(b"are you still there, b?!");
        client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: public_key_b,
                datagrams: msg.clone(),
            })
            .await?;
        match new_client_b.next().await.expect("eos")? {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                assert_eq!(public_key_a, remote_endpoint_id);
                assert_eq!(msg, datagrams);
            }
            msg => {
                bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
            }
        }

        info!("Send message from B to A.");
        let msg = Datagrams::from(b"just had a spot of trouble but I'm back now,a!!");
        new_client_b
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: public_key_a,
                datagrams: msg.clone(),
            })
            .await?;
        match client_a.next().await.expect("eos")? {
            RelayToClientMsg::Datagrams {
                remote_endpoint_id,
                datagrams,
            } => {
                assert_eq!(public_key_b, remote_endpoint_id);
                assert_eq!(msg, datagrams);
            }
            msg => {
                bail_any!("expected ReceivedDatagrams msg, got {msg:?}");
            }
        }

        info!("Close the server and clients");
        service.shutdown().await;

        info!("Sending message from A to B fails");
        let res = client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: public_key_b,
                datagrams: Datagrams::from(b"try to send"),
            })
            .await;
        assert!(res.is_err());
        assert!(new_client_b.next().await.is_none());
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_establish_timeout() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);

        // Start server with a very short establish timeout.
        let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .establish_timeout(Duration::from_millis(500))
            .spawn()
            .await?;

        let addr = server.addr();
        let port = addr.port();
        let addr = if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
            ipv4_addr
        } else {
            bail_any!("cannot get ipv4 addr from socket addr {addr:?}");
        };
        let relay_url: Url = format!("http://{addr}:{port}").parse().unwrap();

        // 1. A lingering connection that never upgrades should be aborted by the timeout.
        info!("opening lingering TCP connection (no upgrade)");
        let mut lingering = TcpStream::connect(format!("{addr}:{port}")).await?;
        // Write a partial HTTP request but never complete the upgrade.
        lingering
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
            .await?;
        // Wait for the server to abort this connection.
        let mut buf = [0u8; 1];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let read = tokio::time::timeout_at(deadline, lingering.read(&mut buf)).await;
        // The server should close the connection, resulting in a read of 0 bytes or an error.
        match read {
            Ok(Ok(0)) => info!("lingering connection closed by server (EOF)"),
            Ok(Err(e)) => info!("lingering connection closed by server (error: {e})"),
            other => bail_any!("expected lingering connection to be closed, got {other:?}"),
        }

        // 2. A properly established client should NOT be aborted by the timeout.
        info!("connecting a proper relay client");
        let key = SecretKey::from_bytes(&rng.random());
        let (_, mut client) = create_test_client(key, relay_url).await?;

        // Wait longer than the establish timeout to prove the connection survives.
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Ping should still work.
        client.send(ClientToRelayMsg::Ping([7u8; 8])).await?;
        let pong = client.next().await.expect("expected pong")?;
        assert!(matches!(pong, RelayToClientMsg::Pong { .. }));
        info!("established connection survived past the timeout");

        client.close().await?;
        server.shutdown();
        Ok(())
    }
}
