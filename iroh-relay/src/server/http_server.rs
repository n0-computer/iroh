use std::{
    collections::HashMap, future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

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
use n0_future::time::Elapsed;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls_acme::AcmeAcceptor;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, error, info, info_span, trace, warn, warn_span};

use super::{AccessConfig, SpawnError, clients::Clients, streams::InvalidBucketConfig};
use crate::{
    KeyCache,
    defaults::{DEFAULT_KEY_CACHE_CAPACITY, timeouts::SERVER_WRITE_TIMEOUT},
    http::{
        CLIENT_AUTH_HEADER, RELAY_PATH, RELAY_PROTOCOL_VERSION, SUPPORTED_WEBSOCKET_VERSION,
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

type BytesBody = http_body_util::Full<hyper::body::Bytes>;
type HyperError = Box<dyn std::error::Error + Send + Sync>;
type HyperResult<T> = std::result::Result<T, HyperError>;
type HyperHandler = Box<
    dyn Fn(Request<Incoming>, ResponseBuilder) -> HyperResult<Response<BytesBody>>
        + Send
        + Sync
        + 'static,
>;

/// WebSocket GUID needed for accepting websocket connections, see RFC 6455 (<https://www.rfc-editor.org/rfc/rfc6455>) section 1.3
const SEC_WEBSOCKET_ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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
    http_body_util::Full::new(content.into())
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
#[derive(Debug, Clone)]
pub(super) struct TlsConfig {
    /// The server config
    pub(super) config: Arc<rustls::ServerConfig>,
    /// The kind
    pub(super) acceptor: TlsAcceptor,
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
    #[error("TLS[manual] timeout")]
    Timeout {
        #[error(std_err)]
        source: Elapsed,
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
    pub fn key_cache_capacity(mut self, capacity: usize) -> Self {
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
                                        .handle_connection(stream, tls_config)
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
#[derive(Clone, Debug)]
struct RelayService(Arc<Inner>);

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
        we_support: &'static str,
        you_support: String,
    },
}

impl RelayService {
    fn build_response(&self) -> http::response::Builder {
        let mut res = Response::builder();
        for (key, value) in self.0.headers.iter() {
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
        let supports_our_version = subprotocols
            .split_whitespace()
            .any(|p| p == RELAY_PROTOCOL_VERSION);
        ensure!(
            supports_our_version,
            RelayUpgradeReqError::UnsupportedRelayVersion {
                we_support: RELAY_PROTOCOL_VERSION,
                you_support: subprotocols.to_string()
            }
        );

        let client_auth_header = req.headers().get(CLIENT_AUTH_HEADER).cloned();

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
                        if let Err(err) = this
                            .0
                            .relay_connection_handler(upgraded, client_auth_header)
                            .await
                        {
                            warn!("error accepting upgraded connection: {err:#}",);
                        } else {
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
            .header(
                SEC_WEBSOCKET_PROTOCOL,
                HeaderValue::from_static(RELAY_PROTOCOL_VERSION),
            )
            .header(CONNECTION, "upgrade")
            .body(body_full("switching to websocket protocol"))
            .expect("valid body"))
    }
}

impl Service<Request<Incoming>> for RelayService {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        // Create a client if the request hits the relay endpoint.
        if matches!(
            (req.method(), req.uri().path()),
            (&hyper::Method::GET, RELAY_PATH)
        ) {
            let res = match self.handle_relay_ws_upgrade(req) {
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
            return Box::pin(async move { res });
        }
        // Otherwise handle the relay connection as normal.

        // Check all other possible endpoints.
        let uri = req.uri().clone();
        if let Some(res) = self.0.handlers.get(&(req.method().clone(), uri.path())) {
            let f = res(req, self.0.default_response());
            return Box::pin(async move { f });
        }
        // Otherwise return 404
        let res = self.0.not_found_fn(req, self.0.default_response());
        Box::pin(async move { res })
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
        client_auth_header: Option<HeaderValue>,
    ) -> Result<(), ConnectionHandlerError> {
        debug!("relay_connection upgraded");
        let (io, read_buf) = downcast_upgrade(upgraded)?;
        if !read_buf.is_empty() {
            return Err(e!(ConnectionHandlerError::BufferNotEmpty { buf: read_buf }));
        }

        self.accept(io, client_auth_header).await?;
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
        client_auth_header: Option<HeaderValue>,
    ) -> Result<(), AcceptError> {
        trace!("accept: start");

        let io = RateLimited::from_cfg(self.rate_limit, io, self.metrics.clone())
            .map_err(|err| e!(AcceptError::RateLimitingMisconfigured, err))?;

        // Create a server builder with default config
        let websocket = tokio_websockets::ServerBuilder::new()
            .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)))
            // Serve will create a WebSocketStream on an already upgraded connection
            .serve(io);

        let mut io = WsBytesFramed { io: websocket };

        let authentication = handshake::serverside(&mut io, client_auth_header).await?;

        trace!(?authentication.mechanism, "accept: verified authentication");

        let is_authorized = self.access.is_allowed(authentication.client_key).await;
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
        };
        trace!("accept: create client");
        let endpoint_id = client_conn_builder.endpoint_id;
        trace!(endpoint_id = %endpoint_id.fmt_short(), "create client");

        // build and register client, starting up read & write loops for the client
        // connection
        self.clients
            .register(client_conn_builder, self.metrics.clone())
            .await;
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
    fn new(
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

    async fn shutdown(&self) {
        self.0.clients.shutdown().await;
    }

    /// Handle the incoming connection.
    ///
    /// If a `tls_config` is given, will serve the connection using HTTPS.
    async fn handle_connection(self, stream: TcpStream, tls_config: Option<TlsConfig>) {
        let res = match tls_config {
            Some(tls_config) => {
                debug!("HTTPS: serve connection");
                self.tls_serve_connection(stream, tls_config).await
            }
            None => {
                debug!("HTTP: serve connection");
                self.serve_connection(MaybeTlsStream::Plain(stream))
                    .await
                    .map_err(|err| e!(ServeConnectionError::Http, err))
            }
        };
        match res {
            Ok(()) => {}
            Err(error) => match error {
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
                    error!(?error, "failed to handle connection");
                }
            },
        }
    }

    /// Serve the tls connection
    async fn tls_serve_connection(
        self,
        stream: TcpStream,
        tls_config: TlsConfig,
    ) -> Result<(), ServeConnectionError> {
        let TlsConfig { acceptor, config } = tls_config;
        match acceptor {
            TlsAcceptor::LetsEncrypt(a) => {
                match a
                    .accept(stream)
                    .await
                    .map_err(|err| e!(ServeConnectionError::LetsEncryptAccept, err))?
                {
                    None => {
                        info!("TLS[acme]: received TLS-ALPN-01 validation request");
                    }
                    Some(start_handshake) => {
                        debug!("TLS[acme]: start handshake");
                        let tls_stream = start_handshake
                            .into_stream(config)
                            .await
                            .map_err(|err| e!(ServeConnectionError::TlsHandshake, err))?;
                        self.serve_connection(MaybeTlsStream::Tls(tls_stream))
                            .await
                            .map_err(|err| e!(ServeConnectionError::Https, err))?;
                    }
                }
            }
            TlsAcceptor::Manual(a) => {
                debug!("TLS[manual]: accept");
                let tls_stream = tokio::time::timeout(Duration::from_secs(30), a.accept(stream))
                    .await
                    .map_err(|err| e!(ServeConnectionError::Timeout, err))?
                    .map_err(|err| e!(ServeConnectionError::ManualAccept, err))?;

                self.serve_connection(MaybeTlsStream::Tls(tls_stream))
                    .await
                    .map_err(|err| e!(ServeConnectionError::ServeConnection, err))?;
            }
        }
        Ok(())
    }

    /// Wrapper for the actual http connection (with upgrades)
    async fn serve_connection<I>(self, io: I) -> Result<(), hyper::Error>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(io), self)
            .with_upgrades()
            .await
    }
}

#[derive(Default)]
struct Handlers(HashMap<(Method, &'static str), HyperHandler>);

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use iroh_base::{PublicKey, SecretKey};
    use n0_error::{Result, StdResultExt, bail_any};
    use n0_future::{SinkExt, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::SeedableRng;
    use reqwest::Url;
    use tracing::info;

    use super::*;
    use crate::{
        client::{Client, ClientBuilder, ConnectError, conn::Conn},
        dns::DnsResolver,
        protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
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

        let config = Arc::new(config);
        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());

        TlsConfig {
            config,
            acceptor: TlsAcceptor::Manual(acceptor),
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_http_clients_and_server() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let a_key = SecretKey::generate(&mut rng);
        let b_key = SecretKey::generate(&mut rng);

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
        let client =
            ClientBuilder::new(server_url, key, DnsResolver::new()).insecure_skip_cert_verify(true);
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
    async fn test_https_clients_and_server() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let a_key = SecretKey::generate(&mut rng);
        let b_key = SecretKey::generate(&mut rng);

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
        let client = Conn::new(client, KeyCache::test(), key).await?;
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
        let key_a = SecretKey::generate(&mut rng);
        let public_key_a = key_a.public();
        let (client_a, rw_a) = tokio::io::duplex(10);
        let s = service.clone();
        let handler_task =
            tokio::spawn(async move { s.0.accept(MaybeTlsStream::Test(rw_a), None).await });
        let mut client_a = make_test_client(client_a, &key_a).await?;
        handler_task.await.std_context("join")??;

        info!("Create client B and connect it to the server.");
        let key_b = SecretKey::generate(&mut rng);
        let public_key_b = key_b.public();
        let (client_b, rw_b) = tokio::io::duplex(10);
        let s = service.clone();
        let handler_task =
            tokio::spawn(async move { s.0.accept(MaybeTlsStream::Test(rw_b), None).await });
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
        let key_a = SecretKey::generate(&mut rng);
        let public_key_a = key_a.public();
        let (client_a, rw_a) = tokio::io::duplex(10);
        let s = service.clone();
        let handler_task =
            tokio::spawn(async move { s.0.accept(MaybeTlsStream::Test(rw_a), None).await });
        let mut client_a = make_test_client(client_a, &key_a).await?;
        handler_task.await.std_context("join")??;

        info!("Create client B and connect it to the server.");
        let key_b = SecretKey::generate(&mut rng);
        let public_key_b = key_b.public();
        let (client_b, rw_b) = tokio::io::duplex(10);
        let s = service.clone();
        let handler_task =
            tokio::spawn(async move { s.0.accept(MaybeTlsStream::Test(rw_b), None).await });
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
        let handler_task =
            tokio::spawn(async move { s.0.accept(MaybeTlsStream::Test(new_rw_b), None).await });
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
}
