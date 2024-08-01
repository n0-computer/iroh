use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, ensure, Context as _, Result};
use bytes::Bytes;
use derive_more::Debug;
use futures_lite::FutureExt;
use http::header::CONNECTION;
use http::response::Builder as ResponseBuilder;
use hyper::body::Incoming;
use hyper::header::{HeaderValue, UPGRADE};
use hyper::service::Service;
use hyper::upgrade::Upgraded;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls_acme::AcmeAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, error, info, info_span, warn, Instrument};
use tungstenite::handshake::derive_accept_key;

use crate::key::SecretKey;
use crate::relay::http::{Protocol, LEGACY_RELAY_PATH, RELAY_PATH, SUPPORTED_WEBSOCKET_VERSION};
use crate::relay::server::actor::{ClientConnHandler, ServerActorTask};
use crate::relay::server::streams::MaybeTlsStream;
use crate::util::AbortingJoinHandle;

type BytesBody = http_body_util::Full<hyper::body::Bytes>;
type HyperError = Box<dyn std::error::Error + Send + Sync>;
type HyperResult<T> = std::result::Result<T, HyperError>;
type HyperHandler = Box<
    dyn Fn(Request<Incoming>, ResponseBuilder) -> HyperResult<Response<BytesBody>>
        + Send
        + Sync
        + 'static,
>;

/// Creates a new [`BytesBody`] with no content.
fn body_empty() -> BytesBody {
    http_body_util::Full::new(hyper::body::Bytes::new())
}

/// Creates a new [`BytesBody`] with given content.
fn body_full(content: impl Into<hyper::body::Bytes>) -> BytesBody {
    http_body_util::Full::new(content.into())
}

fn downcast_upgrade(upgraded: Upgraded) -> Result<(MaybeTlsStream, Bytes)> {
    match upgraded.downcast::<hyper_util::rt::TokioIo<MaybeTlsStream>>() {
        Ok(parts) => Ok((parts.io.into_inner(), parts.read_buf)),
        Err(_) => {
            bail!("could not downcast the upgraded connection to MaybeTlsStream")
        }
    }
}

/// The server HTTP handler to do HTTP upgrades.
async fn relay_connection_handler(
    protocol: Protocol,
    conn_handler: &ClientConnHandler,
    upgraded: Upgraded,
) -> Result<()> {
    debug!(?protocol, "relay_connection upgraded");
    let (io, read_buf) = downcast_upgrade(upgraded)?;
    ensure!(
        read_buf.is_empty(),
        "can not deal with buffered data yet: {:?}",
        read_buf
    );

    conn_handler.accept(protocol, io).await
}

/// The Relay HTTP server.
///
/// A running HTTP server serving the relay endpoint and optionally a number of additional
/// HTTP services added with [`ServerBuilder::request_handler`].  If configured using
/// [`ServerBuilder::tls_config`] the server will handle TLS as well.
///
/// Created using [`ServerBuilder::spawn`].
#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
    http_server_task: AbortingJoinHandle<()>,
    cancel_server_loop: CancellationToken,
}

impl Server {
    /// Returns a handle for this server.
    ///
    /// The server runs in the background as several async tasks.  This allows controlling
    /// the server, in particular it allows gracefully shutting down the server.
    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            cancel_token: self.cancel_server_loop.clone(),
        }
    }

    /// Closes the underlying relay server and the HTTP(S) server tasks.
    pub fn shutdown(&self) {
        self.cancel_server_loop.cancel();
    }

    /// Returns the [`AbortingJoinHandle`] for the supervisor task managing the server.
    ///
    /// This is the root of all the tasks for the server.  Aborting it will abort all the
    /// other tasks for the server.  Awaiting it will complete when all the server tasks are
    /// completed.
    pub fn task_handle(&mut self) -> &mut AbortingJoinHandle<()> {
        &mut self.http_server_task
    }

    /// Returns the local address of this server.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// A handle for the [`Server`].
///
/// This does not allow access to the task but can communicate with it.
#[derive(Debug, Clone)]
pub struct ServerHandle {
    cancel_token: CancellationToken,
}

impl ServerHandle {
    /// Gracefully shut down the server.
    pub fn shutdown(&self) {
        self.cancel_token.cancel()
    }
}

/// Configuration to use for the TLS connection
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// The server config
    pub config: Arc<rustls::ServerConfig>,
    /// The kind
    pub acceptor: TlsAcceptor,
}

/// Builder for the Relay HTTP Server.
///
/// Defaults to handling relay requests on the "/relay" (and "/derp" for backwards compatibility) endpoint.
/// Other HTTP endpoints can be added using [`ServerBuilder::request_handler`].
///
/// If no [`SecretKey`] is provided, it is assumed that you will provide a
/// [`ServerBuilder::relay_override`] function that handles requests to the relay
/// endpoint. Not providing a [`ServerBuilder::relay_override`] in this case will result in
/// an error on `spawn`.
#[derive(derive_more::Debug)]
pub struct ServerBuilder {
    /// The secret key for this Server.
    ///
    /// When `None`, you must also provide a `relay_override` function that
    /// will be run when someone hits the relay endpoint.
    secret_key: Option<SecretKey>,
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
    /// Use a custom relay response handler.
    ///
    /// Typically used when you want to disable any relay connections.
    #[debug("{}", relay_override.as_ref().map_or("None", |_| "Some(Box<Fn(Request<Incoming>, ResponseBuilder) -> Result<Response<BytesBody> + Send + Sync + 'static>)"))]
    relay_override: Option<HyperHandler>,
    /// Headers to use for HTTP responses.
    headers: HeaderMap,
    /// 404 not found response.
    ///
    /// When `None`, a default is provided.
    #[debug("{}", not_found_fn.as_ref().map_or("None", |_| "Some(Box<Fn(ResponseBuilder) -> Result<Response<Body>> + Send + Sync + 'static>)"))]
    not_found_fn: Option<HyperHandler>,
}

impl ServerBuilder {
    /// Creates a new [ServerBuilder].
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            secret_key: None,
            addr,
            tls_config: None,
            handlers: Default::default(),
            relay_override: None,
            headers: HeaderMap::new(),
            not_found_fn: None,
        }
    }

    /// The [`SecretKey`] identity for this relay server.
    ///
    /// When set to `None`, the builder assumes you do not want to run a relay service.
    pub fn secret_key(mut self, secret_key: Option<SecretKey>) -> Self {
        self.secret_key = secret_key;
        self
    }

    /// Serves all requests content using TLS.
    pub fn tls_config(mut self, config: Option<TlsConfig>) -> Self {
        self.tls_config = config;
        self
    }

    /// Adds a custom handler for a specific Method & URI.
    pub fn request_handler(
        mut self,
        method: Method,
        uri_path: &'static str,
        handler: HyperHandler,
    ) -> Self {
        self.handlers.insert((method, uri_path), handler);
        self
    }

    /// Sets a custom "404" handler.
    #[allow(unused)]
    pub fn not_found_handler(mut self, handler: HyperHandler) -> Self {
        self.not_found_fn = Some(handler);
        self
    }

    /// Handles the relay endpoint in a custom way.
    ///
    /// This is required if no [`SecretKey`] was provided to the builder.
    pub fn relay_override(mut self, handler: HyperHandler) -> Self {
        self.relay_override = Some(handler);
        self
    }

    /// Adds HTTP headers to responses.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        for (k, v) in headers.iter() {
            self.headers.insert(k.clone(), v.clone());
        }
        self
    }

    /// Builds and spawns an HTTP(S) Relay Server.
    pub async fn spawn(self) -> Result<Server> {
        ensure!(
            self.secret_key.is_some() || self.relay_override.is_some(),
            "Must provide a `SecretKey` for the relay server OR pass in an override function for the 'relay' endpoint"
        );
        let (relay_handler, relay_server) = if let Some(secret_key) = self.secret_key {
            // spawns a server actor/task
            let server = ServerActorTask::new(secret_key.clone());
            (
                RelayHandler::ConnHandler(server.client_conn_handler(self.headers.clone())),
                Some(server),
            )
        } else {
            (
                RelayHandler::Override(
                    self.relay_override
                        .context("no relay handler override but also no secret key")?,
                ),
                None,
            )
        };
        let h = self.headers.clone();
        let not_found_fn = match self.not_found_fn {
            Some(f) => f,
            None => Box::new(move |_req: Request<Incoming>, mut res: ResponseBuilder| {
                for (k, v) in h.iter() {
                    res = res.header(k.clone(), v.clone());
                }
                let body = body_full("Not Found");
                let r = res.status(StatusCode::NOT_FOUND).body(body)?;
                HyperResult::Ok(r)
            }),
        };

        let service = RelayService::new(self.handlers, relay_handler, not_found_fn, self.headers);

        let server_state = ServerState {
            addr: self.addr,
            tls_config: self.tls_config,
            server: relay_server,
            service,
        };

        // Spawns some server tasks, we only wait till all tasks are started.
        server_state.serve().await
    }
}

#[derive(Debug)]
struct ServerState {
    addr: SocketAddr,
    tls_config: Option<TlsConfig>,
    server: Option<ServerActorTask>,
    service: RelayService,
}

impl ServerState {
    // Binds a TCP listener on `addr` and handles content using HTTPS.
    // Returns the local [`SocketAddr`] on which the server is listening.
    async fn serve(self) -> Result<Server> {
        let ServerState {
            addr,
            tls_config,
            server,
            service,
        } = self;
        let listener = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("failed to bind server socket to {addr}"))?;
        // we will use this cancel token to stop the infinite loop in the `listener.accept() task`
        let cancel_server_loop = CancellationToken::new();
        let addr = listener.local_addr()?;
        let http_str = tls_config.as_ref().map_or("HTTP/WS", |_| "HTTPS/WSS");
        info!("[{http_str}] relay: serving on {addr}");
        let cancel = cancel_server_loop.clone();
        let task = tokio::task::spawn(async move {
            // create a join set to track all our connection tasks
            let mut set = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        break;
                    }
                    res = listener.accept() => match res {
                        Ok((stream, peer_addr)) => {
                            debug!("[{http_str}] relay: Connection opened from {peer_addr}");
                            let tls_config = tls_config.clone();
                            let service = service.clone();
                            // spawn a task to handle the connection
                            set.spawn(async move {
                                if let Err(error) = service
                                    .handle_connection(stream, tls_config)
                                    .await
                                {
                                    match error.downcast_ref::<std::io::Error>() {
                                        Some(io_error) if io_error.kind() == std::io::ErrorKind::UnexpectedEof => {
                                            debug!(reason=?error, "[{http_str}] relay: peer disconnected");
                                        },
                                        _ => {
                                            error!(?error, "[{http_str}] relay: failed to handle connection");
                                        }
                                    }
                                }
                            }.instrument(info_span!("conn", peer = %peer_addr)));
                        }
                        Err(err) => {
                            error!("[{http_str}] relay: failed to accept connection: {err}");
                        }
                    }
                }
            }
            if let Some(server) = server {
                // TODO: if the task this is running in is aborted this server is not shut
                // down.
                server.close().await;
            }
            set.shutdown().await;
            debug!("[{http_str}] relay: server has been shutdown.");
        }.instrument(info_span!("relay-http-serve")));

        Ok(Server {
            addr,
            http_server_task: AbortingJoinHandle::from(task),
            cancel_server_loop,
        })
    }
}

impl Service<Request<Incoming>> for ClientConnHandler {
    type Response = Response<BytesBody>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        // TODO: soooo much cloning. See if there is an alternative
        let closure_conn_handler = self.clone();
        let mut builder = Response::builder();
        for (key, value) in self.default_headers.iter() {
            builder = builder.header(key, value);
        }

        async move {
            {
                // Send a 400 to any request that doesn't have an `Upgrade` header.
                let Some(protocol) = req.headers().get(UPGRADE).and_then(Protocol::parse_header)
                else {
                    return Ok(builder
                        .status(StatusCode::BAD_REQUEST)
                        .body(body_empty())
                        .expect("valid body"));
                };

                let websocket_headers = if protocol == Protocol::Websocket {
                    let Some(key) = req.headers().get("Sec-WebSocket-Key").cloned() else {
                        warn!("missing header Sec-WebSocket-Key for websocket relay protocol");
                        return Ok(builder
                            .status(StatusCode::BAD_REQUEST)
                            .body(body_empty())
                            .expect("valid body"));
                    };

                    let Some(version) = req.headers().get("Sec-WebSocket-Version").cloned() else {
                        warn!("missing header Sec-WebSocket-Version for websocket relay protocol");
                        return Ok(builder
                            .status(StatusCode::BAD_REQUEST)
                            .body(body_empty())
                            .expect("valid body"));
                    };

                    if version.as_bytes() != SUPPORTED_WEBSOCKET_VERSION.as_bytes() {
                        warn!("invalid header Sec-WebSocket-Version: {:?}", version);
                        return Ok(builder
                            .status(StatusCode::BAD_REQUEST)
                            // It's convention to send back the version(s) we *do* support
                            .header("Sec-WebSocket-Version", SUPPORTED_WEBSOCKET_VERSION)
                            .body(body_empty())
                            .expect("valid body"));
                    }

                    Some((key, version))
                } else {
                    None
                };

                debug!("upgrading protocol: {:?}", protocol);

                // Setup a future that will eventually receive the upgraded
                // connection and talk a new protocol, and spawn the future
                // into the runtime.
                //
                // Note: This can't possibly be fulfilled until the 101 response
                // is returned below, so it's better to spawn this future instead
                // waiting for it to complete to then return a response.
                tokio::task::spawn(
                    async move {
                        match hyper::upgrade::on(&mut req).await {
                            Ok(upgraded) => {
                                if let Err(e) = relay_connection_handler(
                                    protocol,
                                    &closure_conn_handler,
                                    upgraded,
                                )
                                .await
                                {
                                    warn!(
                                        "upgrade to \"{}\": io error: {:?}",
                                        e,
                                        protocol.upgrade_header()
                                    );
                                } else {
                                    debug!("upgrade to \"{}\" success", protocol.upgrade_header());
                                };
                            }
                            Err(e) => warn!("upgrade error: {:?}", e),
                        }
                    }
                    .instrument(debug_span!("handler")),
                );

                // Now return a 101 Response saying we agree to the upgrade to the
                // HTTP_UPGRADE_PROTOCOL
                builder = builder
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header(UPGRADE, HeaderValue::from_static(protocol.upgrade_header()));

                if let Some((key, _version)) = websocket_headers {
                    Ok(builder
                        .header("Sec-WebSocket-Accept", &derive_accept_key(key.as_bytes()))
                        .header(CONNECTION, "upgrade")
                        .body(body_full("switching to websocket protocol"))
                        .expect("valid body"))
                } else {
                    Ok(builder.body(body_empty()).expect("valid body"))
                }
            }
        }
        .boxed()
    }
}

impl Service<Request<Incoming>> for RelayService {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        // if the request hits the relay endpoint
        // or /derp for backwards compat
        if matches!(
            (req.method(), req.uri().path()),
            (&hyper::Method::GET, LEGACY_RELAY_PATH | RELAY_PATH)
        ) {
            match &self.0.relay_handler {
                RelayHandler::Override(f) => {
                    // see if we have some override response
                    let res = f(req, self.0.default_response());
                    return Box::pin(async move { res });
                }
                RelayHandler::ConnHandler(handler) => {
                    let h = handler.clone();
                    // otherwise handle the relay connection as normal
                    return Box::pin(async move { h.call(req).await.map_err(Into::into) });
                }
            }
        }
        // check all other possible endpoints
        let uri = req.uri().clone();
        if let Some(res) = self.0.handlers.get(&(req.method().clone(), uri.path())) {
            let f = res(req, self.0.default_response());
            return Box::pin(async move { f });
        }
        // otherwise return 404
        let res = (self.0.not_found_fn)(req, self.0.default_response());
        Box::pin(async move { res })
    }
}

/// The hyper Service that servers the actual relay endpoints
#[derive(Clone, Debug)]
struct RelayService(Arc<Inner>);

#[derive(derive_more::Debug)]
struct Inner {
    pub relay_handler: RelayHandler,
    #[debug("Box<Fn(ResponseBuilder) -> Result<Response<BytesBody>> + Send + Sync + 'static>")]
    pub not_found_fn: HyperHandler,
    pub handlers: Handlers,
    pub headers: HeaderMap,
}

/// Action to take when a connection is made at the relay endpoint.`
#[derive(derive_more::Debug)]
enum RelayHandler {
    /// Pass the connection to a [`ClientConnHandler`] to get added to the relay server. The default.
    ConnHandler(ClientConnHandler),
    /// Return some static response. Used when the http(s) should be running, but the relay portion
    /// of the server is disabled.
    // TODO: Can we remove this debug override?
    Override(
        #[debug(
            "{}",
            "Box<Fn(Request<Incoming>, ResponseBuilder) -> Result<Response<BytesBody> + Send + Sync + 'static>"
        )]
        HyperHandler,
    ),
}

impl Inner {
    fn default_response(&self) -> ResponseBuilder {
        let mut response = Response::builder();
        for (key, value) in self.headers.iter() {
            response = response.header(key.clone(), value.clone());
        }
        response
    }
}

/// TLS Certificate Authority acceptor.
#[derive(Clone, derive_more::Debug)]
pub enum TlsAcceptor {
    /// Uses Let's Encrypt as the Certificate Authority. This is used in production.
    LetsEncrypt(#[debug("tokio_rustls_acme::AcmeAcceptor")] AcmeAcceptor),
    /// Manually added tls acceptor. Generally used for tests or for when we've passed in
    /// a certificate via a file.
    Manual(#[debug("tokio_rustls::TlsAcceptor")] tokio_rustls::TlsAcceptor),
}

impl RelayService {
    fn new(
        handlers: Handlers,
        relay_handler: RelayHandler,
        not_found_fn: HyperHandler,
        headers: HeaderMap,
    ) -> Self {
        Self(Arc::new(Inner {
            relay_handler,
            handlers,
            not_found_fn,
            headers,
        }))
    }

    /// Handle the incoming connection.
    ///
    /// If a `tls_config` is given, will serve the connection using HTTPS.
    async fn handle_connection(
        self,
        stream: TcpStream,
        tls_config: Option<TlsConfig>,
    ) -> Result<()> {
        match tls_config {
            Some(tls_config) => self.tls_serve_connection(stream, tls_config).await,
            None => {
                debug!("HTTP: serve connection");
                self.serve_connection(MaybeTlsStream::Plain(stream)).await
            }
        }
    }

    /// Serve the tls connection
    async fn tls_serve_connection(self, stream: TcpStream, tls_config: TlsConfig) -> Result<()> {
        let TlsConfig { acceptor, config } = tls_config;
        match acceptor {
            TlsAcceptor::LetsEncrypt(a) => match a.accept(stream).await? {
                None => {
                    info!("TLS[acme]: received TLS-ALPN-01 validation request");
                }
                Some(start_handshake) => {
                    debug!("TLS[acme]: start handshake");
                    let tls_stream = start_handshake
                        .into_stream(config)
                        .await
                        .context("TLS[acme] handshake")?;
                    self.serve_connection(MaybeTlsStream::Tls(tls_stream))
                        .await
                        .context("TLS[acme] serve connection")?;
                }
            },
            TlsAcceptor::Manual(a) => {
                debug!("TLS[manual]: accept");
                let tls_stream = a.accept(stream).await.context("TLS[manual] accept")?;
                self.serve_connection(MaybeTlsStream::Tls(tls_stream))
                    .await
                    .context("TLS[manual] serve connection")?;
            }
        }
        Ok(())
    }

    /// Wrapper for the actual http connection (with upgrades)
    async fn serve_connection<I>(self, io: I) -> Result<()>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(io), self)
            .with_upgrades()
            .await?;
        Ok(())
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

    use anyhow::Result;
    use bytes::Bytes;
    use reqwest::Url;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tracing::{info, info_span, Instrument};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use crate::key::{PublicKey, SecretKey};
    use crate::relay::client::conn::ReceivedMessage;
    use crate::relay::client::{Client, ClientBuilder};

    use super::*;

    pub(crate) fn make_tls_config() -> TlsConfig {
        let subject_alt_names = vec!["localhost".to_string()];

        let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
        let rustls_certificate =
            rustls::pki_types::CertificateDer::from(cert.serialize_der().unwrap());
        let rustls_key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.get_key_pair().serialize_der());
        let rustls_key = rustls::pki_types::PrivateKeyDer::from(rustls_key);
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocols supported by ring")
        .with_no_client_auth()
        .with_single_cert(vec![(rustls_certificate)], rustls_key)
        .expect("cert is right");

        let config = Arc::new(config);
        let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());

        TlsConfig {
            config,
            acceptor: TlsAcceptor::Manual(acceptor),
        }
    }

    #[tokio::test]
    async fn test_http_clients_and_server() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let server_key = SecretKey::generate();
        let a_key = SecretKey::generate();
        let b_key = SecretKey::generate();

        // start server
        let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(server_key))
            .spawn()
            .await?;

        let addr = server.addr();

        // get dial info
        let port = addr.port();
        let addr = {
            if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
                ipv4_addr
            } else {
                anyhow::bail!("cannot get ipv4 addr from socket addr {addr:?}");
            }
        };
        info!("addr: {addr}:{port}");
        let relay_addr: Url = format!("http://{addr}:{port}").parse().unwrap();

        // create clients
        let (a_key, mut a_recv, client_a_task, client_a) = {
            let span = info_span!("client-a");
            let _guard = span.enter();
            create_test_client(a_key, relay_addr.clone())
        };
        info!("created client {a_key:?}");
        let (b_key, mut b_recv, client_b_task, client_b) = {
            let span = info_span!("client-b");
            let _guard = span.enter();
            create_test_client(b_key, relay_addr)
        };
        info!("created client {b_key:?}");

        info!("ping a");
        client_a.ping().await?;

        info!("ping b");
        client_b.ping().await?;

        info!("sending message from a to b");
        let msg = Bytes::from_static(b"hi there, client b!");
        client_a.send(b_key, msg.clone()).await?;
        info!("waiting for message from a on b");
        let (got_key, got_msg) = b_recv.recv().await.expect("expected message from client_a");
        assert_eq!(a_key, got_key);
        assert_eq!(msg, got_msg);

        info!("sending message from b to a");
        let msg = Bytes::from_static(b"right back at ya, client b!");
        client_b.send(a_key, msg.clone()).await?;
        info!("waiting for message b on a");
        let (got_key, got_msg) = a_recv.recv().await.expect("expected message from client_b");
        assert_eq!(b_key, got_key);
        assert_eq!(msg, got_msg);

        client_a.close().await?;
        client_a_task.abort();
        client_b.close().await?;
        client_b_task.abort();
        server.shutdown();

        Ok(())
    }

    fn create_test_client(
        key: SecretKey,
        server_url: Url,
    ) -> (
        PublicKey,
        mpsc::Receiver<(PublicKey, Bytes)>,
        JoinHandle<()>,
        Client,
    ) {
        let client = ClientBuilder::new(server_url).insecure_skip_cert_verify(true);
        let dns_resolver = crate::dns::default_resolver();
        let (client, mut client_reader) = client.build(key.clone(), dns_resolver.clone());
        let public_key = key.public();
        let (received_msg_s, received_msg_r) = tokio::sync::mpsc::channel(10);
        let client_reader_task = tokio::spawn(
            async move {
                loop {
                    info!("waiting for message on {:?}", key.public());
                    match client_reader.recv().await {
                        None => {
                            info!("client received nothing");
                            return;
                        }
                        Some(Err(e)) => {
                            info!("client {:?} `recv` error {e}", key.public());
                            return;
                        }
                        Some(Ok((msg, _))) => {
                            info!("got message on {:?}: {msg:?}", key.public());
                            if let ReceivedMessage::ReceivedPacket { source, data } = msg {
                                received_msg_s
                                    .send((source, data))
                                    .await
                                    .unwrap_or_else(|err| {
                                        panic!(
                                            "client {:?}, error sending message over channel: {:?}",
                                            key.public(),
                                            err
                                        )
                                    });
                            }
                        }
                    }
                }
            }
            .instrument(info_span!("test-client-reader")),
        );
        (public_key, received_msg_r, client_reader_task, client)
    }

    #[tokio::test]
    async fn test_https_clients_and_server() -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();

        let server_key = SecretKey::generate();
        let a_key = SecretKey::generate();
        let b_key = SecretKey::generate();

        // create tls_config
        let tls_config = make_tls_config();

        // start server
        let mut server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(server_key))
            .tls_config(Some(tls_config))
            .spawn()
            .await?;

        let addr = server.addr();

        // get dial info
        let port = addr.port();
        let addr = {
            if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
                ipv4_addr
            } else {
                anyhow::bail!("cannot get ipv4 addr from socket addr {addr:?}");
            }
        };
        info!("Relay listening on: {addr}:{port}");

        let url: Url = format!("https://localhost:{port}").parse().unwrap();

        // create clients
        let (a_key, mut a_recv, client_a_task, client_a) = create_test_client(a_key, url.clone());
        info!("created client {a_key:?}");
        let (b_key, mut b_recv, client_b_task, client_b) = create_test_client(b_key, url);
        info!("created client {b_key:?}");

        client_a.ping().await?;
        client_b.ping().await?;

        info!("sending message from a to b");
        let msg = Bytes::from_static(b"hi there, client b!");
        client_a.send(b_key, msg.clone()).await?;
        info!("waiting for message from a on b");
        let (got_key, got_msg) = b_recv.recv().await.expect("expected message from client_a");
        assert_eq!(a_key, got_key);
        assert_eq!(msg, got_msg);

        info!("sending message from b to a");
        let msg = Bytes::from_static(b"right back at ya, client b!");
        client_b.send(a_key, msg.clone()).await?;
        info!("waiting for message b on a");
        let (got_key, got_msg) = a_recv.recv().await.expect("expected message from client_b");
        assert_eq!(b_key, got_key);
        assert_eq!(msg, got_msg);

        server.shutdown();
        server.task_handle().await?;
        client_a.close().await?;
        client_a_task.abort();
        client_b.close().await?;
        client_b_task.abort();
        Ok(())
    }
}
