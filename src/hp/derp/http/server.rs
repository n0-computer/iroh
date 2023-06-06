use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{bail, ensure, Context as _, Result};
use bytes::Bytes;
use derive_more::Debug;
use futures::future::{Future, FutureExt};
use http::response::Builder as ResponseBuilder;
use hyper::{
    header::{HeaderValue, UPGRADE},
    server::conn::Http,
    upgrade::Upgraded,
    Body, HeaderMap, Method, Request, Response, StatusCode,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls_acme::AcmeAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::HTTP_UPGRADE_PROTOCOL;
use crate::hp::{
    derp::{
        http::client::Client as HttpClient, server::ClientConnHandler, server::MaybeTlsStream,
        types::MeshKey, types::PacketForwarder, MaybeTlsStreamServer,
    },
    key::node::SecretKey,
};

type HyperError = Box<dyn std::error::Error + Send + Sync>;
type HyperResult<T> = std::result::Result<T, HyperError>;

fn downcast_upgrade(upgraded: Upgraded) -> Result<(MaybeTlsStream, Bytes)> {
    match upgraded.downcast::<MaybeTlsStream>() {
        Ok(parts) => Ok((parts.io, parts.read_buf)),
        Err(_) => {
            bail!("could not downcast the upgraded connection to MaybeTlsStream")
        }
    }
}

/// The server HTTP handler to do HTTP upgrades
async fn derp_connection_handler<P>(
    conn_handler: &ClientConnHandler<P>,
    upgraded: Upgraded,
) -> Result<()>
where
    P: PacketForwarder,
{
    debug!("derp_connection upgraded");
    let (io, read_buf) = downcast_upgrade(upgraded)?;
    ensure!(
        read_buf.is_empty(),
        "can not deal with buffered data yet: {:?}",
        read_buf
    );

    conn_handler.accept(io).await
}

#[derive(Debug)]
/// A Derp Server handler. Created using `Server::Builder::spawn`, it starts a derp server
/// listening over HTTP or HTTPS.
pub struct Server {
    addr: SocketAddr,
    server: Option<crate::hp::derp::server::Server<HttpClient>>,
    http_server_task: JoinHandle<()>,
    cancel: CancellationToken,
}

impl Server {
    /// Close the underlying derp server and the HTTP(S) server task
    pub async fn shutdown(self) {
        if let Some(server) = self.server {
            server.close().await;
        }
        self.cancel.cancel();
        self.http_server_task.abort();
    }

    /// Get the local address of this server.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Configuration to use for the TLS connection
#[derive(Debug)]
pub struct TlsConfig {
    /// The server config
    pub config: Arc<rustls::ServerConfig>,
    /// The kind
    pub acceptor: TlsAcceptor,
}

/// Build a Derp Server that communicates over HTTP or HTTPS, on a given address.
///
/// Defaults to handling "derp" requests on the "/derp" endpoint.
///
/// If no `SecretKey` is provided, it is assumed that you will provide a `derp_override` function
/// that handles requests to the derp endpoint. Not providing a `derp_override` in this case will
/// result in an error on `spawn`.
pub struct ServerBuilder {
    /// The SecretKey for this Server.
    ///
    /// When `None`, you must also provide a `derp_override` function that
    /// will be run when someone hits the derp endpoint.
    secret_key: Option<SecretKey>,
    /// The ip + port combination for this server.
    addr: SocketAddr,
    /// Optional MeshKey for this server. When it exists it will ensure that This
    /// server will only mesh with other servers with the same key.
    mesh_key: Option<MeshKey>,
    /// Optional tls configuration/TlsAcceptor combination.
    ///
    /// When `None`, the server will serve HTTP, otherwise it will serve HTTPS.
    tls_config: Option<TlsConfig>,
    /// A map of request handlers to routes. Used when certain routes in your server should be made
    /// available at the same port as the derp server, and so must be handled along side requests
    /// to the derp endpoint.
    handlers: Handlers,
    /// Defaults to `GET` request at "/derp".
    derp_endpoint: &'static str,
    /// Use a custom derp response handler. Typically used when you want to disable any derp connections.
    derp_override: Option<HyperFn>,
    /// Headers to use for HTTP or HTTPS messages.
    headers: Headers,
    /// 404 not found response
    ///
    /// When `None`, a default is provided.
    not_found_fn: Option<HyperFn>,
}

impl ServerBuilder {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            secret_key: None,
            addr,
            mesh_key: None,
            tls_config: None,
            handlers: Default::default(),
            derp_endpoint: "/derp",
            derp_override: None,
            headers: Vec::new(),
            not_found_fn: None,
        }
    }

    /// The SecretKey identity for this derp server. When set to `None`, the builder assumes
    /// you do not want to run a derp service.
    pub fn secret_key(mut self, secret_key: Option<SecretKey>) -> Self {
        self.secret_key = secret_key;
        self
    }

    /// The MeshKey for the mesh network this server belongs to.
    pub fn mesh_key(mut self, mesh_key: Option<MeshKey>) -> Self {
        self.mesh_key = mesh_key;
        self
    }

    /// Serve derp content using TLS.
    pub fn tls_config(mut self, config: Option<TlsConfig>) -> Self {
        self.tls_config = config;
        self
    }

    /// Add a custom handler for a specific Method & URI.
    pub fn request_handler(
        mut self,
        method: Method,
        uri_path: &'static str,
        handler: HyperFn,
    ) -> Self {
        self.handlers.insert((method, uri_path), handler);
        self
    }

    /// Pass in a custom "404" handler.
    pub fn not_found_handler(mut self, handler: HyperFn) -> Self {
        self.not_found_fn = Some(handler);
        self
    }

    /// Handle the derp endpoint in a custom way. This is required if no `SecretKey` was provided
    /// to the builder.
    pub fn derp_override(mut self, handler: HyperFn) -> Self {
        self.derp_override = Some(handler);
        self
    }

    /// Change the derp endpoint from "/derp" to `endpoint`.
    pub fn derp_endpoint(mut self, endpoint: &'static str) -> Self {
        self.derp_endpoint = endpoint;
        self
    }

    /// Add http headers.
    pub fn headers(mut self, headers: Headers) -> Self {
        self.headers = headers;
        self
    }

    /// Build and spawn an HTTP(S) derp Server
    pub async fn spawn(self) -> Result<Server> {
        ensure!(self.secret_key.is_some() || self.derp_override.is_some(), "Must provide a `SecretKey` for the derp server OR pass in an override function for the 'derp' endpoint");
        let (derp_handler, derp_server) = if let Some(secret_key) = self.secret_key {
            let server = crate::hp::derp::server::Server::new(secret_key, self.mesh_key);
            println!("headers: {:?}", self.headers);
            let header_map: HeaderMap = HeaderMap::from_iter(
                self.headers
                    .iter()
                    .map(|(k, v)| (k.parse().unwrap(), v.parse().unwrap())),
            );

            (
                DerpHandler::ConnHandler(server.client_conn_handler(header_map)),
                Some(server),
            )
        } else {
            (DerpHandler::Override(self.derp_override.unwrap()), None)
        };
        let h = self.headers.clone();
        let not_found_fn = match self.not_found_fn {
            Some(f) => f,
            None => Box::new(move |mut res: ResponseBuilder| {
                for (k, v) in h.iter() {
                    res = res.header(*k, *v);
                }
                let r = res
                    .status(StatusCode::NOT_FOUND)
                    .body(b"Not Found"[..].into())
                    .unwrap();
                HyperResult::Ok(r)
            }),
        };

        let service = DerpService::new(
            self.handlers,
            derp_handler,
            self.derp_endpoint,
            not_found_fn,
            self.headers,
        );

        let server_state = ServerState {
            addr: self.addr,
            tls_config: self.tls_config,
            server: derp_server,
            service,
        };

        server_state.serve().await
    }
}

impl std::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hyper_fn =
            "Some(Box<dyn Fn(ResponseBuilder) -> HyperResult<Response<Body>> + Send + Sync + 'static)";
        let derp_override = if let Some(_) = self.derp_override {
            hyper_fn
        } else {
            "None"
        };

        let not_found_fn = if let Some(_) = self.not_found_fn {
            hyper_fn
        } else {
            "None"
        };

        write!(f, "ServerBuilder {{ secret_key: {:?}, addr: {:?}, mesh_key: {:?}, tls_config: {:?}, handlers: {:?}, derp_endpoint: {:?}, derp_override: {derp_override}, headers: {:?}, not_found_fn: {not_found_fn}  }}", self.secret_key, self.addr, self.mesh_key, self.tls_config, self.handlers, self.derp_endpoint, self.headers)
    }
}

#[derive(Debug)]
pub struct ServerState {
    addr: SocketAddr,
    tls_config: Option<TlsConfig>,
    server: Option<crate::hp::derp::server::Server<HttpClient>>,
    service: DerpService,
}

impl ServerState {
    async fn serve(self) -> Result<Server> {
        match &self.tls_config {
            Some(_) => self.https_serve().await,
            None => self.http_serve().await,
        }
    }

    /// Binds a TCP listener on `addr` and handles content using HTTP.
    /// Returns the local `SocketAddr` on which the server is listening.
    async fn http_serve(self) -> Result<Server> {
        let http_listener = TcpListener::bind(&self.addr)
            .await
            .context("failed to bind https")?;
        let addr = http_listener.local_addr()?;
        let cancel = CancellationToken::new();
        info!("[HTTP] derp: serving on {addr}");
        let c = cancel.clone();
        let task = tokio::task::spawn(async move {
            debug!("about to loop");
            loop {
                match http_listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        debug!("[HTTP] derp: Connection opened from {}", peer_addr);
                        let service = self.service.clone();
                        let cancel = c.clone();
                        tokio::task::spawn(async move {
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => {
                                    warn!("[HTTP] derp: shutting down connection...");
                                }
                                res = service
                                .serve_connection(MaybeTlsStreamServer::Plain(stream))
                            => {
                                if let Err(err) = res {error!("[HTTP] derp: failed to serve connection: {:?}", err);
                                }
                            }
                            }
                        });
                    }
                    Err(err) => {
                        error!("[HTTP] derp: failed to accept connection: {:#?}", err);
                    }
                }
                error!("DONE");
            }
        });
        Ok(Server {
            addr,
            server: self.server,
            http_server_task: task,
            cancel,
        })
    }

    // Binds a TCP listener on `addr` and handles content using HTTPS.
    // Returns the local `SocketAddr` on which the server is listening.
    async fn https_serve(self) -> Result<Server> {
        ensure!(self.tls_config.is_some());
        let TlsConfig {
            config, acceptor, ..
        } = self.tls_config.unwrap();
        let https_listener = TcpListener::bind(&self.addr)
            .await
            .context("failed to bind https")?;
        let cancel = CancellationToken::new();
        let addr = https_listener.local_addr()?;
        info!("[HTTPS] derp: serving on {addr}");
        let c = cancel.clone();
        let task = tokio::task::spawn(async move {
            loop {
                match https_listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        debug!("[HTTPS] derp: Connection opened from {}", peer_addr);
                        let tls_acceptor = acceptor.clone();
                        let tls_config = config.clone();
                        let service = self.service.clone();
                        let cancel = c.clone();
                        tokio::task::spawn(async move {
                            tokio::select! {
                                    biased;
                                    _ = cancel.cancelled() => {
                                        warn!("[HTTPS] derp: shutting down connection...");
                                    }
                                    res = service.tls_serve_connection(stream, tls_acceptor, tls_config)
                                => {
                                    if let Err(err) = res {
                                    error!("[HTTPS] derp: failed to serve connection: {:?}", err);
                                    }
                                }
                            }
                        });
                    }
                    Err(err) => {
                        error!("[HTTPS] derp: failed to accept connection: {:#?}", err);
                    }
                }
            }
        });
        Ok(Server {
            addr,
            server: self.server,
            http_server_task: task,
            cancel,
        })
    }
}

impl<P> hyper::service::Service<Request<Body>> for ClientConnHandler<P>
where
    P: PacketForwarder,
{
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // TODO: soooo much cloning. See if there is an alternative
        let closure_conn_handler = self.clone();
        let mut builder = Response::builder();
        for (key, value) in self.default_headers.iter() {
            builder = builder.header(key, value);
        }

        async move {
            {
                let mut res = builder.body(Body::empty()).unwrap();

                // Send a 400 to any request that doesn't have an `Upgrade` header.
                if !req.headers().contains_key(UPGRADE) {
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(res);
                }

                // Setup a future that will eventually receive the upgraded
                // connection and talk a new protocol, and spawn the future
                // into the runtime.
                //
                // Note: This can't possibly be fulfilled until the 101 response
                // is returned below, so it's better to spawn this future instead
                // waiting for it to complete to then return a response.
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(&mut req).await {
                        Ok(upgraded) => {
                            if let Err(e) =
                                derp_connection_handler(&closure_conn_handler, upgraded).await
                            {
                                tracing::warn!(
                                    "server \"{HTTP_UPGRADE_PROTOCOL}\" io error: {:?}",
                                    e
                                )
                            };
                        }
                        Err(e) => tracing::warn!("upgrade error: {:?}", e),
                    }
                });

                // Now return a 101 Response saying we agree to the upgrade to the
                // HTTP_UPGRADE_PROTOCOL
                *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                res.headers_mut()
                    .insert(UPGRADE, HeaderValue::from_static(HTTP_UPGRADE_PROTOCOL));
                Ok(res)
            }
        }
        .boxed()
    }
}

impl hyper::service::Service<Request<Body>> for DerpService {
    type Response = Response<Body>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // if the request hits the derp endpoint
        if req.method() == &hyper::Method::GET && req.uri().path() == self.0.derp_endpoint {
            match &self.0.derp_handler {
                DerpHandler::Override(f) => {
                    // see if we have some override response
                    let res = f(self.0.default_response());
                    return Box::pin(async move { res });
                }
                DerpHandler::ConnHandler(handler) => {
                    let mut h = handler.clone();
                    // otherwise handle the derp connection as normal
                    return Box::pin(async move { h.call(req).await.map_err(Into::into) });
                }
            }
        }
        // check all other possible endpoints
        if let Some(res) = self
            .0
            .handlers
            .get(&(req.method().clone(), req.uri().path()))
        {
            let f = res(self.0.default_response());
            return Box::pin(async move { f });
        }
        // otherwise return 404
        let res = (self.0.not_found_fn)(self.0.default_response());
        Box::pin(async move { res })
    }
}

#[derive(Clone)]
/// The hyper Service that
struct DerpService(Arc<Inner>);

type HyperFn = Box<dyn Fn(ResponseBuilder) -> HyperResult<Response<Body>> + Send + Sync + 'static>;
type Headers = Vec<(&'static str, &'static str)>;

struct Inner {
    pub derp_handler: DerpHandler,
    pub derp_endpoint: &'static str,
    pub not_found_fn: HyperFn,
    pub handlers: Handlers,
    pub headers: Headers,
}

/// Action to take when a connection is made at the derp endpoint.`
enum DerpHandler {
    /// Pass the connection to a ClientConnHandler to get added to the derp server. The default.
    ConnHandler(ClientConnHandler<crate::hp::derp::http::Client>),
    /// Return some static response. Used when the http(s) should be running, but the derp portion
    /// of the server is disabled.
    Override(HyperFn),
}

impl std::fmt::Debug for DerpHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DerpHandler::ConnHandler(_) => write!(
                f,
                "DerpHandler::ConnHandler(ClientConnHandler<HttpDerpClient>)"
            ),
            DerpHandler::Override(_) => write!(
                f,
                "DerpHandler::Override(Box<dyn Fn(ResponseBuilder) -> HyperResult<Response<Body>>)"
            ),
        }
    }
}

impl Inner {
    fn default_response(&self) -> ResponseBuilder {
        let mut response = Response::builder();
        for (key, value) in self.headers.iter() {
            response = response.header(*key, *value);
        }
        response
    }
}

#[derive(Clone)]
/// TLS Certificate Authority acceptor.
pub enum TlsAcceptor {
    /// Uses Let's Encrypt as the Certificate Authority. This is used in production.
    LetsEncrypt(AcmeAcceptor),
    /// Manually added tls acceptor. Generally used for tests or for when we've passed in
    /// a certificate via a file.
    Manual(tokio_rustls::TlsAcceptor),
}

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsAcceptor::LetsEncrypt(_) => write!(f, "TlsAcceptor::LetsEncrypt"),
            TlsAcceptor::Manual(_) => write!(f, "TlsAcceptor::Manual"),
        }
    }
}

impl DerpService {
    fn new(
        handlers: Handlers,
        derp_handler: DerpHandler,
        derp_endpoint: &'static str,
        not_found_fn: HyperFn,
        headers: Headers,
    ) -> Self {
        Self(Arc::new(Inner {
            derp_handler,
            handlers,
            derp_endpoint,
            not_found_fn,
            headers,
        }))
    }

    /// Serve the tls connection
    async fn tls_serve_connection(
        self,
        stream: TcpStream,
        acceptor: TlsAcceptor,
        rustls_config: Arc<rustls::ServerConfig>,
    ) -> Result<()> {
        match acceptor {
            TlsAcceptor::LetsEncrypt(a) => match a.accept(stream).await? {
                None => {
                    info!("received TLS-ALPN-01 validation request");
                }
                Some(start_handshake) => {
                    let tls_stream = start_handshake.into_stream(rustls_config).await?;
                    self.serve_connection(MaybeTlsStreamServer::Tls(tls_stream))
                        .await?;
                }
            },
            TlsAcceptor::Manual(a) => {
                let tls_stream = a.accept(stream).await?;
                self.serve_connection(MaybeTlsStreamServer::Tls(tls_stream))
                    .await?;
            }
        }
        Ok(())
    }

    /// Wrapper for the actual http connection (with upgrades)
    async fn serve_connection<I>(self, io: I) -> Result<()>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        Http::new()
            .serve_connection(io, self)
            .with_upgrades()
            .await?;
        Ok(())
    }
}

#[derive(Default)]
struct Handlers(pub HashMap<(Method, &'static str), HyperFn>);

impl std::fmt::Debug for Handlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0.keys().fold(String::new(), |curr, next| {
            let (method, uri) = next;
            format!("{curr}\n({method},{uri}): Fn -> HyperResult<Response<Body>>")
        });
        write!(f, "HashMap<{s}>")
    }
}

impl std::ops::Deref for Handlers {
    type Target = HashMap<(Method, &'static str), HyperFn>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Handlers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::Debug for DerpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DerpServer {{ handlers: {:?}, derp_endpoint: {:?}, derp_handler: {:?}, not_found_fn: Fn -> HyperResult<Response<Body>> }}", self.0.handlers, self.0.derp_endpoint, self.0.derp_handler)
    }
}
