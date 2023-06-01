use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{bail, ensure, Context as _, Result};
use bytes::Bytes;
use futures::future::{FutureExt, Join};
use futures::Future;
use http::response::Builder as ResponseBuilder;
use hyper::header::{HeaderValue, UPGRADE};
use hyper::server::conn::Http;
use hyper::upgrade::Upgraded;
use hyper::{Body, HeaderMap, Method, Request, Response, StatusCode};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls_acme::AcmeAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use super::HTTP_UPGRADE_PROTOCOL;
use crate::hp::derp::MaybeTlsStreamServer;
use crate::hp::derp::{
    http::client::Client as HttpClient, server::ClientConnHandler, types::PacketForwarder,
};
use crate::hp::derp::{server::MaybeTlsStream, types::MeshKey};
use crate::hp::key::node::SecretKey;
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
pub async fn derp_connection_handler<P>(
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

#[derive(Debug)]
/// A Derp Server that binds on a TCP socket & can serve content over
/// HTTP or HTTPS.
pub struct Server(Inner);

impl Server {
    // Handle requests to the Derp Server. If there is a `TlsConfig`, this method will serve
    // requests over HTTPS, otherwise it will be served over HTTP.
    //
    // The `serve` method returns the local `SocketAddr` on which the server is listening.
    pub async fn serve(self) -> Result<SocketAddr> {
        match self.0.tls_config {
            Some(_) => self.0.https_serve().await,
            None => self.0.http_serve().await,
        }
    }

    //     pub async fn shutdown(self) {
    //         self.0.shutdown().await;
    //     }
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
pub struct ServerBuilder {
    /// The SecretKey for this Server. If `None`, you must provide a `derp_override` function that
    /// will be run when someone hits the derp endpoint.
    pub secret_key: Option<SecretKey>,
    /// The ip + port combination for this server.
    pub addr: SocketAddr,
    /// Optional MeshKey for this server. When it exists it will ensure that This
    /// server will only mesh with other servers with the same key.
    pub mesh_key: Option<MeshKey>,
    /// Optional tls configuration/TlsAcceptor combination.
    ///
    /// When `None`, the server will serve HTTP, otherwise it will serve HTTPS.
    pub tls_config: Option<TlsConfig>,
    /// A map of handlers to routes.
    pub handlers: HashMap<(Method, &'static str), HyperFn>,
    /// Defaults to "/derp". Expects the HTTP request to be a `GET` request.
    pub derp_endpoint: &'static str,
    /// Use a custom derp response handler. Typically used when you want to disable any derp connections.
    pub derp_override: Option<HyperFn>,
    /// Headers to use for HTTP or HTTPS messages.
    pub headers: Headers,
    /// 404 not found response
    pub not_found_fn: Option<HyperFn>,
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

    /// The SecretKey identity for this derp server.
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

    /// Handle the derp endpoint in a custom way.
    pub fn derp_override(mut self, handler: HyperFn) -> Self {
        self.derp_override = Some(handler);
        self
    }

    /// Change the derp endpoint from "/derp" to `endpoint`.
    pub fn derp_endpoint(mut self, endpoint: &'static str) -> Self {
        self.derp_endpoint = endpoint;
        self
    }

    /// Add http headers
    pub fn headers(mut self, headers: Headers) -> Self {
        self.headers = headers;
        self
    }

    /// Build an HTTP(S) derp Server
    pub fn build(self) -> Result<Server> {
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
            Handlers(self.handlers),
            derp_handler,
            self.derp_endpoint,
            not_found_fn,
            self.headers,
        );
        Ok(Server(Inner {
            addr: self.addr,
            tls_config: self.tls_config,
            server: derp_server,
            service,
            tasks: JoinSet::new(),
            server_task: JoinSet::new(),
        }))
    }
}

#[derive(Debug)]
pub struct Inner {
    addr: SocketAddr,
    tls_config: Option<TlsConfig>,
    server: Option<crate::hp::derp::server::Server<HttpClient>>,
    service: DerpService,
    tasks: JoinSet<()>,
    server_task: JoinSet<()>,
}

impl Inner {
    /// Binds a TCP listener on `addr` and handles content using HTTP.
    /// Returns the local `SocketAddr` on which the server is listening.
    async fn http_serve(mut self) -> Result<SocketAddr> {
        let http_listener = TcpListener::bind(&self.addr)
            .await
            .context("failed to bind https")?;
        let addr = http_listener.local_addr()?;
        info!("[HTTP] derp: serving on {addr}");
        tokio::task::spawn(async move {
            debug!("about to loop");
            loop {
                match http_listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        debug!("[HTTP] derp: Connection opened from {}", peer_addr);
                        let service = self.service.clone();
                        self.tasks.spawn(async move {
                            if let Err(err) = service
                                .serve_connection(MaybeTlsStreamServer::Plain(stream))
                                .await
                            {
                                error!("[HTTP] derp: failed to serve connection: {:?}", err);
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
        Ok(addr)
    }

    // Binds a TCP listener on `addr` and handles content using HTTPS.
    // Returns the local `SocketAddr` on which the server is listening.
    async fn https_serve(mut self) -> Result<SocketAddr> {
        ensure!(self.tls_config.is_some());
        let TlsConfig {
            config, acceptor, ..
        } = self.tls_config.unwrap();
        let https_listener = TcpListener::bind(&self.addr)
            .await
            .context("failed to bind https")?;
        let addr = https_listener.local_addr()?;
        info!("[HTTPS] derp: serving on {addr}");
        self.server_task.spawn(async move {
            loop {
                match https_listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        debug!("[HTTPS] derp: Connection opened from {}", peer_addr);
                        let tls_acceptor = acceptor.clone();
                        let tls_config = config.clone();
                        let service = self.service.clone();
                        self.tasks.spawn(async move {
                            if let Err(err) = service
                                .tls_serve_connection(stream, tls_acceptor, tls_config)
                                .await
                            {
                                error!("[HTTPS] derp: failed to serve connection: {:?}", err);
                            }
                        });
                    }
                    Err(err) => {
                        error!("[HTTPS] derp: failed to accept connection: {:#?}", err);
                    }
                }
            }
        });
        Ok(addr)
    }

    async fn shutdown(mut self) {
        match self.server {
            Some(s) => s.close().await,
            None => {}
        }
        self.server_task.shutdown().await;
        self.tasks.shutdown().await;
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
        if req.method() == &hyper::Method::GET && req.uri().path() == self.inner.derp_endpoint {
            match &self.inner.derp_handler {
                DerpHandler::Override(f) => {
                    // see if we have some override response
                    let res = f(self.inner.default_response());
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
            .inner
            .handlers
            .get(&(req.method().clone(), req.uri().path()))
        {
            let f = res(self.inner.default_response());
            return Box::pin(async move { f });
        }
        // otherwise return 404
        let res = (self.inner.not_found_fn)(self.inner.default_response());
        Box::pin(async move { res })
    }
}

#[derive(Clone)]
struct DerpService {
    pub inner: Arc<InnerService>,
}

type HyperFn = Box<dyn Fn(ResponseBuilder) -> HyperResult<Response<Body>> + Send + Sync + 'static>;
type Headers = Vec<(&'static str, &'static str)>;

struct InnerService {
    pub derp_handler: DerpHandler,
    pub derp_endpoint: &'static str,
    pub not_found_fn: HyperFn,
    pub handlers: Handlers,
    pub headers: Headers,
}

enum DerpHandler {
    ConnHandler(ClientConnHandler<crate::hp::derp::http::Client>),
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

impl InnerService {
    fn default_response(&self) -> ResponseBuilder {
        let mut response = Response::builder();
        for (key, value) in self.headers.iter() {
            response = response.header(*key, *value);
        }
        response
    }
}

#[derive(Clone)]
pub enum TlsAcceptor {
    LetsEncrypt(AcmeAcceptor),
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
    pub(crate) fn new(
        handlers: Handlers,
        derp_handler: DerpHandler,
        derp_endpoint: &'static str,
        not_found_fn: HyperFn,
        headers: Headers,
    ) -> Self {
        Self {
            inner: Arc::new(InnerService {
                derp_handler,
                handlers,
                derp_endpoint,
                not_found_fn,
                headers,
            }),
        }
    }

    pub(crate) async fn tls_serve_connection(
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

pub(crate) struct Handlers(pub HashMap<(Method, &'static str), HyperFn>);

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
        write!(f, "DerpServer {{ handlers: {:?}, derp_endpoint: {:?}, derp_handler: {:?}, not_found_fn: Fn -> HyperResult<Response<Body>> }}", self.inner.handlers, self.inner.derp_endpoint, self.inner.derp_handler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    use hyper::header::UPGRADE;
    use hyper::server::conn::Http;
    use hyper::upgrade::Upgraded;
    use hyper::{Body, Request, StatusCode};
    use tokio::sync::oneshot;

    use crate::hp::derp::server::Server as DerpServer;
    use crate::hp::key::node::{PublicKey, SecretKey};

    /// Handle client-side I/O after HTTP upgraded.
    async fn derp_client(mut upgraded: Upgraded) -> Result<()> {
        println!("in derp_client handshake");
        let secret_key = SecretKey::generate();
        let got_server_key = crate::hp::derp::client::recv_server_key(&mut upgraded).await?;
        let client_info = crate::hp::derp::types::ClientInfo {
            version: crate::hp::derp::PROTOCOL_VERSION,
            mesh_key: None,
            can_ack_pings: true,
            is_prober: true,
        };
        crate::hp::derp::send_client_key(&mut upgraded, &secret_key, &got_server_key, &client_info)
            .await?;
        let mut buf = bytes::BytesMut::new();
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut upgraded, crate::hp::derp::MAX_FRAME_SIZE, &mut buf)
                .await?;
        assert_eq!(crate::hp::derp::FrameType::ServerInfo, frame_type);
        let msg = secret_key.open_from(&got_server_key, &buf)?;
        let _info: crate::hp::derp::types::ServerInfo = postcard::from_bytes(&msg)?;
        Ok(())
    }

    /// Our client HTTP handler to initiate HTTP upgrades.
    async fn client_upgrade_request(addr: SocketAddr) -> Result<()> {
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let (mut request_sender, connection) =
            hyper::client::conn::handshake(tcp_stream).await.unwrap();

        let task = tokio::spawn(async move {
            let _ = connection.without_shutdown().await;
        });

        let req = Request::builder()
            .header(UPGRADE, super::HTTP_UPGRADE_PROTOCOL)
            .body(Body::empty())
            .unwrap();

        let res = request_sender.send_request(req).await.unwrap();

        if res.status() != StatusCode::SWITCHING_PROTOCOLS {
            panic!("Our server didn't upgrade: {}", res.status());
        }

        match hyper::upgrade::on(res).await {
            Ok(upgraded) => {
                if let Err(e) = derp_client(upgraded).await {
                    eprintln!("client foobar io error: {}", e)
                };
            }
            Err(e) => eprintln!("upgrade error: {}", e),
        }
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_connection_handler() -> Result<()> {
        // inspired by https://github.com/hyperium/hyper/blob/v0.14.25/examples/upgrades.rs

        let mut addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // create derp_server
        let server_key = SecretKey::generate();
        let derp_server = ServerBuilder::new(addr)
            .secret_key(Some(server_key))
            .build()?;

        // run server
        addr = derp_server.serve().await?;
        println!("server running on {addr}");

        // Client requests a HTTP connection upgrade.
        let request = client_upgrade_request(addr);
        request.await?;

        // derp_server.shutdown().await;
        Ok(())
    }
}
