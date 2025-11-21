use std::pin::Pin;

use iroh_base::EndpointAddr;
use quinn::VarInt;

use crate::endpoint::connection::ConnectionInfo;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Outcome of [`Middleware::before_connect`]
#[derive(Debug)]
pub enum BeforeConnectOutcome {
    /// Accept the connect attempt.
    Accept,
    /// Reject the connect attempt.
    Reject,
}

/// Outcome of [`Middleware::after_handshake`]
#[derive(Debug)]
pub enum AfterHandshakeOutcome {
    /// Accept the connection.
    Accept,
    /// Reject and close the connection.
    ///
    /// See [`Connection::close`] for details on `error_code` and `reason`.
    ///
    /// [`Connection::close`]: crate::endpoint::Connection::close
    Reject {
        /// Error code to send with the connection close frame.
        error_code: VarInt,
        /// Close reason to send with the connection close frame.
        reason: Vec<u8>,
    },
}

impl AfterHandshakeOutcome {
    /// Returns [`Self::Accept`].
    pub fn accept() -> Self {
        Self::Accept
    }

    /// Returns [`Self::Reject`].
    pub fn reject(&self, error_code: VarInt, reason: &[u8]) -> Self {
        Self::Reject {
            error_code,
            reason: reason.to_vec(),
        }
    }
}

/// Middlewares intercept the connection establishment process of an [`Endpoint`].
///
/// Use [`Builder::middleware`] to install middlewares onto an endpoint.
///
/// For each hook, all installed middlewares are invoked in the order they were installed on
/// the endpoint builder. If a middleware returns `Accept`, processing continues with the next
/// middleware. If a middleware returns `Reject`, processing is aborted and further middlewares
/// are not invoked for this hook.
///
/// ## Notes to implementers
///
/// As middlewares are stored on the endpoint, you must make sure to never store an [`Endpoint`]
/// on the middleware struct itself, as this would create reference counting loop and cause the
/// endpoint to never be dropped, leaking memory.
///
/// [`Endpoint`]: crate::Endpoint
/// [`Builder::middleware`]: crate::endpoint::Builder::middleware
pub trait Middleware: std::fmt::Debug + Send + Sync {
    /// Intercept outgoing connections before they are started.
    ///
    /// This is called whenever a new outgoing connection is initiated via [`Endpoint::connect`]
    /// or [`Endpoint::connect_with_opts`].
    ///
    /// If any middleware returns [`BeforeConnectOutcome::Reject`], the connection attempt is aborted
    /// before any packets are sent to the remote.
    ///
    /// [`Endpoint::connect`]: crate::Endpoint::connect
    /// [`Endpoint::connect_with_opts`]: crate::Endpoint::connect_with_opts
    fn before_connect<'a>(
        &'a self,
        _remote_addr: &'a EndpointAddr,
        _alpn: &'a [u8],
    ) -> impl Future<Output = BeforeConnectOutcome> + Send + 'a {
        async { BeforeConnectOutcome::Accept }
    }

    /// Intercept both incoming and outgoing connections once the TLS handshake has completed.
    ///
    /// At this point in time, we know the remote's endpoint id and ALPN. If any middleware returns
    /// [`AfterHandshakeOutcome::Reject`], the connection is closed with the provided error code
    /// and reason.
    fn after_handshake<'a>(
        &'a self,
        _conn: &'a ConnectionInfo,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        async { AfterHandshakeOutcome::accept() }
    }
}

pub(crate) trait DynMiddleware: std::fmt::Debug + Send + Sync {
    fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BoxFuture<'a, BeforeConnectOutcome>;
    fn after_handshake<'a>(
        &'a self,
        conn: &'a ConnectionInfo,
    ) -> BoxFuture<'a, AfterHandshakeOutcome>;
}

impl<T: Middleware> DynMiddleware for T {
    fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BoxFuture<'a, BeforeConnectOutcome> {
        Box::pin(Middleware::before_connect(self, remote_addr, alpn))
    }

    fn after_handshake<'a>(
        &'a self,
        conn: &'a ConnectionInfo,
    ) -> BoxFuture<'a, AfterHandshakeOutcome> {
        Box::pin(Middleware::after_handshake(self, conn))
    }
}

#[derive(Debug, Default)]
pub(crate) struct MiddlewareList {
    inner: Vec<Box<dyn DynMiddleware>>,
}

impl MiddlewareList {
    pub(super) fn push(&mut self, middleware: impl Middleware + 'static) {
        let middleware: Box<dyn DynMiddleware> = Box::new(middleware);
        self.inner.push(middleware);
    }

    pub(super) async fn before_connect(
        &self,
        remote_addr: &EndpointAddr,
        alpn: &[u8],
    ) -> BeforeConnectOutcome {
        for middleware in self.inner.iter() {
            match middleware.before_connect(remote_addr, alpn).await {
                BeforeConnectOutcome::Accept => continue,
                reject @ BeforeConnectOutcome::Reject => {
                    return reject;
                }
            }
        }
        BeforeConnectOutcome::Accept
    }

    pub(super) async fn after_handshake(&self, conn: &ConnectionInfo) -> AfterHandshakeOutcome {
        for middleware in self.inner.iter() {
            match middleware.after_handshake(conn).await {
                AfterHandshakeOutcome::Accept => continue,
                reject @ AfterHandshakeOutcome::Reject { .. } => {
                    return reject;
                }
            }
        }
        AfterHandshakeOutcome::Accept
    }
}
