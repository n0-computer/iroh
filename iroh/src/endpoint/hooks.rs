use std::pin::Pin;

use iroh_base::EndpointAddr;

use crate::endpoint::{connection::ConnectionInfo, quic::VarInt};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Outcome of [`EndpointHooks::before_connect`]
#[derive(Debug)]
pub enum BeforeConnectOutcome {
    /// Accept the connect attempt.
    Accept,
    /// Reject the connect attempt.
    Reject,
}

/// Outcome of [`EndpointHooks::after_handshake`]
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

/// EndpointHooks intercept the connection establishment process of an [`Endpoint`].
///
/// Use [`Builder::hooks`] to install hooks onto an endpoint.
///
/// For each hook, all installed hooks are invoked in the order they were installed on
/// the endpoint builder. If a hook returns `Accept`, processing continues with the next
/// hook. If a hook returns `Reject`, processing is aborted and further hooks
/// are not invoked for this hook.
///
/// ## Notes to implementers
///
/// As hooks are stored on the endpoint, you must make sure to never store an [`Endpoint`]
/// on the hook struct itself, as this would create reference counting loop and cause the
/// endpoint to never be dropped, leaking memory.
///
/// [`Endpoint`]: crate::Endpoint
/// [`Builder::hooks`]: crate::endpoint::Builder::hooks
pub trait EndpointHooks: std::fmt::Debug + Send + Sync {
    /// Intercept outgoing connections before they are started.
    ///
    /// This is called whenever a new outgoing connection is initiated via [`Endpoint::connect`]
    /// or [`Endpoint::connect_with_opts`].
    ///
    /// If any hook returns [`BeforeConnectOutcome::Reject`], the connection attempt is aborted
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
    /// At this point in time, we know the remote's endpoint id and ALPN. If any hook returns
    /// [`AfterHandshakeOutcome::Reject`], the connection is closed with the provided error code
    /// and reason.
    fn after_handshake<'a>(
        &'a self,
        _conn: &'a ConnectionInfo,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        async { AfterHandshakeOutcome::accept() }
    }
}

pub(crate) trait DynEndpointHooks: std::fmt::Debug + Send + Sync {
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

impl<T: EndpointHooks> DynEndpointHooks for T {
    fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BoxFuture<'a, BeforeConnectOutcome> {
        Box::pin(EndpointHooks::before_connect(self, remote_addr, alpn))
    }

    fn after_handshake<'a>(
        &'a self,
        conn: &'a ConnectionInfo,
    ) -> BoxFuture<'a, AfterHandshakeOutcome> {
        Box::pin(EndpointHooks::after_handshake(self, conn))
    }
}

#[derive(Debug, Default)]
pub(crate) struct EndpointHooksList {
    inner: Vec<Box<dyn DynEndpointHooks>>,
}

impl EndpointHooksList {
    pub(super) fn push(&mut self, hook: impl EndpointHooks + 'static) {
        let hook: Box<dyn DynEndpointHooks> = Box::new(hook);
        self.inner.push(hook);
    }

    pub(super) async fn before_connect(
        &self,
        remote_addr: &EndpointAddr,
        alpn: &[u8],
    ) -> BeforeConnectOutcome {
        for hook in self.inner.iter() {
            match hook.before_connect(remote_addr, alpn).await {
                BeforeConnectOutcome::Accept => continue,
                reject @ BeforeConnectOutcome::Reject => {
                    return reject;
                }
            }
        }
        BeforeConnectOutcome::Accept
    }

    pub(super) async fn after_handshake(&self, conn: &ConnectionInfo) -> AfterHandshakeOutcome {
        for hook in self.inner.iter() {
            match hook.after_handshake(conn).await {
                AfterHandshakeOutcome::Accept => continue,
                reject @ AfterHandshakeOutcome::Reject { .. } => {
                    return reject;
                }
            }
        }
        AfterHandshakeOutcome::Accept
    }
}
