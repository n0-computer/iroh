//! Tools for spawning an accept loop that routes incoming requests to the right protocol.
//!
//! ## Example
//!
//! ```no_run
//! # use iroh::{endpoint::{Connection, BindError}, protocol::{AcceptError, ProtocolHandler, Router}, Endpoint, NodeAddr};
//! #
//! # async fn test_compile() -> Result<(), BindError> {
//! let endpoint = Endpoint::builder().discovery_n0().bind().await?;
//!
//! let router = Router::builder(endpoint)
//!     .accept(b"/my/alpn", Echo)
//!     .spawn();
//! # Ok(())
//! # }
//!
//! // The protocol definition:
//! #[derive(Debug, Clone)]
//! struct Echo;
//!
//! impl ProtocolHandler for Echo {
//!     async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
//!         let (mut send, mut recv) = connection.accept_bi().await?;
//!
//!         // Echo any bytes received back directly.
//!         let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
//!
//!         send.finish()?;
//!         connection.closed().await;
//!
//!         Ok(())
//!     }
//! }
//! ```
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use iroh_base::NodeId;
use n0_future::{
    join_all,
    task::{self, AbortOnDropHandle, JoinSet},
};
use snafu::{Backtrace, Snafu};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, info_span, trace, warn, Instrument};

use crate::{
    endpoint::{Connecting, Connection, RemoteNodeIdError},
    Endpoint,
};

/// The built router.
///
/// Construct this using [`Router::builder`].
///
/// When dropped, this will abort listening the tasks, so make sure to store it.
///
/// Even with this abort-on-drop behaviour, it's recommended to call and await
/// [`Router::shutdown`] before ending the process.
///
/// As an example for graceful shutdown, e.g. for tests or CLI tools,
/// wait for [`tokio::signal::ctrl_c()`]:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use futures_lite::future::Boxed as BoxedFuture;
/// # use n0_snafu::ResultExt;
/// # use iroh::{endpoint::Connecting, protocol::{ProtocolHandler, Router}, Endpoint, NodeAddr};
/// #
/// # async fn test_compile() -> n0_snafu::Result<()> {
/// let endpoint = Endpoint::builder().discovery_n0().bind().await?;
///
/// let router = Router::builder(endpoint)
///     // .accept(&ALPN, <something>)
///     .spawn();
///
/// // wait until the user wants to
/// tokio::signal::ctrl_c().await.context("ctrl+c")?;
/// router.shutdown().await.context("shutdown")?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Router {
    endpoint: Endpoint,
    // `Router` needs to be `Clone + Send`, and we need to `task.await` in its `shutdown()` impl.
    task: Arc<Mutex<Option<AbortOnDropHandle<()>>>>,
    cancel_token: CancellationToken,
}

/// Builder for creating a [`Router`] for accepting protocols.
#[derive(Debug)]
pub struct RouterBuilder {
    endpoint: Endpoint,
    protocols: ProtocolMap,
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum AcceptError {
    #[snafu(transparent)]
    Connection {
        source: crate::endpoint::ConnectionError,
        backtrace: Option<Backtrace>,
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(transparent)]
    MissingRemoteNodeId { source: RemoteNodeIdError },
    #[snafu(display("Not allowed."))]
    NotAllowed {},

    #[snafu(transparent)]
    User {
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl AcceptError {
    /// Creates a new user error from an arbitrary error type.
    pub fn from_err<T: std::error::Error + Send + Sync + 'static>(value: T) -> Self {
        Self::User {
            source: Box::new(value),
        }
    }
}

impl From<std::io::Error> for AcceptError {
    fn from(err: std::io::Error) -> Self {
        Self::from_err(err)
    }
}

impl From<quinn::ClosedStream> for AcceptError {
    fn from(err: quinn::ClosedStream) -> Self {
        Self::from_err(err)
    }
}

/// Handler for incoming connections.
///
/// A router accepts connections for arbitrary ALPN protocols.
///
/// With this trait, you can handle incoming connections for any protocol.
///
/// Implement this trait on a struct that should handle incoming connections.
/// The protocol handler must then be registered on the node for an ALPN protocol with
/// [`crate::protocol::RouterBuilder::accept`].
///
/// See the [module documentation](crate::protocol) for an example.
pub trait ProtocolHandler: Send + Sync + std::fmt::Debug + 'static {
    /// Optional interception point to handle the `Connecting` state.
    ///
    /// Can be implemented as `async fn on_connecting(&self, connecting: Connecting) -> Result<Connection>`.
    ///
    /// This enables accepting 0-RTT data from clients, among other things.
    fn on_connecting(
        &self,
        connecting: Connecting,
    ) -> impl Future<Output = Result<Connection, AcceptError>> + Send {
        async move {
            let conn = connecting.await?;
            Ok(conn)
        }
    }

    /// Handle an incoming connection.
    ///
    /// Can be implemented as `async fn accept(&self, connection: Connection) -> Result<Connection>`.
    ///
    /// The returned future runs on a freshly spawned tokio task so it can be long-running.
    ///
    /// When [`Router::shutdown`] is called, no further connections will be accepted, and
    /// the futures returned by [`Self::accept`] will be aborted after the future returned
    /// from [`ProtocolHandler::shutdown`] completes.
    fn accept(
        &self,
        connection: Connection,
    ) -> impl Future<Output = Result<(), AcceptError>> + Send;

    /// Called when the router shuts down.
    ///
    /// Can be implemented as `async fn shutdown(&self)`.
    ///
    /// This is called from [`Router::shutdown`]. The returned future is awaited before
    /// the router closes the endpoint.
    fn shutdown(&self) -> impl Future<Output = ()> + Send {
        async move {}
    }
}

impl<T: ProtocolHandler> ProtocolHandler for Arc<T> {
    async fn on_connecting(&self, conn: Connecting) -> Result<Connection, AcceptError> {
        self.as_ref().on_connecting(conn).await
    }

    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.as_ref().accept(conn).await
    }

    async fn shutdown(&self) {
        self.as_ref().shutdown().await
    }
}

impl<T: ProtocolHandler> ProtocolHandler for Box<T> {
    async fn on_connecting(&self, conn: Connecting) -> Result<Connection, AcceptError> {
        self.as_ref().on_connecting(conn).await
    }

    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.as_ref().accept(conn).await
    }

    async fn shutdown(&self) {
        self.as_ref().shutdown().await
    }
}

/// A dyn-compatible version of [`ProtocolHandler`] that returns boxed futures.
///
/// We are not using [`n0_future::boxed::BoxFuture] because we don't need a `'static` bound
/// on these futures.
pub(crate) trait DynProtocolHandler: Send + Sync + std::fmt::Debug + 'static {
    /// See [`ProtocolHandler::on_connecting`].
    fn on_connecting(
        &self,
        connecting: Connecting,
    ) -> Pin<Box<dyn Future<Output = Result<Connection, AcceptError>> + Send + '_>> {
        Box::pin(async move {
            let conn = connecting.await?;
            Ok(conn)
        })
    }

    /// See [`ProtocolHandler::accept`].
    fn accept(
        &self,
        connection: Connection,
    ) -> Pin<Box<dyn Future<Output = Result<(), AcceptError>> + Send + '_>>;

    /// See [`ProtocolHandler::shutdown`].
    fn shutdown(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {})
    }
}

impl<P: ProtocolHandler> DynProtocolHandler for P {
    fn accept(
        &self,
        connection: Connection,
    ) -> Pin<Box<dyn Future<Output = Result<(), AcceptError>> + Send + '_>> {
        Box::pin(<Self as ProtocolHandler>::accept(self, connection))
    }

    fn on_connecting(
        &self,
        connecting: Connecting,
    ) -> Pin<Box<dyn Future<Output = Result<Connection, AcceptError>> + Send + '_>> {
        Box::pin(<Self as ProtocolHandler>::on_connecting(self, connecting))
    }

    fn shutdown(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(<Self as ProtocolHandler>::shutdown(self))
    }
}

/// A typed map of protocol handlers, mapping them from ALPNs.
#[derive(Debug, Default)]
pub(crate) struct ProtocolMap(BTreeMap<Vec<u8>, Box<dyn DynProtocolHandler>>);

impl ProtocolMap {
    /// Returns the registered protocol handler for an ALPN as a [`Arc<dyn ProtocolHandler>`].
    pub(crate) fn get(&self, alpn: &[u8]) -> Option<&dyn DynProtocolHandler> {
        self.0.get(alpn).map(|p| &**p)
    }

    /// Inserts a protocol handler.
    pub(crate) fn insert(&mut self, alpn: Vec<u8>, handler: impl ProtocolHandler) {
        let handler = Box::new(handler);
        self.0.insert(alpn, handler);
    }

    /// Returns an iterator of all registered ALPN protocol identifiers.
    pub(crate) fn alpns(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.0.keys()
    }

    /// Shuts down all protocol handlers.
    ///
    /// Calls and awaits [`ProtocolHandler::shutdown`] for all registered handlers concurrently.
    pub(crate) async fn shutdown(&self) {
        let handlers = self.0.values().map(|p| p.shutdown());
        join_all(handlers).await;
    }
}

impl Router {
    /// Creates a new [`Router`] using given [`Endpoint`].
    pub fn builder(endpoint: Endpoint) -> RouterBuilder {
        RouterBuilder::new(endpoint)
    }

    /// Returns the [`Endpoint`] stored in this router.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Checks if the router is already shutdown.
    pub fn is_shutdown(&self) -> bool {
        self.cancel_token.is_cancelled()
    }

    /// Shuts down the accept loop cleanly.
    ///
    /// When this function returns, all [`ProtocolHandler`]s will be shutdown and
    /// `Endpoint::close` will have been called.
    ///
    /// If already shutdown, it returns `Ok`.
    ///
    /// If some [`ProtocolHandler`] panicked in the accept loop, this will propagate
    /// that panic into the result here.
    pub async fn shutdown(&self) -> Result<(), n0_future::task::JoinError> {
        if self.is_shutdown() {
            return Ok(());
        }

        // Trigger shutdown of the main run task by activating the cancel token.
        self.cancel_token.cancel();

        // Wait for the main task to terminate.
        if let Some(task) = self.task.lock().await.take() {
            task.await?;
        }

        Ok(())
    }
}

impl RouterBuilder {
    /// Creates a new router builder using given [`Endpoint`].
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            protocols: ProtocolMap::default(),
        }
    }

    /// Configures the router to accept the [`ProtocolHandler`] when receiving a connection
    /// with this `alpn`.
    pub fn accept(mut self, alpn: impl AsRef<[u8]>, handler: impl ProtocolHandler) -> Self {
        self.protocols.insert(alpn.as_ref().to_vec(), handler);
        self
    }

    /// Returns the [`Endpoint`] of the node.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Spawns an accept loop and returns a handle to it encapsulated as the [`Router`].
    pub fn spawn(self) -> Router {
        // Update the endpoint with our alpns.
        let alpns = self
            .protocols
            .alpns()
            .map(|alpn| alpn.to_vec())
            .collect::<Vec<_>>();

        let protocols = Arc::new(self.protocols);
        self.endpoint.set_alpns(alpns);

        let mut join_set = JoinSet::new();
        let endpoint = self.endpoint.clone();

        // Our own shutdown works with a cancellation token.
        let cancel = CancellationToken::new();
        let cancel_token = cancel.clone();

        let run_loop_fut = async move {
            // Make sure to cancel the token, if this future ever exits.
            let _cancel_guard = cancel_token.clone().drop_guard();
            // We create a separate cancellation token to stop any `ProtocolHandler::accept` futures
            // that are still running after `ProtocolHandler::shutdown` was called.
            let handler_cancel_token = CancellationToken::new();

            loop {
                tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        break;
                    },
                    // handle task terminations and quit on panics.
                    Some(res) = join_set.join_next() => {
                        match res {
                            Err(outer) => {
                                if outer.is_panic() {
                                    error!("Task panicked: {outer:?}");
                                    break;
                                } else if outer.is_cancelled() {
                                    trace!("Task cancelled: {outer:?}");
                                } else {
                                    error!("Task failed: {outer:?}");
                                    break;
                                }
                            }
                            Ok(Some(())) => {
                                trace!("Task finished");
                            }
                            Ok(None) => {
                                trace!("Task cancelled");
                            }
                        }
                    },

                    // handle incoming p2p connections.
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else {
                            break; // Endpoint is closed.
                        };

                        let protocols = protocols.clone();
                        let token = handler_cancel_token.child_token();
                        join_set.spawn(async move {
                            token.run_until_cancelled(handle_connection(incoming, protocols)).await
                        }.instrument(info_span!("router.accept")));
                    },
                }
            }

            // We first shutdown the protocol handlers to give them a chance to close connections gracefully.
            protocols.shutdown().await;
            // We now cancel the remaining `ProtocolHandler::accept` futures.
            handler_cancel_token.cancel();
            // Now we close the endpoint. This will force-close all connections that are not yet closed.
            endpoint.close().await;
            // Finally, we abort the remaining accept tasks. This should be a noop because we already cancelled
            // the futures above.
            tracing::debug!("Shutting down remaining tasks");
            join_set.abort_all();
            while let Some(res) = join_set.join_next().await {
                match res {
                    Err(err) if err.is_panic() => error!("Task panicked: {err:?}"),
                    _ => {}
                }
            }
        };
        let task = task::spawn(run_loop_fut);
        let task = AbortOnDropHandle::new(task);

        Router {
            endpoint: self.endpoint,
            task: Arc::new(Mutex::new(Some(task))),
            cancel_token: cancel,
        }
    }
}

async fn handle_connection(incoming: crate::endpoint::Incoming, protocols: Arc<ProtocolMap>) {
    let mut connecting = match incoming.accept() {
        Ok(conn) => conn,
        Err(err) => {
            warn!("Ignoring connection: accepting failed: {err:#}");
            return;
        }
    };
    let alpn = match connecting.alpn().await {
        Ok(alpn) => alpn,
        Err(err) => {
            warn!("Ignoring connection: invalid handshake: {err:#}");
            return;
        }
    };
    let Some(handler) = protocols.get(&alpn) else {
        warn!("Ignoring connection: unsupported ALPN protocol");
        return;
    };
    match handler.on_connecting(connecting).await {
        Ok(connection) => {
            if let Err(err) = handler.accept(connection).await {
                warn!("Handling incoming connection ended with error: {err}");
            }
        }
        Err(err) => {
            warn!("Handling incoming connecting ended with error: {err}");
        }
    }
}

/// Wraps an existing protocol, limiting its access,
/// based on the provided function.
///
/// Any refused connection will be closed with an error code of `0` and reason `not allowed`.
#[derive(derive_more::Debug, Clone)]
pub struct AccessLimit<P: ProtocolHandler + Clone> {
    proto: P,
    #[debug("limiter")]
    limiter: Arc<dyn Fn(NodeId) -> bool + Send + Sync + 'static>,
}

impl<P: ProtocolHandler + Clone> AccessLimit<P> {
    /// Create a new `AccessLimit`.
    ///
    /// The function should return `true` for nodes that are allowed to
    /// connect, and `false` otherwise.
    pub fn new<F>(proto: P, limiter: F) -> Self
    where
        F: Fn(NodeId) -> bool + Send + Sync + 'static,
    {
        Self {
            proto,
            limiter: Arc::new(limiter),
        }
    }
}

impl<P: ProtocolHandler + Clone> ProtocolHandler for AccessLimit<P> {
    fn on_connecting(
        &self,
        conn: Connecting,
    ) -> impl Future<Output = Result<Connection, AcceptError>> + Send {
        self.proto.on_connecting(conn)
    }

    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_node_id()?;
        let is_allowed = (self.limiter)(remote);
        if !is_allowed {
            conn.close(0u32.into(), b"not allowed");
            return Err(NotAllowedSnafu.build());
        }
        self.proto.accept(conn).await?;
        Ok(())
    }

    fn shutdown(&self) -> impl Future<Output = ()> + Send {
        self.proto.shutdown()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, time::Duration};

    use n0_snafu::{Result, ResultExt};
    use quinn::ApplicationClose;

    use super::*;
    use crate::{endpoint::ConnectionError, watcher::Watcher, RelayMode};

    #[tokio::test]
    async fn test_shutdown() -> Result {
        let endpoint = Endpoint::builder().bind().await?;
        let router = Router::builder(endpoint.clone()).spawn();

        assert!(!router.is_shutdown());
        assert!(!endpoint.is_closed());

        router.shutdown().await.e()?;

        assert!(router.is_shutdown());
        assert!(endpoint.is_closed());

        Ok(())
    }

    // The protocol definition:
    #[derive(Debug, Clone)]
    struct Echo;

    const ECHO_ALPN: &[u8] = b"/iroh/echo/1";

    impl ProtocolHandler for Echo {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            println!("accepting echo");
            let (mut send, mut recv) = connection.accept_bi().await?;

            // Echo any bytes received back directly.
            let _bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;

            send.finish()?;
            connection.closed().await;

            Ok(())
        }
    }
    #[tokio::test]
    async fn test_limiter() -> Result {
        let e1 = Endpoint::builder().bind().await?;
        // deny all access
        let proto = AccessLimit::new(Echo, |_node_id| false);
        let r1 = Router::builder(e1.clone()).accept(ECHO_ALPN, proto).spawn();

        let addr1 = r1.endpoint().node_addr().initialized().await?;

        let e2 = Endpoint::builder().bind().await?;

        println!("connecting");
        let conn = e2.connect(addr1, ECHO_ALPN).await?;

        let (_send, mut recv) = conn.open_bi().await.e()?;
        let response = recv.read_to_end(1000).await.unwrap_err();
        assert!(format!("{:#?}", response).contains("not allowed"));

        r1.shutdown().await.e()?;
        e2.close().await;

        Ok(())
    }

    #[tokio::test]
    async fn test_graceful_shutdown() -> Result {
        #[derive(Debug, Clone, Default)]
        struct TestProtocol {
            connections: Arc<Mutex<Vec<Connection>>>,
        }

        const TEST_ALPN: &[u8] = b"/iroh/test/1";

        impl ProtocolHandler for TestProtocol {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                self.connections.lock().expect("poisoned").push(connection);
                Ok(())
            }

            async fn shutdown(&self) {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut connections = self.connections.lock().expect("poisoned");
                for conn in connections.drain(..) {
                    conn.close(42u32.into(), b"shutdown");
                }
            }
        }

        let endpoint = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let router = Router::builder(endpoint)
            .accept(TEST_ALPN, TestProtocol::default())
            .spawn();
        let addr = router.endpoint().node_addr().initialized().await?;

        let endpoint2 = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let conn = endpoint2.connect(addr, TEST_ALPN).await?;

        router.shutdown().await.e()?;

        let reason = conn.closed().await;
        assert_eq!(
            reason,
            ConnectionError::ApplicationClosed(ApplicationClose {
                error_code: 42u32.into(),
                reason: b"shutdown".to_vec().into()
            })
        );
        Ok(())
    }
}
