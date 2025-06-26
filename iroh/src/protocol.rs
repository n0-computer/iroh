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
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use iroh_base::NodeId;
use n0_future::{
    join_all,
    task::{self, AbortOnDropHandle, JoinSet},
    time,
};
use snafu::{Backtrace, Snafu};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info_span, trace, warn, Instrument};

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
    tx: mpsc::Sender<ToRouterTask>,
}

enum ToRouterTask {
    Accept {
        alpn: Vec<u8>,
        handler: Arc<dyn DynProtocolHandler>,
        reply: oneshot::Sender<AddProtocolOutcome>,
    },
    StopAccepting {
        alpn: Vec<u8>,
        reply: oneshot::Sender<Result<(), StopAcceptingError>>,
    },
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

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RouterError {
    #[snafu(display("Endpoint closed"))]
    Closed {},
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum StopAcceptingError {
    #[snafu(display("Endpoint closed"))]
    Closed {},
    #[snafu(display("The ALPN requested to be removed is not registered"))]
    UnknownAlpn {},
}

/// Returned from [`Router::accept`]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AddProtocolOutcome {
    /// The protocol handler has been newly inserted.
    Inserted,
    /// The protocol handler replaced a previously registered protocol handler.
    Replaced,
}

/// Timeout applied to [`ProtocolHandler::shutdown] futures.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

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

async fn shutdown_timeout(alpn: Vec<u8>, handler: Arc<dyn DynProtocolHandler>) -> Option<()> {
    if let Err(_elapsed) = time::timeout(SHUTDOWN_TIMEOUT, handler.shutdown()).await {
        debug!(
            alpn = String::from_utf8_lossy(&alpn).to_string(),
            "Protocol handler exceeded the shutdown timeout and was aborted"
        );
        None
    } else {
        Some(())
    }
}

/// A typed map of protocol handlers, mapping them from ALPNs.
#[derive(Debug, Default)]
pub(crate) struct ProtocolMap(std::sync::RwLock<BTreeMap<Vec<u8>, Arc<dyn DynProtocolHandler>>>);

impl ProtocolMap {
    /// Returns the registered protocol handler for an ALPN as a [`Arc<dyn ProtocolHandler>`].
    pub(crate) fn get(&self, alpn: &[u8]) -> Option<Arc<dyn DynProtocolHandler>> {
        self.0.read().expect("poisoned").get(alpn).cloned()
    }

    /// Inserts a protocol handler.
    pub(crate) fn insert(
        &self,
        alpn: Vec<u8>,
        handler: Arc<dyn DynProtocolHandler>,
    ) -> Option<Arc<dyn DynProtocolHandler>> {
        self.0.write().expect("poisoned").insert(alpn, handler)
    }

    pub(crate) fn remove(&self, alpn: &[u8]) -> Option<Arc<dyn DynProtocolHandler>> {
        self.0.write().expect("poisoned").remove(alpn)
    }

    /// Returns an iterator of all registered ALPN protocol identifiers.
    pub(crate) fn alpns(&self) -> Vec<Vec<u8>> {
        self.0.read().expect("poisoned").keys().cloned().collect()
    }

    /// Shuts down all protocol handlers.
    ///
    /// Calls and awaits [`ProtocolHandler::shutdown`] for all registered handlers concurrently.
    pub(crate) async fn shutdown(&self) {
        let mut futures = Vec::new();
        {
            let mut inner = self.0.write().expect("poisoned");
            while let Some((alpn, handler)) = inner.pop_first() {
                futures.push(shutdown_timeout(alpn, handler));
            }
        }
        join_all(futures).await;
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

    /// Accepts incoming connections with this `alpn` via [`ProtocolHandler`].
    ///
    /// After this function returns, new connections with this `alpn` will be handled
    /// by the passed `handler`.
    ///
    /// If a protocol handler was already registered for `alpn`, the previous handler will be
    /// shutdown. Existing connections will not be aborted by the router, but some protocol
    /// handlers may abort existing connections in their [`Router::shutdown`] implementation.
    /// Consult the documentation of the protocol handler to see if that is the case.
    pub async fn accept(
        &self,
        alpn: impl AsRef<[u8]>,
        handler: impl ProtocolHandler,
    ) -> Result<AddProtocolOutcome, RouterError> {
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(ToRouterTask::Accept {
                alpn: alpn.as_ref().to_vec(),
                handler: Arc::new(handler),
                reply,
            })
            .await
            .map_err(|_| RouterError::Closed {})?;
        reply_rx.await.map_err(|_| RouterError::Closed {})
    }

    /// Stops accepting connections with this `alpn`.
    ///
    /// After this function returns, new connections with `alpn` will no longer be accepted.
    ///
    /// If a protocol handler was registered for `alpn`, the handler will be
    /// shutdown. Existing connections will not be aborted by the router, but some protocol
    /// handlers may abort existing connections in their [`Router::shutdown`] implementation.
    /// Consult the documentation of the protocol handler to see if that is the case.
    ///
    /// Returns an error if the router has been shutdown or no protocol is registered for `alpn`.
    pub async fn stop_accepting(&self, alpn: impl AsRef<[u8]>) -> Result<(), StopAcceptingError> {
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(ToRouterTask::StopAccepting {
                alpn: alpn.as_ref().to_vec(),
                reply,
            })
            .await
            .map_err(|_| StopAcceptingError::Closed {})?;
        reply_rx.await.map_err(|_| StopAcceptingError::Closed {})?
    }

    /// Shuts down the accept loop and endpoint cleanly.
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

    /// Configures the router to accept incoming connections with this `alpn` via [`ProtocolHandler`].
    pub fn accept(self, alpn: impl AsRef<[u8]>, handler: impl ProtocolHandler) -> Self {
        self.protocols
            .insert(alpn.as_ref().to_vec(), Arc::new(handler));
        self
    }

    /// Returns the [`Endpoint`] of the node.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Spawns an accept loop and returns a handle to it encapsulated as the [`Router`].
    pub fn spawn(self) -> Router {
        // Update the endpoint with our alpns.
        self.endpoint.set_alpns(self.protocols.alpns());

        let protocols = Arc::new(self.protocols);

        let mut join_set = JoinSet::new();
        let endpoint = self.endpoint.clone();

        // Our own shutdown works with a cancellation token.
        let cancel = CancellationToken::new();
        let cancel_token = cancel.clone();

        let (tx, mut rx) = mpsc::channel(8);

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
                    Some(msg) = rx.recv() => {
                        match msg {
                            ToRouterTask::Accept { alpn, handler, reply } => {
                                let outcome = if let Some(previous) = protocols.insert(alpn.clone(), handler) {
                                    join_set.spawn(shutdown_timeout(alpn, previous));
                                    AddProtocolOutcome::Replaced
                                } else {
                                    AddProtocolOutcome::Inserted
                                };
                                endpoint.set_alpns(protocols.alpns());
                                reply.send(outcome).ok();
                            }
                            ToRouterTask::StopAccepting { alpn, reply } => {
                                if let Some(handler) = protocols.remove(&alpn) {
                                    join_set.spawn(shutdown_timeout(alpn, handler));
                                    endpoint.set_alpns(protocols.alpns());
                                    reply.send(Ok(())).ok();
                                } else {
                                    reply.send(Err(StopAcceptingError::UnknownAlpn {})).ok();
                                }
                            }
                        }
                    }
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
            debug!("Shutting down remaining tasks");
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
            tx,
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

    use iroh_base::NodeAddr;
    use n0_snafu::{Result, ResultExt};
    use n0_watcher::Watcher;
    use quinn::{ApplicationClose, TransportErrorCode};

    use super::*;
    use crate::{
        endpoint::{ConnectError, ConnectionError},
        RelayMode,
    };

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
        // tracing_subscriber::fmt::try_init().ok();
        let e1 = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        // deny all access
        let proto = AccessLimit::new(Echo, |_node_id| false);
        let r1 = Router::builder(e1.clone()).accept(ECHO_ALPN, proto).spawn();

        let addr1 = r1.endpoint().node_addr().initialized().await?;
        dbg!(&addr1);
        let e2 = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;

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

        eprintln!("creating ep1");
        let endpoint = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let router = Router::builder(endpoint)
            .accept(TEST_ALPN, TestProtocol::default())
            .spawn();
        eprintln!("waiting for node addr");
        let addr = router.endpoint().node_addr().initialized().await?;

        eprintln!("creating ep2");
        let endpoint2 = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        eprintln!("connecting to {:?}", addr);
        let conn = endpoint2.connect(addr, TEST_ALPN).await?;

        eprintln!("starting shutdown");
        router.shutdown().await.e()?;

        eprintln!("waiting for closed conn");
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

    #[tokio::test]
    async fn test_add_and_remove_protocol() -> Result {
        async fn connect_assert_ok(
            endpoint: &Endpoint,
            addr: &NodeAddr,
            alpn: &[u8],
            expected_code: u32,
        ) {
            let conn = endpoint
                .connect(addr.clone(), alpn)
                .await
                .expect("expected connection to succeed");
            let reason = conn.closed().await;
            assert!(matches!(reason,
                ConnectionError::ApplicationClosed(ApplicationClose { error_code, .. }) if error_code == expected_code.into()
            ));
        }

        async fn connect_assert_fail(endpoint: &Endpoint, addr: &NodeAddr, alpn: &[u8]) {
            let conn = endpoint.connect(addr.clone(), alpn).await;
            assert!(matches!(
                &conn,
                Err(ConnectError::Connection { source, .. })
                if matches!(
                    source.as_ref(),
                    ConnectionError::ConnectionClosed(frame)
                    if frame.error_code == TransportErrorCode::crypto(rustls::AlertDescription::NoApplicationProtocol.into())
                )
            ));
        }

        #[derive(Debug, Clone, Default)]
        struct TestProtocol(u32);

        const ALPN_1: &[u8] = b"/iroh/test/1";
        const ALPN_2: &[u8] = b"/iroh/test/2";

        impl ProtocolHandler for TestProtocol {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                connection.close(self.0.into(), b"bye");
                Ok(())
            }
        }

        let server = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let router = Router::builder(server)
            .accept(ALPN_1, TestProtocol(1))
            .spawn();

        let addr = router.endpoint().node_addr().initialized().await?;

        let client = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;

        connect_assert_ok(&client, &addr, ALPN_1, 1).await;
        connect_assert_fail(&client, &addr, ALPN_2).await;

        router.stop_accepting(ALPN_1).await?;
        connect_assert_fail(&client, &addr, ALPN_1).await;
        connect_assert_fail(&client, &addr, ALPN_2).await;

        let outcome = router.accept(ALPN_2, TestProtocol(2)).await?;
        assert_eq!(outcome, AddProtocolOutcome::Inserted);
        connect_assert_fail(&client, &addr, ALPN_1).await;
        connect_assert_ok(&client, &addr, ALPN_2, 2).await;

        let outcome = router.accept(ALPN_1, TestProtocol(3)).await?;
        assert_eq!(outcome, AddProtocolOutcome::Inserted);
        connect_assert_ok(&client, &addr, ALPN_1, 3).await;
        connect_assert_ok(&client, &addr, ALPN_2, 2).await;

        let outcome = router.accept(ALPN_1, TestProtocol(4)).await?;
        assert_eq!(outcome, AddProtocolOutcome::Replaced);
        connect_assert_ok(&client, &addr, ALPN_1, 4).await;

        router.stop_accepting(ALPN_2).await?;
        connect_assert_ok(&client, &addr, ALPN_1, 4).await;
        connect_assert_fail(&client, &addr, ALPN_2).await;

        router.stop_accepting(ALPN_1).await?;
        connect_assert_fail(&client, &addr, ALPN_1).await;
        connect_assert_fail(&client, &addr, ALPN_2).await;

        assert!(matches!(
            router.stop_accepting(ALPN_1).await,
            Err(StopAcceptingError::UnknownAlpn {})
        ));
        assert!(matches!(
            router.stop_accepting(ALPN_2).await,
            Err(StopAcceptingError::UnknownAlpn {})
        ));

        Ok(())
    }
}
