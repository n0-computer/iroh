//! Tools for spawning an accept loop that routes incoming requests to the right protocol.
//!
//! ## Example
//!
//! ```no_run
//! # #[cfg(with_crypto_provider)]
//! # use iroh::{
//! #     endpoint::{BindError, presets},
//! #     protocol::Router,
//! #     Endpoint,
//! # };
//! # use iroh::{
//! #     endpoint::Connection,
//! #     protocol::{AcceptError, ProtocolHandler},
//! # };
//! #
//! # #[cfg(with_crypto_provider)]
//! # async fn test_compile() -> Result<(), BindError> {
//! let endpoint = Endpoint::bind(presets::N0).await?;
//!
//! let router = Router::builder(endpoint).accept(b"/my/alpn", Echo).spawn();
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
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use n0_error::{AnyError, e, stack_error};
use n0_future::{
    join_all,
    task::{self, AbortOnDropHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, error, field::Empty, info_span, trace, warn};

use crate::{
    Endpoint,
    endpoint::{Accepting, Connection, RemoteEndpointIdError, quic},
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
/// # #[cfg(with_crypto_provider)]
/// # {
/// # use std::sync::Arc;
/// # use n0_error::StdResultExt;
/// # use iroh::{endpoint::{Connecting, presets}, protocol::{ProtocolHandler, Router}, Endpoint, EndpointAddr};
/// #
/// # async fn test_compile() -> n0_error::Result<()> {
/// let endpoint = Endpoint::bind(presets::N0).await?;
///
/// let router = Router::builder(endpoint)
///     // .accept(&ALPN, <something>)
///     .spawn();
///
/// // wait until the user wants to
/// tokio::signal::ctrl_c().await.std_context("ctrl+c")?;
/// router.shutdown().await.std_context("shutdown")?;
/// # Ok(())
/// # }
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
#[derive(derive_more::Debug)]
pub struct RouterBuilder {
    endpoint: Endpoint,
    protocols: ProtocolMap,
    #[debug(skip)]
    incoming_filter: Option<IncomingFilter>,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum AcceptError {
    #[error(transparent)]
    Connecting {
        source: crate::endpoint::ConnectingError,
    },
    #[error(transparent)]
    Connection {
        source: crate::endpoint::ConnectionError,
    },
    #[error(transparent)]
    MissingRemoteEndpointId { source: RemoteEndpointIdError },
    #[error("Not allowed.")]
    NotAllowed {},
    #[error(transparent)]
    User { source: AnyError },
}

impl AcceptError {
    /// Creates a new user error from an arbitrary error type.
    // TODO(Frando): Rename to `from_std`
    #[track_caller]
    pub fn from_err<T: std::error::Error + Send + Sync + 'static>(value: T) -> Self {
        e!(AcceptError::User {
            source: AnyError::from_std(value)
        })
    }

    /// Creates a new user error from an arbitrary boxed error.
    #[track_caller]
    pub fn from_boxed(value: Box<dyn std::error::Error + Send + Sync>) -> Self {
        e!(AcceptError::User {
            source: AnyError::from_std_box(value)
        })
    }
}

impl From<std::io::Error> for AcceptError {
    fn from(err: std::io::Error) -> Self {
        Self::from_err(err)
    }
}

impl From<quic::ClosedStream> for AcceptError {
    fn from(err: quic::ClosedStream) -> Self {
        Self::from_err(err)
    }
}

/// Verdict from a [`IncomingFilter`] for an incoming connection.
///
/// The filter can accept the connection, send a retry token to validate
/// the source address, actively refuse the connection, or silently drop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncomingFilterOutcome {
    /// Accept the connection.
    Accept,
    /// Tell the remote to retry with a token (a QUIC `RETRY` packet).
    ///
    /// What this does depends on the connection type:
    ///
    /// - **Direct (UDP) connections** : this is QUIC source address
    ///   validation. If the socket address was spoofed, the retry token is
    ///   sent to the spoofed address, so we never hear from the attacker
    ///   again. If the address was real, the client repeats the connection
    ///   attempt with the token, and the next [`Incoming`] for that flow has
    ///   [`Incoming::remote_addr_validated`] set to `true`. The token is
    ///   bound to the source address.
    ///
    /// - **Relay connections** : there is no source address to validate
    ///   (the relay already vouches for the packet origin), so the
    ///   "validation" itself has no security meaning. However, the retry
    ///   still imposes a real cost on the client: an extra round trip
    ///   through the relay plus the work of sending a fresh ClientHello
    ///   with the token. This filters out adversarial clients that
    ///   don't bother to handle retry tokens, and adds latency before
    ///   we get to the more expensive part of the handshake. The next
    ///   [`Incoming`] for that flow will also have
    ///   [`Incoming::remote_addr_validated`] set to `true`, but again,
    ///   that just means the client cooperated with the retry.
    ///
    /// In short: for direct connections, `Retry` is address validation;
    /// for relay connections, it is a cost-imposition mechanism.
    ///
    /// [`Incoming`]: crate::endpoint::Incoming
    /// [`Incoming::remote_addr_validated`]: crate::endpoint::Incoming::remote_addr_validated
    Retry,
    /// Actively refuse the connection. The remote will receive a
    /// CONNECTION_REFUSED error immediately.
    Reject,
    /// Ignore the connection entirely. The remote gets no response and will
    /// eventually time out.
    Ignore,
}

/// Filter predicate used for early filtering of incoming connections before the handshake completes.
///
/// See [`RouterBuilder::incoming_filter`] for more details.
pub type IncomingFilter =
    Arc<dyn Fn(&crate::endpoint::Incoming) -> IncomingFilterOutcome + Send + Sync + 'static>;

/// Handler for incoming connections.
///
/// A router accepts connections for arbitrary ALPN protocols.
///
/// With this trait, you can handle incoming connections for any protocol.
///
/// Implement this trait on a struct that should handle incoming connections.
/// The protocol handler must then be registered on the endpoint for an ALPN protocol with
/// [`crate::protocol::RouterBuilder::accept`].
///
/// See the [module documentation](crate::protocol) for an example.
pub trait ProtocolHandler: Send + Sync + std::fmt::Debug + 'static {
    /// Optional interception point to handle the `Accepting` state.
    ///
    /// Can be implemented as `async fn on_accepting(&self, accepting: Accepting) -> Result<Connection>`.
    ///
    /// Typically, this method is used as an early interception point to accept
    /// or reject a connection.
    ///
    /// However, this method can also be used to implement the accept side of a
    /// 0-RTT connection.
    ///
    /// ## 0-RTT
    ///
    /// `ProtocolHandler::on_accepting` allows you to take over the connection
    /// state machine early in the handshake processes, by calling [`Accepting::into_0rtt`].
    ///
    /// When working with 0-RTT, you may want to implement all of your protocol
    /// logic in `on_accepting`. This is fine because `on_accepting` can handle
    /// long-running processes. In this case, the [`ProtocolHandler::accept`] method
    /// can simply return `Ok(())`.
    fn on_accepting(
        &self,
        accepting: Accepting,
    ) -> impl Future<Output = Result<Connection, AcceptError>> + Send {
        async move {
            let conn = accepting.await?;
            Ok(conn)
        }
    }

    /// Handle an incoming connection.
    ///
    /// Can be implemented as `async fn accept(&self, connection: Connection) -> Result<()>`.
    ///
    /// The returned future runs on a freshly spawned tokio task so it can be long-running. Once
    /// `accept()` returns, the connection is dropped. This means that it will be closed
    /// if there are no other clones of the connection.  If there is a protocol error, you
    /// can use [`Connection::close`] to send an error code to the remote peer. Returning
    /// an `Err<AcceptError>` will also drop the connection and log a warning, but no
    /// dedicated error code will be sent to the peer, so it's recommended to explicitly
    /// close the connection within your accept handler.
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
    async fn on_accepting(&self, accepting: Accepting) -> Result<Connection, AcceptError> {
        self.as_ref().on_accepting(accepting).await
    }

    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.as_ref().accept(conn).await
    }

    async fn shutdown(&self) {
        self.as_ref().shutdown().await
    }
}

impl<T: ProtocolHandler> ProtocolHandler for Box<T> {
    async fn on_accepting(&self, accepting: Accepting) -> Result<Connection, AcceptError> {
        self.as_ref().on_accepting(accepting).await
    }

    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.as_ref().accept(conn).await
    }

    async fn shutdown(&self) {
        self.as_ref().shutdown().await
    }
}

impl<T: ProtocolHandler> From<T> for Box<dyn DynProtocolHandler> {
    fn from(value: T) -> Self {
        Box::new(value)
    }
}

/// A dyn-compatible version of [`ProtocolHandler`] that returns boxed futures.
///
/// Any type that implements [`ProtocolHandler`] automatically also implements [`DynProtocolHandler`].
/// There is a also [`From`] impl to turn any type that implements [`ProtocolHandler`] into a
/// `Box<dyn DynProtocolHandler>`.
//
// We are not using [`n0_future::boxed::BoxFuture] because we don't need a `'static` bound
// on these futures.
pub trait DynProtocolHandler: Send + Sync + std::fmt::Debug + 'static {
    /// See [`ProtocolHandler::on_accepting`].
    fn on_accepting(
        &self,
        accepting: Accepting,
    ) -> Pin<Box<dyn Future<Output = Result<Connection, AcceptError>> + Send + '_>> {
        Box::pin(async move {
            let conn = accepting.await?;
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

    fn on_accepting(
        &self,
        accepting: Accepting,
    ) -> Pin<Box<dyn Future<Output = Result<Connection, AcceptError>> + Send + '_>> {
        Box::pin(<Self as ProtocolHandler>::on_accepting(self, accepting))
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
    pub(crate) fn insert(&mut self, alpn: Vec<u8>, handler: Box<dyn DynProtocolHandler>) {
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

        // MutexGuard is not held across await point
        let task = self.task.lock().expect("poisoned").take();
        if let Some(task) = task {
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
            incoming_filter: None,
        }
    }

    /// Sets a filter that decides whether to accept an incoming connection before the
    /// TLS handshake completes.
    ///
    /// The filter is called with the raw [`Incoming`] for each connection attempt
    /// and returns an [`IncomingFilterOutcome`] that determines what happens next.
    ///
    /// Implementers have full access to the [`Incoming`] and can use any of its
    /// methods (including [`Incoming::decrypt`]) to make their decision. Note that
    /// `decrypt()` is relatively expensive, so filters should reject based on
    /// cheaper signals (e.g. remote address) first.
    ///
    /// [`Incoming`]: crate::endpoint::Incoming
    /// [`Incoming::decrypt`]: crate::endpoint::Incoming::decrypt
    pub fn incoming_filter(mut self, filter: IncomingFilter) -> Self {
        self.incoming_filter = Some(filter);
        self
    }

    /// Configures the router to accept the [`ProtocolHandler`] when receiving a connection
    /// with this `alpn`.
    ///
    /// `handler` can either be a type that implements [`ProtocolHandler`] or a
    /// [`Box<dyn DynProtocolHandler>`].
    ///
    /// [`Box<dyn DynProtocolHandler>`]: DynProtocolHandler
    pub fn accept(
        mut self,
        alpn: impl AsRef<[u8]>,
        handler: impl Into<Box<dyn DynProtocolHandler>>,
    ) -> Self {
        self.protocols
            .insert(alpn.as_ref().to_vec(), handler.into());
        self
    }

    /// Returns the [`Endpoint`] of the endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Spawns an accept loop and returns a handle to it encapsulated as the [`Router`].
    #[must_use = "Router aborts when dropped, use Router::shutdown to shut the router down cleanly"]
    pub fn spawn(self) -> Router {
        // Update the endpoint with our alpns.
        let alpns = self
            .protocols
            .alpns()
            .map(|alpn| alpn.to_vec())
            .collect::<Vec<_>>();

        let protocols = Arc::new(self.protocols);
        let incoming_filter = self.incoming_filter;
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

                        if let Some(filter) = &incoming_filter {
                            match filter(&incoming) {
                                IncomingFilterOutcome::Accept => {}
                                IncomingFilterOutcome::Retry => {
                                    if !incoming.remote_addr_validated() {
                                        warn!(
                                            "filter returned Retry for an already validated connection",
                                        );
                                    }
                                    if let Err(err) = incoming.retry() {
                                        err.into_incoming().refuse();
                                    }
                                    continue;
                                }
                                IncomingFilterOutcome::Reject => {
                                    incoming.refuse();
                                    continue;
                                }
                                IncomingFilterOutcome::Ignore => {
                                    incoming.ignore();
                                    continue;
                                }
                            }
                        }

                        let protocols = protocols.clone();
                        let token = handler_cancel_token.child_token();
                        let span = info_span!("router.accept", me=%endpoint.id().fmt_short(), remote=Empty, alpn=Empty);
                        join_set.spawn(async move {
                            token.run_until_cancelled(handle_connection(incoming, protocols)).await
                        }.instrument(span));
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
        let task = task::spawn(run_loop_fut.instrument(tracing::Span::current()));
        let task = AbortOnDropHandle::new(task);

        Router {
            endpoint: self.endpoint,
            task: Arc::new(Mutex::new(Some(task))),
            cancel_token: cancel,
        }
    }
}

async fn handle_connection(incoming: crate::endpoint::Incoming, protocols: Arc<ProtocolMap>) {
    let mut accepting = match incoming.accept() {
        Ok(conn) => conn,
        Err(err) => {
            warn!("Ignoring connection: accepting failed: {err:#}");
            return;
        }
    };
    let alpn = match accepting.alpn().await {
        Ok(alpn) => alpn,
        Err(err) => {
            warn!("Ignoring connection: invalid handshake: {err:#}");
            return;
        }
    };
    tracing::Span::current().record("alpn", String::from_utf8_lossy(&alpn).to_string());

    let Some(handler) = protocols.get(&alpn) else {
        warn!("Ignoring connection: unsupported ALPN protocol");
        return;
    };
    match handler.on_accepting(accepting).await {
        Ok(connection) => {
            tracing::Span::current().record(
                "remote",
                tracing::field::display(connection.remote_id().fmt_short()),
            );

            if let Err(err) = handler.accept(connection).await {
                warn!("Handling incoming connection ended with error: {err}");
            }
        }
        Err(err) => {
            warn!("Accepting incoming connection ended with error: {err}");
        }
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::{sync::Mutex, time::Duration};

    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;

    use super::*;
    use crate::endpoint::{
        ApplicationClose, BeforeConnectOutcome, ConnectError, ConnectWithOptsError,
        ConnectionError, EndpointHooks, presets,
    };

    #[tokio::test]
    async fn test_shutdown() -> Result {
        let endpoint = Endpoint::bind(presets::Minimal).await?;
        let router = Router::builder(endpoint.clone()).spawn();

        assert!(!router.is_shutdown());
        assert!(!endpoint.is_closed());

        router.shutdown().await.anyerr()?;

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
    async fn test_limiter_hook() -> Result {
        // tracing_subscriber::fmt::try_init().ok();
        #[derive(Debug, Default)]
        struct LimitHook;
        impl EndpointHooks for LimitHook {
            async fn before_connect<'a>(
                &'a self,
                _remote_addr: &'a iroh_base::EndpointAddr,
                alpn: &'a [u8],
            ) -> BeforeConnectOutcome {
                assert_eq!(alpn, ECHO_ALPN);

                // deny all access
                BeforeConnectOutcome::Reject
            }
        }

        let e1 = Endpoint::bind(presets::Minimal).await?;

        let r1 = Router::builder(e1.clone()).accept(ECHO_ALPN, Echo).spawn();

        let addr1 = r1.endpoint().addr();
        dbg!(&addr1);
        let e2 = Endpoint::builder(presets::Minimal)
            .hooks(LimitHook)
            .bind()
            .await?;

        println!("connecting");
        let conn_err = e2.connect(addr1, ECHO_ALPN).await.unwrap_err();

        assert!(matches!(
            conn_err,
            ConnectError::Connect {
                source: ConnectWithOptsError::LocallyRejected { .. },
                ..
            }
        ));

        r1.shutdown().await.anyerr()?;
        e2.close().await;

        Ok(())
    }

    /// Test that `Accepting::remote_addr()` is consistent with `Incoming::remote_addr()`.
    #[tokio::test]
    #[traced_test]
    async fn test_accepting_remote_addr() -> Result {
        use crate::endpoint::{IncomingAddr, presets};

        let e1 = Endpoint::builder(presets::Minimal)
            .alpns(vec![ECHO_ALPN.to_vec()])
            .bind()
            .await?;
        let addr1 = e1.addr();

        let e2 = Endpoint::bind(presets::Minimal).await?;

        // Spawn the client connect so it runs concurrently with accept.
        let connect_task = tokio::spawn({
            let addr1 = addr1.clone();
            let e2 = e2.clone();
            async move { e2.connect(addr1, ECHO_ALPN).await }
        });

        let incoming = e1.accept().await.expect("accept");
        let incoming_addr = incoming.remote_addr();
        assert!(matches!(incoming_addr, IncomingAddr::Ip(_)));

        let accepting = incoming.accept().anyerr()?;
        assert_eq!(incoming_addr, accepting.remote_addr());

        // Clean up.
        drop(accepting);
        drop(connect_task);
        e1.close().await;
        e2.close().await;
        Ok(())
    }

    mod incoming_filter {
        use std::{
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering::Relaxed},
            },
            time::Duration,
        };

        use n0_error::{Result, StdResultExt};
        use n0_tracing_test::traced_test;

        use crate::{
            Endpoint, EndpointAddr,
            endpoint::presets,
            protocol::{
                IncomingFilterOutcome, Router,
                tests::{ECHO_ALPN, Echo},
            },
        };

        /// Two direct endpoints with a filtered router on the first.
        ///
        /// Binds to IPv4 loopback only so retry-token validation works on
        /// multi-homed CI hosts (tokens are tied to the source address).
        async fn direct_pair<F>(filter: F) -> Result<(Router, Endpoint, EndpointAddr)>
        where
            F: Fn(&crate::endpoint::Incoming) -> IncomingFilterOutcome + Send + Sync + 'static,
        {
            let e1 = Endpoint::builder(presets::Minimal)
                .clear_ip_transports()
                .bind_addr((std::net::Ipv4Addr::LOCALHOST, 0))
                .anyerr()?
                .bind()
                .await?;
            let r1 = Router::builder(e1.clone())
                .incoming_filter(Arc::new(filter))
                .accept(ECHO_ALPN, Echo)
                .spawn();
            let addr = r1.endpoint().addr();
            let e2 = Endpoint::builder(presets::Minimal)
                .clear_ip_transports()
                .bind_addr((std::net::Ipv4Addr::LOCALHOST, 0))
                .anyerr()?
                .bind()
                .await?;
            Ok((r1, e2, addr))
        }

        /// Two relay-only endpoints with a filtered router on the first.
        async fn relay_pair<F>(
            filter: F,
        ) -> Result<(Router, Endpoint, EndpointAddr, impl std::any::Any)>
        where
            F: Fn(&crate::endpoint::Incoming) -> IncomingFilterOutcome + Send + Sync + 'static,
        {
            let (_relay_map, relay_url, guard) =
                crate::test_utils::run_relay_server().await.anyerr()?;
            let relay_mode = crate::RelayMode::Custom(crate::RelayMap::from(relay_url.clone()));

            let e1 = Endpoint::builder(presets::Minimal)
                .relay_mode(relay_mode.clone())
                .ca_roots_config(crate::tls::CaRootsConfig::insecure_skip_verify())
                .bind()
                .await?;
            let r1 = Router::builder(e1.clone())
                .incoming_filter(Arc::new(filter))
                .accept(ECHO_ALPN, Echo)
                .spawn();
            let addr = EndpointAddr::new(e1.id()).with_relay_url(relay_url);
            let e2 = Endpoint::builder(presets::Minimal)
                .relay_mode(relay_mode)
                .ca_roots_config(crate::tls::CaRootsConfig::insecure_skip_verify())
                .bind()
                .await?;
            Ok((r1, e2, addr, guard))
        }

        #[tokio::test]
        #[traced_test]
        async fn addr_retry() -> Result {
            let (r1, e2, addr) = direct_pair(|incoming| {
                if !incoming.remote_addr_validated() {
                    IncomingFilterOutcome::Retry
                } else {
                    IncomingFilterOutcome::Accept
                }
            })
            .await?;
            // Server sends retry (unvalidated), then accepts once validated.
            assert!(e2.connect(addr, ECHO_ALPN).await.is_ok());
            r1.shutdown().await.anyerr()?;
            e2.close().await;
            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn addr_reject() -> Result {
            let (r1, e2, addr) = direct_pair(|_| IncomingFilterOutcome::Reject).await?;
            assert!(e2.connect(addr, ECHO_ALPN).await.is_err());
            r1.shutdown().await.anyerr()?;
            e2.close().await;
            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn addr_ignore() -> Result {
            let (r1, e2, addr) = direct_pair(|_| IncomingFilterOutcome::Ignore).await?;
            // No response at all — connect times out.
            let result =
                tokio::time::timeout(Duration::from_millis(500), e2.connect(addr, ECHO_ALPN)).await;
            assert!(result.is_err(), "expected timeout");
            r1.shutdown().await.anyerr()?;
            e2.close().await;
            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn relay_reject() -> Result {
            let (r1, e2, addr, _guard) = relay_pair(|_| IncomingFilterOutcome::Reject).await?;
            assert!(e2.connect(addr, ECHO_ALPN).await.is_err());
            r1.shutdown().await.anyerr()?;
            e2.close().await;
            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn relay_ignore() -> Result {
            let (r1, e2, addr, _guard) = relay_pair(|_| IncomingFilterOutcome::Ignore).await?;
            let result =
                tokio::time::timeout(Duration::from_millis(500), e2.connect(addr, ECHO_ALPN)).await;
            assert!(result.is_err(), "expected timeout");
            r1.shutdown().await.anyerr()?;
            e2.close().await;
            Ok(())
        }

        /// Verify that returning `Retry` for a direct connection causes the
        /// remote to retry with a token, after which `validated` is true.
        #[tokio::test]
        #[traced_test]
        async fn addr_retry_then_validated() -> Result {
            let saw_validated = Arc::<AtomicBool>::default();
            let saw_unvalidated = Arc::<AtomicBool>::default();
            let (sv, su) = (saw_validated.clone(), saw_unvalidated.clone());

            let (r1, e2, addr) = direct_pair(move |incoming| {
                if incoming.remote_addr_validated() {
                    sv.store(true, Relaxed);
                    IncomingFilterOutcome::Accept
                } else {
                    su.store(true, Relaxed);
                    IncomingFilterOutcome::Retry
                }
            })
            .await?;

            // The connection should now succeed: first attempt returns Retry,
            // the client retries with the token, the second attempt is
            // validated and accepted.
            let _conn = e2.connect(addr, ECHO_ALPN).await?;

            assert!(saw_unvalidated.load(Relaxed));
            assert!(saw_validated.load(Relaxed));

            r1.shutdown().await.anyerr()?;
            e2.close().await;
            Ok(())
        }

        /// Verify that returning `Retry` for a relay connection also causes
        /// the remote to retry with a token. The "validation" has no
        /// security meaning over a relay, but it does impose a round-trip
        /// cost on the client.
        #[tokio::test]
        #[traced_test]
        async fn relay_retry_then_validated() -> Result {
            let saw_validated = Arc::<AtomicBool>::default();
            let saw_unvalidated = Arc::<AtomicBool>::default();
            let (sv, su) = (saw_validated.clone(), saw_unvalidated.clone());

            let (r1, e2, addr, _guard) = relay_pair(move |incoming| {
                if incoming.remote_addr_validated() {
                    sv.store(true, Relaxed);
                    IncomingFilterOutcome::Accept
                } else {
                    su.store(true, Relaxed);
                    IncomingFilterOutcome::Retry
                }
            })
            .await?;

            let _conn = e2.connect(addr, ECHO_ALPN).await?;

            assert!(
                saw_unvalidated.load(Relaxed),
                "expected unvalidated incoming"
            );
            assert!(
                saw_validated.load(Relaxed),
                "expected validated incoming after retry"
            );

            r1.shutdown().await.anyerr()?;
            e2.close().await;
            Ok(())
        }
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
        let endpoint = Endpoint::bind(presets::Minimal).await?;
        let router = Router::builder(endpoint)
            .accept(TEST_ALPN, TestProtocol::default())
            .spawn();
        eprintln!("waiting for endpoint addr");
        let addr = router.endpoint().addr();

        eprintln!("creating ep2");
        let endpoint2 = Endpoint::bind(presets::Minimal).await?;
        eprintln!("connecting to {addr:?}");
        let conn = endpoint2.connect(addr, TEST_ALPN).await?;

        eprintln!("starting shutdown");
        router.shutdown().await.anyerr()?;

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
}
