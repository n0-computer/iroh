//! This example showcases how to build a custom router.
//!
//! We will create a router that allows adding or removing protocols at runtime.

use iroh::{
    endpoint::{ApplicationClose, ConnectError, Connection, ConnectionError, TransportErrorCode},
    protocol::{AcceptError, ProtocolHandler},
    Endpoint, NodeAddr, RelayMode, Watcher,
};

use self::router::{AddProtocolOutcome, Router, StopAcceptingError};

#[tokio::main]
async fn main() -> n0_snafu::Result {
    // Create our server endpoint.
    let server = Endpoint::builder()
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;

    // Create our custom router, and accept a protocol at `ALPN_1`.
    // Our protocol closes all connections immediately with the passed-in error code.
    let router = Router::builder(server)
        .accept(ALPN_1, TestProtocol(1))
        .spawn();

    let addr = router.endpoint().node_addr().initialized().await?;

    // Create our client endpoint.
    let client = Endpoint::builder()
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;

    // Assert that we can connect on ALPN_1, but not on ALPN_2.
    connect_assert_ok(&client, &addr, ALPN_1, 1).await;
    connect_assert_fail(&client, &addr, ALPN_2).await;

    // Stop accepting ALPN_1 and assert that connections now fail.
    router.stop_accepting(ALPN_1).await?;
    connect_assert_fail(&client, &addr, ALPN_1).await;
    connect_assert_fail(&client, &addr, ALPN_2).await;

    // Start accepting ALPN_2.
    let outcome = router.accept(ALPN_2, TestProtocol(2)).await?;
    assert_eq!(outcome, AddProtocolOutcome::Inserted);
    connect_assert_fail(&client, &addr, ALPN_1).await;
    connect_assert_ok(&client, &addr, ALPN_2, 2).await;

    // Start accepting ALPN_1 again.
    let outcome = router.accept(ALPN_1, TestProtocol(3)).await?;
    assert_eq!(outcome, AddProtocolOutcome::Inserted);
    connect_assert_ok(&client, &addr, ALPN_1, 3).await;
    connect_assert_ok(&client, &addr, ALPN_2, 2).await;

    // Replace the protocol handler at ALPN_1 and assert that we get
    // the close reason code from the newly inserted protocol.
    let outcome = router.accept(ALPN_1, TestProtocol(4)).await?;
    assert_eq!(outcome, AddProtocolOutcome::Replaced);
    connect_assert_ok(&client, &addr, ALPN_1, 4).await;

    // Stop accepting ALPN_2.
    router.stop_accepting(ALPN_2).await?;
    connect_assert_ok(&client, &addr, ALPN_1, 4).await;
    connect_assert_fail(&client, &addr, ALPN_2).await;

    // Stop accepting ALPN_1.
    router.stop_accepting(ALPN_1).await?;
    connect_assert_fail(&client, &addr, ALPN_1).await;
    connect_assert_fail(&client, &addr, ALPN_2).await;

    // Assert that stop_accepting with a removed protocol produces an error.
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

async fn connect_assert_ok(endpoint: &Endpoint, addr: &NodeAddr, alpn: &[u8], expected_code: u32) {
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

pub mod router {
    use std::{collections::BTreeMap, sync::Arc, time::Duration};

    use futures_util::future::join_all;
    use iroh::{
        protocol::{DynProtocolHandler, ProtocolHandler},
        Endpoint,
    };
    use n0_future::{
        task::{self, AbortOnDropHandle},
        time,
    };
    use snafu::Snafu;
    use tokio::{
        sync::{mpsc, oneshot, Mutex},
        task::JoinSet,
    };
    use tokio_util::sync::CancellationToken;
    use tracing::{debug, error, info_span, trace, warn, Instrument};

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

    /// A typed map of protocol handlers, mapping them from ALPNs.
    #[derive(Debug, Default)]
    pub(crate) struct ProtocolMap(
        std::sync::RwLock<BTreeMap<Vec<u8>, Arc<dyn DynProtocolHandler>>>,
    );

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
        pub async fn stop_accepting(
            &self,
            alpn: impl AsRef<[u8]>,
        ) -> Result<(), StopAcceptingError> {
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

    /// Timeout applied to [`ProtocolHandler::shutdown] futures.
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

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

    async fn handle_connection(incoming: iroh::endpoint::Incoming, protocols: Arc<ProtocolMap>) {
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
}
