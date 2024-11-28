//! Tools for spawning an accept loop that routes incoming requests to the right protocol.
//!
//! ## Example
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use anyhow::Result;
//! # use futures_lite::future::Boxed as BoxedFuture;
//! # use iroh::{endpoint::Connecting, protocol::{ProtocolHandler, Router}, Endpoint, NodeAddr};
//! #
//! # async fn test_compile() -> Result<()> {
//! let endpoint = Endpoint::builder().discovery_n0().bind().await?;
//!
//! const ALPN: &[u8] = b"/my/alpn";
//! let router = Router::builder(endpoint)
//!     .accept(&ALPN, Arc::new(Echo))
//!     .spawn()
//!     .await?;
//! # Ok(())
//! # }
//!
//! // The protocol definition:
//! #[derive(Debug, Clone)]
//! struct Echo;
//!
//! impl ProtocolHandler for Echo {
//!     fn accept(self: Arc<Self>, connecting: Connecting) -> BoxedFuture<Result<()>> {
//!         Box::pin(async move {
//!             let connection = connecting.await?;
//!             let (mut send, mut recv) = connection.accept_bi().await?;
//!
//!             // Echo any bytes received back directly.
//!             let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
//!
//!             send.finish()?;
//!             connection.closed().await;
//!
//!             Ok(())
//!         })
//!     }
//! }
//! ```
use std::{any::Any, collections::BTreeMap, sync::Arc};

use anyhow::{anyhow, Result};
use futures_buffered::join_all;
use futures_lite::future::Boxed as BoxedFuture;
use futures_util::{
    future::{MapErr, Shared},
    FutureExt, TryFutureExt,
};
use tokio::task::{JoinError, JoinSet};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, error, warn};

use crate::{endpoint::Connecting, Endpoint};

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
/// # use anyhow::Result;
/// # use futures_lite::future::Boxed as BoxedFuture;
/// # use iroh::{endpoint::Connecting, protocol::{ProtocolHandler, Router}, Endpoint, NodeAddr};
/// #
/// # async fn test_compile() -> Result<()> {
/// let endpoint = Endpoint::builder().discovery_n0().bind().await?;
///
/// let router = Router::builder(endpoint)
///     // .accept(&ALPN, <something>)
///     .spawn()
///     .await?;
///
/// // wait until the user wants to
/// tokio::signal::ctrl_c().await?;
/// router.shutdown().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Router {
    endpoint: Endpoint,
    protocols: Arc<ProtocolMap>,
    // `Router` needs to be `Clone + Send`, and we need to `task.await` in its `shutdown()` impl.
    // So we need
    // - `Shared` so we can `task.await` from all `Node` clones
    // - `MapErr` to map the `JoinError` to a `String`, because `JoinError` is `!Clone`
    // - `AbortOnDropHandle` to make sure that the `task` is cancelled when all `Node`s are dropped
    //   (`Shared` acts like an `Arc` around its inner future).
    task: Shared<MapErr<AbortOnDropHandle<()>, JoinErrToStr>>,
    cancel_token: CancellationToken,
}

type JoinErrToStr = Box<dyn Fn(JoinError) -> String + Send + Sync + 'static>;

/// Builder for creating a [`Router`] for accepting protocols.
#[derive(Debug)]
pub struct RouterBuilder {
    endpoint: Endpoint,
    protocols: ProtocolMap,
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
pub trait ProtocolHandler: Send + Sync + IntoArcAny + std::fmt::Debug + 'static {
    /// Handle an incoming connection.
    ///
    /// This runs on a freshly spawned tokio task so this can be long-running.
    fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>>;

    /// Called when the node shuts down.
    fn shutdown(self: Arc<Self>) -> BoxedFuture<()> {
        Box::pin(async move {})
    }
}

/// Helper trait to facilite casting from `Arc<dyn T>` to `Arc<dyn Any>`.
///
/// This trait has a blanket implementation so there is no need to implement this yourself.
pub trait IntoArcAny {
    /// Casts `Arc<Self>` into `Arc<dyn Any + Send + Sync>`.
    fn into_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

impl<T: Send + Sync + 'static> IntoArcAny for T {
    fn into_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// A typed map of protocol handlers, mapping them from ALPNs.
#[derive(Debug, Clone, Default)]
pub struct ProtocolMap(BTreeMap<Vec<u8>, Arc<dyn ProtocolHandler>>);

impl ProtocolMap {
    /// Returns the registered protocol handler for an ALPN as a concrete type.
    pub fn get_typed<P: ProtocolHandler>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        let protocol: Arc<dyn ProtocolHandler> = self.0.get(alpn)?.clone();
        let protocol_any: Arc<dyn Any + Send + Sync> = protocol.into_arc_any();
        let protocol_ref = Arc::downcast(protocol_any).ok()?;
        Some(protocol_ref)
    }

    /// Returns the registered protocol handler for an ALPN as a [`Arc<dyn ProtocolHandler>`].
    pub fn get(&self, alpn: &[u8]) -> Option<Arc<dyn ProtocolHandler>> {
        self.0.get(alpn).cloned()
    }

    /// Inserts a protocol handler.
    pub fn insert(&mut self, alpn: Vec<u8>, handler: Arc<dyn ProtocolHandler>) {
        self.0.insert(alpn, handler);
    }

    /// Returns an iterator of all registered ALPN protocol identifiers.
    pub fn alpns(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.0.keys()
    }

    /// Shuts down all protocol handlers.
    ///
    /// Calls and awaits [`ProtocolHandler::shutdown`] for all registered handlers concurrently.
    pub async fn shutdown(&self) {
        let handlers = self.0.values().cloned().map(ProtocolHandler::shutdown);
        join_all(handlers).await;
    }
}

impl Router {
    /// Creates a new [`Router`] using given [`Endpoint`].
    pub fn builder(endpoint: Endpoint) -> RouterBuilder {
        RouterBuilder::new(endpoint)
    }

    /// Returns a protocol handler for an ALPN.
    ///
    /// This downcasts to the concrete type and returns `None` if the handler registered for `alpn`
    /// does not match the passed type.
    pub fn get_protocol<P: ProtocolHandler>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        self.protocols.get_typed(alpn)
    }

    /// Returns the [`Endpoint`] stored in this router.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Shuts down the accept loop cleanly.
    ///
    /// If some [`ProtocolHandler`] panicked in the accept loop, this will propagate
    /// that panic into the result here.
    pub async fn shutdown(self) -> Result<()> {
        // Trigger shutdown of the main run task by activating the cancel token.
        self.cancel_token.cancel();

        // Wait for the main task to terminate.
        self.task.await.map_err(|err| anyhow!(err))?;

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
    pub fn accept(mut self, alpn: impl AsRef<[u8]>, handler: Arc<dyn ProtocolHandler>) -> Self {
        self.protocols.insert(alpn.as_ref().to_vec(), handler);
        self
    }

    /// Returns the [`Endpoint`] of the node.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns a protocol handler for an ALPN.
    ///
    /// This downcasts to the concrete type and returns `None` if the handler registered for `alpn`
    /// does not match the passed type.
    pub fn get_protocol<P: ProtocolHandler>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        self.protocols.get_typed(alpn)
    }

    /// Spawns an accept loop and returns a handle to it encapsulated as the [`Router`].
    pub async fn spawn(self) -> Result<Router> {
        // Update the endpoint with our alpns.
        let alpns = self
            .protocols
            .alpns()
            .map(|alpn| alpn.to_vec())
            .collect::<Vec<_>>();

        let protocols = Arc::new(self.protocols);
        if let Err(err) = self.endpoint.set_alpns(alpns) {
            shutdown(&self.endpoint, protocols.clone()).await;
            return Err(err);
        }

        let mut join_set = JoinSet::new();
        let endpoint = self.endpoint.clone();
        let protos = protocols.clone();
        let cancel = CancellationToken::new();
        let cancel_token = cancel.clone();

        let run_loop_fut = async move {
            let protocols = protos;
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        break;
                    },
                    // handle incoming p2p connections.
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else {
                            break;
                        };

                        let protocols = protocols.clone();
                        join_set.spawn(async move {
                            handle_connection(incoming, protocols).await;
                            anyhow::Ok(())
                        });
                    },
                    // handle task terminations and quit on panics.
                    res = join_set.join_next(), if !join_set.is_empty() => {
                        match res {
                            Some(Err(outer)) => {
                                if outer.is_panic() {
                                    error!("Task panicked: {outer:?}");
                                    break;
                                } else if outer.is_cancelled() {
                                    debug!("Task cancelled: {outer:?}");
                                } else {
                                    error!("Task failed: {outer:?}");
                                    break;
                                }
                            }
                            Some(Ok(Err(inner))) => {
                                debug!("Task errored: {inner:?}");
                            }
                            _ => {}
                        }
                    },
                }
            }

            shutdown(&endpoint, protocols).await;

            // Abort remaining tasks.
            tracing::info!("Shutting down remaining tasks");
            join_set.shutdown().await;
        };
        let task = tokio::task::spawn(run_loop_fut);
        let task = AbortOnDropHandle::new(task)
            .map_err(Box::new(|e: JoinError| e.to_string()) as JoinErrToStr)
            .shared();

        Ok(Router {
            endpoint: self.endpoint,
            protocols,
            task,
            cancel_token: cancel,
        })
    }
}

/// Shutdown the different parts of the router concurrently.
async fn shutdown(endpoint: &Endpoint, protocols: Arc<ProtocolMap>) {
    let error_code = 1u16;

    // We ignore all errors during shutdown.
    let _ = tokio::join!(
        // Close the endpoint.
        // Closing the Endpoint is the equivalent of calling Connection::close on all
        // connections: Operations will immediately fail with ConnectionError::LocallyClosed.
        // All streams are interrupted, this is not graceful.
        endpoint.close(error_code.into(), b"provider terminating"),
        // Shutdown protocol handlers.
        protocols.shutdown(),
    );
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
    if let Err(err) = handler.accept(connecting).await {
        warn!("Handling incoming connection ended with error: {err}");
    }
}
