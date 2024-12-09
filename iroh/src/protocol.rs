//! Tools for spawning an accept loop that routes incoming requests to the right protocol.
//!
//! ## Example
//!
//! ```no_run
//! # use anyhow::Result;
//! # use futures_lite::future::Boxed as BoxedFuture;
//! # use iroh::{endpoint::Connecting, protocol::{ProtocolHandler, Router}, Endpoint, NodeAddr};
//! #
//! # async fn test_compile() -> Result<()> {
//! let endpoint = Endpoint::builder().discovery_n0().bind().await?;
//!
//! let router = Router::builder(endpoint)
//!     .accept(b"/my/alpn", Echo)
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
//!     fn accept(&self, connecting: Connecting) -> BoxedFuture<Result<()>> {
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
use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use futures_buffered::join_all;
use futures_lite::future::Boxed as BoxedFuture;
use futures_util::future;
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{error, info_span, trace, warn, Instrument};

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

/// Handler for incoming connections.
///
/// A router accepts connections for arbitrary ALPN protocols.
///
/// With this trait, you can handle incoming connections for any protocol.
///
/// Implement this trait on a struct that should handle incoming connections.
/// The protocol handler must then be registered on the node for an ALPN protocol with
/// [`crate::protocol::RouterBuilder::accept`].
pub trait ProtocolHandler: Send + Sync + std::fmt::Debug + 'static {
    /// Handle an incoming connection.
    ///
    /// This runs on a freshly spawned tokio task so this can be long-running.
    fn accept(&self, conn: Connecting) -> BoxedFuture<Result<()>>;

    /// Called when the node shuts down.
    fn shutdown(&self) -> BoxedFuture<()> {
        Box::pin(async move {})
    }
}

// impl<T: ProtocolHandler> ProtocolHandler for Arc<T> {
//     fn accept(&self, conn: Connecting) -> BoxedFuture<Result<()>> {
//         self.as_ref().accept(conn)
//     }

//     fn shutdown(&self) -> BoxedFuture<()> {
//         self.as_ref().shutdown()
//     }
// }

// impl<T: ProtocolHandler> ProtocolHandler for Box<T> {
//     fn accept(&self, conn: Connecting) -> BoxedFuture<Result<()>> {
//         self.as_ref().accept(conn)
//     }

//     fn shutdown(&self) -> BoxedFuture<()> {
//         self.as_ref().shutdown()
//     }
// }

/// A trait for protocol handlers that can be implemented without boxing.
pub trait UnboxedProtocolHandler: Sized + Send + Sync + std::fmt::Debug + Clone + 'static {
    /// Handle an incoming connection.
    ///
    /// Unboxed equivalent of [`ProtocolHandler::accept`].
    fn accept(
        self,
        conn: Connecting,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static;

    /// Called when the node shuts down.
    ///
    /// Unboxed equivalent of [`ProtocolHandler::shutdown`].
    fn shutdown(self) -> impl std::future::Future<Output = ()> + Send + 'static {
        future::ready(())
    }
}

impl<T: UnboxedProtocolHandler> ProtocolHandler for T {
    fn accept(&self, conn: Connecting) -> BoxedFuture<Result<()>> {
        Box::pin(UnboxedProtocolHandler::accept(self.clone(), conn))
    }

    fn shutdown(&self) -> BoxedFuture<()> {
        Box::pin(UnboxedProtocolHandler::shutdown(self.clone()))
    }
}

/// A typed map of protocol handlers, mapping them from ALPNs.
#[derive(Debug, Default)]
pub(crate) struct ProtocolMap(BTreeMap<Vec<u8>, Box<dyn ProtocolHandler>>);

impl ProtocolMap {
    /// Returns the registered protocol handler for an ALPN as a [`Arc<dyn ProtocolHandler>`].
    pub(crate) fn get(&self, alpn: &[u8]) -> Option<&dyn ProtocolHandler> {
        self.0.get(alpn).map(|p| &**p)
    }

    /// Inserts a protocol handler.
    pub(crate) fn insert(&mut self, alpn: Vec<u8>, handler: Box<dyn ProtocolHandler>) {
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
    pub async fn shutdown(&self) -> Result<()> {
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
    pub fn accept<T: ProtocolHandler>(mut self, alpn: impl AsRef<[u8]>, handler: T) -> Self {
        let handler = Box::new(handler);
        self.protocols.insert(alpn.as_ref().to_vec(), handler);
        self
    }

    /// Returns the [`Endpoint`] of the node.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
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

        // We use a child token of the endpoint, to ensure that this is shutdown
        // when the endpoint is shutdown, but that we can shutdown ourselves independently.
        let cancel = endpoint.cancel_token().child_token();
        let cancel_token = cancel.clone();

        let run_loop_fut = async move {
            // Make sure to cancel the token, if this future ever exits.
            let _cancel_guard = cancel_token.clone().drop_guard();

            loop {
                tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        break;
                    },
                    // handle task terminations and quit on panics.
                    res = join_set.join_next(), if !join_set.is_empty() => {
                        match res {
                            Some(Err(outer)) => {
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
                            Some(Ok(Some(()))) => {
                                trace!("Task finished");
                            }
                            Some(Ok(None)) => {
                                trace!("Task cancelled");
                            }
                            _ => {}
                        }
                    },

                    // handle incoming p2p connections.
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else {
                            break;
                        };

                        let protocols = protocols.clone();
                        let token = cancel_token.child_token();
                        join_set.spawn(async move {
                            token.run_until_cancelled(handle_connection(incoming, protocols)).await
                        }.instrument(info_span!("router.accept")));
                    },
                }
            }

            shutdown(&endpoint, protocols).await;

            // Abort remaining tasks.
            tracing::info!("Shutting down remaining tasks");
            join_set.shutdown().await;
        };
        let task = tokio::task::spawn(run_loop_fut);
        let task = AbortOnDropHandle::new(task);

        Ok(Router {
            endpoint: self.endpoint,
            task: Arc::new(Mutex::new(Some(task))),
            cancel_token: cancel,
        })
    }
}

/// Shutdown the different parts of the router concurrently.
async fn shutdown(endpoint: &Endpoint, protocols: Arc<ProtocolMap>) {
    // We ignore all errors during shutdown.
    let _ = tokio::join!(
        // Close the endpoint.
        endpoint.close(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown() -> Result<()> {
        let endpoint = Endpoint::builder().bind().await?;
        let router = Router::builder(endpoint.clone()).spawn().await?;

        assert!(!router.is_shutdown());
        assert!(!endpoint.is_closed());

        router.shutdown().await?;

        assert!(router.is_shutdown());
        assert!(endpoint.is_closed());

        Ok(())
    }
}
