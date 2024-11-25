use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures_util::{
    future::{MapErr, Shared},
    FutureExt, TryFutureExt,
};
use iroh_net::Endpoint;
use tokio::task::{JoinError, JoinSet};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, error, warn};

use crate::{ProtocolHandler, ProtocolMap};

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

impl Router {
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

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub async fn shutdown(self) -> Result<()> {
        // Trigger shutdown of the main run task by activating the cancel token.
        self.cancel_token.cancel();

        // Wait for the main task to terminate.
        self.task.await.map_err(|err| anyhow!(err))?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct RouterBuilder {
    endpoint: Endpoint,
    protocols: ProtocolMap,
}

impl RouterBuilder {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            protocols: ProtocolMap::default(),
        }
    }

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
        endpoint
            .clone()
            .close(error_code.into(), b"provider terminating"),
        // Shutdown protocol handlers.
        protocols.shutdown(),
    );
}

async fn handle_connection(incoming: iroh_net::endpoint::Incoming, protocols: Arc<ProtocolMap>) {
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
