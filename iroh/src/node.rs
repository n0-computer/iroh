//! Node API
//!
//! An iroh node is a server that is identified by an Ed25519 keypair and is
//! globally reachable via the [node id](crate::net::NodeId), which is the
//! public key of the keypair.
//!
//! By default, an iroh node speaks a number of built-in protocols. You can
//! *extend* the node with custom protocols or *disable* built-in protocols.
//!
//! # Building a node
//!
//! Nodes get created using the [`Builder`] which provides a very powerful API
//! to configure every aspect of the node.
//!
//! When using the default set of protocols, use [spawn](Builder::spawn)
//! to spawn a node directly from the builder.
//!
//! When adding custom protocols, use [build](Builder::build) to get a
//! [`ProtocolBuilder`] that allows to add custom protocols, then call
//! [spawn](ProtocolBuilder::spawn) to spawn the fully configured node.
//!
//! To implement a custom protocol, implement the [`ProtocolHandler`] trait
//! and use [`ProtocolBuilder::accept`] to add it to the node.
//!
//! # Using a node
//!
//! Once created, a node offers a small number of methods to interact with it,
//! most notably the iroh-net [endpoint](Node::endpoint) it is bound to.
//!
//! The main way to interact with a node is through the
//! [`client`](crate::client::Iroh).
//!
//! (The Node implements [Deref](std::ops::Deref) for client, which means that
//! methods defined on [Client](crate::client::Iroh) can be called on Node as
//! well, without going through [`client`](crate::client::Iroh))
//!
//! To shut down the node, call [`Node::shutdown`].
use std::{
    collections::BTreeSet,
    fmt::Debug,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Result};
use futures_lite::StreamExt;
use futures_util::future::{MapErr, Shared};
use iroh_base::key::PublicKey;
use iroh_net::{
    endpoint::{DirectAddrsStream, RemoteInfo},
    AddrInfo, Endpoint, NodeAddr,
};
use iroh_router::{ProtocolHandler, Router};
use quic_rpc::{transport::Listener as _, RpcServer};
use tokio::task::{JoinError, JoinSet};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};

use crate::node::nodes_storage::store_node_addrs;

mod builder;
mod nodes_storage;
mod rpc;
mod rpc_status;

pub use self::{
    builder::{Builder, DiscoveryConfig, ProtocolBuilder, StorageConfig, DEFAULT_RPC_ADDR},
    rpc_status::RpcStatus,
};

/// How often to save node data.
const SAVE_NODES_INTERVAL: Duration = Duration::from_secs(30);

/// The quic-rpc server endpoint for the iroh node.
///
/// We use a boxed endpoint here to allow having a concrete type for the server endpoint.
pub type IrohServerEndpoint = quic_rpc::transport::boxed::BoxedListener<
    crate::rpc_protocol::Request,
    crate::rpc_protocol::Response,
>;

/// A server which implements the iroh node.
///
/// Clients can connect to this server and requests hashes from it.
///
/// The only way to create this is by using the [`Builder::spawn`]. You can use [`Node::memory`]
/// or [`Node::persistent`] to create a suitable [`Builder`].
///
/// This runs a tokio task which can be aborted and joined if desired.  To join the task
/// await the [`Node`] struct directly, it will complete when the task completes.  If
/// this is dropped the node task is not stopped but keeps running.
#[derive(Debug, Clone)]
pub struct Node {
    inner: Arc<NodeInner>,
    // `Node` needs to be `Clone + Send`, and we need to `task.await` in its `shutdown()` impl.
    // So we need
    // - `Shared` so we can `task.await` from all `Node` clones
    // - `MapErr` to map the `JoinError` to a `String`, because `JoinError` is `!Clone`
    // - `AbortOnDropHandle` to make sure that the `task` is cancelled when all `Node`s are dropped
    //   (`Shared` acts like an `Arc` around its inner future).
    task: Shared<MapErr<AbortOnDropHandle<()>, JoinErrToStr>>,
    router: Router,
}

pub(crate) type JoinErrToStr = Box<dyn Fn(JoinError) -> String + Send + Sync + 'static>;

#[derive(derive_more::Debug)]
struct NodeInner {
    rpc_addr: Option<SocketAddr>,
    endpoint: Endpoint,
    cancel_token: CancellationToken,
    client: crate::client::Iroh,
}

/// In memory node.
#[deprecated]
pub type MemNode = Node;

/// Persistent node.
#[deprecated]
pub type FsNode = Node;

impl Node {
    /// Returns a new builder for the [`Node`], by default configured to run in memory.
    ///
    /// Once done with the builder call [`Builder::spawn`] to create the node.
    pub fn memory() -> Builder {
        Builder::memory()
    }

    /// Returns a new builder for the [`Node`], configured to persist all data
    /// from the given path.
    ///
    /// Once done with the builder call [`Builder::spawn`] to create the node.
    pub async fn persistent(root: impl AsRef<Path>) -> Result<Builder> {
        Builder::memory().persist(root).await
    }

    /// Returns the [`Endpoint`] of the node.
    ///
    /// This can be used to establish connections to other nodes under any
    /// ALPNs other than the iroh internal ones. This is useful for some advanced
    /// use cases.
    pub fn endpoint(&self) -> &Endpoint {
        &self.inner.endpoint
    }

    /// The address on which the node socket is bound.
    ///
    /// Note that this could be an unspecified address, if you need an address on which you
    /// can contact the node consider using [`Node::local_endpoint_addresses`].  However the
    /// port will always be the concrete port.
    pub fn local_address(&self) -> Vec<SocketAddr> {
        let (v4, v6) = self.inner.endpoint.bound_sockets();
        let mut addrs = vec![v4];
        if let Some(v6) = v6 {
            addrs.push(v6);
        }
        addrs
    }

    /// Lists the local endpoint of this node.
    pub fn local_endpoints(&self) -> DirectAddrsStream {
        self.inner.endpoint.direct_addresses()
    }

    /// Convenience method to get just the addr part of [`Node::local_endpoints`].
    pub async fn local_endpoint_addresses(&self) -> Result<Vec<SocketAddr>> {
        self.inner.local_endpoint_addresses().await
    }

    /// Returns the [`PublicKey`] of the node.
    pub fn node_id(&self) -> PublicKey {
        self.inner.endpoint.secret_key().public()
    }

    /// Return a client to control this node over an in-memory channel.
    pub fn client(&self) -> &crate::client::Iroh {
        &self.inner.client
    }

    /// Get the relay server we are connected to.
    pub fn home_relay(&self) -> Option<iroh_net::RelayUrl> {
        self.inner.endpoint.home_relay()
    }

    /// Returns `Some(addr)` if an RPC endpoint is running, `None` otherwise.
    pub fn my_rpc_addr(&self) -> Option<SocketAddr> {
        self.inner.rpc_addr
    }

    /// Shutdown the node.
    ///
    /// This does not gracefully terminate currently: all connections are closed and
    /// anything in-transit is lost. The shutdown behaviour will become more graceful
    /// in the future.
    ///
    /// Returns a future that completes once all tasks terminated and all resources are closed.
    /// The future resolves to an error if the main task panicked.
    pub async fn shutdown(self) -> Result<()> {
        // Trigger shutdown of the main run task by activating the cancel token.
        self.inner.cancel_token.cancel();

        // Wait for the main task to terminate.
        self.task.await.map_err(|err| anyhow!(err))?;

        Ok(())
    }

    /// Returns a token that can be used to cancel the node.
    pub fn cancel_token(&self) -> CancellationToken {
        self.inner.cancel_token.clone()
    }

    /// Returns a protocol handler for an ALPN.
    ///
    /// This downcasts to the concrete type and returns `None` if the handler registered for `alpn`
    /// does not match the passed type.
    pub fn get_protocol<P: ProtocolHandler>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        self.router.get_protocol(alpn)
    }
}

impl std::ops::Deref for Node {
    type Target = crate::client::Iroh;

    fn deref(&self) -> &Self::Target {
        &self.inner.client
    }
}

impl NodeInner {
    async fn local_endpoint_addresses(&self) -> Result<Vec<SocketAddr>> {
        let endpoints = self
            .endpoint
            .direct_addresses()
            .next()
            .await
            .ok_or(anyhow!("no endpoints found"))?;
        Ok(endpoints.into_iter().map(|x| x.addr).collect())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        self: Arc<Self>,
        external_rpc: IrohServerEndpoint,
        internal_rpc: IrohServerEndpoint,
        router: Router,
        nodes_data_path: Option<PathBuf>,
    ) {
        let (ipv4, ipv6) = self.endpoint.bound_sockets();
        debug!(
            "listening at: {}{}",
            ipv4,
            ipv6.map(|addr| format!(" and {addr}")).unwrap_or_default()
        );
        debug!("rpc listening at: {:?}", external_rpc.local_addr());

        let mut join_set = JoinSet::new();

        // Setup the RPC servers.
        let external_rpc = RpcServer::new(external_rpc);
        let internal_rpc = RpcServer::new(internal_rpc);

        if let Some(nodes_data_path) = nodes_data_path {
            let ep = self.endpoint.clone();
            let token = self.cancel_token.clone();

            join_set.spawn(
                async move {
                    let mut save_timer = tokio::time::interval_at(
                        tokio::time::Instant::now() + SAVE_NODES_INTERVAL,
                        SAVE_NODES_INTERVAL,
                    );

                    loop {
                        tokio::select! {
                            biased;
                            _ = token.cancelled() => {
                                trace!("save known node addresses shutdown");
                                let addrs = node_addresses_for_storage(&ep);
                                if let Err(err) = store_node_addrs(&nodes_data_path, &addrs).await {
                                    warn!("failed to store known node addresses: {:?}", err);
                                }
                                break;
                            }
                            _ = save_timer.tick() => {
                                trace!("save known node addresses tick");
                                let addrs = node_addresses_for_storage(&ep);
                                if let Err(err) = store_node_addrs(&nodes_data_path, &addrs).await {
                                    warn!("failed to store known node addresses: {:?}", err);
                                }
                            }
                        }
                    }

                    Ok(())
                }
                .instrument(info_span!("known-addrs")),
            );
        }

        loop {
            tokio::select! {
                biased;
                _ = self.cancel_token.cancelled() => {
                    break;
                },
                // handle rpc requests. This will do nothing if rpc is not configured, since
                // accept is just a pending future.
                request = external_rpc.accept() => {
                    match request {
                        Ok(accepting) => {
                            rpc::Handler::spawn_rpc_request(self.clone(), &mut join_set, accepting, router.clone());
                        }
                        Err(e) => {
                            info!("rpc request error: {:?}", e);
                        }
                    }
                },
                // handle internal rpc requests.
                request = internal_rpc.accept() => {
                    match request {
                        Ok(accepting) => {
                            rpc::Handler::spawn_rpc_request(self.clone(), &mut join_set, accepting, router.clone());
                        }
                        Err(e) => {
                            info!("internal rpc request error: {:?}", e);
                        }
                    }
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

        if let Err(err) = router.shutdown().await {
            tracing::warn!("Error when shutting down router: {:?}", err);
        };

        // Abort remaining tasks.
        join_set.shutdown().await;
        tracing::info!("Shutting down remaining tasks");

        // Abort remaining local tasks.
        tracing::info!("Shutting down local pool");
    }
}

fn node_addresses_for_storage(ep: &Endpoint) -> Vec<NodeAddr> {
    ep.remote_info_iter()
        .filter_map(node_address_for_storage)
        .collect()
}
/// Get the addressing information of this endpoint that should be stored.
///
/// If the endpoint was not used at all in this session, all known addresses will be returned.
/// If the endpoint was used, only the paths that were in use will be returned.
///
/// Returns `None` if the resulting [`NodeAddr`] would be empty.
fn node_address_for_storage(info: RemoteInfo) -> Option<NodeAddr> {
    let direct_addresses = if info.last_used.is_none() {
        info.addrs
            .into_iter()
            .map(|info| info.addr)
            .collect::<BTreeSet<_>>()
    } else {
        info.addrs
            .iter()
            .filter_map(|info| {
                if info.last_alive.is_some() {
                    Some(info.addr)
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>()
    };
    if direct_addresses.is_empty() && info.relay_url.is_none() {
        None
    } else {
        Some(NodeAddr {
            node_id: info.node_id,
            info: AddrInfo {
                relay_url: info.relay_url.map(|u| u.into()),
                direct_addresses,
            },
        })
    }
}
