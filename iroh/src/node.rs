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
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures_lite::StreamExt;
use futures_util::future::MapErr;
use futures_util::future::Shared;
use iroh_base::key::PublicKey;
use iroh_blobs::protocol::Closed;
use iroh_blobs::store::Store as BaoStore;
use iroh_blobs::util::local_pool::{LocalPool, LocalPoolHandle};
use iroh_docs::net::DOCS_ALPN;
use iroh_net::endpoint::{DirectAddrsStream, RemoteInfo};
use iroh_net::{AddrInfo, Endpoint, NodeAddr};
use protocol::BlobsProtocol;
use quic_rpc::transport::ServerEndpoint as _;
use quic_rpc::RpcServer;
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, error, info, info_span, trace, warn, Instrument};

use crate::node::nodes_storage::store_node_addrs;
use crate::node::{docs::DocsEngine, protocol::ProtocolMap};

mod builder;
mod docs;
mod nodes_storage;
mod protocol;
mod rpc;
mod rpc_status;

pub use self::builder::{
    Builder, DiscoveryConfig, DocsStorage, GcPolicy, ProtocolBuilder, StorageConfig,
    DEFAULT_RPC_ADDR,
};
pub use self::rpc_status::RpcStatus;
pub use protocol::ProtocolHandler;

/// How often to save node data.
const SAVE_NODES_INTERVAL: Duration = Duration::from_secs(30);

/// The quic-rpc server endpoint for the iroh node.
///
/// We use a boxed endpoint here to allow having a concrete type for the server endpoint.
pub type IrohServerEndpoint = quic_rpc::transport::boxed::ServerEndpoint<
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
pub struct Node<D> {
    inner: Arc<NodeInner<D>>,
    // `Node` needs to be `Clone + Send`, and we need to `task.await` in its `shutdown()` impl.
    // So we need
    // - `Shared` so we can `task.await` from all `Node` clones
    // - `MapErr` to map the `JoinError` to a `String`, because `JoinError` is `!Clone`
    // - `AbortOnDropHandle` to make sure that the `task` is cancelled when all `Node`s are dropped
    //   (`Shared` acts like an `Arc` around its inner future).
    task: Shared<MapErr<AbortOnDropHandle<()>, JoinErrToStr>>,
    protocols: Arc<ProtocolMap>,
}

pub(crate) type JoinErrToStr = Box<dyn Fn(JoinError) -> String + Send + Sync + 'static>;

#[derive(derive_more::Debug)]
struct NodeInner<D> {
    db: PhantomData<D>,
    rpc_addr: Option<SocketAddr>,
    endpoint: Endpoint,
    cancel_token: CancellationToken,
    client: crate::client::Iroh,
    local_pool_handle: LocalPoolHandle,
}

/// In memory node.
pub type MemNode = Node<iroh_blobs::store::mem::Store>;

/// Persistent node.
pub type FsNode = Node<iroh_blobs::store::fs::Store>;

impl MemNode {
    /// Returns a new builder for the [`Node`], by default configured to run in memory.
    ///
    /// Once done with the builder call [`Builder::spawn`] to create the node.
    pub fn memory() -> Builder<iroh_blobs::store::mem::Store> {
        Builder::default()
    }
}

impl FsNode {
    /// Returns a new builder for the [`Node`], configured to persist all data
    /// from the given path.
    ///
    /// Once done with the builder call [`Builder::spawn`] to create the node.
    pub async fn persistent(
        root: impl AsRef<Path>,
    ) -> Result<Builder<iroh_blobs::store::fs::Store>> {
        Builder::default().persist(root).await
    }
}

impl<D: BaoStore> Node<D> {
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

    /// Returns a reference to the used `LocalPoolHandle`.
    pub fn local_pool_handle(&self) -> &LocalPoolHandle {
        &self.inner.local_pool_handle
    }

    /// Get the relay server we are connected to.
    pub fn home_relay(&self) -> Option<iroh_net::relay::RelayUrl> {
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
        self.protocols.get_typed(alpn)
    }
}

impl<D> std::ops::Deref for Node<D> {
    type Target = crate::client::Iroh;

    fn deref(&self) -> &Self::Target {
        &self.inner.client
    }
}

impl<D: iroh_blobs::store::Store> NodeInner<D> {
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
        protocols: Arc<ProtocolMap>,
        gc_policy: GcPolicy,
        gc_done_callback: Option<Box<dyn Fn() + Send>>,
        nodes_data_path: Option<PathBuf>,
        local_pool: LocalPool,
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

        tracing::error!("starting with gc policy {:?}", gc_policy);

        // Spawn a task for the garbage collection.
        if let GcPolicy::Interval(gc_period) = gc_policy {
            let protocols = protocols.clone();
            let handle = local_pool.spawn(move || async move {
                let docs_engine = protocols.get_typed::<DocsEngine>(DOCS_ALPN);
                let blobs = protocols
                    .get_typed::<BlobsProtocol<D>>(iroh_blobs::protocol::ALPN)
                    .expect("missing blobs");

                blobs
                    .store()
                    .gc_run(
                        iroh_blobs::store::GcConfig {
                            period: gc_period,
                            done_callback: gc_done_callback,
                        },
                        move || {
                            let docs_engine = docs_engine.clone();
                            async move {
                                let mut live = BTreeSet::default();
                                if let Some(docs) = docs_engine {
                                    let doc_hashes = match docs.sync.content_hashes().await {
                                        Ok(hashes) => hashes,
                                        Err(err) => {
                                            tracing::warn!("Error getting doc hashes: {}", err);
                                            return live;
                                        }
                                    };
                                    for hash in doc_hashes {
                                        match hash {
                                            Ok(hash) => {
                                                live.insert(hash);
                                            }
                                            Err(err) => {
                                                tracing::error!("Error getting doc hash: {}", err);
                                            }
                                        }
                                    }
                                }
                                live
                            }
                        },
                    )
                    .await;
            });
            // We cannot spawn tasks that run on the local pool directly into the join set,
            // so instead we create a new task that supervises the local task.
            join_set.spawn({
                async move {
                    if let Err(err) = handle.await {
                        return Err(anyhow::Error::from(err));
                    }
                    Ok(())
                }
            });
        }

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
                            rpc::Handler::spawn_rpc_request(self.clone(), &mut join_set, accepting, protocols.clone());
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
                            rpc::Handler::spawn_rpc_request(self.clone(), &mut join_set, accepting, protocols.clone());
                        }
                        Err(e) => {
                            info!("internal rpc request error: {:?}", e);
                        }
                    }
                },
                // handle incoming p2p connections.
                Some(incoming) = self.endpoint.accept() => {
                    let protocols = protocols.clone();
                    join_set.spawn(async move {
                        handle_connection(incoming, protocols).await;
                        Ok(())
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
                else => break,
            }
        }

        self.shutdown(protocols).await;

        // Abort remaining tasks.
        join_set.shutdown().await;
        tracing::info!("Shutting down remaining tasks");

        // Abort remaining local tasks.
        tracing::info!("Shutting down local pool");
        local_pool.shutdown().await;
    }

    /// Shutdown the different parts of the node concurrently.
    async fn shutdown(&self, protocols: Arc<ProtocolMap>) {
        let error_code = Closed::ProviderTerminating;

        // We ignore all errors during shutdown.
        let _ = tokio::join!(
            // Close the endpoint.
            // Closing the Endpoint is the equivalent of calling Connection::close on all
            // connections: Operations will immediately fail with ConnectionError::LocallyClosed.
            // All streams are interrupted, this is not graceful.
            self.endpoint
                .clone()
                .close(error_code.into(), error_code.reason()),
            // Shutdown protocol handlers.
            protocols.shutdown(),
        );
    }
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

#[cfg(test)]
mod tests {
    use anyhow::{bail, Context};
    use bytes::Bytes;
    use iroh_base::node_addr::AddrInfoOptions;
    use iroh_blobs::{provider::AddProgress, util::SetTagOption, BlobFormat};
    use iroh_net::{key::SecretKey, relay::RelayMode, test_utils::DnsPkarrServer, NodeAddr};

    use crate::client::blobs::{AddOutcome, WrapOption};

    use super::*;

    #[tokio::test]
    async fn test_ticket_multiple_addrs() {
        let _guard = iroh_test::logging::setup();

        let node = Node::memory().spawn().await.unwrap();
        let hash = node
            .client()
            .blobs()
            .add_bytes(Bytes::from_static(b"hello"))
            .await
            .unwrap()
            .hash;

        let _drop_guard = node.cancel_token().drop_guard();
        let ticket = node
            .blobs()
            .share(hash, BlobFormat::Raw, AddrInfoOptions::RelayAndAddresses)
            .await
            .unwrap();
        println!("addrs: {:?}", ticket.node_addr().info);
        assert!(!ticket.node_addr().info.direct_addresses.is_empty());
    }

    #[tokio::test]
    async fn test_node_add_blob_stream() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        use std::io::Cursor;
        let node = Node::memory().bind_random_port().spawn().await?;

        let _drop_guard = node.cancel_token().drop_guard();
        let client = node.client();
        let input = vec![2u8; 1024 * 256]; // 265kb so actually streaming, chunk size is 64kb
        let reader = Cursor::new(input.clone());
        let progress = client
            .blobs()
            .add_reader(reader, SetTagOption::Auto)
            .await?;
        let outcome = progress.finish().await?;
        let hash = outcome.hash;
        let output = client.blobs().read_to_bytes(hash).await?;
        assert_eq!(input, output.to_vec());
        Ok(())
    }

    #[tokio::test]
    async fn test_node_add_tagged_blob_event() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let node = Node::memory().bind_random_port().spawn().await?;

        let _drop_guard = node.cancel_token().drop_guard();

        let _got_hash = tokio::time::timeout(Duration::from_secs(10), async move {
            let mut stream = node
                .blobs()
                .add_from_path(
                    Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"),
                    false,
                    SetTagOption::Auto,
                    WrapOption::NoWrap,
                )
                .await?;

            while let Some(progress) = stream.next().await {
                match progress? {
                    AddProgress::AllDone { hash, .. } => {
                        return Ok(hash);
                    }
                    AddProgress::Abort(e) => {
                        bail!("Error while adding data: {e}");
                    }
                    _ => {}
                }
            }
            bail!("stream ended without providing data");
        })
        .await
        .context("timeout")?
        .context("get failed")?;

        Ok(())
    }

    #[cfg(feature = "fs-store")]
    #[tokio::test]
    async fn test_shutdown() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let iroh_root = tempfile::TempDir::new()?;
        {
            let iroh = Node::persistent(iroh_root.path())
                .await?
                .enable_docs()
                .spawn()
                .await?;
            let doc = iroh.docs().create().await?;
            drop(doc);
            iroh.shutdown().await?;
        }

        let iroh = Node::persistent(iroh_root.path())
            .await?
            .enable_docs()
            .spawn()
            .await?;
        let _doc = iroh.docs().create().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_download_via_relay() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let (relay_map, relay_url, _guard) = iroh_net::test_utils::run_relay_server().await?;

        let node1 = Node::memory()
            .bind_random_port()
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .spawn()
            .await?;
        let node2 = Node::memory()
            .bind_random_port()
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .spawn()
            .await?;
        let AddOutcome { hash, .. } = node1.blobs().add_bytes(b"foo".to_vec()).await?;

        // create a node addr with only a relay URL, no direct addresses
        let addr = NodeAddr::new(node1.node_id()).with_relay_url(relay_url);
        node2.blobs().download(hash, addr).await?.await?;
        assert_eq!(
            node2
                .blobs()
                .read_to_bytes(hash)
                .await
                .context("get")?
                .as_ref(),
            b"foo"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "flaky"]
    async fn test_download_via_relay_with_discovery() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let (relay_map, _relay_url, _guard) = iroh_net::test_utils::run_relay_server().await?;
        let dns_pkarr_server = DnsPkarrServer::run().await?;

        let secret1 = SecretKey::generate();
        let node1 = Node::memory()
            .secret_key(secret1.clone())
            .bind_random_port()
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .dns_resolver(dns_pkarr_server.dns_resolver())
            .node_discovery(dns_pkarr_server.discovery(secret1).into())
            .spawn()
            .await?;
        let secret2 = SecretKey::generate();
        let node2 = Node::memory()
            .secret_key(secret2.clone())
            .bind_random_port()
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .dns_resolver(dns_pkarr_server.dns_resolver())
            .node_discovery(dns_pkarr_server.discovery(secret2).into())
            .spawn()
            .await?;
        let hash = node1.blobs().add_bytes(b"foo".to_vec()).await?.hash;

        // create a node addr with node id only
        let addr = NodeAddr::new(node1.node_id());
        node2.blobs().download(hash, addr).await?.await?;
        assert_eq!(
            node2
                .blobs()
                .read_to_bytes(hash)
                .await
                .context("get")?
                .as_ref(),
            b"foo"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_default_author_memory() -> Result<()> {
        let iroh = Node::memory().enable_docs().spawn().await?;
        let author = iroh.authors().default().await?;
        assert!(iroh.authors().export(author).await?.is_some());
        assert!(iroh.authors().delete(author).await.is_err());
        Ok(())
    }

    #[cfg(feature = "fs-store")]
    #[tokio::test]
    async fn test_default_author_persist() -> Result<()> {
        use crate::util::path::IrohPaths;

        let _guard = iroh_test::logging::setup();

        let iroh_root_dir = tempfile::TempDir::new().unwrap();
        let iroh_root = iroh_root_dir.path();

        // check that the default author exists and cannot be deleted.
        let default_author = {
            let iroh = Node::persistent(iroh_root)
                .await
                .unwrap()
                .enable_docs()
                .spawn()
                .await
                .unwrap();
            let author = iroh.authors().default().await.unwrap();
            assert!(iroh.authors().export(author).await.unwrap().is_some());
            assert!(iroh.authors().delete(author).await.is_err());
            iroh.shutdown().await.unwrap();
            author
        };

        // check that the default author is persisted across restarts.
        {
            let iroh = Node::persistent(iroh_root)
                .await
                .unwrap()
                .enable_docs()
                .spawn()
                .await
                .unwrap();
            let author = iroh.authors().default().await.unwrap();
            assert_eq!(author, default_author);
            assert!(iroh.authors().export(author).await.unwrap().is_some());
            assert!(iroh.authors().delete(author).await.is_err());
            iroh.shutdown().await.unwrap();
        };

        // check that a new default author is created if the default author file is deleted
        // manually.
        let default_author = {
            tokio::fs::remove_file(IrohPaths::DefaultAuthor.with_root(iroh_root))
                .await
                .unwrap();
            let iroh = Node::persistent(iroh_root)
                .await
                .unwrap()
                .enable_docs()
                .spawn()
                .await
                .unwrap();
            let author = iroh.authors().default().await.unwrap();
            assert!(author != default_author);
            assert!(iroh.authors().export(author).await.unwrap().is_some());
            assert!(iroh.authors().delete(author).await.is_err());
            iroh.shutdown().await.unwrap();
            author
        };

        // check that the node fails to start if the default author is missing from the docs store.
        {
            let mut docs_store = iroh_docs::store::fs::Store::persistent(
                IrohPaths::DocsDatabase.with_root(iroh_root),
            )
            .unwrap();
            docs_store.delete_author(default_author).unwrap();
            docs_store.flush().unwrap();
            drop(docs_store);
            let iroh = Node::persistent(iroh_root)
                .await
                .unwrap()
                .enable_docs()
                .spawn()
                .await;
            assert!(iroh.is_err());

            // somehow the blob store is not shutdown correctly (yet?) on macos.
            // so we give it some time until we find a proper fix.
            #[cfg(target_os = "macos")]
            tokio::time::sleep(Duration::from_secs(1)).await;

            tokio::fs::remove_file(IrohPaths::DefaultAuthor.with_root(iroh_root))
                .await
                .unwrap();
            drop(iroh);
            let iroh = Node::persistent(iroh_root)
                .await
                .unwrap()
                .enable_docs()
                .spawn()
                .await;
            assert!(iroh.is_ok());
            iroh.unwrap().shutdown().await.unwrap();
        }

        // check that the default author can be set manually and is persisted.
        let default_author = {
            let iroh = Node::persistent(iroh_root)
                .await
                .unwrap()
                .enable_docs()
                .spawn()
                .await
                .unwrap();
            let author = iroh.authors().create().await.unwrap();
            iroh.authors().set_default(author).await.unwrap();
            assert_eq!(iroh.authors().default().await.unwrap(), author);
            iroh.shutdown().await.unwrap();
            author
        };
        {
            let iroh = Node::persistent(iroh_root)
                .await
                .unwrap()
                .enable_docs()
                .spawn()
                .await
                .unwrap();
            assert_eq!(iroh.authors().default().await.unwrap(), default_author);
            iroh.shutdown().await.unwrap();
        }

        Ok(())
    }
}
