//! Node API
//!
//! A node is a server that serves various protocols.
//!
//! To shut down the node, call [`Node::shutdown`].
use std::path::Path;
use std::sync::Arc;
use std::{collections::BTreeSet, net::SocketAddr};
use std::{fmt::Debug, time::Duration};

use anyhow::{anyhow, Result};
use futures_lite::StreamExt;
use iroh_base::key::PublicKey;
use iroh_blobs::store::{GcMarkEvent, GcSweepEvent, Store as BaoStore};
use iroh_blobs::{downloader::Downloader, protocol::Closed};
use iroh_gossip::net::Gossip;
use iroh_net::key::SecretKey;
use iroh_net::Endpoint;
use iroh_net::{endpoint::DirectAddrsStream, util::SharedAbortingJoinHandle};
use quic_rpc::{RpcServer, ServiceEndpoint};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::LocalPoolHandle;
use tracing::{debug, error, info, warn};

use crate::{
    client::RpcService,
    node::{docs::DocsEngine, protocol::ProtocolMap},
};

mod builder;
mod docs;
mod protocol;
mod rpc;
mod rpc_status;

pub use self::builder::{Builder, DiscoveryConfig, DocsStorage, GcPolicy, StorageConfig};
pub use self::rpc_status::RpcStatus;
pub use protocol::ProtocolHandler;

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
    task: SharedAbortingJoinHandle<()>,
    protocols: Arc<ProtocolMap>,
}

#[derive(derive_more::Debug)]
struct NodeInner<D> {
    db: D,
    docs: Option<DocsEngine>,
    endpoint: Endpoint,
    gossip: Gossip,
    secret_key: SecretKey,
    cancel_token: CancellationToken,
    client: crate::client::Iroh,
    #[debug("rt")]
    rt: LocalPoolHandle,
    downloader: Downloader,
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
        self.inner.secret_key.public()
    }

    /// Return a client to control this node over an in-memory channel.
    pub fn client(&self) -> &crate::client::Iroh {
        &self.inner.client
    }

    /// Returns a referenc to the used `LocalPoolHandle`.
    pub fn local_pool_handle(&self) -> &LocalPoolHandle {
        &self.inner.rt
    }

    /// Get the relay server we are connected to.
    pub fn my_relay(&self) -> Option<iroh_net::relay::RelayUrl> {
        self.inner.endpoint.home_relay()
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

    async fn run(
        self: Arc<Self>,
        external_rpc: impl ServiceEndpoint<RpcService>,
        internal_rpc: impl ServiceEndpoint<RpcService>,
        protocols: Arc<ProtocolMap>,
        gc_policy: GcPolicy,
        gc_done_callback: Option<Box<dyn Fn() + Send>>,
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

        // TODO(frando): I think this is not needed as we do the same in a task just below.
        // forward the initial endpoints to the gossip protocol.
        // it may happen the the first endpoint update callback is missed because the gossip cell
        // is only initialized once the endpoint is fully bound
        if let Some(direct_addresses) = self.endpoint.direct_addresses().next().await {
            debug!(me = ?self.endpoint.node_id(), "gossip initial update: {direct_addresses:?}");
            self.gossip.update_direct_addresses(&direct_addresses).ok();
        }

        // Spawn a task for the garbage collection.
        if let GcPolicy::Interval(gc_period) = gc_policy {
            let inner = self.clone();
            let handle = self
                .rt
                .spawn_pinned(move || inner.run_gc_loop(gc_period, gc_done_callback));
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

        // Spawn a task that updates the gossip endpoints.
        let inner = self.clone();
        join_set.spawn(async move {
            let mut stream = inner.endpoint.direct_addresses();
            while let Some(eps) = stream.next().await {
                if let Err(err) = inner.gossip.update_direct_addresses(&eps) {
                    warn!("Failed to update direct addresses for gossip: {err:?}");
                }
            }
            warn!("failed to retrieve local endpoints");
            Ok(())
        });

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
                        Ok((msg, chan)) => {
                            rpc::Handler::spawn_rpc_request(self.clone(), &mut join_set, msg, chan);
                        }
                        Err(e) => {
                            info!("rpc request error: {:?}", e);
                        }
                    }
                },
                // handle internal rpc requests.
                request = internal_rpc.accept() => {
                    match request {
                        Ok((msg, chan)) => {
                            rpc::Handler::spawn_rpc_request(self.clone(), &mut join_set, msg, chan);
                        }
                        Err(e) => {
                            info!("internal rpc request error: {:?}", e);
                        }
                    }
                },
                // handle incoming p2p connections.
                Some(connecting) = self.endpoint.accept() => {
                    let protocols = protocols.clone();
                    join_set.spawn(async move {
                        handle_connection(connecting, protocols).await;
                        Ok(())
                    });
                },
                // handle task terminations and quit on panics.
                res = join_set.join_next(), if !join_set.is_empty() => {
                    if let Some(Err(err)) = res {
                        error!("Task failed: {err:?}");
                        break;
                    }
                },
                else => break,
            }
        }

        self.shutdown(protocols).await;

        // Abort remaining tasks.
        join_set.shutdown().await;
    }

    /// Shutdown the different parts of the node concurrently.
    async fn shutdown(&self, protocols: Arc<ProtocolMap>) {
        let error_code = Closed::ProviderTerminating;

        // Shutdown future for the docs engine, if enabled.
        let docs_shutdown = {
            let docs = self.docs.clone();
            async move {
                if let Some(docs) = docs {
                    docs.shutdown().await
                } else {
                    Ok(())
                }
            }
        };

        // We ignore all errors during shutdown.
        let _ = tokio::join!(
            // Close the endpoint.
            // Closing the Endpoint is the equivalent of calling Connection::close on all
            // connections: Operations will immediately fail with ConnectionError::LocallyClosed.
            // All streams are interrupted, this is not graceful.
            self.endpoint
                .clone()
                .close(error_code.into(), error_code.reason()),
            // Shutdown docs engine.
            docs_shutdown,
            // Shutdown blobs store engine.
            self.db.shutdown(),
            // Shutdown protocol handlers.
            protocols.shutdown(),
        );
    }

    async fn run_gc_loop(
        self: Arc<Self>,
        gc_period: Duration,
        done_cb: Option<Box<dyn Fn() + Send>>,
    ) {
        tracing::info!("Starting GC task with interval {:?}", gc_period);
        let db = &self.db;
        let mut live = BTreeSet::new();
        'outer: loop {
            if let Err(cause) = db.gc_start().await {
                tracing::debug!(
                    "unable to notify the db of GC start: {cause}. Shutting down GC loop."
                );
                break;
            }
            // do delay before the two phases of GC
            tokio::time::sleep(gc_period).await;
            tracing::debug!("Starting GC");
            live.clear();

            if let Some(docs) = &self.docs {
                let doc_hashes = match docs.sync.content_hashes().await {
                    Ok(hashes) => hashes,
                    Err(err) => {
                        tracing::warn!("Error getting doc hashes: {}", err);
                        continue 'outer;
                    }
                };
                for hash in doc_hashes {
                    match hash {
                        Ok(hash) => {
                            live.insert(hash);
                        }
                        Err(err) => {
                            tracing::error!("Error getting doc hash: {}", err);
                            continue 'outer;
                        }
                    }
                }
            }

            tracing::debug!("Starting GC mark phase");
            let mut stream = db.gc_mark(&mut live);
            while let Some(item) = stream.next().await {
                match item {
                    GcMarkEvent::CustomDebug(text) => {
                        tracing::debug!("{}", text);
                    }
                    GcMarkEvent::CustomWarning(text, _) => {
                        tracing::warn!("{}", text);
                    }
                    GcMarkEvent::Error(err) => {
                        tracing::error!("Fatal error during GC mark {}", err);
                        continue 'outer;
                    }
                }
            }
            drop(stream);

            tracing::debug!("Starting GC sweep phase");
            let mut stream = db.gc_sweep(&live);
            while let Some(item) = stream.next().await {
                match item {
                    GcSweepEvent::CustomDebug(text) => {
                        tracing::debug!("{}", text);
                    }
                    GcSweepEvent::CustomWarning(text, _) => {
                        tracing::warn!("{}", text);
                    }
                    GcSweepEvent::Error(err) => {
                        tracing::error!("Fatal error during GC mark {}", err);
                        continue 'outer;
                    }
                }
            }
            if let Some(ref cb) = done_cb {
                cb();
            }
        }
    }
}

async fn handle_connection(
    mut connecting: iroh_net::endpoint::Connecting,
    protocols: Arc<ProtocolMap>,
) {
    let alpn = match connecting.alpn().await {
        Ok(alpn) => alpn,
        Err(err) => {
            warn!("Ignoring connection: invalid handshake: {:?}", err);
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
    use std::time::Duration;

    use anyhow::{bail, Context};
    use bytes::Bytes;
    use iroh_base::node_addr::AddrInfoOptions;
    use iroh_blobs::{provider::AddProgress, BlobFormat};
    use iroh_net::{relay::RelayMode, test_utils::DnsPkarrServer, NodeAddr};

    use crate::{
        client::blobs::{AddOutcome, WrapOption},
        rpc_protocol::SetTagOption,
    };

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
        let node = Node::memory().bind_port(0).spawn().await?;

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
    #[ignore = "flaky"]
    async fn test_node_add_tagged_blob_event() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let node = Node::memory().bind_port(0).spawn().await?;

        let _drop_guard = node.cancel_token().drop_guard();

        let _got_hash = tokio::time::timeout(Duration::from_secs(1), async move {
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
            let iroh = Node::persistent(iroh_root.path()).await?.spawn().await?;
            let doc = iroh.docs().create().await?;
            drop(doc);
            iroh.shutdown().await?;
        }

        let iroh = Node::persistent(iroh_root.path()).await?.spawn().await?;
        let _doc = iroh.docs().create().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_download_via_relay() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let (relay_map, relay_url, _guard) = iroh_net::test_utils::run_relay_server().await?;

        let node1 = Node::memory()
            .bind_port(0)
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .spawn()
            .await?;
        let node2 = Node::memory()
            .bind_port(0)
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
    async fn test_download_via_relay_with_discovery() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let (relay_map, _relay_url, _guard) = iroh_net::test_utils::run_relay_server().await?;
        let dns_pkarr_server = DnsPkarrServer::run().await?;

        let secret1 = SecretKey::generate();
        let node1 = Node::memory()
            .secret_key(secret1.clone())
            .bind_port(0)
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .dns_resolver(dns_pkarr_server.dns_resolver())
            .node_discovery(dns_pkarr_server.discovery(secret1).into())
            .spawn()
            .await?;
        let secret2 = SecretKey::generate();
        let node2 = Node::memory()
            .secret_key(secret2.clone())
            .bind_port(0)
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
        let iroh = Node::memory().spawn().await?;
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
            let iroh = Node::persistent(iroh_root).await.unwrap().spawn().await;
            dbg!(&iroh);
            assert!(iroh.is_err());

            // somehow the blob store is not shutdown correctly (yet?) on macos.
            // so we give it some time until we find a proper fix.
            #[cfg(target_os = "macos")]
            tokio::time::sleep(Duration::from_secs(1)).await;

            tokio::fs::remove_file(IrohPaths::DefaultAuthor.with_root(iroh_root))
                .await
                .unwrap();
            drop(iroh);
            let iroh = Node::persistent(iroh_root).await.unwrap().spawn().await;
            assert!(iroh.is_ok());
            iroh.unwrap().shutdown().await.unwrap();
        }

        // check that the default author can be set manually and is persisted.
        let default_author = {
            let iroh = Node::persistent(iroh_root)
                .await
                .unwrap()
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
                .spawn()
                .await
                .unwrap();
            assert_eq!(iroh.authors().default().await.unwrap(), default_author);
            iroh.shutdown().await.unwrap();
        }

        Ok(())
    }
}
