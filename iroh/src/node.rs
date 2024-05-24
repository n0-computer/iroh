//! Node API
//!
//! A node is a server that serves various protocols.
//!
//! To shut down the node, call [`Node::shutdown`].
use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures_lite::StreamExt;
use iroh_base::key::PublicKey;
use iroh_blobs::downloader::Downloader;
use iroh_blobs::store::Store as BaoStore;
use iroh_net::util::AbortingJoinHandle;
use iroh_net::{endpoint::LocalEndpointsStream, key::SecretKey, Endpoint};
use quic_rpc::transport::flume::FlumeConnection;
use quic_rpc::RpcClient;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::LocalPoolHandle;
use tracing::debug;

use crate::client::RpcService;
use crate::docs_engine::Engine;

mod builder;
mod rpc;
mod rpc_status;

pub use self::builder::{Builder, DiscoveryConfig, GcPolicy, StorageConfig};
pub use self::rpc_status::RpcStatus;

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
    task: Arc<JoinHandle<()>>,
    client: crate::client::MemIroh,
}

#[derive(derive_more::Debug)]
struct NodeInner<D> {
    db: D,
    endpoint: Endpoint,
    secret_key: SecretKey,
    cancel_token: CancellationToken,
    controller: FlumeConnection<RpcService>,
    #[allow(dead_code)]
    gc_task: Option<AbortingJoinHandle<()>>,
    #[debug("rt")]
    rt: LocalPoolHandle,
    pub(crate) sync: Engine,
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
        let (v4, v6) = self.inner.endpoint.local_addr();
        let mut addrs = vec![v4];
        if let Some(v6) = v6 {
            addrs.push(v6);
        }
        addrs
    }

    /// Lists the local endpoint of this node.
    pub fn local_endpoints(&self) -> LocalEndpointsStream {
        self.inner.endpoint.local_endpoints()
    }

    /// Convenience method to get just the addr part of [`Node::local_endpoints`].
    pub async fn local_endpoint_addresses(&self) -> Result<Vec<SocketAddr>> {
        self.inner.local_endpoint_addresses().await
    }

    /// Returns the [`PublicKey`] of the node.
    pub fn node_id(&self) -> PublicKey {
        self.inner.secret_key.public()
    }

    /// Returns a handle that can be used to do RPC calls to the node internally.
    pub fn controller(&self) -> crate::client::MemRpcClient {
        RpcClient::new(self.inner.controller.clone())
    }

    /// Return a client to control this node over an in-memory channel.
    pub fn client(&self) -> &crate::client::MemIroh {
        &self.client
    }

    /// Returns a referenc to the used `LocalPoolHandle`.
    pub fn local_pool_handle(&self) -> &LocalPoolHandle {
        &self.inner.rt
    }

    /// Get the relay server we are connected to.
    pub fn my_relay(&self) -> Option<iroh_net::relay::RelayUrl> {
        self.inner.endpoint.my_relay()
    }

    /// Aborts the node.
    ///
    /// This does not gracefully terminate currently: all connections are closed and
    /// anything in-transit is lost.  The task will stop running.
    /// If this is the last copy of the `Node`, this will finish once the task is
    /// fully shutdown.
    ///
    /// The shutdown behaviour will become more graceful in the future.
    pub async fn shutdown(self) -> Result<()> {
        self.inner.cancel_token.cancel();

        if let Ok(task) = Arc::try_unwrap(self.task) {
            task.await?;
        }
        Ok(())
    }

    /// Returns a token that can be used to cancel the node.
    pub fn cancel_token(&self) -> CancellationToken {
        self.inner.cancel_token.clone()
    }
}

impl<D> std::ops::Deref for Node<D> {
    type Target = crate::client::MemIroh;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl<D> NodeInner<D> {
    async fn local_endpoint_addresses(&self) -> Result<Vec<SocketAddr>> {
        let endpoints = self
            .endpoint
            .local_endpoints()
            .next()
            .await
            .ok_or(anyhow!("no endpoints found"))?;
        Ok(endpoints.into_iter().map(|x| x.addr).collect())
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
        rpc_protocol::{BlobAddPathRequest, BlobAddPathResponse, SetTagOption},
    };

    use super::*;

    #[tokio::test]
    async fn test_ticket_multiple_addrs() {
        let _guard = iroh_test::logging::setup();

        let node = Node::memory().spawn().await.unwrap();
        let hash = node
            .client()
            .blobs
            .add_bytes(Bytes::from_static(b"hello"))
            .await
            .unwrap()
            .hash;

        let _drop_guard = node.cancel_token().drop_guard();
        let ticket = node
            .blobs
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
        let progress = client.blobs.add_reader(reader, SetTagOption::Auto).await?;
        let outcome = progress.finish().await?;
        let hash = outcome.hash;
        let output = client.blobs.read_to_bytes(hash).await?;
        assert_eq!(input, output.to_vec());
        Ok(())
    }

    #[tokio::test]
    async fn test_node_add_tagged_blob_event() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let node = Node::memory().bind_port(0).spawn().await?;

        let _drop_guard = node.cancel_token().drop_guard();

        let _got_hash = tokio::time::timeout(Duration::from_secs(1), async move {
            let mut stream = node
                .controller()
                .server_streaming(BlobAddPathRequest {
                    path: Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"),
                    in_place: false,
                    tag: SetTagOption::Auto,
                    wrap: WrapOption::NoWrap,
                })
                .await?;

            while let Some(item) = stream.next().await {
                let BlobAddPathResponse(progress) = item?;
                match progress {
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
            let doc = iroh.docs.create().await?;
            drop(doc);
            iroh.shutdown().await?;
        }

        let iroh = Node::persistent(iroh_root.path()).await?.spawn().await?;
        let _doc = iroh.docs.create().await?;

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
        let AddOutcome { hash, .. } = node1.blobs.add_bytes(b"foo".to_vec()).await?;

        // create a node addr with only a relay URL, no direct addresses
        let addr = NodeAddr::new(node1.node_id()).with_relay_url(relay_url);
        node2.blobs.download(hash, addr).await?.await?;
        assert_eq!(
            node2
                .blobs
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
        let hash = node1.blobs.add_bytes(b"foo".to_vec()).await?.hash;

        // create a node addr with node id only
        let addr = NodeAddr::new(node1.node_id());
        node2.blobs.download(hash, addr).await?.await?;
        assert_eq!(
            node2
                .blobs
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
        let author = iroh.authors.default().await?;
        assert!(iroh.authors.export(author).await?.is_some());
        assert!(iroh.authors.delete(author).await.is_err());
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
            let author = iroh.authors.default().await.unwrap();
            assert!(iroh.authors.export(author).await.unwrap().is_some());
            assert!(iroh.authors.delete(author).await.is_err());
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
            let author = iroh.authors.default().await.unwrap();
            assert_eq!(author, default_author);
            assert!(iroh.authors.export(author).await.unwrap().is_some());
            assert!(iroh.authors.delete(author).await.is_err());
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
            let author = iroh.authors.default().await.unwrap();
            assert!(author != default_author);
            assert!(iroh.authors.export(author).await.unwrap().is_some());
            assert!(iroh.authors.delete(author).await.is_err());
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
            let author = iroh.authors.create().await.unwrap();
            iroh.authors.set_default(author).await.unwrap();
            assert_eq!(iroh.authors.default().await.unwrap(), author);
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
            assert_eq!(iroh.authors.default().await.unwrap(), default_author);
            iroh.shutdown().await.unwrap();
        }

        Ok(())
    }
}
