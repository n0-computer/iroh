//! Node API
//!
//! A node is a server that serves various protocols.
//!
//! You can monitor what is happening in the node using [`Node::subscribe`].
//!
//! To shut down the node, call [`Node::shutdown`].
use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use anyhow::{anyhow, Result};
use futures::future::{BoxFuture, Shared};
use futures::{FutureExt, StreamExt};
use iroh_bytes::downloader::Downloader;
use iroh_bytes::store::Store as BaoStore;
use iroh_bytes::BlobFormat;
use iroh_bytes::Hash;
use iroh_net::magicsock::LocalEndpointsStream;
use iroh_net::relay::RelayUrl;
use iroh_net::util::AbortingJoinHandle;
use iroh_net::{
    key::{PublicKey, SecretKey},
    MagicEndpoint, NodeAddr,
};
use iroh_sync::store::Store as DocStore;
use quic_rpc::transport::flume::FlumeConnection;
use quic_rpc::RpcClient;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinError;
use tokio_util::sync::CancellationToken;
use tokio_util::task::LocalPoolHandle;
use tracing::debug;

use crate::rpc_protocol::{ProviderRequest, ProviderResponse};
use crate::sync_engine::SyncEngine;
use crate::ticket::BlobTicket;

mod builder;
mod rpc;
mod rpc_status;

pub use builder::{Builder, GcPolicy, StorageConfig};
pub use rpc_status::RpcStatus;

type EventCallback = Box<dyn Fn(Event) -> BoxFuture<'static, ()> + 'static + Sync + Send>;

#[derive(Default, derive_more::Debug, Clone)]
struct Callbacks(#[debug("..")] Arc<RwLock<Vec<EventCallback>>>);

impl Callbacks {
    async fn push(&self, cb: EventCallback) {
        self.0.write().await.push(cb);
    }

    #[allow(dead_code)]
    async fn send(&self, event: Event) {
        let cbs = self.0.read().await;
        for cb in &*cbs {
            cb(event.clone()).await;
        }
    }
}

impl iroh_bytes::provider::EventSender for Callbacks {
    fn send(&self, event: iroh_bytes::provider::Event) -> BoxFuture<()> {
        async move {
            let cbs = self.0.read().await;
            for cb in &*cbs {
                cb(Event::ByteProvide(event.clone())).await;
            }
        }
        .boxed()
    }
}

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
    task: Shared<BoxFuture<'static, Result<(), Arc<JoinError>>>>,
    client: crate::client::mem::Iroh,
}

#[derive(derive_more::Debug)]
struct NodeInner<D> {
    db: D,
    endpoint: MagicEndpoint,
    secret_key: SecretKey,
    cancel_token: CancellationToken,
    controller: FlumeConnection<ProviderResponse, ProviderRequest>,
    #[debug("callbacks: Sender<Box<dyn Fn(Event)>>")]
    cb_sender: mpsc::Sender<Box<dyn Fn(Event) -> BoxFuture<'static, ()> + Send + Sync + 'static>>,
    callbacks: Callbacks,
    #[allow(dead_code)]
    gc_task: Option<AbortingJoinHandle<()>>,
    #[debug("rt")]
    rt: LocalPoolHandle,
    pub(crate) sync: SyncEngine,
    downloader: Downloader,
}

/// Events emitted by the [`Node`] informing about the current status.
#[derive(Debug, Clone)]
pub enum Event {
    /// Events from the iroh-bytes transfer protocol.
    ByteProvide(iroh_bytes::provider::Event),
    /// Events from database
    Db(iroh_bytes::store::Event),
}

/// In memory node.
pub type MemNode = Node<iroh_bytes::store::mem::Store>;

/// Persistent node.
pub type FsNode = Node<iroh_bytes::store::fs::Store>;

impl MemNode {
    /// Returns a new builder for the [`Node`], by default configured to run in memory.
    ///
    /// Once done with the builder call [`Builder::spawn`] to create the node.
    pub fn memory() -> Builder<iroh_bytes::store::mem::Store, iroh_sync::store::memory::Store> {
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
    ) -> Result<Builder<iroh_bytes::store::fs::Store, iroh_sync::store::fs::Store>> {
        Builder::default().persist(root).await
    }
}

impl<D: BaoStore> Node<D> {
    /// Returns the [`MagicEndpoint`] of the node.
    ///
    /// This can be used to establish connections to other nodes under any
    /// ALPNs other than the iroh internal ones. This is useful for some advanced
    /// use cases.
    pub fn magic_endpoint(&self) -> &MagicEndpoint {
        &self.inner.endpoint
    }

    /// The address on which the node socket is bound.
    ///
    /// Note that this could be an unspecified address, if you need an address on which you
    /// can contact the node consider using [`Node::local_endpoint_addresses`].  However the
    /// port will always be the concrete port.
    pub fn local_address(&self) -> Result<Vec<SocketAddr>> {
        let (v4, v6) = self.inner.endpoint.local_addr()?;
        let mut addrs = vec![v4];
        if let Some(v6) = v6 {
            addrs.push(v6);
        }
        Ok(addrs)
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

    /// Subscribe to [`Event`]s emitted from the node, informing about connections and
    /// progress.
    ///
    /// Warning: The callback must complete quickly, as otherwise it will block ongoing work.
    pub async fn subscribe<F: Fn(Event) -> BoxFuture<'static, ()> + Send + Sync + 'static>(
        &self,
        cb: F,
    ) -> Result<()> {
        self.inner.cb_sender.send(Box::new(cb)).await?;
        Ok(())
    }

    /// Returns a handle that can be used to do RPC calls to the node internally.
    pub fn controller(&self) -> crate::client::mem::RpcClient {
        RpcClient::new(self.inner.controller.clone())
    }

    /// Return a client to control this node over an in-memory channel.
    pub fn client(&self) -> &crate::client::mem::Iroh {
        &self.client
    }

    /// Returns a referenc to the used `LocalPoolHandle`.
    pub fn local_pool_handle(&self) -> &LocalPoolHandle {
        &self.inner.rt
    }

    /// Return a single token containing everything needed to get a hash.
    ///
    /// See [`BlobTicket`] for more details of how it can be used.
    pub async fn ticket(&self, hash: Hash, format: BlobFormat) -> Result<BlobTicket> {
        // TODO: Verify that the hash exists in the db?
        let me = self.my_addr().await?;
        BlobTicket::new(me, hash, format)
    }

    /// Return the [`NodeAddr`] for this node.
    pub async fn my_addr(&self) -> Result<NodeAddr> {
        self.inner.endpoint.my_addr().await
    }

    /// Get the relay server we are connected to.
    pub fn my_relay(&self) -> Option<RelayUrl> {
        self.inner.endpoint.my_relay()
    }

    /// Aborts the node.
    ///
    /// This does not gracefully terminate currently: all connections are closed and
    /// anything in-transit is lost.  The task will stop running and awaiting this
    /// [`Node`] will complete.
    ///
    /// The shutdown behaviour will become more graceful in the future.
    pub fn shutdown(&self) {
        self.inner.cancel_token.cancel();
    }

    /// Returns a token that can be used to cancel the node.
    pub fn cancel_token(&self) -> CancellationToken {
        self.inner.cancel_token.clone()
    }
}

/// The future completes when the spawned tokio task finishes.
impl<D> Future for Node<D> {
    type Output = Result<(), Arc<JoinError>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}

impl<D> std::ops::Deref for Node<D> {
    type Target = crate::client::mem::Iroh;

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

#[cfg(all(test, feature = "fs-store"))]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use anyhow::{bail, Context};
    use bytes::Bytes;
    use futures::StreamExt;
    use iroh_bytes::provider::AddProgress;

    use crate::rpc_protocol::{BlobAddPathRequest, BlobAddPathResponse, SetTagOption, WrapOption};

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
        let ticket = node.ticket(hash, BlobFormat::Raw).await.unwrap();
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

        let (r, mut s) = mpsc::channel(1);
        node.subscribe(move |event| {
            let r = r.clone();
            async move {
                if let Event::ByteProvide(iroh_bytes::provider::Event::TaggedBlobAdded {
                    hash,
                    ..
                }) = event
                {
                    r.send(hash).await.ok();
                }
            }
            .boxed()
        })
        .await?;

        let got_hash = tokio::time::timeout(Duration::from_secs(1), async move {
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

        let event_hash = s.recv().await.expect("missing add tagged blob event");
        assert_eq!(got_hash, event_hash);

        Ok(())
    }
}
