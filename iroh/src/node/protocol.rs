use std::{any::Any, collections::BTreeMap, fmt, sync::Arc};

use anyhow::{anyhow, Result};
use futures_lite::future::Boxed as BoxedFuture;
use futures_util::future::join_all;
use iroh_blobs::{
    downloader::{DownloadRequest, Downloader},
    get::{
        db::{DownloadProgress, GetState},
        Stats,
    },
    provider::EventSender,
    util::{
        local_pool::LocalPoolHandle,
        progress::{AsyncChannelProgressSender, ProgressSender},
        SetTagOption,
    },
    HashAndFormat,
};
use iroh_net::{endpoint::Connecting, Endpoint, NodeAddr};
use tracing::{debug, warn};

use crate::{
    client::blobs::DownloadMode, rpc_protocol::blobs::DownloadRequest as BlobDownloadRequest,
};

/// Handler for incoming connections.
///
/// An iroh node can accept connections for arbitrary ALPN protocols. By default, the iroh node
/// only accepts connections for the ALPNs of the core iroh protocols (blobs, gossip, docs).
///
/// With this trait, you can handle incoming connections for custom protocols.
///
/// Implement this trait on a struct that should handle incoming connections.
/// The protocol handler must then be registered on the node for an ALPN protocol with
/// [`crate::node::builder::ProtocolBuilder::accept`].
pub trait ProtocolHandler: Send + Sync + IntoArcAny + fmt::Debug + 'static {
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
    fn into_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

impl<T: Send + Sync + 'static> IntoArcAny for T {
    fn into_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct ProtocolMap(BTreeMap<Vec<u8>, Arc<dyn ProtocolHandler>>);

impl ProtocolMap {
    /// Returns the registered protocol handler for an ALPN as a concrete type.
    pub(super) fn get_typed<P: ProtocolHandler>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        let protocol: Arc<dyn ProtocolHandler> = self.0.get(alpn)?.clone();
        let protocol_any: Arc<dyn Any + Send + Sync> = protocol.into_arc_any();
        let protocol_ref = Arc::downcast(protocol_any).ok()?;
        Some(protocol_ref)
    }

    /// Returns the registered protocol handler for an ALPN as a [`Arc<dyn ProtocolHandler>`].
    pub(super) fn get(&self, alpn: &[u8]) -> Option<Arc<dyn ProtocolHandler>> {
        self.0.get(alpn).cloned()
    }

    /// Inserts a protocol handler.
    pub(super) fn insert(&mut self, alpn: Vec<u8>, handler: Arc<dyn ProtocolHandler>) {
        self.0.insert(alpn, handler);
    }

    /// Returns an iterator of all registered ALPN protocol identifiers.
    pub(super) fn alpns(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.0.keys()
    }

    /// Shuts down all protocol handlers.
    ///
    /// Calls and awaits [`ProtocolHandler::shutdown`] for all registered handlers concurrently.
    pub(super) async fn shutdown(&self) {
        let handlers = self.0.values().cloned().map(ProtocolHandler::shutdown);
        join_all(handlers).await;
    }
}

#[derive(Debug)]
pub(crate) struct BlobsProtocol<S> {
    rt: LocalPoolHandle,
    store: S,
    events: EventSender,
    downloader: Downloader,
}

/// Name used for logging when new node addresses are added from gossip.
const BLOB_DOWNLOAD_SOURCE_NAME: &str = "blob_download";

impl<S: iroh_blobs::store::Store> BlobsProtocol<S> {
    pub fn new_with_events(
        store: S,
        rt: LocalPoolHandle,
        events: EventSender,
        downloader: Downloader,
    ) -> Self {
        Self {
            rt,
            store,
            events,
            downloader,
        }
    }

    pub async fn download(
        &self,
        endpoint: Endpoint,
        req: BlobDownloadRequest,
        progress: AsyncChannelProgressSender<DownloadProgress>,
    ) -> Result<()> {
        let BlobDownloadRequest {
            hash,
            format,
            nodes,
            tag,
            mode,
        } = req;
        let hash_and_format = HashAndFormat { hash, format };
        let temp_tag = self.store.temp_tag(hash_and_format);
        let stats = match mode {
            DownloadMode::Queued => {
                self.download_queued(endpoint, hash_and_format, nodes, progress.clone())
                    .await?
            }
            DownloadMode::Direct => {
                self.download_direct_from_nodes(endpoint, hash_and_format, nodes, progress.clone())
                    .await?
            }
        };

        progress.send(DownloadProgress::AllDone(stats)).await.ok();
        match tag {
            SetTagOption::Named(tag) => {
                self.store.set_tag(tag, Some(hash_and_format)).await?;
            }
            SetTagOption::Auto => {
                self.store.create_tag(hash_and_format).await?;
            }
        }
        drop(temp_tag);

        Ok(())
    }

    async fn download_queued(
        &self,
        endpoint: Endpoint,
        hash_and_format: HashAndFormat,
        nodes: Vec<NodeAddr>,
        progress: AsyncChannelProgressSender<DownloadProgress>,
    ) -> Result<Stats> {
        let mut node_ids = Vec::with_capacity(nodes.len());
        let mut any_added = false;
        for node in nodes {
            node_ids.push(node.node_id);
            if !node.info.is_empty() {
                endpoint.add_node_addr_with_source(node, BLOB_DOWNLOAD_SOURCE_NAME)?;
                any_added = true;
            }
        }
        let can_download = !node_ids.is_empty() && (any_added || endpoint.discovery().is_some());
        anyhow::ensure!(can_download, "no way to reach a node for download");
        let req = DownloadRequest::new(hash_and_format, node_ids).progress_sender(progress);
        let handle = self.downloader.queue(req).await;
        let stats = handle.await?;
        Ok(stats)
    }

    #[tracing::instrument("download_direct", skip_all, fields(hash=%hash_and_format.hash.fmt_short()))]
    async fn download_direct_from_nodes(
        &self,
        endpoint: Endpoint,
        hash_and_format: HashAndFormat,
        nodes: Vec<NodeAddr>,
        progress: AsyncChannelProgressSender<DownloadProgress>,
    ) -> Result<Stats> {
        let mut last_err = None;
        let mut remaining_nodes = nodes.len();
        let mut nodes_iter = nodes.into_iter();
        'outer: loop {
            match iroh_blobs::get::db::get_to_db_in_steps(
                self.store.clone(),
                hash_and_format,
                progress.clone(),
            )
            .await?
            {
                GetState::Complete(stats) => return Ok(stats),
                GetState::NeedsConn(needs_conn) => {
                    let (conn, node_id) = 'inner: loop {
                        match nodes_iter.next() {
                            None => break 'outer,
                            Some(node) => {
                                remaining_nodes -= 1;
                                let node_id = node.node_id;
                                if node_id == endpoint.node_id() {
                                    debug!(
                                        ?remaining_nodes,
                                        "skip node {} (it is the node id of ourselves)",
                                        node_id.fmt_short()
                                    );
                                    continue 'inner;
                                }
                                match endpoint.connect(node, iroh_blobs::protocol::ALPN).await {
                                    Ok(conn) => break 'inner (conn, node_id),
                                    Err(err) => {
                                        debug!(
                                            ?remaining_nodes,
                                            "failed to connect to {}: {err}",
                                            node_id.fmt_short()
                                        );
                                        continue 'inner;
                                    }
                                }
                            }
                        }
                    };
                    match needs_conn.proceed(conn).await {
                        Ok(stats) => return Ok(stats),
                        Err(err) => {
                            warn!(
                                ?remaining_nodes,
                                "failed to download from {}: {err}",
                                node_id.fmt_short()
                            );
                            last_err = Some(err);
                        }
                    }
                }
            }
        }
        match last_err {
            Some(err) => Err(err.into()),
            None => Err(anyhow!("No nodes to download from provided")),
        }
    }
}

impl<S: iroh_blobs::store::Store> ProtocolHandler for BlobsProtocol<S> {
    fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>> {
        Box::pin(async move {
            iroh_blobs::provider::handle_connection(
                conn.await?,
                self.store.clone(),
                self.events.clone(),
                self.rt.clone(),
            )
            .await;
            Ok(())
        })
    }
}

impl ProtocolHandler for iroh_gossip::net::Gossip {
    fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>> {
        Box::pin(async move { self.handle_connection(conn.await?).await })
    }
}
