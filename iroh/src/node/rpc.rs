use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Result};
use futures_lite::{Stream, StreamExt};
use iroh_blobs::{
    export::ExportProgress,
    net_protocol::Blobs as BlobsProtocol,
    store::{ExportFormat, ImportProgress, Store as BaoStore},
    util::{
        local_pool::LocalPoolHandle,
        progress::{AsyncChannelProgressSender, ProgressSender},
    },
    BlobFormat, HashAndFormat,
};
use iroh_docs::{engine::Engine, net::DOCS_ALPN};
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_net::{relay::RelayUrl, NodeAddr, NodeId};
use iroh_router::Router;
use quic_rpc::server::{RpcChannel, RpcServerError};
use tokio::task::JoinSet;
use tokio_util::either::Either;
use tracing::{debug, info, warn};

use super::IrohServerEndpoint;
use crate::{
    client::NodeStatus,
    node::NodeInner,
    rpc_protocol::{
        authors,
        docs::{
            ExportFileRequest, ExportFileResponse, ImportFileRequest, ImportFileResponse,
            Request as DocsRequest, SetHashRequest,
        },
        net::{
            self, AddAddrRequest, AddrRequest, IdRequest, NodeWatchRequest, RelayRequest,
            RemoteInfoRequest, RemoteInfoResponse, RemoteInfosIterRequest, RemoteInfosIterResponse,
            WatchResponse,
        },
        node::{self, ShutdownRequest, StatsRequest, StatsResponse, StatusRequest},
        Request, RpcService,
    },
};

mod docs;

const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);
pub(crate) type RpcError = serde_error::Error;
pub(crate) type RpcResult<T> = Result<T, RpcError>;

#[derive(Debug, Clone)]
pub(crate) struct Handler<D> {
    pub(crate) inner: Arc<NodeInner<D>>,
    pub(crate) router: Router,
}

impl<D> Handler<D> {
    pub fn new(inner: Arc<NodeInner<D>>, router: Router) -> Self {
        Self { inner, router }
    }
}

impl<D: BaoStore> Handler<D> {
    fn docs(&self) -> Option<Arc<Engine>> {
        self.router.get_protocol::<Engine>(DOCS_ALPN)
    }

    fn blobs(&self) -> Arc<BlobsProtocol<D>> {
        self.router
            .get_protocol::<BlobsProtocol<D>>(iroh_blobs::protocol::ALPN)
            .expect("missing blobs")
    }

    fn blobs_store(&self) -> D {
        self.blobs().store().clone()
    }

    async fn with_docs<T, F, Fut>(self, f: F) -> RpcResult<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Engine>) -> Fut,
        Fut: std::future::Future<Output = RpcResult<T>>,
    {
        if let Some(docs) = self.docs() {
            f(docs).await
        } else {
            Err(docs_disabled())
        }
    }

    fn with_docs_stream<T, F, S>(self, f: F) -> impl Stream<Item = RpcResult<T>>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Engine>) -> S,
        S: Stream<Item = RpcResult<T>>,
    {
        if let Some(docs) = self.docs() {
            Either::Left(f(docs))
        } else {
            Either::Right(futures_lite::stream::once(Err(docs_disabled())))
        }
    }

    pub(crate) fn spawn_rpc_request(
        inner: Arc<NodeInner<D>>,
        join_set: &mut JoinSet<anyhow::Result<()>>,
        accepting: quic_rpc::server::Accepting<RpcService, IrohServerEndpoint>,
        router: Router,
    ) {
        let handler = Self::new(inner, router);
        join_set.spawn(async move {
            let (msg, chan) = accepting.read_first().await?;
            if let Err(err) = handler.handle_rpc_request(msg, chan).await {
                warn!("rpc request handler error: {err:?}");
            }
            Ok(())
        });
    }

    async fn handle_node_request(
        self,
        msg: node::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use node::Request::*;
        debug!("handling node request: {msg}");
        match msg {
            Status(msg) => chan.rpc(msg, self, Self::node_status).await,
            Shutdown(msg) => chan.rpc(msg, self, Self::node_shutdown).await,
            Stats(msg) => chan.rpc(msg, self, Self::node_stats).await,
        }
    }

    async fn handle_net_request(
        self,
        msg: net::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use net::Request::*;
        debug!("handling node request: {msg}");
        match msg {
            Watch(msg) => chan.server_streaming(msg, self, Self::node_watch).await,
            Id(msg) => chan.rpc(msg, self, Self::node_id).await,
            Addr(msg) => chan.rpc(msg, self, Self::node_addr).await,
            Relay(msg) => chan.rpc(msg, self, Self::node_relay).await,
            RemoteInfosIter(msg) => {
                chan.server_streaming(msg, self, Self::remote_infos_iter)
                    .await
            }
            RemoteInfo(msg) => chan.rpc(msg, self, Self::remote_info).await,
            AddAddr(msg) => chan.rpc(msg, self, Self::node_add_addr).await,
        }
    }

    async fn handle_blobs_and_tags_request(
        self,
        msg: iroh_blobs::rpc::proto::Request,
        chan: RpcChannel<
            iroh_blobs::rpc::proto::RpcService,
            IrohServerEndpoint,
        >,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        self.blobs().handle_rpc_request(msg, chan).await
    }

    // async fn handle_blobs_request(
    //     self,
    //     msg: blobs::Request,
    //     chan: RpcChannel<
    //         iroh_blobs::rpc::proto::RpcService,
    //         IrohServerEndpoint,
    //         crate::rpc_protocol::RpcService,
    //     >,
    // ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
    //     use blobs::Request::*;
    //     debug!("handling blob request: {msg}");
    //     match msg {
    //         List(msg) => chan.server_streaming(msg, self, Self::blob_list).await,
    //         ListIncomplete(msg) => {
    //             chan.server_streaming(msg, self, Self::blob_list_incomplete)
    //                 .await
    //         }
    //         CreateCollection(msg) => chan.rpc(msg, self, Self::create_collection).await,
    //         Delete(msg) => chan.rpc(msg, self, Self::blob_delete_blob).await,
    //         AddPath(msg) => {
    //             chan.server_streaming(msg, self, Self::blob_add_from_path)
    //                 .await
    //         }
    //         Download(msg) => chan.server_streaming(msg, self, Self::blob_download).await,
    //         Export(msg) => chan.server_streaming(msg, self, Self::blob_export).await,
    //         Validate(msg) => chan.server_streaming(msg, self, Self::blob_validate).await,
    //         Fsck(msg) => {
    //             chan.server_streaming(msg, self, Self::blob_consistency_check)
    //                 .await
    //         }
    //         ReadAt(msg) => chan.server_streaming(msg, self, Self::blob_read_at).await,
    //         AddStream(msg) => chan.bidi_streaming(msg, self, Self::blob_add_stream).await,
    //         AddStreamUpdate(_msg) => Err(RpcServerError::UnexpectedUpdateMessage),
    //         BlobStatus(msg) => chan.rpc(msg, self, Self::blob_status).await,
    //         BatchCreate(msg) => chan.bidi_streaming(msg, self, Self::batch_create).await,
    //         BatchUpdate(_) => Err(RpcServerError::UnexpectedStartMessage),
    //         BatchAddStream(msg) => chan.bidi_streaming(msg, self, Self::batch_add_stream).await,
    //         BatchAddStreamUpdate(_) => Err(RpcServerError::UnexpectedStartMessage),
    //         BatchAddPath(msg) => {
    //             chan.server_streaming(msg, self, Self::batch_add_from_path)
    //                 .await
    //         }
    //         BatchCreateTempTag(msg) => chan.rpc(msg, self, Self::batch_create_temp_tag).await,
    //     }
    // }

    // async fn handle_tags_request(
    //     self,
    //     msg: tags::Request,
    //     chan: RpcChannel<
    //         iroh_blobs::rpc::proto::RpcService,
    //         IrohServerEndpoint,
    //         crate::rpc_protocol::RpcService,
    //     >,
    // ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
    //     use tags::Request::*;
    //     match msg {
    //         ListTags(msg) => chan.server_streaming(msg, self, Self::blob_list_tags).await,
    //         DeleteTag(msg) => chan.rpc(msg, self, Self::blob_delete_tag).await,
    //         Create(msg) => chan.rpc(msg, self, Self::tags_create).await,
    //         Set(msg) => chan.rpc(msg, self, Self::tags_set).await,
    //     }
    // }

    async fn handle_gossip_request(
        self,
        msg: iroh_gossip::RpcRequest,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        let gossip = self
            .router
            .get_protocol::<Gossip>(GOSSIP_ALPN)
            .expect("missing gossip");
        let chan = chan.map::<iroh_gossip::RpcService>();
        gossip.handle_rpc_request(msg, chan).await
    }

    async fn handle_authors_request(
        self,
        msg: authors::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use authors::Request::*;
        match msg {
            List(msg) => chan.server_streaming(msg, self, Self::author_list).await,
            Create(msg) => chan.rpc(msg, self, Self::author_create).await,
            Import(msg) => chan.rpc(msg, self, Self::author_import).await,
            Export(msg) => chan.rpc(msg, self, Self::author_export).await,
            Delete(msg) => chan.rpc(msg, self, Self::author_delete).await,
            GetDefault(msg) => chan.rpc(msg, self, Self::author_default).await,
            SetDefault(msg) => chan.rpc(msg, self, Self::author_set_default).await,
        }
    }

    async fn handle_docs_request(
        self,
        msg: DocsRequest,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use DocsRequest::*;
        match msg {
            Open(msg) => chan.rpc(msg, self, Self::doc_open).await,
            Close(msg) => chan.rpc(msg, self, Self::doc_close).await,
            Status(msg) => chan.rpc(msg, self, Self::doc_status).await,
            List(msg) => chan.server_streaming(msg, self, Self::doc_list).await,
            Create(msg) => chan.rpc(msg, self, Self::doc_create).await,
            Drop(msg) => chan.rpc(msg, self, Self::doc_drop).await,
            Import(msg) => chan.rpc(msg, self, Self::doc_import).await,
            Set(msg) => chan.rpc(msg, self, Self::doc_set).await,
            ImportFile(msg) => {
                chan.server_streaming(msg, self, Self::doc_import_file)
                    .await
            }
            ExportFile(msg) => {
                chan.server_streaming(msg, self, Self::doc_export_file)
                    .await
            }
            Del(msg) => chan.rpc(msg, self, Self::doc_del).await,
            SetHash(msg) => chan.rpc(msg, self, Self::doc_set_hash).await,
            Get(msg) => chan.server_streaming(msg, self, Self::doc_get_many).await,
            GetExact(msg) => chan.rpc(msg, self, Self::doc_get_exact).await,
            StartSync(msg) => chan.rpc(msg, self, Self::doc_start_sync).await,
            Leave(msg) => chan.rpc(msg, self, Self::doc_leave).await,
            Share(msg) => chan.rpc(msg, self, Self::doc_share).await,
            Subscribe(msg) => {
                chan.try_server_streaming(msg, self, Self::doc_subscribe)
                    .await
            }
            SetDownloadPolicy(msg) => chan.rpc(msg, self, Self::doc_set_download_policy).await,
            GetDownloadPolicy(msg) => chan.rpc(msg, self, Self::doc_get_download_policy).await,
            GetSyncPeers(msg) => chan.rpc(msg, self, Self::doc_get_sync_peers).await,
        }
    }

    pub(crate) async fn handle_rpc_request(
        self,
        msg: Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use Request::*;
        debug!("handling rpc request: {msg}");
        match msg {
            Net(msg) => self.handle_net_request(msg, chan).await,
            Node(msg) => self.handle_node_request(msg, chan).await,
            BlobsAndTags(msg) => self.handle_blobs_and_tags_request(msg, chan.map()).await,
            Authors(msg) => self.handle_authors_request(msg, chan).await,
            Docs(msg) => self.handle_docs_request(msg, chan).await,
            Gossip(msg) => self.handle_gossip_request(msg, chan).await,
        }
    }

    fn doc_import_file(self, msg: ImportFileRequest) -> impl Stream<Item = ImportFileResponse> {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = async_channel::bounded(32);
        let tx2 = tx.clone();
        self.local_pool_handle().spawn_detached(|| async move {
            if let Err(e) = self.doc_import_file0(msg, tx).await {
                tx2.send(crate::client::docs::ImportProgress::Abort(RpcError::new(
                    &*e,
                )))
                .await
                .ok();
            }
        });
        rx.map(ImportFileResponse)
    }

    async fn doc_import_file0(
        self,
        msg: ImportFileRequest,
        progress: async_channel::Sender<crate::client::docs::ImportProgress>,
    ) -> anyhow::Result<()> {
        use std::collections::BTreeMap;

        use iroh_blobs::store::ImportMode;

        use crate::client::docs::ImportProgress as DocImportProgress;

        let progress = AsyncChannelProgressSender::new(progress);
        let names = Arc::new(Mutex::new(BTreeMap::new()));
        // convert import progress to provide progress
        let import_progress = progress.clone().with_filter_map(move |x| match x {
            ImportProgress::Found { id, name } => {
                names.lock().unwrap().insert(id, name);
                None
            }
            ImportProgress::Size { id, size } => {
                let name = names.lock().unwrap().remove(&id)?;
                Some(DocImportProgress::Found { id, name, size })
            }
            ImportProgress::OutboardProgress { id, offset } => {
                Some(DocImportProgress::Progress { id, offset })
            }
            ImportProgress::OutboardDone { hash, id } => {
                Some(DocImportProgress::IngestDone { hash, id })
            }
            _ => None,
        });
        let ImportFileRequest {
            doc_id,
            author_id,
            key,
            path: root,
            in_place,
        } = msg;
        // Check that the path is absolute and exists.
        anyhow::ensure!(root.is_absolute(), "path must be absolute");
        anyhow::ensure!(
            root.exists(),
            "trying to add missing path: {}",
            root.display()
        );

        let import_mode = match in_place {
            true => ImportMode::TryReference,
            false => ImportMode::Copy,
        };

        let blobs = self.blobs();
        let (temp_tag, size) = blobs
            .store()
            .import_file(root, import_mode, BlobFormat::Raw, import_progress)
            .await?;

        let hash_and_format = temp_tag.inner();
        let HashAndFormat { hash, .. } = *hash_and_format;
        self.doc_set_hash(SetHashRequest {
            doc_id,
            author_id,
            key: key.clone(),
            hash,
            size,
        })
        .await?;
        drop(temp_tag);
        progress.send(DocImportProgress::AllDone { key }).await?;
        Ok(())
    }

    fn doc_export_file(self, msg: ExportFileRequest) -> impl Stream<Item = ExportFileResponse> {
        let (tx, rx) = async_channel::bounded(1024);
        let tx2 = tx.clone();
        self.local_pool_handle().spawn_detached(|| async move {
            if let Err(e) = self.doc_export_file0(msg, tx).await {
                tx2.send(ExportProgress::Abort(RpcError::new(&*e)))
                    .await
                    .ok();
            }
        });
        rx.map(ExportFileResponse)
    }

    async fn doc_export_file0(
        self,
        msg: ExportFileRequest,
        progress: async_channel::Sender<ExportProgress>,
    ) -> anyhow::Result<()> {
        let _docs = self.docs().ok_or_else(|| anyhow!("docs are disabled"))?;
        let progress = AsyncChannelProgressSender::new(progress);
        let ExportFileRequest { entry, path, mode } = msg;
        let key = bytes::Bytes::from(entry.key().to_vec());
        let export_progress = progress.clone().with_map(move |mut x| {
            // assign the doc key to the `meta` field of the initial progress event
            if let ExportProgress::Found { meta, .. } = &mut x {
                *meta = Some(key.clone())
            }
            x
        });
        let blobs = self.blobs();
        iroh_blobs::export::export(
            blobs.store(),
            entry.content_hash(),
            path,
            ExportFormat::Blob,
            mode,
            export_progress,
        )
        .await?;
        progress.send(ExportProgress::AllDone).await?;
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn node_stats(self, _req: StatsRequest) -> RpcResult<StatsResponse> {
        #[cfg(feature = "metrics")]
        let res = Ok(StatsResponse {
            stats: crate::metrics::get_metrics().map_err(|e| RpcError::new(&*e))?,
        });

        #[cfg(not(feature = "metrics"))]
        let res = Err(RpcError::new(&*anyhow::anyhow!("metrics are disabled")));

        res
    }

    async fn node_status(self, _: StatusRequest) -> RpcResult<NodeStatus> {
        Ok(NodeStatus {
            addr: self
                .inner
                .endpoint
                .node_addr()
                .await
                .map_err(|e| RpcError::new(&*e))?,
            listen_addrs: self
                .inner
                .local_endpoint_addresses()
                .await
                .unwrap_or_default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            rpc_addr: self.inner.rpc_addr,
        })
    }

    #[allow(clippy::unused_async)]
    async fn node_id(self, _: IdRequest) -> RpcResult<NodeId> {
        Ok(self.inner.endpoint.secret_key().public())
    }

    async fn node_addr(self, _: AddrRequest) -> RpcResult<NodeAddr> {
        let addr = self
            .inner
            .endpoint
            .node_addr()
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(addr)
    }

    #[allow(clippy::unused_async)]
    async fn node_relay(self, _: RelayRequest) -> RpcResult<Option<RelayUrl>> {
        Ok(self.inner.endpoint.home_relay())
    }

    #[allow(clippy::unused_async)]
    async fn node_shutdown(self, request: ShutdownRequest) {
        if request.force {
            info!("hard shutdown requested");
            std::process::exit(0);
        } else {
            // trigger a graceful shutdown
            info!("graceful shutdown requested");
            self.inner.cancel_token.cancel();
        }
    }

    fn node_watch(self, _: NodeWatchRequest) -> impl Stream<Item = WatchResponse> {
        futures_lite::stream::unfold((), |()| async move {
            tokio::time::sleep(HEALTH_POLL_WAIT).await;
            Some((
                WatchResponse {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                (),
            ))
        })
    }

    fn local_pool_handle(&self) -> LocalPoolHandle {
        self.inner.local_pool_handle.clone()
    }

    fn remote_infos_iter(
        self,
        _: RemoteInfosIterRequest,
    ) -> impl Stream<Item = RpcResult<RemoteInfosIterResponse>> + Send + 'static {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = async_channel::bounded(32);
        let mut infos: Vec<_> = self.inner.endpoint.remote_info_iter().collect();
        infos.sort_by_key(|n| n.node_id.to_string());
        self.local_pool_handle().spawn_detached(|| async move {
            for info in infos {
                tx.send(Ok(RemoteInfosIterResponse { info })).await.ok();
            }
        });
        rx
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn remote_info(self, req: RemoteInfoRequest) -> RpcResult<RemoteInfoResponse> {
        let RemoteInfoRequest { node_id } = req;
        let info = self.inner.endpoint.remote_info(node_id);
        Ok(RemoteInfoResponse { info })
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn node_add_addr(self, req: AddAddrRequest) -> RpcResult<()> {
        let AddAddrRequest { addr } = req;
        self.inner
            .endpoint
            .add_node_addr(addr)
            .map_err(|e| RpcError::new(&*e))?;
        Ok(())
    }
}

fn docs_disabled() -> RpcError {
    RpcError::new(&*anyhow!("docs are disabled"))
}
