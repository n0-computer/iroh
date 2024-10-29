use std::{
    fmt::Debug,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Result};
use futures_buffered::BufferedStreamExt;
use futures_lite::{Stream, StreamExt};
use futures_util::FutureExt;
use genawaiter::sync::{Co, Gen};
use iroh_base::rpc::{RpcError, RpcResult};
use iroh_blobs::{
    export::ExportProgress,
    format::collection::Collection,
    get::db::DownloadProgress,
    provider::{AddProgress, BatchAddPathProgress},
    store::{
        ConsistencyCheckProgress, ExportFormat, ImportProgress, MapEntry, Store as BaoStore,
        ValidateProgress,
    },
    util::{
        local_pool::LocalPoolHandle,
        progress::{AsyncChannelProgressSender, ProgressSender},
        SetTagOption,
    },
    BlobFormat, HashAndFormat, Tag,
};
use iroh_docs::net::DOCS_ALPN;
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_io::AsyncSliceReader;
use iroh_net::{relay::RelayUrl, NodeAddr, NodeId};
use quic_rpc::server::{RpcChannel, RpcServerError};
use tokio::task::JoinSet;
use tokio_util::either::Either;
use tracing::{debug, info, warn};

use super::{protocol::ProtocolMap, IrohServerEndpoint};
use crate::{
    client::{
        blobs::{BlobInfo, BlobStatus, IncompleteBlobInfo, WrapOption},
        tags::TagInfo,
        NodeStatus,
    },
    node::{docs::DocsEngine, protocol::BlobsProtocol, NodeInner},
    rpc_protocol::{
        authors, blobs,
        blobs::{
            AddPathRequest, AddPathResponse, AddStreamRequest, AddStreamResponse, AddStreamUpdate,
            BatchAddPathRequest, BatchAddPathResponse, BatchAddStreamRequest,
            BatchAddStreamResponse, BatchAddStreamUpdate, BatchCreateRequest, BatchCreateResponse,
            BatchCreateTempTagRequest, BatchUpdate, BlobStatusRequest, BlobStatusResponse,
            ConsistencyCheckRequest, CreateCollectionRequest, CreateCollectionResponse,
            DeleteRequest, DownloadRequest as BlobDownloadRequest, DownloadResponse, ExportRequest,
            ExportResponse, ListIncompleteRequest, ListRequest, ReadAtRequest, ReadAtResponse,
            ValidateRequest,
        },
        docs::{
            ExportFileRequest, ExportFileResponse, ImportFileRequest, ImportFileResponse,
            Request as DocsRequest, SetHashRequest,
        },
        net,
        net::{
            AddAddrRequest, AddrRequest, IdRequest, NodeWatchRequest, RelayRequest,
            RemoteInfoRequest, RemoteInfoResponse, RemoteInfosIterRequest, RemoteInfosIterResponse,
            WatchResponse,
        },
        node,
        node::{ShutdownRequest, StatsRequest, StatsResponse, StatusRequest},
        tags,
        tags::{DeleteRequest as TagDeleteRequest, ListRequest as ListTagsRequest, SyncMode},
        Request, RpcService,
    },
};

mod docs;

const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);
/// Chunk size for getting blobs over RPC
const RPC_BLOB_GET_CHUNK_SIZE: usize = 1024 * 64;
/// Channel cap for getting blobs over RPC
const RPC_BLOB_GET_CHANNEL_CAP: usize = 2;

#[derive(Debug, Clone)]
pub(crate) struct Handler<D> {
    pub(crate) inner: Arc<NodeInner<D>>,
    pub(crate) protocols: Arc<ProtocolMap>,
}

impl<D> Handler<D> {
    pub fn new(inner: Arc<NodeInner<D>>, protocols: Arc<ProtocolMap>) -> Self {
        Self { inner, protocols }
    }
}

impl<D: BaoStore> Handler<D> {
    fn docs(&self) -> Option<Arc<DocsEngine>> {
        self.protocols.get_typed::<DocsEngine>(DOCS_ALPN)
    }

    fn blobs(&self) -> Arc<BlobsProtocol<D>> {
        self.protocols
            .get_typed::<BlobsProtocol<D>>(iroh_blobs::protocol::ALPN)
            .expect("missing blobs")
    }

    fn blobs_store(&self) -> D {
        self.blobs().store().clone()
    }

    async fn with_docs<T, F, Fut>(self, f: F) -> RpcResult<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<DocsEngine>) -> Fut,
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
        F: FnOnce(Arc<DocsEngine>) -> S,
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
        protocols: Arc<ProtocolMap>,
    ) {
        let handler = Self::new(inner, protocols);
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

    async fn handle_blobs_request(
        self,
        msg: blobs::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use blobs::Request::*;
        debug!("handling blob request: {msg}");
        match msg {
            List(msg) => chan.server_streaming(msg, self, Self::blob_list).await,
            ListIncomplete(msg) => {
                chan.server_streaming(msg, self, Self::blob_list_incomplete)
                    .await
            }
            CreateCollection(msg) => chan.rpc(msg, self, Self::create_collection).await,
            Delete(msg) => chan.rpc(msg, self, Self::blob_delete_blob).await,
            AddPath(msg) => {
                chan.server_streaming(msg, self, Self::blob_add_from_path)
                    .await
            }
            Download(msg) => chan.server_streaming(msg, self, Self::blob_download).await,
            Export(msg) => chan.server_streaming(msg, self, Self::blob_export).await,
            Validate(msg) => chan.server_streaming(msg, self, Self::blob_validate).await,
            Fsck(msg) => {
                chan.server_streaming(msg, self, Self::blob_consistency_check)
                    .await
            }
            ReadAt(msg) => chan.server_streaming(msg, self, Self::blob_read_at).await,
            AddStream(msg) => chan.bidi_streaming(msg, self, Self::blob_add_stream).await,
            AddStreamUpdate(_msg) => Err(RpcServerError::UnexpectedUpdateMessage),
            BlobStatus(msg) => chan.rpc(msg, self, Self::blob_status).await,
            BatchCreate(msg) => chan.bidi_streaming(msg, self, Self::batch_create).await,
            BatchUpdate(_) => Err(RpcServerError::UnexpectedStartMessage),
            BatchAddStream(msg) => chan.bidi_streaming(msg, self, Self::batch_add_stream).await,
            BatchAddStreamUpdate(_) => Err(RpcServerError::UnexpectedStartMessage),
            BatchAddPath(msg) => {
                chan.server_streaming(msg, self, Self::batch_add_from_path)
                    .await
            }
            BatchCreateTempTag(msg) => chan.rpc(msg, self, Self::batch_create_temp_tag).await,
        }
    }

    async fn handle_tags_request(
        self,
        msg: tags::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use tags::Request::*;
        match msg {
            ListTags(msg) => chan.server_streaming(msg, self, Self::blob_list_tags).await,
            DeleteTag(msg) => chan.rpc(msg, self, Self::blob_delete_tag).await,
            Create(msg) => chan.rpc(msg, self, Self::tags_create).await,
            Set(msg) => chan.rpc(msg, self, Self::tags_set).await,
        }
    }

    async fn handle_gossip_request(
        self,
        msg: iroh_gossip::RpcRequest,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        let chan = chan.map::<iroh_gossip::RpcService>();

        let gossip = self.protocols.get_typed::<Gossip>(GOSSIP_ALPN).unwrap();
        gossip.handle_rpc_request(msg, chan).await
    }

    async fn handle_authors_request(
        self,
        msg: authors::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use authors::Request::*;
        match msg {
            List(msg) => {
                chan.server_streaming(msg, self, |handler, req: authors::ListRequest| {
                    handler.with_docs_stream(|docs| docs.author_list(req))
                })
                .await
            }
            Create(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.author_create(req).await })
                })
                .await
            }
            Import(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.author_import(req).await })
                })
                .await
            }
            Export(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.author_export(req).await })
                })
                .await
            }
            Delete(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.author_delete(req).await })
                })
                .await
            }
            GetDefault(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { Ok(docs.author_default(req)) })
                })
                .await
            }
            SetDefault(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.author_set_default(req).await })
                })
                .await
            }
        }
    }

    async fn handle_docs_request(
        self,
        msg: DocsRequest,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use DocsRequest::*;
        match msg {
            Open(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_open(req).await })
                })
                .await
            }
            Close(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_close(req).await })
                })
                .await
            }
            Status(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_status(req).await })
                })
                .await
            }
            List(msg) => {
                chan.server_streaming(msg, self, |handler, req| {
                    handler.with_docs_stream(|docs| docs.doc_list(req))
                })
                .await
            }
            Create(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_create(req).await })
                })
                .await
            }
            Drop(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_drop(req).await })
                })
                .await
            }
            Import(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_import(req).await })
                })
                .await
            }
            Set(msg) => {
                let blobs_store = self.blobs_store();
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_set(&blobs_store, req).await })
                })
                .await
            }
            ImportFile(msg) => {
                chan.server_streaming(msg, self, Self::doc_import_file)
                    .await
            }
            ExportFile(msg) => {
                chan.server_streaming(msg, self, Self::doc_export_file)
                    .await
            }
            Del(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_del(req).await })
                })
                .await
            }
            SetHash(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_set_hash(req).await })
                })
                .await
            }
            Get(msg) => {
                chan.server_streaming(msg, self, |handler, req| {
                    handler.with_docs_stream(|docs| docs.doc_get_many(req))
                })
                .await
            }
            GetExact(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_get_exact(req).await })
                })
                .await
            }
            StartSync(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_start_sync(req).await })
                })
                .await
            }
            Leave(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_leave(req).await })
                })
                .await
            }
            Share(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_share(req).await })
                })
                .await
            }
            Subscribe(msg) => {
                chan.try_server_streaming(msg, self, |handler, req| async move {
                    handler
                        .with_docs(|docs| async move { docs.doc_subscribe(req).await })
                        .await
                })
                .await
            }
            SetDownloadPolicy(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_set_download_policy(req).await })
                })
                .await
            }
            GetDownloadPolicy(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_get_download_policy(req).await })
                })
                .await
            }
            GetSyncPeers(msg) => {
                chan.rpc(msg, self, |handler, req| {
                    handler.with_docs(|docs| async move { docs.doc_get_sync_peers(req).await })
                })
                .await
            }
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
            Blobs(msg) => self.handle_blobs_request(msg, chan).await,
            Tags(msg) => self.handle_tags_request(msg, chan).await,
            Authors(msg) => self.handle_authors_request(msg, chan).await,
            Docs(msg) => self.handle_docs_request(msg, chan).await,
            Gossip(msg) => self.handle_gossip_request(msg, chan).await,
        }
    }

    fn local_pool_handle(&self) -> LocalPoolHandle {
        self.inner.local_pool_handle.clone()
    }

    async fn blob_status(self, msg: BlobStatusRequest) -> RpcResult<BlobStatusResponse> {
        let blobs = self.blobs();
        let entry = blobs.store().get(&msg.hash).await?;
        Ok(BlobStatusResponse(match entry {
            Some(entry) => {
                if entry.is_complete() {
                    BlobStatus::Complete {
                        size: entry.size().value(),
                    }
                } else {
                    BlobStatus::Partial { size: entry.size() }
                }
            }
            None => BlobStatus::NotFound,
        }))
    }

    async fn blob_list_impl(self, co: &Co<RpcResult<BlobInfo>>) -> io::Result<()> {
        use bao_tree::io::fsm::Outboard;

        let blobs = self.blobs();
        let db = blobs.store();
        for blob in db.blobs().await? {
            let blob = blob?;
            let Some(entry) = db.get(&blob).await? else {
                continue;
            };
            let hash = entry.hash();
            let size = entry.outboard().await?.tree().size();
            let path = "".to_owned();
            co.yield_(Ok(BlobInfo { hash, size, path })).await;
        }
        Ok(())
    }

    async fn blob_list_incomplete_impl(
        self,
        co: &Co<RpcResult<IncompleteBlobInfo>>,
    ) -> io::Result<()> {
        let blobs = self.blobs();
        let db = blobs.store();
        for hash in db.partial_blobs().await? {
            let hash = hash?;
            let Ok(Some(entry)) = db.get_mut(&hash).await else {
                continue;
            };
            if entry.is_complete() {
                continue;
            }
            let size = 0;
            let expected_size = entry.size().value();
            co.yield_(Ok(IncompleteBlobInfo {
                hash,
                size,
                expected_size,
            }))
            .await;
        }
        Ok(())
    }

    fn blob_list(
        self,
        _msg: ListRequest,
    ) -> impl Stream<Item = RpcResult<BlobInfo>> + Send + 'static {
        Gen::new(|co| async move {
            if let Err(e) = self.blob_list_impl(&co).await {
                co.yield_(Err(e.into())).await;
            }
        })
    }

    fn blob_list_incomplete(
        self,
        _msg: ListIncompleteRequest,
    ) -> impl Stream<Item = RpcResult<IncompleteBlobInfo>> + Send + 'static {
        Gen::new(move |co| async move {
            if let Err(e) = self.blob_list_incomplete_impl(&co).await {
                co.yield_(Err(e.into())).await;
            }
        })
    }

    async fn blob_delete_tag(self, msg: TagDeleteRequest) -> RpcResult<()> {
        self.blobs_store().set_tag(msg.name, None).await?;
        Ok(())
    }

    async fn blob_delete_blob(self, msg: DeleteRequest) -> RpcResult<()> {
        self.blobs_store().delete(vec![msg.hash]).await?;
        Ok(())
    }

    fn blob_list_tags(self, msg: ListTagsRequest) -> impl Stream<Item = TagInfo> + Send + 'static {
        tracing::info!("blob_list_tags");
        let blobs = self.blobs();
        Gen::new(|co| async move {
            let tags = blobs.store().tags().await.unwrap();
            #[allow(clippy::manual_flatten)]
            for item in tags {
                if let Ok((name, HashAndFormat { hash, format })) = item {
                    if (format.is_raw() && msg.raw) || (format.is_hash_seq() && msg.hash_seq) {
                        co.yield_(TagInfo { name, hash, format }).await;
                    }
                }
            }
        })
    }

    /// Invoke validate on the database and stream out the result
    fn blob_validate(
        self,
        msg: ValidateRequest,
    ) -> impl Stream<Item = ValidateProgress> + Send + 'static {
        let (tx, rx) = async_channel::bounded(1);
        let tx2 = tx.clone();
        let blobs = self.blobs();
        tokio::task::spawn(async move {
            if let Err(e) = blobs
                .store()
                .validate(msg.repair, AsyncChannelProgressSender::new(tx).boxed())
                .await
            {
                tx2.send(ValidateProgress::Abort(e.into())).await.ok();
            }
        });
        rx
    }

    /// Invoke validate on the database and stream out the result
    fn blob_consistency_check(
        self,
        msg: ConsistencyCheckRequest,
    ) -> impl Stream<Item = ConsistencyCheckProgress> + Send + 'static {
        let (tx, rx) = async_channel::bounded(1);
        let tx2 = tx.clone();
        let blobs = self.blobs();
        tokio::task::spawn(async move {
            if let Err(e) = blobs
                .store()
                .consistency_check(msg.repair, AsyncChannelProgressSender::new(tx).boxed())
                .await
            {
                tx2.send(ConsistencyCheckProgress::Abort(e.into()))
                    .await
                    .ok();
            }
        });
        rx
    }

    fn blob_add_from_path(self, msg: AddPathRequest) -> impl Stream<Item = AddPathResponse> {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = async_channel::bounded(32);
        let tx2 = tx.clone();
        self.local_pool_handle().spawn_detached(|| async move {
            if let Err(e) = self.blob_add_from_path0(msg, tx).await {
                tx2.send(AddProgress::Abort(e.into())).await.ok();
            }
        });
        rx.map(AddPathResponse)
    }

    fn doc_import_file(self, msg: ImportFileRequest) -> impl Stream<Item = ImportFileResponse> {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = async_channel::bounded(32);
        let tx2 = tx.clone();
        self.local_pool_handle().spawn_detached(|| async move {
            if let Err(e) = self.doc_import_file0(msg, tx).await {
                tx2.send(crate::client::docs::ImportProgress::Abort(e.into()))
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
        let docs = self.docs().ok_or_else(|| anyhow!("docs are disabled"))?;
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
        docs.doc_set_hash(SetHashRequest {
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
                tx2.send(ExportProgress::Abort(e.into())).await.ok();
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

    fn blob_download(self, msg: BlobDownloadRequest) -> impl Stream<Item = DownloadResponse> {
        let (sender, receiver) = async_channel::bounded(1024);
        let endpoint = self.inner.endpoint.clone();
        let progress = AsyncChannelProgressSender::new(sender);

        let blobs_protocol = self
            .protocols
            .get_typed::<BlobsProtocol<D>>(iroh_blobs::protocol::ALPN)
            .expect("missing blobs");

        self.local_pool_handle().spawn_detached(move || async move {
            if let Err(err) = blobs_protocol
                .download(endpoint, msg, progress.clone())
                .await
            {
                progress
                    .send(DownloadProgress::Abort(err.into()))
                    .await
                    .ok();
            }
        });

        receiver.map(DownloadResponse)
    }

    fn blob_export(self, msg: ExportRequest) -> impl Stream<Item = ExportResponse> {
        let (tx, rx) = async_channel::bounded(1024);
        let progress = AsyncChannelProgressSender::new(tx);
        self.local_pool_handle().spawn_detached(move || async move {
            let res = iroh_blobs::export::export(
                self.blobs().store(),
                msg.hash,
                msg.path,
                msg.format,
                msg.mode,
                progress.clone(),
            )
            .await;
            match res {
                Ok(()) => progress.send(ExportProgress::AllDone).await.ok(),
                Err(err) => progress.send(ExportProgress::Abort(err.into())).await.ok(),
            };
        });
        rx.map(ExportResponse)
    }

    async fn blob_add_from_path0(
        self,
        msg: AddPathRequest,
        progress: async_channel::Sender<AddProgress>,
    ) -> anyhow::Result<()> {
        use std::collections::BTreeMap;

        use iroh_blobs::store::ImportMode;

        let blobs = self.blobs();
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
                Some(AddProgress::Found { id, name, size })
            }
            ImportProgress::OutboardProgress { id, offset } => {
                Some(AddProgress::Progress { id, offset })
            }
            ImportProgress::OutboardDone { hash, id } => Some(AddProgress::Done { hash, id }),
            _ => None,
        });
        let AddPathRequest {
            wrap,
            path: root,
            in_place,
            tag,
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

        let create_collection = match wrap {
            WrapOption::Wrap { .. } => true,
            WrapOption::NoWrap => root.is_dir(),
        };

        let temp_tag = if create_collection {
            // import all files below root recursively
            let data_sources = crate::util::fs::scan_path(root, wrap)?;
            let blobs = self.blobs();

            const IO_PARALLELISM: usize = 4;
            let result: Vec<_> = futures_lite::stream::iter(data_sources)
                .map(|source| {
                    let import_progress = import_progress.clone();
                    let blobs = blobs.clone();
                    async move {
                        let name = source.name().to_string();
                        let (tag, size) = blobs
                            .store()
                            .import_file(
                                source.path().to_owned(),
                                import_mode,
                                BlobFormat::Raw,
                                import_progress,
                            )
                            .await?;
                        let hash = *tag.hash();
                        io::Result::Ok((name, hash, size, tag))
                    }
                })
                .buffered_ordered(IO_PARALLELISM)
                .try_collect()
                .await?;

            // create a collection
            let (collection, _child_tags): (Collection, Vec<_>) = result
                .into_iter()
                .map(|(name, hash, _, tag)| ((name, hash), tag))
                .unzip();

            collection.store(blobs.store()).await?
        } else {
            // import a single file
            let (tag, _size) = blobs
                .store()
                .import_file(root, import_mode, BlobFormat::Raw, import_progress)
                .await?;
            tag
        };

        let hash_and_format = temp_tag.inner();
        let HashAndFormat { hash, format } = *hash_and_format;
        let tag = match tag {
            SetTagOption::Named(tag) => {
                blobs
                    .store()
                    .set_tag(tag.clone(), Some(*hash_and_format))
                    .await?;
                tag
            }
            SetTagOption::Auto => blobs.store().create_tag(*hash_and_format).await?,
        };
        progress
            .send(AddProgress::AllDone {
                hash,
                format,
                tag: tag.clone(),
            })
            .await?;
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn node_stats(self, _req: StatsRequest) -> RpcResult<StatsResponse> {
        #[cfg(feature = "metrics")]
        let res = Ok(StatsResponse {
            stats: crate::metrics::get_metrics()?,
        });

        #[cfg(not(feature = "metrics"))]
        let res = Err(anyhow::anyhow!("metrics are disabled").into());

        res
    }

    async fn node_status(self, _: StatusRequest) -> RpcResult<NodeStatus> {
        Ok(NodeStatus {
            addr: self.inner.endpoint.node_addr().await?,
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
        let addr = self.inner.endpoint.node_addr().await?;
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

    async fn tags_set(self, msg: tags::SetRequest) -> RpcResult<()> {
        let blobs = self.blobs();
        blobs.store().set_tag(msg.name, msg.value).await?;
        if let SyncMode::Full = msg.sync {
            blobs.store().sync().await?;
        }
        if let Some(batch) = msg.batch {
            if let Some(content) = msg.value.as_ref() {
                blobs.batches().await.remove_one(batch, content)?;
            }
        }
        Ok(())
    }

    async fn tags_create(self, msg: tags::CreateRequest) -> RpcResult<Tag> {
        let blobs = self.blobs();
        let tag = blobs.store().create_tag(msg.value).await?;
        if let SyncMode::Full = msg.sync {
            blobs.store().sync().await?;
        }
        if let Some(batch) = msg.batch {
            blobs.batches().await.remove_one(batch, &msg.value)?;
        }
        Ok(tag)
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

    async fn batch_create_temp_tag(self, msg: BatchCreateTempTagRequest) -> RpcResult<()> {
        let blobs = self.blobs();
        let tag = blobs.store().temp_tag(msg.content);
        blobs.batches().await.store(msg.batch, tag);
        Ok(())
    }

    fn batch_add_stream(
        self,
        msg: BatchAddStreamRequest,
        stream: impl Stream<Item = BatchAddStreamUpdate> + Send + Unpin + 'static,
    ) -> impl Stream<Item = BatchAddStreamResponse> {
        let (tx, rx) = async_channel::bounded(32);
        let this = self.clone();

        self.local_pool_handle().spawn_detached(|| async move {
            if let Err(err) = this.batch_add_stream0(msg, stream, tx.clone()).await {
                tx.send(BatchAddStreamResponse::Abort(err.into()))
                    .await
                    .ok();
            }
        });
        rx
    }

    fn batch_add_from_path(
        self,
        msg: BatchAddPathRequest,
    ) -> impl Stream<Item = BatchAddPathResponse> {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = async_channel::bounded(32);
        let tx2 = tx.clone();
        self.local_pool_handle().spawn_detached(|| async move {
            if let Err(e) = self.batch_add_from_path0(msg, tx).await {
                tx2.send(BatchAddPathProgress::Abort(e.into())).await.ok();
            }
        });
        rx.map(BatchAddPathResponse)
    }

    async fn batch_add_stream0(
        self,
        msg: BatchAddStreamRequest,
        stream: impl Stream<Item = BatchAddStreamUpdate> + Send + Unpin + 'static,
        progress: async_channel::Sender<BatchAddStreamResponse>,
    ) -> anyhow::Result<()> {
        let blobs = self.blobs();
        let progress = AsyncChannelProgressSender::new(progress);

        let stream = stream.map(|item| match item {
            BatchAddStreamUpdate::Chunk(chunk) => Ok(chunk),
            BatchAddStreamUpdate::Abort => {
                Err(io::Error::new(io::ErrorKind::Interrupted, "Remote abort"))
            }
        });

        let import_progress = progress.clone().with_filter_map(move |x| match x {
            ImportProgress::OutboardProgress { offset, .. } => {
                Some(BatchAddStreamResponse::OutboardProgress { offset })
            }
            _ => None,
        });
        let (temp_tag, _len) = blobs
            .store()
            .import_stream(stream, msg.format, import_progress)
            .await?;
        let hash = temp_tag.inner().hash;
        blobs.batches().await.store(msg.batch, temp_tag);
        progress
            .send(BatchAddStreamResponse::Result { hash })
            .await?;
        Ok(())
    }

    async fn batch_add_from_path0(
        self,
        msg: BatchAddPathRequest,
        progress: async_channel::Sender<BatchAddPathProgress>,
    ) -> anyhow::Result<()> {
        let progress = AsyncChannelProgressSender::new(progress);
        // convert import progress to provide progress
        let import_progress = progress.clone().with_filter_map(move |x| match x {
            ImportProgress::Size { size, .. } => Some(BatchAddPathProgress::Found { size }),
            ImportProgress::OutboardProgress { offset, .. } => {
                Some(BatchAddPathProgress::Progress { offset })
            }
            ImportProgress::OutboardDone { hash, .. } => Some(BatchAddPathProgress::Done { hash }),
            _ => None,
        });
        let BatchAddPathRequest {
            path: root,
            import_mode,
            format,
            batch,
        } = msg;
        // Check that the path is absolute and exists.
        anyhow::ensure!(root.is_absolute(), "path must be absolute");
        anyhow::ensure!(
            root.exists(),
            "trying to add missing path: {}",
            root.display()
        );
        let blobs = self.blobs();
        let (tag, _) = blobs
            .store()
            .import_file(root, import_mode, format, import_progress)
            .await?;
        let hash = *tag.hash();
        blobs.batches().await.store(batch, tag);

        progress.send(BatchAddPathProgress::Done { hash }).await?;
        Ok(())
    }

    fn blob_add_stream(
        self,
        msg: AddStreamRequest,
        stream: impl Stream<Item = AddStreamUpdate> + Send + Unpin + 'static,
    ) -> impl Stream<Item = AddStreamResponse> {
        let (tx, rx) = async_channel::bounded(32);
        let this = self.clone();

        self.local_pool_handle().spawn_detached(|| async move {
            if let Err(err) = this.blob_add_stream0(msg, stream, tx.clone()).await {
                tx.send(AddProgress::Abort(err.into())).await.ok();
            }
        });

        rx.map(AddStreamResponse)
    }

    async fn blob_add_stream0(
        self,
        msg: AddStreamRequest,
        stream: impl Stream<Item = AddStreamUpdate> + Send + Unpin + 'static,
        progress: async_channel::Sender<AddProgress>,
    ) -> anyhow::Result<()> {
        let progress = AsyncChannelProgressSender::new(progress);

        let stream = stream.map(|item| match item {
            AddStreamUpdate::Chunk(chunk) => Ok(chunk),
            AddStreamUpdate::Abort => {
                Err(io::Error::new(io::ErrorKind::Interrupted, "Remote abort"))
            }
        });

        let name_cache = Arc::new(Mutex::new(None));
        let import_progress = progress.clone().with_filter_map(move |x| match x {
            ImportProgress::Found { id: _, name } => {
                let _ = name_cache.lock().unwrap().insert(name);
                None
            }
            ImportProgress::Size { id, size } => {
                let name = name_cache.lock().unwrap().take()?;
                Some(AddProgress::Found { id, name, size })
            }
            ImportProgress::OutboardProgress { id, offset } => {
                Some(AddProgress::Progress { id, offset })
            }
            ImportProgress::OutboardDone { hash, id } => Some(AddProgress::Done { hash, id }),
            _ => None,
        });
        let blobs = self.blobs();
        let (temp_tag, _len) = blobs
            .store()
            .import_stream(stream, BlobFormat::Raw, import_progress)
            .await?;
        let hash_and_format = *temp_tag.inner();
        let HashAndFormat { hash, format } = hash_and_format;
        let tag = match msg.tag {
            SetTagOption::Named(tag) => {
                blobs
                    .store()
                    .set_tag(tag.clone(), Some(hash_and_format))
                    .await?;
                tag
            }
            SetTagOption::Auto => blobs.store().create_tag(hash_and_format).await?,
        };
        progress
            .send(AddProgress::AllDone { hash, tag, format })
            .await?;
        Ok(())
    }

    fn blob_read_at(
        self,
        req: ReadAtRequest,
    ) -> impl Stream<Item = RpcResult<ReadAtResponse>> + Send + 'static {
        let (tx, rx) = async_channel::bounded(RPC_BLOB_GET_CHANNEL_CAP);
        let db = self.blobs_store();
        self.local_pool_handle().spawn_detached(move || async move {
            if let Err(err) = read_loop(req, db, tx.clone(), RPC_BLOB_GET_CHUNK_SIZE).await {
                tx.send(RpcResult::Err(err.into())).await.ok();
            }
        });

        async fn read_loop<D: iroh_blobs::store::Store>(
            req: ReadAtRequest,
            db: D,
            tx: async_channel::Sender<RpcResult<ReadAtResponse>>,
            max_chunk_size: usize,
        ) -> anyhow::Result<()> {
            let entry = db.get(&req.hash).await?;
            let entry = entry.ok_or_else(|| anyhow!("Blob not found"))?;
            let size = entry.size();

            anyhow::ensure!(
                req.offset <= size.value(),
                "requested offset is out of range: {} > {:?}",
                req.offset,
                size
            );

            let len: usize = req
                .len
                .as_result_len(size.value() - req.offset)
                .try_into()?;

            anyhow::ensure!(
                req.offset + len as u64 <= size.value(),
                "requested range is out of bounds: offset: {}, len: {} > {:?}",
                req.offset,
                len,
                size
            );

            tx.send(Ok(ReadAtResponse::Entry {
                size,
                is_complete: entry.is_complete(),
            }))
            .await?;
            let mut reader = entry.data_reader().await?;

            let (num_chunks, chunk_size) = if len <= max_chunk_size {
                (1, len)
            } else {
                let num_chunks = len / max_chunk_size + (len % max_chunk_size != 0) as usize;
                (num_chunks, max_chunk_size)
            };

            let mut read = 0u64;
            for i in 0..num_chunks {
                let chunk_size = if i == num_chunks - 1 {
                    // last chunk might be smaller
                    len - read as usize
                } else {
                    chunk_size
                };
                let chunk = reader.read_at(req.offset + read, chunk_size).await?;
                let chunk_len = chunk.len();
                if !chunk.is_empty() {
                    tx.send(Ok(ReadAtResponse::Data { chunk })).await?;
                }
                if chunk_len < chunk_size {
                    break;
                } else {
                    read += chunk_len as u64;
                }
            }
            Ok(())
        }

        rx
    }

    fn batch_create(
        self,
        _: BatchCreateRequest,
        mut updates: impl Stream<Item = BatchUpdate> + Send + Unpin + 'static,
    ) -> impl Stream<Item = BatchCreateResponse> {
        let blobs = self.blobs();
        async move {
            let batch = blobs.batches().await.create();
            tokio::spawn(async move {
                while let Some(item) = updates.next().await {
                    match item {
                        BatchUpdate::Drop(content) => {
                            // this can not fail, since we keep the batch alive.
                            // therefore it is safe to ignore the result.
                            let _ = blobs.batches().await.remove_one(batch, &content);
                        }
                        BatchUpdate::Ping => {}
                    }
                }
                blobs.batches().await.remove(batch);
            });
            BatchCreateResponse::Id(batch)
        }
        .into_stream()
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
        self.inner.endpoint.add_node_addr(addr)?;
        Ok(())
    }

    async fn create_collection(
        self,
        req: CreateCollectionRequest,
    ) -> RpcResult<CreateCollectionResponse> {
        let CreateCollectionRequest {
            collection,
            tag,
            tags_to_delete,
        } = req;

        let blobs = self.blobs();

        let temp_tag = collection.store(blobs.store()).await?;
        let hash_and_format = temp_tag.inner();
        let HashAndFormat { hash, .. } = *hash_and_format;
        let tag = match tag {
            SetTagOption::Named(tag) => {
                blobs
                    .store()
                    .set_tag(tag.clone(), Some(*hash_and_format))
                    .await?;
                tag
            }
            SetTagOption::Auto => blobs.store().create_tag(*hash_and_format).await?,
        };

        for tag in tags_to_delete {
            blobs.store().set_tag(tag, None).await?;
        }

        Ok(CreateCollectionResponse { hash, tag })
    }
}

fn docs_disabled() -> RpcError {
    anyhow!("docs are disabled").into()
}
