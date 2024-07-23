use std::fmt::Debug;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, ensure, Result};
use futures_buffered::BufferedStreamExt;
use futures_lite::{Stream, StreamExt};
use genawaiter::sync::{Co, Gen};
use iroh_base::rpc::{RpcError, RpcResult};
use iroh_blobs::downloader::{DownloadRequest, Downloader};
use iroh_blobs::export::ExportProgress;
use iroh_blobs::format::collection::Collection;
use iroh_blobs::get::db::DownloadProgress;
use iroh_blobs::get::Stats;
use iroh_blobs::store::{ConsistencyCheckProgress, ExportFormat, ImportProgress, MapEntry};
use iroh_blobs::util::local_pool::LocalPoolHandle;
use iroh_blobs::util::progress::ProgressSender;
use iroh_blobs::util::SetTagOption;
use iroh_blobs::BlobFormat;
use iroh_blobs::{
    provider::AddProgress,
    store::{Store as BaoStore, ValidateProgress},
    util::progress::FlumeProgressSender,
    HashAndFormat,
};
use iroh_io::AsyncSliceReader;
use iroh_net::relay::RelayUrl;
use iroh_net::{Endpoint, NodeAddr, NodeId};
use quic_rpc::server::{RpcChannel, RpcServerError};
use tokio::task::JoinSet;
use tokio_util::either::Either;
use tracing::{debug, info, warn};

use crate::client::{
    blobs::{BlobInfo, DownloadMode, IncompleteBlobInfo, WrapOption},
    tags::TagInfo,
    NodeStatus,
};
use crate::node::{docs::DocsEngine, NodeInner};
use crate::rpc_protocol::{
    authors, blobs,
    blobs::{
        AddPathRequest, AddPathResponse, AddStreamRequest, AddStreamResponse, AddStreamUpdate,
        ConsistencyCheckRequest, CreateCollectionRequest, CreateCollectionResponse, DeleteRequest,
        DownloadRequest as BlobDownloadRequest, DownloadResponse, ExportRequest, ExportResponse,
        ListIncompleteRequest, ListRequest, ReadAtRequest, ReadAtResponse, ValidateRequest,
    },
    docs::Request as DocsRequest,
    docs::{
        ExportFileRequest, ExportFileResponse, ImportFileRequest, ImportFileResponse,
        SetHashRequest,
    },
    gossip, node,
    node::{
        AddAddrRequest, AddrRequest, ConnectionInfoRequest, ConnectionInfoResponse,
        ConnectionsRequest, ConnectionsResponse, IdRequest, NodeWatchRequest, RelayRequest,
        ShutdownRequest, StatsRequest, StatsResponse, StatusRequest, WatchResponse,
    },
    tags,
    tags::{DeleteRequest as TagDeleteRequest, ListRequest as ListTagsRequest},
    Request, RpcService,
};

use super::IrohServerEndpoint;

mod docs;

const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);
/// Chunk size for getting blobs over RPC
const RPC_BLOB_GET_CHUNK_SIZE: usize = 1024 * 64;
/// Channel cap for getting blobs over RPC
const RPC_BLOB_GET_CHANNEL_CAP: usize = 2;
/// Name used for logging when new node addresses are added from gossip.
const BLOB_DOWNLOAD_SOURCE_NAME: &str = "blob_download";

#[derive(Debug, Clone)]
pub(crate) struct Handler<D> {
    pub(crate) inner: Arc<NodeInner<D>>,
}

impl<D> Handler<D> {
    pub fn new(inner: Arc<NodeInner<D>>) -> Self {
        Self { inner }
    }
}

impl<D: BaoStore> Handler<D> {
    fn docs(&self) -> Option<&DocsEngine> {
        self.inner.docs.as_ref()
    }

    async fn with_docs<T, F, Fut>(self, f: F) -> RpcResult<T>
    where
        T: Send + 'static,
        F: FnOnce(DocsEngine) -> Fut,
        Fut: std::future::Future<Output = RpcResult<T>>,
    {
        if let Some(docs) = self.docs() {
            let docs = docs.clone();
            f(docs).await
        } else {
            Err(docs_disabled())
        }
    }

    fn with_docs_stream<T, F, S>(self, f: F) -> impl Stream<Item = RpcResult<T>>
    where
        T: Send + 'static,
        F: FnOnce(DocsEngine) -> S,
        S: Stream<Item = RpcResult<T>>,
    {
        if let Some(docs) = self.docs() {
            let docs = docs.clone();
            Either::Left(f(docs))
        } else {
            Either::Right(futures_lite::stream::once(Err(docs_disabled())))
        }
    }

    pub(crate) fn spawn_rpc_request(
        inner: Arc<NodeInner<D>>,
        join_set: &mut JoinSet<anyhow::Result<()>>,
        accepting: quic_rpc::server::Accepting<RpcService, IrohServerEndpoint>,
    ) {
        let handler = Self::new(inner);
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
            Watch(msg) => chan.server_streaming(msg, self, Self::node_watch).await,
            Status(msg) => chan.rpc(msg, self, Self::node_status).await,
            Id(msg) => chan.rpc(msg, self, Self::node_id).await,
            Addr(msg) => chan.rpc(msg, self, Self::node_addr).await,
            Relay(msg) => chan.rpc(msg, self, Self::node_relay).await,
            Shutdown(msg) => chan.rpc(msg, self, Self::node_shutdown).await,
            Stats(msg) => chan.rpc(msg, self, Self::node_stats).await,
            Connections(msg) => {
                chan.server_streaming(msg, self, Self::node_connections)
                    .await
            }
            ConnectionInfo(msg) => chan.rpc(msg, self, Self::node_connection_info).await,
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
        }
    }

    async fn handle_gossip_request(
        self,
        msg: gossip::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use gossip::Request::*;
        match msg {
            Subscribe(msg) => {
                chan.bidi_streaming(msg, self, |handler, req, updates| {
                    handler.inner.gossip_dispatcher.subscribe_with_opts(
                        req.topic,
                        iroh_gossip::dispatcher::SubscribeOptions {
                            bootstrap: req.bootstrap,
                            subscription_capacity: req.subscription_capacity,
                        },
                        Box::new(updates),
                    )
                })
                .await
            }
            Update(_msg) => Err(RpcServerError::UnexpectedUpdateMessage),
        }
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
                let blobs_store = self.inner.db.clone();
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

    async fn blob_list_impl(self, co: &Co<RpcResult<BlobInfo>>) -> io::Result<()> {
        use bao_tree::io::fsm::Outboard;

        let db = self.inner.db.clone();
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
        let db = self.inner.db.clone();
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
        self.inner.db.set_tag(msg.name, None).await?;
        Ok(())
    }

    async fn blob_delete_blob(self, msg: DeleteRequest) -> RpcResult<()> {
        self.inner.db.delete(vec![msg.hash]).await?;
        Ok(())
    }

    fn blob_list_tags(self, msg: ListTagsRequest) -> impl Stream<Item = TagInfo> + Send + 'static {
        tracing::info!("blob_list_tags");
        Gen::new(|co| async move {
            let tags = self.inner.db.tags().await.unwrap();
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
        let db = self.inner.db.clone();
        tokio::task::spawn(async move {
            if let Err(e) = db
                .validate(msg.repair, FlumeProgressSender::new(tx).boxed())
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
        let db = self.inner.db.clone();
        tokio::task::spawn(async move {
            if let Err(e) = db
                .consistency_check(msg.repair, FlumeProgressSender::new(tx).boxed())
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
        use crate::client::docs::ImportProgress as DocImportProgress;
        use iroh_blobs::store::ImportMode;
        use std::collections::BTreeMap;

        let progress = FlumeProgressSender::new(progress);
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

        let (temp_tag, size) = self
            .inner
            .db
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
        let progress = FlumeProgressSender::new(progress);
        let ExportFileRequest { entry, path, mode } = msg;
        let key = bytes::Bytes::from(entry.key().to_vec());
        let export_progress = progress.clone().with_map(move |mut x| {
            // assign the doc key to the `meta` field of the initial progress event
            if let ExportProgress::Found { meta, .. } = &mut x {
                *meta = Some(key.clone())
            }
            x
        });
        iroh_blobs::export::export(
            &self.inner.db,
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
        let db = self.inner.db.clone();
        let downloader = self.inner.downloader.clone();
        let endpoint = self.inner.endpoint.clone();
        let progress = FlumeProgressSender::new(sender);
        self.local_pool_handle().spawn_detached(move || async move {
            if let Err(err) = download(&db, endpoint, &downloader, msg, progress.clone()).await {
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
        let progress = FlumeProgressSender::new(tx);
        self.local_pool_handle().spawn_detached(move || async move {
            let res = iroh_blobs::export::export(
                &self.inner.db,
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
        use iroh_blobs::store::ImportMode;
        use std::collections::BTreeMap;

        let progress = FlumeProgressSender::new(progress);
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
            const IO_PARALLELISM: usize = 4;
            let result: Vec<_> = futures_lite::stream::iter(data_sources)
                .map(|source| {
                    let import_progress = import_progress.clone();
                    let db = self.inner.db.clone();
                    async move {
                        let name = source.name().to_string();
                        let (tag, size) = db
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

            collection.store(&self.inner.db).await?
        } else {
            // import a single file
            let (tag, _size) = self
                .inner
                .db
                .import_file(root, import_mode, BlobFormat::Raw, import_progress)
                .await?;
            tag
        };

        let hash_and_format = temp_tag.inner();
        let HashAndFormat { hash, format } = *hash_and_format;
        let tag = match tag {
            SetTagOption::Named(tag) => {
                self.inner
                    .db
                    .set_tag(tag.clone(), Some(*hash_and_format))
                    .await?;
                tag
            }
            SetTagOption::Auto => self.inner.db.create_tag(*hash_and_format).await?,
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
        Ok(self.inner.secret_key.public())
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
        let progress = FlumeProgressSender::new(progress);

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
        let (temp_tag, _len) = self
            .inner
            .db
            .import_stream(stream, BlobFormat::Raw, import_progress)
            .await?;
        let hash_and_format = *temp_tag.inner();
        let HashAndFormat { hash, format } = hash_and_format;
        let tag = match msg.tag {
            SetTagOption::Named(tag) => {
                self.inner
                    .db
                    .set_tag(tag.clone(), Some(hash_and_format))
                    .await?;
                tag
            }
            SetTagOption::Auto => self.inner.db.create_tag(hash_and_format).await?,
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
        let (tx, rx) = flume::bounded(RPC_BLOB_GET_CHANNEL_CAP);
        let db = self.inner.db.clone();
        self.local_pool_handle().spawn_detached(move || async move {
            if let Err(err) = read_loop(req, db, tx.clone(), RPC_BLOB_GET_CHUNK_SIZE).await {
                tx.send_async(RpcResult::Err(err.into())).await.ok();
            }
        });

        async fn read_loop<D: iroh_blobs::store::Store>(
            req: ReadAtRequest,
            db: D,
            tx: flume::Sender<RpcResult<ReadAtResponse>>,
            max_chunk_size: usize,
        ) -> anyhow::Result<()> {
            let entry = db.get(&req.hash).await?;
            let entry = entry.ok_or_else(|| anyhow!("Blob not found"))?;
            let size = entry.size();
            tx.send_async(Ok(ReadAtResponse::Entry {
                size,
                is_complete: entry.is_complete(),
            }))
            .await?;
            let mut reader = entry.data_reader().await?;

            let len = req.len.unwrap_or((size.value() - req.offset) as usize);

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
                    tx.send_async(Ok(ReadAtResponse::Data { chunk })).await?;
                }
                if chunk_len < chunk_size {
                    break;
                } else {
                    read += chunk_len as u64;
                }
            }
            Ok(())
        }

        rx.into_stream()
    }

    fn node_connections(
        self,
        _: ConnectionsRequest,
    ) -> impl Stream<Item = RpcResult<ConnectionsResponse>> + Send + 'static {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = flume::bounded(32);
        let mut conn_infos = self.inner.endpoint.connection_infos();
        conn_infos.sort_by_key(|n| n.node_id.to_string());
        self.local_pool_handle().spawn_detached(|| async move {
            for conn_info in conn_infos {
                tx.send_async(Ok(ConnectionsResponse { conn_info }))
                    .await
                    .ok();
            }
        });
        rx.into_stream()
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn node_connection_info(
        self,
        req: ConnectionInfoRequest,
    ) -> RpcResult<ConnectionInfoResponse> {
        let ConnectionInfoRequest { node_id } = req;
        let conn_info = self.inner.endpoint.connection_info(node_id);
        Ok(ConnectionInfoResponse { conn_info })
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

        let temp_tag = collection.store(&self.inner.db).await?;
        let hash_and_format = temp_tag.inner();
        let HashAndFormat { hash, .. } = *hash_and_format;
        let tag = match tag {
            SetTagOption::Named(tag) => {
                self.inner
                    .db
                    .set_tag(tag.clone(), Some(*hash_and_format))
                    .await?;
                tag
            }
            SetTagOption::Auto => self.inner.db.create_tag(*hash_and_format).await?,
        };

        for tag in tags_to_delete {
            self.inner.db.set_tag(tag, None).await?;
        }

        Ok(CreateCollectionResponse { hash, tag })
    }
}

async fn download<D>(
    db: &D,
    endpoint: Endpoint,
    downloader: &Downloader,
    req: BlobDownloadRequest,
    progress: FlumeProgressSender<DownloadProgress>,
) -> Result<()>
where
    D: iroh_blobs::store::Store,
{
    let BlobDownloadRequest {
        hash,
        format,
        nodes,
        tag,
        mode,
    } = req;
    let hash_and_format = HashAndFormat { hash, format };
    let temp_tag = db.temp_tag(hash_and_format);
    let stats = match mode {
        DownloadMode::Queued => {
            download_queued(
                endpoint,
                downloader,
                hash_and_format,
                nodes,
                progress.clone(),
            )
            .await?
        }
        DownloadMode::Direct => {
            download_direct_from_nodes(db, endpoint, hash_and_format, nodes, progress.clone())
                .await?
        }
    };

    progress.send(DownloadProgress::AllDone(stats)).await.ok();
    match tag {
        SetTagOption::Named(tag) => {
            db.set_tag(tag, Some(hash_and_format)).await?;
        }
        SetTagOption::Auto => {
            db.create_tag(hash_and_format).await?;
        }
    }
    drop(temp_tag);

    Ok(())
}

async fn download_queued(
    endpoint: Endpoint,
    downloader: &Downloader,
    hash_and_format: HashAndFormat,
    nodes: Vec<NodeAddr>,
    progress: FlumeProgressSender<DownloadProgress>,
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
    let handle = downloader.queue(req).await;
    let stats = handle.await?;
    Ok(stats)
}

async fn download_direct_from_nodes<D>(
    db: &D,
    endpoint: Endpoint,
    hash_and_format: HashAndFormat,
    nodes: Vec<NodeAddr>,
    progress: FlumeProgressSender<DownloadProgress>,
) -> Result<Stats>
where
    D: BaoStore,
{
    ensure!(!nodes.is_empty(), "No nodes to download from provided.");
    let mut last_err = None;
    for node in nodes {
        let node_id = node.node_id;
        match download_direct(
            db,
            endpoint.clone(),
            hash_and_format,
            node,
            progress.clone(),
        )
        .await
        {
            Ok(stats) => return Ok(stats),
            Err(err) => {
                debug!(?err, node = &node_id.fmt_short(), "Download failed");
                last_err = Some(err)
            }
        }
    }
    Err(last_err.unwrap())
}

async fn download_direct<D>(
    db: &D,
    endpoint: Endpoint,
    hash_and_format: HashAndFormat,
    node: NodeAddr,
    progress: FlumeProgressSender<DownloadProgress>,
) -> Result<Stats>
where
    D: BaoStore,
{
    let get_conn = {
        let progress = progress.clone();
        move || async move {
            let conn = endpoint.connect(node, iroh_blobs::protocol::ALPN).await?;
            progress.send(DownloadProgress::Connected).await?;
            Ok(conn)
        }
    };

    let res = iroh_blobs::get::db::get_to_db(db, get_conn, &hash_and_format, progress).await;

    res.map_err(Into::into)
}

fn docs_disabled() -> RpcError {
    anyhow!("docs are disabled").into()
}
