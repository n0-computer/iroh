use std::fmt::Debug;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::{FutureExt, Stream, StreamExt};
use genawaiter::sync::{Co, Gen};
use iroh_base::rpc::RpcResult;
use iroh_bytes::downloader::{DownloadRequest, Downloader};
use iroh_bytes::export::ExportProgress;
use iroh_bytes::format::collection::Collection;
use iroh_bytes::get::db::DownloadProgress;
use iroh_bytes::get::Stats;
use iroh_bytes::store::{ExportMode, ImportProgress, MapEntry};
use iroh_bytes::util::progress::ProgressSender;
use iroh_bytes::BlobFormat;
use iroh_bytes::{
    hashseq::parse_hash_seq,
    provider::AddProgress,
    store::{PossiblyPartialEntry, Store as BaoStore, ValidateProgress},
    util::progress::FlumeProgressSender,
    HashAndFormat,
};
use iroh_io::AsyncSliceReader;
use iroh_net::{MagicEndpoint, NodeAddr, NodeId};
use quic_rpc::{
    server::{RpcChannel, RpcServerError},
    ServiceEndpoint,
};
use tokio::sync::mpsc;
use tokio_util::task::LocalPoolHandle;
use tracing::{debug, info};

use crate::rpc_protocol::{
    BlobAddPathRequest, BlobAddPathResponse, BlobAddStreamRequest, BlobAddStreamResponse,
    BlobAddStreamUpdate, BlobDeleteBlobRequest, BlobDownloadRequest, BlobDownloadResponse,
    BlobGetCollectionRequest, BlobGetCollectionResponse, BlobListCollectionsRequest,
    BlobListCollectionsResponse, BlobListIncompleteRequest, BlobListIncompleteResponse,
    BlobListRequest, BlobListResponse, BlobReadAtRequest, BlobReadAtResponse, BlobValidateRequest,
    CreateCollectionRequest, CreateCollectionResponse, DeleteTagRequest, DocExportFileRequest,
    DocExportFileResponse, DocImportFileRequest, DocImportFileResponse, DocImportProgress,
    DocSetHashRequest, DownloadLocation, DownloadMode, ListTagsRequest, ListTagsResponse,
    NodeConnectionInfoRequest, NodeConnectionInfoResponse, NodeConnectionsRequest,
    NodeConnectionsResponse, NodeShutdownRequest, NodeStatsRequest, NodeStatsResponse,
    NodeStatusRequest, NodeStatusResponse, NodeWatchRequest, NodeWatchResponse, ProviderRequest,
    ProviderService, SetTagOption,
};

use super::{Event, NodeInner};

const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);
/// Chunk size for getting blobs over RPC
const RPC_BLOB_GET_CHUNK_SIZE: usize = 1024 * 64;
/// Channel cap for getting blobs over RPC
const RPC_BLOB_GET_CHANNEL_CAP: usize = 2;

#[derive(Debug, Clone)]
pub(crate) struct Handler<D> {
    pub(crate) inner: Arc<NodeInner<D>>,
}

impl<D: BaoStore> Handler<D> {
    pub(crate) fn handle_rpc_request<E: ServiceEndpoint<ProviderService>>(
        &self,
        msg: ProviderRequest,
        chan: RpcChannel<ProviderService, E>,
    ) {
        let handler = self.clone();
        tokio::task::spawn(async move {
            use ProviderRequest::*;
            debug!("handling rpc request: {msg}");
            match msg {
                NodeWatch(msg) => chan.server_streaming(msg, handler, Self::node_watch).await,
                NodeStatus(msg) => chan.rpc(msg, handler, Self::node_status).await,
                NodeShutdown(msg) => chan.rpc(msg, handler, Self::node_shutdown).await,
                NodeStats(msg) => chan.rpc(msg, handler, Self::node_stats).await,
                NodeConnections(msg) => {
                    chan.server_streaming(msg, handler, Self::node_connections)
                        .await
                }
                NodeConnectionInfo(msg) => chan.rpc(msg, handler, Self::node_connection_info).await,
                BlobList(msg) => chan.server_streaming(msg, handler, Self::blob_list).await,
                BlobListIncomplete(msg) => {
                    chan.server_streaming(msg, handler, Self::blob_list_incomplete)
                        .await
                }
                BlobListCollections(msg) => {
                    chan.server_streaming(msg, handler, Self::blob_list_collections)
                        .await
                }
                CreateCollection(msg) => chan.rpc(msg, handler, Self::create_collection).await,
                BlobGetCollection(msg) => chan.rpc(msg, handler, Self::blob_get_collection).await,
                ListTags(msg) => {
                    chan.server_streaming(msg, handler, Self::blob_list_tags)
                        .await
                }
                DeleteTag(msg) => chan.rpc(msg, handler, Self::blob_delete_tag).await,
                BlobDeleteBlob(msg) => chan.rpc(msg, handler, Self::blob_delete_blob).await,
                BlobAddPath(msg) => {
                    chan.server_streaming(msg, handler, Self::blob_add_from_path)
                        .await
                }
                BlobDownload(msg) => {
                    chan.server_streaming(msg, handler, Self::blob_download)
                        .await
                }
                BlobValidate(msg) => {
                    chan.server_streaming(msg, handler, Self::blob_validate)
                        .await
                }
                BlobReadAt(msg) => {
                    chan.server_streaming(msg, handler, Self::blob_read_at)
                        .await
                }
                BlobAddStream(msg) => {
                    chan.bidi_streaming(msg, handler, Self::blob_add_stream)
                        .await
                }
                BlobAddStreamUpdate(_msg) => Err(RpcServerError::UnexpectedUpdateMessage),
                AuthorList(msg) => {
                    chan.server_streaming(msg, handler, |handler, req| {
                        handler.inner.sync.author_list(req)
                    })
                    .await
                }
                AuthorCreate(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.author_create(req).await
                    })
                    .await
                }
                AuthorImport(_msg) => {
                    todo!()
                }
                DocOpen(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_open(req).await
                    })
                    .await
                }
                DocClose(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_close(req).await
                    })
                    .await
                }
                DocStatus(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_status(req).await
                    })
                    .await
                }
                DocList(msg) => {
                    chan.server_streaming(msg, handler, |handler, req| {
                        handler.inner.sync.doc_list(req)
                    })
                    .await
                }
                DocCreate(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_create(req).await
                    })
                    .await
                }
                DocDrop(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_drop(req).await
                    })
                    .await
                }
                DocImport(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_import(req).await
                    })
                    .await
                }
                DocSet(msg) => {
                    let bao_store = handler.inner.db.clone();
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_set(&bao_store, req).await
                    })
                    .await
                }
                DocImportFile(msg) => {
                    chan.server_streaming(msg, handler, Self::doc_import_file)
                        .await
                }
                DocExportFile(msg) => {
                    chan.server_streaming(msg, handler, Self::doc_export_file)
                        .await
                }
                DocDel(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_del(req).await
                    })
                    .await
                }
                DocSetHash(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_set_hash(req).await
                    })
                    .await
                }
                DocGet(msg) => {
                    chan.server_streaming(msg, handler, |handler, req| {
                        handler.inner.sync.doc_get_many(req)
                    })
                    .await
                }
                DocGetExact(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_get_exact(req).await
                    })
                    .await
                }
                DocStartSync(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_start_sync(req).await
                    })
                    .await
                }
                DocLeave(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_leave(req).await
                    })
                    .await
                }
                DocShare(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_share(req).await
                    })
                    .await
                }
                DocSubscribe(msg) => {
                    chan.server_streaming(msg, handler, |handler, req| {
                        async move { handler.inner.sync.doc_subscribe(req) }.flatten_stream()
                    })
                    .await
                }
                DocSetDownloadPolicy(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_set_download_policy(req).await
                    })
                    .await
                }
                DocGetDownloadPolicy(msg) => {
                    chan.rpc(msg, handler, |handler, req| async move {
                        handler.inner.sync.doc_get_download_policy(req).await
                    })
                    .await
                }
            }
        });
    }

    fn rt(&self) -> LocalPoolHandle {
        self.inner.rt.clone()
    }

    async fn blob_list_impl(self, co: &Co<RpcResult<BlobListResponse>>) -> io::Result<()> {
        use bao_tree::io::fsm::Outboard;

        let db = self.inner.db.clone();
        for blob in db.blobs().await? {
            let blob = blob?;
            let Some(entry) = db.get(&blob).await? else {
                continue;
            };
            let hash = entry.hash();
            let size = entry.outboard().await?.tree().size().0;
            let path = "".to_owned();
            co.yield_(Ok(BlobListResponse { hash, size, path })).await;
        }
        Ok(())
    }

    async fn blob_list_incomplete_impl(
        self,
        co: &Co<RpcResult<BlobListIncompleteResponse>>,
    ) -> io::Result<()> {
        let db = self.inner.db.clone();
        for hash in db.partial_blobs().await? {
            let hash = hash?;
            let Ok(PossiblyPartialEntry::Partial(entry)) = db.get_possibly_partial(&hash).await
            else {
                continue;
            };
            let size = 0;
            let expected_size = entry.size().value();
            co.yield_(Ok(BlobListIncompleteResponse {
                hash,
                size,
                expected_size,
            }))
            .await;
        }
        Ok(())
    }

    async fn blob_list_collections_impl(
        self,
        co: &Co<RpcResult<BlobListCollectionsResponse>>,
    ) -> anyhow::Result<()> {
        let db = self.inner.db.clone();
        let local = self.inner.rt.clone();
        let tags = db.tags().await.unwrap();
        for item in tags {
            let (name, HashAndFormat { hash, format }) = item?;
            if !format.is_hash_seq() {
                continue;
            }
            let Some(entry) = db.get(&hash).await? else {
                continue;
            };
            let count = local
                .spawn_pinned(|| async move {
                    let reader = entry.data_reader().await?;
                    let (_collection, count) = parse_hash_seq(reader).await?;
                    anyhow::Ok(count)
                })
                .await??;
            co.yield_(Ok(BlobListCollectionsResponse {
                tag: name,
                hash,
                total_blobs_count: Some(count),
                total_blobs_size: None,
            }))
            .await;
        }
        Ok(())
    }

    fn blob_list(
        self,
        _msg: BlobListRequest,
    ) -> impl Stream<Item = RpcResult<BlobListResponse>> + Send + 'static {
        Gen::new(|co| async move {
            if let Err(e) = self.blob_list_impl(&co).await {
                co.yield_(Err(e.into())).await;
            }
        })
    }

    fn blob_list_incomplete(
        self,
        _msg: BlobListIncompleteRequest,
    ) -> impl Stream<Item = RpcResult<BlobListIncompleteResponse>> + Send + 'static {
        Gen::new(move |co| async move {
            if let Err(e) = self.blob_list_incomplete_impl(&co).await {
                co.yield_(Err(e.into())).await;
            }
        })
    }

    fn blob_list_collections(
        self,
        _msg: BlobListCollectionsRequest,
    ) -> impl Stream<Item = RpcResult<BlobListCollectionsResponse>> + Send + 'static {
        Gen::new(move |co| async move {
            if let Err(e) = self.blob_list_collections_impl(&co).await {
                co.yield_(Err(e.into())).await;
            }
        })
    }

    async fn blob_delete_tag(self, msg: DeleteTagRequest) -> RpcResult<()> {
        self.inner.db.set_tag(msg.name, None).await?;
        Ok(())
    }

    async fn blob_delete_blob(self, msg: BlobDeleteBlobRequest) -> RpcResult<()> {
        self.inner.db.delete(vec![msg.hash]).await?;
        Ok(())
    }

    fn blob_list_tags(
        self,
        _msg: ListTagsRequest,
    ) -> impl Stream<Item = ListTagsResponse> + Send + 'static {
        tracing::info!("blob_list_tags");
        Gen::new(|co| async move {
            let tags = self.inner.db.tags().await.unwrap();
            #[allow(clippy::manual_flatten)]
            for item in tags {
                if let Ok((name, HashAndFormat { hash, format })) = item {
                    tracing::info!("{:?} {} {:?}", name, hash, format);
                    co.yield_(ListTagsResponse { name, hash, format }).await;
                }
            }
        })
    }

    /// Invoke validate on the database and stream out the result
    fn blob_validate(
        self,
        msg: BlobValidateRequest,
    ) -> impl Stream<Item = ValidateProgress> + Send + 'static {
        let (tx, rx) = mpsc::channel(1);
        let tx2 = tx.clone();
        let db = self.inner.db.clone();
        tokio::task::spawn(async move {
            if let Err(e) = db.validate(msg.repair, tx).await {
                tx2.send(ValidateProgress::Abort(e.into())).await.unwrap();
            }
        });
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    fn blob_add_from_path(
        self,
        msg: BlobAddPathRequest,
    ) -> impl Stream<Item = BlobAddPathResponse> {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = flume::bounded(32);
        let tx2 = tx.clone();
        self.rt().spawn_pinned(|| async move {
            if let Err(e) = self.blob_add_from_path0(msg, tx).await {
                tx2.send_async(AddProgress::Abort(e.into())).await.ok();
            }
        });
        rx.into_stream().map(BlobAddPathResponse)
    }

    fn doc_import_file(
        self,
        msg: DocImportFileRequest,
    ) -> impl Stream<Item = DocImportFileResponse> {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = flume::bounded(32);
        let tx2 = tx.clone();
        self.rt().spawn_pinned(|| async move {
            if let Err(e) = self.doc_import_file0(msg, tx).await {
                tx2.send_async(DocImportProgress::Abort(e.into()))
                    .await
                    .ok();
            }
        });
        rx.into_stream().map(DocImportFileResponse)
    }

    async fn doc_import_file0(
        self,
        msg: DocImportFileRequest,
        progress: flume::Sender<DocImportProgress>,
    ) -> anyhow::Result<()> {
        use iroh_bytes::store::ImportMode;
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
        let DocImportFileRequest {
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
        self.inner
            .sync
            .doc_set_hash(DocSetHashRequest {
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

    fn doc_export_file(
        self,
        msg: DocExportFileRequest,
    ) -> impl Stream<Item = DocExportFileResponse> {
        let (tx, rx) = flume::bounded(1024);
        let tx2 = tx.clone();
        self.rt().spawn_pinned(|| async move {
            if let Err(e) = self.doc_export_file0(msg, tx).await {
                tx2.send_async(ExportProgress::Abort(e.into())).await.ok();
            }
        });
        rx.into_stream().map(DocExportFileResponse)
    }

    async fn doc_export_file0(
        self,
        msg: DocExportFileRequest,
        progress: flume::Sender<ExportProgress>,
    ) -> anyhow::Result<()> {
        let progress = FlumeProgressSender::new(progress);
        let DocExportFileRequest { entry, path, mode } = msg;
        let key = bytes::Bytes::from(entry.key().to_vec());
        let export_progress = progress.clone().with_map(move |mut x| {
            // assign the doc key to the `meta` field of the initial progress event
            if let ExportProgress::Found { meta, .. } = &mut x {
                *meta = Some(key.clone())
            }
            x
        });
        iroh_bytes::export::export(
            &self.inner.db,
            entry.content_hash(),
            path,
            false,
            mode,
            export_progress,
        )
        .await?;
        progress.send(ExportProgress::AllDone).await?;
        Ok(())
    }

    fn blob_download(self, msg: BlobDownloadRequest) -> impl Stream<Item = BlobDownloadResponse> {
        let (sender, receiver) = flume::bounded(1024);
        let db = self.inner.db.clone();
        let downloader = self.inner.downloader.clone();
        let endpoint = self.inner.endpoint.clone();
        let progress = FlumeProgressSender::new(sender);
        self.inner.rt.spawn_pinned(move || async move {
            match download(&db, endpoint, &downloader, msg, progress.clone()).await {
                Err(err) => progress
                    .send(DownloadProgress::Abort(err.into()))
                    .await
                    .ok(),
                Ok(()) => progress.send(DownloadProgress::AllDone).await.ok(),
            }
        });

        receiver.into_stream().map(BlobDownloadResponse)
    }

    async fn blob_add_from_path0(
        self,
        msg: BlobAddPathRequest,
        progress: flume::Sender<AddProgress>,
    ) -> anyhow::Result<()> {
        use crate::rpc_protocol::WrapOption;
        use futures::TryStreamExt;
        use iroh_bytes::store::ImportMode;
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
        let BlobAddPathRequest {
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
            let result: Vec<_> = futures::stream::iter(data_sources)
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
                .buffered(IO_PARALLELISM)
                .try_collect::<Vec<_>>()
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
        self.inner
            .callbacks
            .send(Event::ByteProvide(
                iroh_bytes::provider::Event::TaggedBlobAdded { hash, format, tag },
            ))
            .await;

        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn node_stats(self, _req: NodeStatsRequest) -> RpcResult<NodeStatsResponse> {
        #[cfg(feature = "metrics")]
        let res = Ok(NodeStatsResponse {
            stats: crate::metrics::get_metrics()?,
        });

        #[cfg(not(feature = "metrics"))]
        let res = Err(anyhow::anyhow!("metrics are disabled").into());

        res
    }

    async fn node_status(self, _: NodeStatusRequest) -> RpcResult<NodeStatusResponse> {
        Ok(NodeStatusResponse {
            addr: self.inner.endpoint.my_addr().await?,
            listen_addrs: self
                .inner
                .local_endpoint_addresses()
                .await
                .unwrap_or_default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    #[allow(clippy::unused_async)]
    async fn node_shutdown(self, request: NodeShutdownRequest) {
        if request.force {
            info!("hard shutdown requested");
            std::process::exit(0);
        } else {
            // trigger a graceful shutdown
            info!("graceful shutdown requested");
            self.inner.cancel_token.cancel();
        }
    }

    fn node_watch(self, _: NodeWatchRequest) -> impl Stream<Item = NodeWatchResponse> {
        futures::stream::unfold((), |()| async move {
            tokio::time::sleep(HEALTH_POLL_WAIT).await;
            Some((
                NodeWatchResponse {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                (),
            ))
        })
    }

    fn blob_add_stream(
        self,
        msg: BlobAddStreamRequest,
        stream: impl Stream<Item = BlobAddStreamUpdate> + Send + Unpin + 'static,
    ) -> impl Stream<Item = BlobAddStreamResponse> {
        let (tx, rx) = flume::bounded(32);
        let this = self.clone();

        self.rt().spawn_pinned(|| async move {
            if let Err(err) = this.blob_add_stream0(msg, stream, tx.clone()).await {
                tx.send_async(AddProgress::Abort(err.into())).await.ok();
            }
        });

        rx.into_stream().map(BlobAddStreamResponse)
    }

    async fn blob_add_stream0(
        self,
        msg: BlobAddStreamRequest,
        stream: impl Stream<Item = BlobAddStreamUpdate> + Send + Unpin + 'static,
        progress: flume::Sender<AddProgress>,
    ) -> anyhow::Result<()> {
        let progress = FlumeProgressSender::new(progress);

        let stream = stream.map(|item| match item {
            BlobAddStreamUpdate::Chunk(chunk) => Ok(chunk),
            BlobAddStreamUpdate::Abort => {
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
        req: BlobReadAtRequest,
    ) -> impl Stream<Item = RpcResult<BlobReadAtResponse>> + Send + 'static {
        let (tx, rx) = flume::bounded(RPC_BLOB_GET_CHANNEL_CAP);
        let db = self.inner.db.clone();
        self.inner.rt.spawn_pinned(move || async move {
            let entry = db.get(&req.hash).await.unwrap();
            if let Err(err) = read_loop(
                req.offset,
                req.len,
                entry,
                tx.clone(),
                RPC_BLOB_GET_CHUNK_SIZE,
            )
            .await
            {
                tx.send_async(RpcResult::Err(err.into())).await.ok();
            }
        });

        async fn read_loop(
            offset: u64,
            len: Option<usize>,
            entry: Option<impl MapEntry>,
            tx: flume::Sender<RpcResult<BlobReadAtResponse>>,
            max_chunk_size: usize,
        ) -> anyhow::Result<()> {
            let entry = entry.ok_or_else(|| anyhow!("Blob not found"))?;
            let size = entry.size();
            tx.send_async(Ok(BlobReadAtResponse::Entry {
                size,
                is_complete: entry.is_complete(),
            }))
            .await?;
            let mut reader = entry.data_reader().await?;

            let len = len.unwrap_or((size.value() - offset) as usize);

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
                let chunk = reader.read_at(offset + read, chunk_size).await?;
                let chunk_len = chunk.len();
                if !chunk.is_empty() {
                    tx.send_async(Ok(BlobReadAtResponse::Data { chunk }))
                        .await?;
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
        _: NodeConnectionsRequest,
    ) -> impl Stream<Item = RpcResult<NodeConnectionsResponse>> + Send + 'static {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = flume::bounded(32);
        let mut conn_infos = self.inner.endpoint.connection_infos();
        conn_infos.sort_by_key(|n| n.node_id.to_string());
        self.rt().spawn_pinned(|| async move {
            for conn_info in conn_infos {
                tx.send_async(Ok(NodeConnectionsResponse { conn_info }))
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
        req: NodeConnectionInfoRequest,
    ) -> RpcResult<NodeConnectionInfoResponse> {
        let NodeConnectionInfoRequest { node_id } = req;
        let conn_info = self.inner.endpoint.connection_info(node_id);
        Ok(NodeConnectionInfoResponse { conn_info })
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

    async fn blob_get_collection(
        self,
        req: BlobGetCollectionRequest,
    ) -> RpcResult<BlobGetCollectionResponse> {
        let hash = req.hash;
        let db = self.inner.db.clone();
        let collection = self
            .rt()
            .spawn_pinned(move || async move { Collection::load(&db, &hash).await })
            .await
            .map_err(|_| anyhow!("join failed"))??;

        Ok(BlobGetCollectionResponse { collection })
    }
}

async fn download<D>(
    db: &D,
    endpoint: MagicEndpoint,
    downloader: &Downloader,
    req: BlobDownloadRequest,
    progress: FlumeProgressSender<DownloadProgress>,
) -> Result<()>
where
    D: iroh_bytes::store::Store,
{
    let BlobDownloadRequest {
        hash,
        format,
        peer: node,
        tag,
        out,
        mode,
    } = req;
    let hash_and_format = HashAndFormat { hash, format };
    let stats = match mode {
        DownloadMode::Queued => {
            let node_id = node.node_id;
            endpoint.add_node_addr(node)?;
            download_queued(downloader, hash_and_format, node_id, tag, progress.clone()).await?
        }
        DownloadMode::Direct => {
            download_direct(db, endpoint, hash_and_format, node, tag, progress.clone()).await?
        }
    };

    progress
        .send(DownloadProgress::NetworkDone(stats))
        .await
        .ok();

    match out {
        DownloadLocation::Internal => {
            // Nothing to do
        }
        DownloadLocation::External { path, in_place } => {
            let mode = match in_place {
                true => ExportMode::TryReference,
                false => ExportMode::Copy,
            };
            export_download(db, hash_and_format, path, mode, progress).await?;
        }
    }

    Ok(())
}

async fn download_queued(
    downloader: &Downloader,
    hash_and_format: HashAndFormat,
    node_id: NodeId,
    tag: SetTagOption,
    progress: FlumeProgressSender<DownloadProgress>,
) -> Result<Stats> {
    let req = DownloadRequest::new(hash_and_format, vec![node_id])
        .progress_sender(progress)
        .tag(tag);
    let handle = downloader.queue(req).await;
    let stats = handle.await?;
    Ok(stats)
}

async fn download_direct<D>(
    db: &D,
    endpoint: MagicEndpoint,
    hash_and_format: HashAndFormat,
    node: NodeAddr,
    tag: SetTagOption,
    progress: FlumeProgressSender<DownloadProgress>,
) -> Result<Stats>
where
    D: BaoStore,
{
    let temp_pin = db.temp_tag(hash_and_format);
    let get_conn = {
        let progress = progress.clone();
        move || async move {
            let conn = endpoint.connect(node, iroh_bytes::protocol::ALPN).await?;
            progress.send(DownloadProgress::Connected).await?;
            Ok(conn)
        }
    };
    let stats =
        iroh_bytes::get::db::get_to_db(db, get_conn, &hash_and_format, progress.clone()).await?;

    match tag {
        SetTagOption::Named(tag) => {
            db.set_tag(tag, Some(hash_and_format)).await?;
        }
        SetTagOption::Auto => {
            db.create_tag(hash_and_format).await?;
        }
    }
    drop(temp_pin);

    Ok(stats)
}

async fn export_download<D>(
    db: &D,
    hash_and_format: HashAndFormat,
    path: PathBuf,
    mode: ExportMode,
    progress: FlumeProgressSender<DownloadProgress>,
) -> Result<()>
where
    D: BaoStore,
{
    let export_progress = progress.clone().with_map(DownloadProgress::Export);
    iroh_bytes::export::export(
        db,
        hash_and_format.hash,
        path,
        hash_and_format.format.is_hash_seq(),
        mode,
        export_progress,
    )
    .await?;

    Ok(())
}
