//! API for blobs management.

use std::{
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use futures_buffered::BufferedStreamExt;
use futures_lite::{Stream, StreamExt};
use futures_util::{FutureExt, SinkExt};
use iroh_base::{node_addr::AddrInfoOptions, ticket::BlobTicket};
use iroh_blobs::{
    export::ExportProgress as BytesExportProgress,
    format::collection::Collection,
    get::db::DownloadProgress as BytesDownloadProgress,
    provider::BatchAddPathProgress,
    store::{ConsistencyCheckProgress, ExportFormat, ExportMode, ValidateProgress},
    util::TagDrop,
    BlobFormat, Hash, HashAndFormat, Tag, TempTag,
};
use iroh_net::NodeAddr;
use portable_atomic::{AtomicU64, Ordering};
use quic_rpc::{
    client::{BoxStreamSync, UpdateSink},
    RpcClient, ServiceConnection,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::warn;

use crate::rpc_protocol::{
    BatchAddPathRequest, BatchAddStreamRequest, BatchAddStreamResponse, BatchAddStreamUpdate,
    BatchCreateRequest, BatchCreateResponse, BatchCreateTempTagRequest, BatchUpdate,
    BlobAddPathRequest, BlobAddStreamRequest, BlobAddStreamUpdate, BlobConsistencyCheckRequest,
    BlobDeleteBlobRequest, BlobDownloadRequest, BlobExportRequest, BlobGetCollectionRequest,
    BlobGetCollectionResponse, BlobListCollectionsRequest, BlobListIncompleteRequest,
    BlobListRequest, BlobReadAtRequest, BlobReadAtResponse, BlobStatusRequest, BlobValidateRequest,
    CreateCollectionRequest, CreateCollectionResponse, NodeStatusRequest, RpcService, SetTagOption,
};

use super::{flatten, Iroh};

pub use crate::rpc_protocol::BlobStatus;
pub use iroh_blobs::store::ImportMode;

/// Iroh blobs client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<RpcService, C>,
}

impl<'a, C: ServiceConnection<RpcService>> From<&'a Iroh<C>> for &'a RpcClient<RpcService, C> {
    fn from(client: &'a Iroh<C>) -> &'a RpcClient<RpcService, C> {
        &client.blobs.rpc
    }
}

impl<C> Client<C>
where
    C: ServiceConnection<RpcService>,
{
    /// Check if a blob is completely stored on the node.
    ///
    /// Note that this will return false for blobs that are partially stored on
    /// the node.
    pub async fn status(&self, hash: Hash) -> Result<BlobStatus> {
        let status = self.rpc.rpc(BlobStatusRequest { hash }).await??;
        Ok(status.0)
    }

    /// Check if a blob is completely stored on the node.
    ///
    /// This is just a convenience wrapper around `status` that returns a boolean.
    pub async fn has(&self, hash: Hash) -> Result<bool> {
        match self.status(hash).await {
            Ok(BlobStatus::Complete { .. }) => Ok(true),
            Ok(_) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Create a new batch for adding data.
    pub async fn batch(&self) -> Result<Batch<C>> {
        let (updates, mut stream) = self.rpc.bidi(BatchCreateRequest).await?;
        let updates = Mutex::new(updates);
        let BatchCreateResponse::Id(scope) = stream.next().await.context("expected scope id")??;
        let rpc = self.rpc.clone();
        Ok(Batch(Arc::new(BatchInner {
            scope,
            rpc,
            updates,
        })))
    }
    /// Stream the contents of a a single blob.
    ///
    /// Returns a [`Reader`], which can report the size of the blob before reading it.
    pub async fn read(&self, hash: Hash) -> Result<Reader> {
        Reader::from_rpc_read(&self.rpc, hash).await
    }

    /// Read offset + len from a single blob.
    ///
    /// If `len` is `None` it will read the full blob.
    pub async fn read_at(&self, hash: Hash, offset: u64, len: Option<usize>) -> Result<Reader> {
        Reader::from_rpc_read_at(&self.rpc, hash, offset, len).await
    }

    /// Read all bytes of single blob.
    ///
    /// This allocates a buffer for the full blob. Use only if you know that the blob you're
    /// reading is small. If not sure, use [`Self::read`] and check the size with
    /// [`Reader::size`] before calling [`Reader::read_to_bytes`].
    pub async fn read_to_bytes(&self, hash: Hash) -> Result<Bytes> {
        Reader::from_rpc_read(&self.rpc, hash)
            .await?
            .read_to_bytes()
            .await
    }

    /// Read all bytes of single blob at `offset` for length `len`.
    ///
    /// This allocates a buffer for the full length.
    pub async fn read_at_to_bytes(
        &self,
        hash: Hash,
        offset: u64,
        len: Option<usize>,
    ) -> Result<Bytes> {
        Reader::from_rpc_read_at(&self.rpc, hash, offset, len)
            .await?
            .read_to_bytes()
            .await
    }

    /// Import a blob from a filesystem path.
    ///
    /// `path` should be an absolute path valid for the file system on which
    /// the node runs.
    /// If `in_place` is true, Iroh will assume that the data will not change and will share it in
    /// place without copying to the Iroh data directory.
    pub async fn add_from_path(
        &self,
        path: PathBuf,
        in_place: bool,
        tag: SetTagOption,
        wrap: WrapOption,
    ) -> Result<AddProgress> {
        let stream = self
            .rpc
            .server_streaming(BlobAddPathRequest {
                path,
                in_place,
                tag,
                wrap,
            })
            .await?;
        Ok(AddProgress::new(stream))
    }

    /// Create a collection from already existing blobs.
    ///
    /// For automatically clearing the tags for the passed in blobs you can set
    /// `tags_to_delete` to those tags, and they will be deleted once the collection is created.
    pub async fn create_collection(
        &self,
        collection: Collection,
        tag: SetTagOption,
        tags_to_delete: Vec<Tag>,
    ) -> anyhow::Result<(Hash, Tag)> {
        let CreateCollectionResponse { hash, tag } = self
            .rpc
            .rpc(CreateCollectionRequest {
                collection,
                tag,
                tags_to_delete,
            })
            .await??;
        Ok((hash, tag))
    }

    /// Write a blob by passing an async reader.
    pub async fn add_reader(
        &self,
        reader: impl AsyncRead + Unpin + Send + 'static,
        tag: SetTagOption,
    ) -> anyhow::Result<AddProgress> {
        const CAP: usize = 1024 * 64; // send 64KB per request by default
        let input = ReaderStream::with_capacity(reader, CAP);
        self.add_stream(input, tag).await
    }

    /// Write a blob by passing a stream of bytes.
    pub async fn add_stream(
        &self,
        input: impl Stream<Item = io::Result<Bytes>> + Send + Unpin + 'static,
        tag: SetTagOption,
    ) -> anyhow::Result<AddProgress> {
        let (mut sink, progress) = self.rpc.bidi(BlobAddStreamRequest { tag }).await?;
        let mut input = input.map(|chunk| match chunk {
            Ok(chunk) => Ok(BlobAddStreamUpdate::Chunk(chunk)),
            Err(err) => {
                warn!("Abort send, reason: failed to read from source stream: {err:?}");
                Ok(BlobAddStreamUpdate::Abort)
            }
        });
        tokio::spawn(async move {
            // TODO: Is it important to catch this error? It should also result in an error on the
            // response stream. If we deem it important, we could one-shot send it into the
            // BlobAddProgress and return from there. Not sure.
            if let Err(err) = sink.send_all(&mut input).await {
                warn!("Failed to send input stream to remote: {err:?}");
            }
        });

        Ok(AddProgress::new(progress))
    }

    /// Write a blob by passing bytes.
    pub async fn add_bytes(&self, bytes: impl Into<Bytes>) -> anyhow::Result<AddOutcome> {
        let input = futures_lite::stream::once(Ok(bytes.into()));
        self.add_stream(input, SetTagOption::Auto).await?.await
    }

    /// Write a blob by passing bytes, setting an explicit tag name.
    pub async fn add_bytes_named(
        &self,
        bytes: impl Into<Bytes>,
        name: impl Into<Tag>,
    ) -> anyhow::Result<AddOutcome> {
        let input = futures_lite::stream::once(Ok(bytes.into()));
        self.add_stream(input, SetTagOption::Named(name.into()))
            .await?
            .await
    }

    /// Validate hashes on the running node.
    ///
    /// If `repair` is true, repair the store by removing invalid data.
    pub async fn validate(
        &self,
        repair: bool,
    ) -> Result<impl Stream<Item = Result<ValidateProgress>>> {
        let stream = self
            .rpc
            .server_streaming(BlobValidateRequest { repair })
            .await?;
        Ok(stream.map(|res| res.map_err(anyhow::Error::from)))
    }

    /// Validate hashes on the running node.
    ///
    /// If `repair` is true, repair the store by removing invalid data.
    pub async fn consistency_check(
        &self,
        repair: bool,
    ) -> Result<impl Stream<Item = Result<ConsistencyCheckProgress>>> {
        let stream = self
            .rpc
            .server_streaming(BlobConsistencyCheckRequest { repair })
            .await?;
        Ok(stream.map(|r| r.map_err(anyhow::Error::from)))
    }

    /// Download a blob from another node and add it to the local database.
    pub async fn download(&self, hash: Hash, node: NodeAddr) -> Result<DownloadProgress> {
        self.download_with_opts(
            hash,
            DownloadOptions {
                format: BlobFormat::Raw,
                nodes: vec![node],
                tag: SetTagOption::Auto,
                mode: DownloadMode::Queued,
            },
        )
        .await
    }

    /// Download a hash sequence from another node and add it to the local database.
    pub async fn download_hash_seq(&self, hash: Hash, node: NodeAddr) -> Result<DownloadProgress> {
        self.download_with_opts(
            hash,
            DownloadOptions {
                format: BlobFormat::HashSeq,
                nodes: vec![node],
                tag: SetTagOption::Auto,
                mode: DownloadMode::Queued,
            },
        )
        .await
    }

    /// Download a blob, with additional options.
    pub async fn download_with_opts(
        &self,
        hash: Hash,
        opts: DownloadOptions,
    ) -> Result<DownloadProgress> {
        let DownloadOptions {
            format,
            nodes,
            tag,
            mode,
        } = opts;
        let stream = self
            .rpc
            .server_streaming(BlobDownloadRequest {
                hash,
                format,
                nodes,
                tag,
                mode,
            })
            .await?;
        Ok(DownloadProgress::new(
            stream.map(|res| res.map_err(anyhow::Error::from)),
        ))
    }

    /// Export a blob from the internal blob store to a path on the node's filesystem.
    ///
    /// `destination` should be an writeable, absolute path on the local node's filesystem.
    ///
    /// If `format` is set to [`ExportFormat::Collection`], and the `hash` refers to a collection,
    /// all children of the collection will be exported. See [`ExportFormat`] for details.
    ///
    /// The `mode` argument defines if the blob should be copied to the target location or moved out of
    /// the internal store into the target location. See [`ExportMode`] for details.
    pub async fn export(
        &self,
        hash: Hash,
        destination: PathBuf,
        format: ExportFormat,
        mode: ExportMode,
    ) -> Result<ExportProgress> {
        let req = BlobExportRequest {
            hash,
            path: destination,
            format,
            mode,
        };
        let stream = self.rpc.server_streaming(req).await?;
        Ok(ExportProgress::new(
            stream.map(|r| r.map_err(anyhow::Error::from)),
        ))
    }

    /// List all complete blobs.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<BlobInfo>>> {
        let stream = self.rpc.server_streaming(BlobListRequest).await?;
        Ok(flatten(stream))
    }

    /// List all incomplete (partial) blobs.
    pub async fn list_incomplete(&self) -> Result<impl Stream<Item = Result<IncompleteBlobInfo>>> {
        let stream = self.rpc.server_streaming(BlobListIncompleteRequest).await?;
        Ok(flatten(stream))
    }

    /// Read the content of a collection.
    pub async fn get_collection(&self, hash: Hash) -> Result<Collection> {
        let BlobGetCollectionResponse { collection } =
            self.rpc.rpc(BlobGetCollectionRequest { hash }).await??;
        Ok(collection)
    }

    /// List all collections.
    pub async fn list_collections(&self) -> Result<impl Stream<Item = Result<CollectionInfo>>> {
        let stream = self
            .rpc
            .server_streaming(BlobListCollectionsRequest)
            .await?;
        Ok(flatten(stream))
    }

    /// Delete a blob.
    pub async fn delete_blob(&self, hash: Hash) -> Result<()> {
        self.rpc.rpc(BlobDeleteBlobRequest { hash }).await??;
        Ok(())
    }

    /// Share a blob.
    pub async fn share(
        &self,
        hash: Hash,
        blob_format: BlobFormat,
        addr_options: AddrInfoOptions,
    ) -> Result<BlobTicket> {
        let mut addr = self.rpc.rpc(NodeStatusRequest).await??.addr;
        addr.apply_options(addr_options);
        let ticket = BlobTicket::new(addr, hash, blob_format).expect("correct ticket");

        Ok(ticket)
    }
}

/// A scope in which blobs can be added.
#[derive(derive_more::Debug)]
struct BatchInner<C: ServiceConnection<RpcService>> {
    /// The id of the scope.
    scope: u64,
    /// The rpc client.
    rpc: RpcClient<RpcService, C>,
    /// The stream to send drop
    #[debug(skip)]
    updates: Mutex<UpdateSink<RpcService, C, BatchUpdate>>,
}

/// A batch for write operations.
///
/// This serves mostly as a scope for temporary tags.
///
/// It is not a transaction, so things in a batch are not atomic. Also, there is
/// no isolation between batches.
#[derive(derive_more::Debug)]
pub struct Batch<C: ServiceConnection<RpcService>>(Arc<BatchInner<C>>);

impl<C: ServiceConnection<RpcService>> TagDrop for BatchInner<C> {
    fn on_drop(&self, content: &HashAndFormat) {
        let mut updates = self.updates.lock().unwrap();
        updates.send(BatchUpdate::Drop(*content)).now_or_never();
    }
}

/// Options for adding a file as a blob
#[derive(Debug, Clone, Copy, Default)]
pub struct AddFileOpts {
    /// The import mode
    import_mode: ImportMode,
    /// The format of the blob
    format: BlobFormat,
}

/// Options for adding a directory as a collection
#[derive(Debug, Clone, Default)]
pub struct AddDirOpts {
    /// The import mode
    import_mode: ImportMode,
    /// Whether to preserve the directory name
    wrap: WrapOption,
}

/// Options for adding a directory as a collection
#[derive(Debug, Clone)]
pub struct AddReaderOpts {
    /// The format of the blob
    format: BlobFormat,
    /// Size of the chunks to send
    chunk_size: usize,
}

impl Default for AddReaderOpts {
    fn default() -> Self {
        Self {
            format: BlobFormat::Raw,
            chunk_size: 1024 * 64,
        }
    }
}

impl<C: ServiceConnection<RpcService>> Batch<C> {
    /// Write a blob by passing bytes.
    pub async fn add_bytes(&self, bytes: impl Into<Bytes>, format: BlobFormat) -> Result<TempTag> {
        let input = futures_lite::stream::once(Ok(bytes.into()));
        self.add_stream(input, format).await
    }

    /// Import a blob from a filesystem path, using the default options.
    ///
    /// For more control, use [`Self::add_file_with_opts`].
    pub async fn add_file(&self, path: PathBuf) -> Result<(TempTag, u64)> {
        self.add_file_with_opts(path, AddFileOpts::default()).await
    }

    /// Import a blob from a filesystem path.
    ///
    /// `path` should be an absolute path valid for the file system on which
    /// the node runs, which refers to a file.
    ///
    /// If you use [ImportMode::TryReference], Iroh will assume that the data will not
    /// change and will share it in place without copying to the Iroh data directory
    /// if appropriate. However, for tiny files, Iroh will copy the data.
    ///
    /// If you use [ImportMode::Copy], Iroh will always copy the data.
    ///
    /// Will return a temp tag for the added blob, as well as the size of the file.
    pub async fn add_file_with_opts(
        &self,
        path: PathBuf,
        opts: AddFileOpts,
    ) -> Result<(TempTag, u64)> {
        let AddFileOpts {
            import_mode,
            format,
        } = opts;
        anyhow::ensure!(
            path.is_absolute(),
            "Path must be absolute, but got: {:?}",
            path
        );
        anyhow::ensure!(path.is_file(), "Path does not refer to a file: {:?}", path);
        let mut stream = self
            .0
            .rpc
            .server_streaming(BatchAddPathRequest {
                path,
                import_mode,
                format,
                scope: self.0.scope,
            })
            .await?;
        let mut res_hash = None;
        let mut res_size = None;
        while let Some(item) = stream.next().await {
            match item?.0 {
                BatchAddPathProgress::Abort(cause) => {
                    Err(cause)?;
                }
                BatchAddPathProgress::Done { hash } => {
                    res_hash = Some(hash);
                }
                BatchAddPathProgress::Found { size } => {
                    res_size = Some(size);
                }
                _ => {}
            }
        }
        let hash = res_hash.context("Missing hash")?;
        let size = res_size.context("Missing size")?;
        Ok((self.local_temp_tag(HashAndFormat { hash, format }), size))
    }

    /// Add a directory as a hashseq in iroh collection format
    pub async fn add_dir(&self, root: PathBuf) -> Result<TempTag> {
        self.add_dir_with_opts(root, Default::default()).await
    }

    /// Add a directory as a hashseq in iroh collection format
    ///
    /// This can also be used to add a single file as a collection, if
    /// wrap is set to [WrapOption::Wrap].
    ///
    /// However, if you want to add a single file as a raw blob, use add_file instead.
    pub async fn add_dir_with_opts(&self, root: PathBuf, opts: AddDirOpts) -> Result<TempTag> {
        let AddDirOpts { import_mode, wrap } = opts;
        anyhow::ensure!(root.is_absolute(), "Path must be absolute");

        // let (send, recv) = flume::bounded(32);
        // let import_progress = FlumeProgressSender::new(send);

        // import all files below root recursively
        let data_sources = crate::util::fs::scan_path(root, wrap)?;
        const IO_PARALLELISM: usize = 4;
        let opts = AddFileOpts {
            import_mode,
            format: BlobFormat::Raw,
        };
        let result: Vec<_> = futures_lite::stream::iter(data_sources)
            .map(|source| {
                // let import_progress = import_progress.clone();
                async move {
                    let name = source.name().to_string();
                    let (tag, size) = self
                        .add_file_with_opts(source.path().to_owned(), opts)
                        .await?;
                    let hash = *tag.hash();
                    anyhow::Ok((name, hash, size, tag))
                }
            })
            .buffered_ordered(IO_PARALLELISM)
            .try_collect()
            .await?;
        println!("{:?}", result);

        // create a collection
        let (collection, child_tags): (Collection, Vec<_>) = result
            .into_iter()
            .map(|(name, hash, _, tag)| ((name, hash), tag))
            .unzip();

        let tag = self.add_collection(collection).await?;
        drop(child_tags);
        Ok(tag)
    }

    /// Add a collection
    ///
    /// This is a convenience function that converts the collection into two blobs
    /// (the metadata and the hash sequence) and adds them, returning a temp tag for
    /// the hash sequence.
    ///
    /// Note that this does not guarantee that the data that the collection refers to
    /// actually exists. It will just create 2 blobs, the metadata and the hash sequence
    /// itself.
    pub async fn add_collection(&self, collection: Collection) -> Result<TempTag> {
        self.add_blob_seq(collection.to_blobs()).await
    }

    /// Write a blob by passing an async reader.
    ///
    /// This will use a default chunk size of 64KB, and a format of [BlobFormat::Raw].
    pub async fn add_reader(
        &self,
        reader: impl AsyncRead + Unpin + Send + 'static,
    ) -> anyhow::Result<TempTag> {
        self.add_reader_with_opts(reader, Default::default()).await
    }

    /// Write a blob by passing an async reader.
    ///
    /// This produces a stream from the reader with a hardcoded buffer size of 64KB.
    pub async fn add_reader_with_opts(
        &self,
        reader: impl AsyncRead + Unpin + Send + 'static,
        opts: AddReaderOpts,
    ) -> anyhow::Result<TempTag> {
        let AddReaderOpts { format, chunk_size } = opts;
        let input = ReaderStream::with_capacity(reader, chunk_size);
        self.add_stream(input, format).await
    }

    /// Write a blob by passing a stream of bytes.
    ///
    /// For convenient interop with common sources of data, this function takes a stream of io::Result<Bytes>.
    /// If you have raw bytes, you need to wrap them in io::Result::Ok.
    pub async fn add_stream(
        &self,
        mut input: impl Stream<Item = io::Result<Bytes>> + Send + Unpin + 'static,
        format: BlobFormat,
    ) -> Result<TempTag> {
        let (mut sink, mut stream) = self
            .0
            .rpc
            .bidi(BatchAddStreamRequest {
                scope: self.0.scope,
                format,
            })
            .await?;
        while let Some(item) = input.next().await {
            match item {
                Ok(chunk) => {
                    sink.send(BatchAddStreamUpdate::Chunk(chunk))
                        .await
                        .map_err(|err| anyhow!("Failed to send input stream to remote: {err:?}"))?;
                }
                Err(err) => {
                    warn!("Abort send, reason: failed to read from source stream: {err:?}");
                    sink.send(BatchAddStreamUpdate::Abort)
                        .await
                        .map_err(|err| anyhow!("Failed to send input stream to remote: {err:?}"))?;
                    break;
                }
            }
        }
        // this is needed for the remote to notice that the stream is closed
        drop(sink);
        let mut res = None;
        while let Some(item) = stream.next().await {
            match item? {
                BatchAddStreamResponse::Abort(cause) => {
                    Err(cause)?;
                }
                BatchAddStreamResponse::Result { hash } => {
                    res = Some(hash);
                }
                _ => {}
            }
        }
        let hash = res.context("Missing answer")?;
        println!(
            "creating temp tag with hash {:?} and format {}",
            hash, format
        );
        Ok(self.local_temp_tag(HashAndFormat { hash, format }))
    }

    /// Add a sequence of blobs, where the last is a hash sequence.
    ///
    /// It is a common pattern in iroh to have a hash sequence with one or more
    /// blobs of metadata, and the remaining blobs being the actual data. E.g.
    /// a collection is a hash sequence where the first child is the metadata.
    pub async fn add_blob_seq(&self, iter: impl Iterator<Item = Bytes>) -> Result<TempTag> {
        let mut blobs = iter.peekable();
        let mut res = vec![];
        let res = loop {
            let blob = blobs.next().context("Failed to get next blob")?;
            if blobs.peek().is_none() {
                println!("last blob");
                break self.add_bytes(blob, BlobFormat::HashSeq).await?;
            } else {
                res.push(self.add_bytes(blob, BlobFormat::Raw).await?);
            }
        };
        Ok(res)
    }

    /// Create a temp tag to protect some content (blob or hashseq) from being deleted.
    ///
    /// A typical use case is that you are downloading some data and want to protect it
    /// from deletion while the download is ongoing, but don't want to protect it permanently
    /// until the download is completed.
    pub async fn temp_tag(&self, content: HashAndFormat) -> Result<TempTag> {
        // Notify the server that we want one temp tag for the given content
        self.0
            .rpc
            .rpc(BatchCreateTempTagRequest {
                scope: self.0.scope,
                content,
            })
            .await??;
        // Only after success of the above call, we can create the corresponding local temp tag
        Ok(self.local_temp_tag(content))
    }

    /// Creates a temp tag for the given hash and format, without notifying the server.
    ///
    /// Caution: only do this for data for which you know the server side has created a temp tag.
    fn local_temp_tag(&self, inner: HashAndFormat) -> TempTag {
        let on_drop: Arc<dyn TagDrop> = self.0.clone();
        let on_drop = Some(Arc::downgrade(&on_drop));
        TempTag::new(inner, on_drop)
    }
}

/// Whether to wrap the added data in a collection.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub enum WrapOption {
    /// Do not wrap the file or directory.
    #[default]
    NoWrap,
    /// Wrap the file or directory in a collection.
    Wrap {
        /// Override the filename in the wrapping collection.
        name: Option<String>,
    },
}

/// Outcome of a blob add operation.
#[derive(Debug, Clone)]
pub struct AddOutcome {
    /// The hash of the blob
    pub hash: Hash,
    /// The format the blob
    pub format: BlobFormat,
    /// The size of the blob
    pub size: u64,
    /// The tag of the blob
    pub tag: Tag,
}

/// Information about a stored collection.
#[derive(Debug, Serialize, Deserialize)]
pub struct CollectionInfo {
    /// Tag of the collection
    pub tag: Tag,

    /// Hash of the collection
    pub hash: Hash,
    /// Number of children in the collection
    ///
    /// This is an optional field, because the data is not always available.
    pub total_blobs_count: Option<u64>,
    /// Total size of the raw data referred to by all links
    ///
    /// This is an optional field, because the data is not always available.
    pub total_blobs_size: Option<u64>,
}

/// Information about a complete blob.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobInfo {
    /// Location of the blob
    pub path: String,
    /// The hash of the blob
    pub hash: Hash,
    /// The size of the blob
    pub size: u64,
}

/// Information about an incomplete blob.
#[derive(Debug, Serialize, Deserialize)]
pub struct IncompleteBlobInfo {
    /// The size we got
    pub size: u64,
    /// The size we expect
    pub expected_size: u64,
    /// The hash of the blob
    pub hash: Hash,
}

/// Progress stream for blob add operations.
#[derive(derive_more::Debug)]
pub struct AddProgress {
    #[debug(skip)]
    stream: Pin<
        Box<dyn Stream<Item = Result<iroh_blobs::provider::AddProgress>> + Send + Unpin + 'static>,
    >,
    current_total_size: Arc<AtomicU64>,
}

impl AddProgress {
    fn new(
        stream: (impl Stream<
            Item = Result<impl Into<iroh_blobs::provider::AddProgress>, impl Into<anyhow::Error>>,
        > + Send
             + Unpin
             + 'static),
    ) -> Self {
        let current_total_size = Arc::new(AtomicU64::new(0));
        let total_size = current_total_size.clone();
        let stream = stream.map(move |item| match item {
            Ok(item) => {
                let item = item.into();
                if let iroh_blobs::provider::AddProgress::Found { size, .. } = &item {
                    total_size.fetch_add(*size, Ordering::Relaxed);
                }
                Ok(item)
            }
            Err(err) => Err(err.into()),
        });
        Self {
            stream: Box::pin(stream),
            current_total_size,
        }
    }
    /// Finish writing the stream, ignoring all intermediate progress events.
    ///
    /// Returns a [`AddOutcome`] which contains a tag, format, hash and a size.
    /// When importing a single blob, this is the hash and size of that blob.
    /// When importing a collection, the hash is the hash of the collection and the size
    /// is the total size of all imported blobs (but excluding the size of the collection blob
    /// itself).
    pub async fn finish(self) -> Result<AddOutcome> {
        self.await
    }
}

impl Stream for AddProgress {
    type Item = Result<iroh_blobs::provider::AddProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

impl Future for AddProgress {
    type Output = Result<AddOutcome>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(anyhow!("Response stream ended prematurely")))
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    iroh_blobs::provider::AddProgress::AllDone { hash, format, tag } => {
                        let outcome = AddOutcome {
                            hash,
                            format,
                            tag,
                            size: self.current_total_size.load(Ordering::Relaxed),
                        };
                        return Poll::Ready(Ok(outcome));
                    }
                    iroh_blobs::provider::AddProgress::Abort(err) => {
                        return Poll::Ready(Err(err.into()));
                    }
                    _ => {}
                },
            }
        }
    }
}

/// Outcome of a blob download operation.
#[derive(Debug, Clone)]
pub struct DownloadOutcome {
    /// The size of the data we already had locally
    pub local_size: u64,
    /// The size of the data we downloaded from the network
    pub downloaded_size: u64,
    /// Statistics about the download
    pub stats: iroh_blobs::get::Stats,
}

/// Progress stream for blob download operations.
#[derive(derive_more::Debug)]
pub struct DownloadProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<BytesDownloadProgress>> + Send + Unpin + 'static>>,
    current_local_size: Arc<AtomicU64>,
    current_network_size: Arc<AtomicU64>,
}

impl DownloadProgress {
    /// Create a [`DownloadProgress`] that can help you easily poll the [`BytesDownloadProgress`] stream from your download until it is finished or errors.
    pub fn new(
        stream: (impl Stream<Item = Result<impl Into<BytesDownloadProgress>, impl Into<anyhow::Error>>>
             + Send
             + Unpin
             + 'static),
    ) -> Self {
        let current_local_size = Arc::new(AtomicU64::new(0));
        let current_network_size = Arc::new(AtomicU64::new(0));

        let local_size = current_local_size.clone();
        let network_size = current_network_size.clone();

        let stream = stream.map(move |item| match item {
            Ok(item) => {
                let item = item.into();
                match &item {
                    BytesDownloadProgress::FoundLocal { size, .. } => {
                        local_size.fetch_add(size.value(), Ordering::Relaxed);
                    }
                    BytesDownloadProgress::Found { size, .. } => {
                        network_size.fetch_add(*size, Ordering::Relaxed);
                    }
                    _ => {}
                }

                Ok(item)
            }
            Err(err) => Err(err.into()),
        });
        Self {
            stream: Box::pin(stream),
            current_local_size,
            current_network_size,
        }
    }

    /// Finish writing the stream, ignoring all intermediate progress events.
    ///
    /// Returns a [`DownloadOutcome`] which contains the size of the content we downloaded and the size of the content we already had locally.
    /// When importing a single blob, this is the size of that blob.
    /// When importing a collection, this is the total size of all imported blobs (but excluding the size of the collection blob itself).
    pub async fn finish(self) -> Result<DownloadOutcome> {
        self.await
    }
}

impl Stream for DownloadProgress {
    type Item = Result<BytesDownloadProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

impl Future for DownloadProgress {
    type Output = Result<DownloadOutcome>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(anyhow!("Response stream ended prematurely")))
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    BytesDownloadProgress::AllDone(stats) => {
                        let outcome = DownloadOutcome {
                            local_size: self.current_local_size.load(Ordering::Relaxed),
                            downloaded_size: self.current_network_size.load(Ordering::Relaxed),
                            stats,
                        };
                        return Poll::Ready(Ok(outcome));
                    }
                    BytesDownloadProgress::Abort(err) => {
                        return Poll::Ready(Err(err.into()));
                    }
                    _ => {}
                },
            }
        }
    }
}

/// Outcome of a blob export operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    /// The total size of the exported data.
    total_size: u64,
}

/// Progress stream for blob export operations.
#[derive(derive_more::Debug)]
pub struct ExportProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<BytesExportProgress>> + Send + Unpin + 'static>>,
    current_total_size: Arc<AtomicU64>,
}

impl ExportProgress {
    /// Create a [`ExportProgress`] that can help you easily poll the [`BytesExportProgress`] stream from your
    /// download until it is finished or errors.
    pub fn new(
        stream: (impl Stream<Item = Result<impl Into<BytesExportProgress>, impl Into<anyhow::Error>>>
             + Send
             + Unpin
             + 'static),
    ) -> Self {
        let current_total_size = Arc::new(AtomicU64::new(0));
        let total_size = current_total_size.clone();
        let stream = stream.map(move |item| match item {
            Ok(item) => {
                let item = item.into();
                if let BytesExportProgress::Found { size, .. } = &item {
                    let size = size.value();
                    total_size.fetch_add(size, Ordering::Relaxed);
                }

                Ok(item)
            }
            Err(err) => Err(err.into()),
        });
        Self {
            stream: Box::pin(stream),
            current_total_size,
        }
    }

    /// Finish writing the stream, ignoring all intermediate progress events.
    ///
    /// Returns a [`ExportOutcome`] which contains the size of the content we exported.
    pub async fn finish(self) -> Result<ExportOutcome> {
        self.await
    }
}

impl Stream for ExportProgress {
    type Item = Result<BytesExportProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

impl Future for ExportProgress {
    type Output = Result<ExportOutcome>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(anyhow!("Response stream ended prematurely")))
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    BytesExportProgress::AllDone => {
                        let outcome = ExportOutcome {
                            total_size: self.current_total_size.load(Ordering::Relaxed),
                        };
                        return Poll::Ready(Ok(outcome));
                    }
                    BytesExportProgress::Abort(err) => {
                        return Poll::Ready(Err(err.into()));
                    }
                    _ => {}
                },
            }
        }
    }
}

/// Data reader for a single blob.
///
/// Implements [`AsyncRead`].
#[derive(derive_more::Debug)]
pub struct Reader {
    size: u64,
    response_size: u64,
    is_complete: bool,
    #[debug("StreamReader")]
    stream: tokio_util::io::StreamReader<BoxStreamSync<'static, io::Result<Bytes>>, Bytes>,
}

impl Reader {
    fn new(
        size: u64,
        response_size: u64,
        is_complete: bool,
        stream: BoxStreamSync<'static, io::Result<Bytes>>,
    ) -> Self {
        Self {
            size,
            response_size,
            is_complete,
            stream: StreamReader::new(stream),
        }
    }

    pub(crate) async fn from_rpc_read<C: ServiceConnection<RpcService>>(
        rpc: &RpcClient<RpcService, C>,
        hash: Hash,
    ) -> anyhow::Result<Self> {
        Self::from_rpc_read_at(rpc, hash, 0, None).await
    }

    async fn from_rpc_read_at<C: ServiceConnection<RpcService>>(
        rpc: &RpcClient<RpcService, C>,
        hash: Hash,
        offset: u64,
        len: Option<usize>,
    ) -> anyhow::Result<Self> {
        let stream = rpc
            .server_streaming(BlobReadAtRequest { hash, offset, len })
            .await?;
        let mut stream = flatten(stream);

        let (size, is_complete) = match stream.next().await {
            Some(Ok(BlobReadAtResponse::Entry { size, is_complete })) => (size, is_complete),
            Some(Err(err)) => return Err(err),
            None | Some(Ok(_)) => return Err(anyhow!("Expected header frame")),
        };

        let stream = stream.map(|item| match item {
            Ok(BlobReadAtResponse::Data { chunk }) => Ok(chunk),
            Ok(_) => Err(io::Error::new(io::ErrorKind::Other, "Expected data frame")),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, format!("{err}"))),
        });
        let len = len
            .map(|l| l as u64)
            .unwrap_or_else(|| size.value() - offset);
        Ok(Self::new(size.value(), len, is_complete, Box::pin(stream)))
    }

    /// Total size of this blob.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether this blob has been downloaded completely.
    ///
    /// Returns false for partial blobs for which some chunks are missing.
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    /// Read all bytes of the blob.
    pub async fn read_to_bytes(&mut self) -> anyhow::Result<Bytes> {
        let mut buf = Vec::with_capacity(self.response_size as usize);
        self.read_to_end(&mut buf).await?;
        Ok(buf.into())
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl Stream for Reader {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).get_pin_mut().poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.get_ref().size_hint()
    }
}

/// Options to configure a download request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadOptions {
    /// The format of the data to download.
    pub format: BlobFormat,
    /// Source nodes to download from.
    ///
    /// If set to more than a single node, they will all be tried. If `mode` is set to
    /// [`DownloadMode::Direct`], they will be tried sequentially until a download succeeds.
    /// If `mode` is set to [`DownloadMode::Queued`], the nodes may be dialed in parallel,
    /// if the concurrency limits permit.
    pub nodes: Vec<NodeAddr>,
    /// Optional tag to tag the data with.
    pub tag: SetTagOption,
    /// Whether to directly start the download or add it to the download queue.
    pub mode: DownloadMode,
}

/// Set the mode for whether to directly start the download or add it to the download queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DownloadMode {
    /// Start the download right away.
    ///
    /// No concurrency limits or queuing will be applied. It is up to the user to manage download
    /// concurrency.
    Direct,
    /// Queue the download.
    ///
    /// The download queue will be processed in-order, while respecting the downloader concurrency limits.
    Queued,
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::RngCore;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_blob_create_collection() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;

        // create temp file
        let temp_dir = tempfile::tempdir().context("tempdir")?;

        let in_root = temp_dir.path().join("in");
        tokio::fs::create_dir_all(in_root.clone())
            .await
            .context("create dir all")?;

        let mut paths = Vec::new();
        for i in 0..5 {
            let path = in_root.join(format!("test-{i}"));
            let size = 100;
            let mut buf = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut buf);
            let mut file = tokio::fs::File::create(path.clone())
                .await
                .context("create file")?;
            file.write_all(&buf.clone()).await.context("write_all")?;
            file.flush().await.context("flush")?;
            paths.push(path);
        }

        let client = node.client();

        let mut collection = Collection::default();
        let mut tags = Vec::new();
        // import files
        for path in &paths {
            let import_outcome = client
                .blobs
                .add_from_path(
                    path.to_path_buf(),
                    false,
                    SetTagOption::Auto,
                    WrapOption::NoWrap,
                )
                .await
                .context("import file")?
                .finish()
                .await
                .context("import finish")?;

            collection.push(
                path.file_name().unwrap().to_str().unwrap().to_string(),
                import_outcome.hash,
            );
            tags.push(import_outcome.tag);
        }

        let (hash, tag) = client
            .blobs
            .create_collection(collection, SetTagOption::Auto, tags)
            .await?;

        let collections: Vec<_> = client.blobs.list_collections().await?.try_collect().await?;

        assert_eq!(collections.len(), 1);
        {
            let CollectionInfo {
                tag,
                hash,
                total_blobs_count,
                ..
            } = &collections[0];
            assert_eq!(tag, tag);
            assert_eq!(hash, hash);
            // 5 blobs + 1 meta
            assert_eq!(total_blobs_count, &Some(5 + 1));
        }

        // check that "temp" tags have been deleted
        let tags: Vec<_> = client.tags.list().await?.try_collect().await?;
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].hash, hash);
        assert_eq!(tags[0].name, tag);
        assert_eq!(tags[0].format, BlobFormat::HashSeq);

        Ok(())
    }

    #[tokio::test]
    async fn test_blob_read_at() -> Result<()> {
        // let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;

        // create temp file
        let temp_dir = tempfile::tempdir().context("tempdir")?;

        let in_root = temp_dir.path().join("in");
        tokio::fs::create_dir_all(in_root.clone())
            .await
            .context("create dir all")?;

        let path = in_root.join("test-blob");
        let size = 1024 * 128;
        let buf: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let mut file = tokio::fs::File::create(path.clone())
            .await
            .context("create file")?;
        file.write_all(&buf.clone()).await.context("write_all")?;
        file.flush().await.context("flush")?;

        let client = node.client();

        let import_outcome = client
            .blobs
            .add_from_path(
                path.to_path_buf(),
                false,
                SetTagOption::Auto,
                WrapOption::NoWrap,
            )
            .await
            .context("import file")?
            .finish()
            .await
            .context("import finish")?;

        let hash = import_outcome.hash;

        // Read everything
        let res = client.blobs.read_to_bytes(hash).await?;
        assert_eq!(&res, &buf[..]);

        // Read at smaller than blob_get_chunk_size
        let res = client.blobs.read_at_to_bytes(hash, 0, Some(100)).await?;
        assert_eq!(res.len(), 100);
        assert_eq!(&res[..], &buf[0..100]);

        let res = client.blobs.read_at_to_bytes(hash, 20, Some(120)).await?;
        assert_eq!(res.len(), 120);
        assert_eq!(&res[..], &buf[20..140]);

        // Read at equal to blob_get_chunk_size
        let res = client
            .blobs
            .read_at_to_bytes(hash, 0, Some(1024 * 64))
            .await?;
        assert_eq!(res.len(), 1024 * 64);
        assert_eq!(&res[..], &buf[0..1024 * 64]);

        let res = client
            .blobs
            .read_at_to_bytes(hash, 20, Some(1024 * 64))
            .await?;
        assert_eq!(res.len(), 1024 * 64);
        assert_eq!(&res[..], &buf[20..(20 + 1024 * 64)]);

        // Read at larger than blob_get_chunk_size
        let res = client
            .blobs
            .read_at_to_bytes(hash, 0, Some(10 + 1024 * 64))
            .await?;
        assert_eq!(res.len(), 10 + 1024 * 64);
        assert_eq!(&res[..], &buf[0..(10 + 1024 * 64)]);

        let res = client
            .blobs
            .read_at_to_bytes(hash, 20, Some(10 + 1024 * 64))
            .await?;
        assert_eq!(res.len(), 10 + 1024 * 64);
        assert_eq!(&res[..], &buf[20..(20 + 10 + 1024 * 64)]);

        // full length
        let res = client.blobs.read_at_to_bytes(hash, 20, None).await?;
        assert_eq!(res.len(), 1024 * 128 - 20);
        assert_eq!(&res[..], &buf[20..]);

        // size should be total
        let reader = client.blobs.read_at(hash, 0, Some(20)).await?;
        assert_eq!(reader.size(), 1024 * 128);
        assert_eq!(reader.response_size, 20);

        Ok(())
    }

    #[tokio::test]
    async fn test_blob_get_collection() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;

        // create temp file
        let temp_dir = tempfile::tempdir().context("tempdir")?;

        let in_root = temp_dir.path().join("in");
        tokio::fs::create_dir_all(in_root.clone())
            .await
            .context("create dir all")?;

        let mut paths = Vec::new();
        for i in 0..5 {
            let path = in_root.join(format!("test-{i}"));
            let size = 100;
            let mut buf = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut buf);
            let mut file = tokio::fs::File::create(path.clone())
                .await
                .context("create file")?;
            file.write_all(&buf.clone()).await.context("write_all")?;
            file.flush().await.context("flush")?;
            paths.push(path);
        }

        let client = node.client();

        let mut collection = Collection::default();
        let mut tags = Vec::new();
        // import files
        for path in &paths {
            let import_outcome = client
                .blobs
                .add_from_path(
                    path.to_path_buf(),
                    false,
                    SetTagOption::Auto,
                    WrapOption::NoWrap,
                )
                .await
                .context("import file")?
                .finish()
                .await
                .context("import finish")?;

            collection.push(
                path.file_name().unwrap().to_str().unwrap().to_string(),
                import_outcome.hash,
            );
            tags.push(import_outcome.tag);
        }

        let (hash, _tag) = client
            .blobs
            .create_collection(collection, SetTagOption::Auto, tags)
            .await?;

        let collection = client.blobs.get_collection(hash).await?;

        // 5 blobs
        assert_eq!(collection.len(), 5);

        Ok(())
    }

    #[tokio::test]
    async fn test_blob_share() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;

        // create temp file
        let temp_dir = tempfile::tempdir().context("tempdir")?;

        let in_root = temp_dir.path().join("in");
        tokio::fs::create_dir_all(in_root.clone())
            .await
            .context("create dir all")?;

        let path = in_root.join("test-blob");
        let size = 1024 * 128;
        let buf: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let mut file = tokio::fs::File::create(path.clone())
            .await
            .context("create file")?;
        file.write_all(&buf.clone()).await.context("write_all")?;
        file.flush().await.context("flush")?;

        let client = node.client();

        let import_outcome = client
            .blobs
            .add_from_path(
                path.to_path_buf(),
                false,
                SetTagOption::Auto,
                WrapOption::NoWrap,
            )
            .await
            .context("import file")?
            .finish()
            .await
            .context("import finish")?;

        let ticket = client
            .blobs
            .share(import_outcome.hash, BlobFormat::Raw, Default::default())
            .await?;
        assert_eq!(ticket.hash(), import_outcome.hash);

        let status = client.blobs.status(import_outcome.hash).await?;
        assert_eq!(status, BlobStatus::Complete { size });

        Ok(())
    }
}
