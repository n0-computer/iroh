use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures_buffered::BufferedStreamExt;
use futures_lite::StreamExt;
use futures_util::{sink::Buffer, FutureExt, SinkExt, Stream};
use iroh_blobs::{
    format::collection::Collection,
    provider::BatchAddPathProgress,
    store::ImportMode,
    util::{SetTagOption, TagDrop},
    BlobFormat, HashAndFormat, Tag, TempTag,
};
use quic_rpc::client::UpdateSink;
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;
use tracing::{debug, warn};

use crate::{
    client::{RpcClient, RpcConnection, RpcService},
    rpc_protocol::{
        blobs::{
            BatchAddPathRequest, BatchAddStreamRequest, BatchAddStreamResponse,
            BatchAddStreamUpdate, BatchCreateTempTagRequest, BatchId, BatchUpdate,
        },
        tags::{self, SyncMode},
    },
};

use super::WrapOption;

/// A scope in which blobs can be added.
#[derive(derive_more::Debug)]
struct BatchInner {
    /// The id of the scope.
    batch: BatchId,
    /// The rpc client.
    rpc: RpcClient,
    /// The stream to send drop
    #[debug(skip)]
    updates: Mutex<Buffer<UpdateSink<RpcService, RpcConnection, BatchUpdate>, BatchUpdate>>,
}

/// A batch for write operations.
///
/// This serves mostly as a scope for temporary tags.
///
/// It is not a transaction, so things in a batch are not atomic. Also, there is
/// no isolation between batches.
#[derive(derive_more::Debug)]
pub struct Batch(Arc<BatchInner>);

impl TagDrop for BatchInner {
    fn on_drop(&self, content: &HashAndFormat) {
        let mut updates = self.updates.lock().unwrap();
        // make a spirited attempt to notify the server that we are dropping the content
        //
        // this will occasionally fail, but that's acceptable. The temp tags for the batch
        // will be cleaned up as soon as the entire batch is dropped.
        //
        // E.g. a typical scenario is that you create a large array of temp tags, and then
        // store them in a hash sequence and then drop the array. You will get many drops
        // at the same time, and might get a send failure here.
        //
        // But that just means that the server will clean up the temp tags when the batch is
        // dropped.
        updates.feed(BatchUpdate::Drop(*content)).now_or_never();
        updates.flush().now_or_never();
    }
}

/// Options for adding a file as a blob
#[derive(Debug, Clone, Copy, Default)]
pub struct AddFileOpts {
    /// The import mode
    pub import_mode: ImportMode,
    /// The format of the blob
    pub format: BlobFormat,
}

/// Options for adding a directory as a collection
#[derive(Debug, Clone)]
pub struct AddDirOpts {
    /// The import mode
    pub import_mode: ImportMode,
    /// Whether to preserve the directory name
    pub wrap: WrapOption,
    /// Io parallelism
    pub io_parallelism: usize,
}

impl Default for AddDirOpts {
    fn default() -> Self {
        Self {
            import_mode: ImportMode::TryReference,
            wrap: WrapOption::NoWrap,
            io_parallelism: 4,
        }
    }
}

/// Options for adding a directory as a collection
#[derive(Debug, Clone)]
pub struct AddReaderOpts {
    /// The format of the blob
    pub format: BlobFormat,
    /// Size of the chunks to send
    pub chunk_size: usize,
}

impl Default for AddReaderOpts {
    fn default() -> Self {
        Self {
            format: BlobFormat::Raw,
            chunk_size: 1024 * 64,
        }
    }
}

impl Batch {
    pub(super) fn new(
        batch: BatchId,
        rpc: RpcClient,
        updates: UpdateSink<RpcService, RpcConnection, BatchUpdate>,
        buffer_size: usize,
    ) -> Self {
        let updates = updates.buffer(buffer_size);
        Self(Arc::new(BatchInner {
            batch,
            rpc,
            updates: updates.into(),
        }))
    }

    /// Write a blob by passing bytes.
    pub async fn add_bytes(&self, bytes: impl Into<Bytes>) -> Result<TempTag> {
        self.add_bytes_with_opts(bytes, Default::default()).await
    }

    /// Import a blob from a filesystem path, using the default options.
    ///
    /// For more control, use [`Self::add_file_with_opts`].
    pub async fn add_file(&self, path: PathBuf) -> Result<(TempTag, u64)> {
        self.add_file_with_opts(path, AddFileOpts::default()).await
    }

    /// Add a directory as a hashseq in iroh collection format
    pub async fn add_dir(&self, root: PathBuf) -> Result<TempTag> {
        self.add_dir_with_opts(root, Default::default()).await
    }

    /// Write a blob by passing an async reader.
    ///
    /// This will consume the stream in 64KB chunks, and use a format of [BlobFormat::Raw].
    ///
    /// For more options, see [`Self::add_reader_with_opts`].
    pub async fn add_reader(
        &self,
        reader: impl AsyncRead + Unpin + Send + 'static,
    ) -> anyhow::Result<TempTag> {
        self.add_reader_with_opts(reader, Default::default()).await
    }

    /// Write a blob by passing a stream of bytes.
    pub async fn add_stream(
        &self,
        input: impl Stream<Item = io::Result<Bytes>> + Send + Unpin + 'static,
    ) -> Result<TempTag> {
        self.add_stream_with_opts(input, Default::default()).await
    }

    /// Creates a temp tag to protect some content (blob or hashseq) from being deleted.
    ///
    /// This is a lower-level API. The other functions in [`Batch`] already create [`TempTag`]s automatically.
    ///
    /// [`TempTag`]s allow you to protect some data from deletion while a download is ongoing,
    /// even if you don't want to protect it permanently.
    pub async fn temp_tag(&self, content: HashAndFormat) -> Result<TempTag> {
        // Notify the server that we want one temp tag for the given content
        self.0
            .rpc
            .rpc(BatchCreateTempTagRequest {
                batch: self.0.batch,
                content,
            })
            .await??;
        // Only after success of the above call, we can create the corresponding local temp tag
        Ok(self.local_temp_tag(content, None))
    }

    /// Write a blob by passing an async reader.
    ///
    /// This consumes the stream in chunks using `opts.chunk_size`. A good default is 64KB.
    pub async fn add_reader_with_opts(
        &self,
        reader: impl AsyncRead + Unpin + Send + 'static,
        opts: AddReaderOpts,
    ) -> anyhow::Result<TempTag> {
        let AddReaderOpts { format, chunk_size } = opts;
        let input = ReaderStream::with_capacity(reader, chunk_size);
        self.add_stream_with_opts(input, format).await
    }

    /// Write a blob by passing bytes.
    pub async fn add_bytes_with_opts(
        &self,
        bytes: impl Into<Bytes>,
        format: BlobFormat,
    ) -> Result<TempTag> {
        let input = futures_lite::stream::once(Ok(bytes.into()));
        self.add_stream_with_opts(input, format).await
    }

    /// Import a blob from a filesystem path.
    ///
    /// `path` should be an absolute path valid for the file system on which
    /// the node runs, which refers to a file.
    ///
    /// If you use [`ImportMode::TryReference`], Iroh will assume that the data will not
    /// change and will share it in place without copying to the Iroh data directory
    /// if appropriate. However, for tiny files, Iroh will copy the data.
    ///
    /// If you use [`ImportMode::Copy`], Iroh will always copy the data.
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
                batch: self.0.batch,
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
        Ok((
            self.local_temp_tag(HashAndFormat { hash, format }, Some(size)),
            size,
        ))
    }

    /// Add a directory as a hashseq in iroh collection format
    ///
    /// This can also be used to add a single file as a collection, if
    /// wrap is set to [WrapOption::Wrap].
    ///
    /// However, if you want to add a single file as a raw blob, use add_file instead.
    pub async fn add_dir_with_opts(&self, root: PathBuf, opts: AddDirOpts) -> Result<TempTag> {
        let AddDirOpts {
            import_mode,
            wrap,
            io_parallelism,
        } = opts;
        anyhow::ensure!(root.is_absolute(), "Path must be absolute");

        // let (send, recv) = flume::bounded(32);
        // let import_progress = FlumeProgressSender::new(send);

        // import all files below root recursively
        let data_sources = crate::util::fs::scan_path(root, wrap)?;
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
            .buffered_ordered(io_parallelism)
            .try_collect()
            .await?;

        // create a collection
        let (collection, child_tags): (Collection, Vec<_>) = result
            .into_iter()
            .map(|(name, hash, _, tag)| ((name, hash), tag))
            .unzip();

        let tag = self.add_collection(collection).await?;
        drop(child_tags);
        Ok(tag)
    }

    /// Write a blob by passing a stream of bytes.
    ///
    /// For convenient interop with common sources of data, this function takes a stream of `io::Result<Bytes>`.
    /// If you have raw bytes, you need to wrap them in `io::Result::Ok`.
    pub async fn add_stream_with_opts(
        &self,
        mut input: impl Stream<Item = io::Result<Bytes>> + Send + Unpin + 'static,
        format: BlobFormat,
    ) -> Result<TempTag> {
        let (mut sink, mut stream) = self
            .0
            .rpc
            .bidi(BatchAddStreamRequest {
                batch: self.0.batch,
                format,
            })
            .await?;
        let mut size = 0u64;
        while let Some(item) = input.next().await {
            match item {
                Ok(chunk) => {
                    size += chunk.len() as u64;
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
        Ok(self.local_temp_tag(HashAndFormat { hash, format }, Some(size)))
    }

    /// Add a collection.
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

    /// Add a sequence of blobs, where the last is a hash sequence.
    ///
    /// It is a common pattern in iroh to have a hash sequence with one or more
    /// blobs of metadata, and the remaining blobs being the actual data. E.g.
    /// a collection is a hash sequence where the first child is the metadata.
    pub async fn add_blob_seq(&self, iter: impl Iterator<Item = Bytes>) -> Result<TempTag> {
        let mut blobs = iter.peekable();
        // put the tags somewhere
        let mut tags = vec![];
        loop {
            let blob = blobs.next().context("Failed to get next blob")?;
            if blobs.peek().is_none() {
                return self.add_bytes_with_opts(blob, BlobFormat::HashSeq).await;
            } else {
                tags.push(self.add_bytes(blob).await?);
            }
        }
    }

    /// Upgrades a temp tag to a persistent tag.
    pub async fn persist(&self, tt: TempTag) -> Result<Tag> {
        let tag = self
            .0
            .rpc
            .rpc(tags::CreateRequest {
                value: tt.hash_and_format(),
                batch: Some(self.0.batch),
                sync: SyncMode::Full,
            })
            .await??;
        Ok(tag)
    }

    /// Upgrades a temp tag to a persistent tag with a specific name.
    pub async fn persist_to(&self, tt: TempTag, tag: Tag) -> Result<()> {
        self.0
            .rpc
            .rpc(tags::SetRequest {
                name: tag,
                value: Some(tt.hash_and_format()),
                batch: Some(self.0.batch),
                sync: SyncMode::Full,
            })
            .await??;
        Ok(())
    }

    /// Upgrades a temp tag to a persistent tag with either a specific name or
    /// an automatically generated name.
    pub async fn persist_with_opts(&self, tt: TempTag, opts: SetTagOption) -> Result<Tag> {
        match opts {
            SetTagOption::Auto => self.persist(tt).await,
            SetTagOption::Named(tag) => {
                self.persist_to(tt, tag.clone()).await?;
                Ok(tag)
            }
        }
    }

    /// Creates a temp tag for the given hash and format, without notifying the server.
    ///
    /// Caution: only do this for data for which you know the server side has created a temp tag.
    fn local_temp_tag(&self, inner: HashAndFormat, _size: Option<u64>) -> TempTag {
        let on_drop: Arc<dyn TagDrop> = self.0.clone();
        let on_drop = Some(Arc::downgrade(&on_drop));
        TempTag::new(inner, on_drop)
    }
}
