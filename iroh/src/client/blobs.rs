//! API for blobs management.
//!
//! The main entry point is the [`Client`].
//!
//! You obtain a [`Client`] via [`Iroh::blobs()`](crate::client::Iroh::blobs).
//!
//! ## Interacting with the local blob store
//!
//! ### Importing data
//!
//! There are several ways to import data into the local blob store:
//!
//! - [`add_bytes`](Client::add_bytes)
//!   imports in memory data.
//! - [`add_stream`](Client::add_stream)
//!   imports data from a stream of bytes.
//! - [`add_reader`](Client::add_reader)
//!   imports data from an [async reader](tokio::io::AsyncRead).
//! - [`add_from_path`](Client::add_from_path)
//!   imports data from a file.
//!
//! The last method imports data from a file on the local filesystem.
//! This is the most efficient way to import large amounts of data.
//!
//! ### Exporting data
//!
//! There are several ways to export data from the local blob store:
//!
//! - [`read_to_bytes`](Client::read_to_bytes) reads data into memory.
//! - [`read`](Client::read) creates a [reader](Reader) to read data from.
//! - [`export`](Client::export) eports data to a file on the local filesystem.
//!
//! ## Interacting with remote nodes
//!
//! - [`download`](Client::download) downloads data from a remote node.
//! - [`share`](Client::share) allows creating a ticket to share data with a
//!   remote node.
//!
//! ## Interacting with the blob store itself
//!
//! These are more advanced operations that are usually not needed in normal
//! operation.
//!
//! - [`consistency_check`](Client::consistency_check) checks the internal
//!   consistency of the local blob store.
//! - [`validate`](Client::validate) validates the locally stored data against
//!   their BLAKE3 hashes.
//! - [`delete_blob`](Client::delete_blob) deletes a blob from the local store.
use std::{
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use futures_util::SinkExt;
use genawaiter::sync::{Co, Gen};
use iroh_base::{node_addr::AddrInfoOptions, ticket::BlobTicket};
use iroh_blobs::{
    export::ExportProgress as BytesExportProgress,
    format::collection::{Collection, SimpleStore},
    get::db::DownloadProgress as BytesDownloadProgress,
    store::{ConsistencyCheckProgress, ExportFormat, ExportMode, ValidateProgress},
    util::SetTagOption,
    BlobFormat, Hash, Tag,
};
use iroh_net::NodeAddr;
use portable_atomic::{AtomicU64, Ordering};
use quic_rpc::client::BoxStreamSync;
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::warn;

use crate::rpc_protocol::blobs::{
    AddPathRequest, AddStreamRequest, AddStreamUpdate, ConsistencyCheckRequest,
    CreateCollectionRequest, CreateCollectionResponse, DeleteRequest, DownloadRequest,
    ExportRequest, ListIncompleteRequest, ListRequest, ReadAtRequest, ReadAtResponse,
    ValidateRequest,
};
use crate::rpc_protocol::node::StatusRequest;

use super::{flatten, tags, Iroh, RpcClient};

/// Iroh blobs client.
#[derive(Debug, Clone, RefCast)]
#[repr(transparent)]
pub struct Client {
    pub(super) rpc: RpcClient,
}

impl<'a> From<&'a Iroh> for &'a RpcClient {
    fn from(client: &'a Iroh) -> &'a RpcClient {
        &client.blobs().rpc
    }
}

impl Client {
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
            .server_streaming(AddPathRequest {
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
        let (mut sink, progress) = self.rpc.bidi(AddStreamRequest { tag }).await?;
        let mut input = input.map(|chunk| match chunk {
            Ok(chunk) => Ok(AddStreamUpdate::Chunk(chunk)),
            Err(err) => {
                warn!("Abort send, reason: failed to read from source stream: {err:?}");
                Ok(AddStreamUpdate::Abort)
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
            .server_streaming(ValidateRequest { repair })
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
            .server_streaming(ConsistencyCheckRequest { repair })
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
            .server_streaming(DownloadRequest {
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
        let req = ExportRequest {
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
        let stream = self.rpc.server_streaming(ListRequest).await?;
        Ok(flatten(stream))
    }

    /// List all incomplete (partial) blobs.
    pub async fn list_incomplete(&self) -> Result<impl Stream<Item = Result<IncompleteBlobInfo>>> {
        let stream = self.rpc.server_streaming(ListIncompleteRequest).await?;
        Ok(flatten(stream))
    }

    /// Read the content of a collection.
    pub async fn get_collection(&self, hash: Hash) -> Result<Collection> {
        Collection::load(hash, self).await
    }

    /// List all collections.
    pub fn list_collections(&self) -> Result<impl Stream<Item = Result<CollectionInfo>>> {
        let this = self.clone();
        Ok(Gen::new(|co| async move {
            if let Err(cause) = this.list_collections_impl(&co).await {
                co.yield_(Err(cause)).await;
            }
        }))
    }

    async fn list_collections_impl(&self, co: &Co<Result<CollectionInfo>>) -> Result<()> {
        let tags = self.tags_client();
        let mut tags = tags.list_hash_seq().await?;
        while let Some(tag) = tags.next().await {
            let tag = tag?;
            if let Ok(collection) = self.get_collection(tag.hash).await {
                let info = CollectionInfo {
                    tag: tag.name,
                    hash: tag.hash,
                    total_blobs_count: Some(collection.len() as u64 + 1),
                    total_blobs_size: Some(0),
                };
                co.yield_(Ok(info)).await;
            }
        }
        Ok(())
    }

    /// Delete a blob.
    ///
    /// **Warning**: this operation deletes the blob from the local store even
    /// if it is tagged. You should usually not do this manually, but rely on the
    /// node to remove data that is not tagged.
    pub async fn delete_blob(&self, hash: Hash) -> Result<()> {
        self.rpc.rpc(DeleteRequest { hash }).await??;
        Ok(())
    }

    /// Share a blob.
    pub async fn share(
        &self,
        hash: Hash,
        blob_format: BlobFormat,
        addr_options: AddrInfoOptions,
    ) -> Result<BlobTicket> {
        let mut addr = self.rpc.rpc(StatusRequest).await??.addr;
        addr.apply_options(addr_options);
        let ticket = BlobTicket::new(addr, hash, blob_format).expect("correct ticket");

        Ok(ticket)
    }

    /// Get the status of a blob.
    pub async fn status(&self, hash: Hash) -> Result<BlobStatus> {
        // TODO: this could be implemented more efficiently
        let reader = self.read(hash).await?;
        if reader.is_complete {
            Ok(BlobStatus::Complete { size: reader.size })
        } else {
            Ok(BlobStatus::Partial { size: reader.size })
        }
    }

    fn tags_client(&self) -> tags::Client {
        tags::Client {
            rpc: self.rpc.clone(),
        }
    }
}

impl SimpleStore for Client {
    async fn load(&self, hash: Hash) -> anyhow::Result<Bytes> {
        self.read_to_bytes(hash).await
    }
}

/// Whether to wrap the added data in a collection.
#[derive(Debug, Serialize, Deserialize)]
pub enum WrapOption {
    /// Do not wrap the file or directory.
    NoWrap,
    /// Wrap the file or directory in a collection.
    Wrap {
        /// Override the filename in the wrapping collection.
        name: Option<String>,
    },
}

/// Status information about a blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobStatus {
    /// The blob is only stored partially.
    Partial {
        /// The size of the currently stored partial blob.
        size: u64,
    },
    /// The blob is stored completely.
    Complete {
        /// The size of the blob.
        size: u64,
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

    pub(crate) async fn from_rpc_read(rpc: &RpcClient, hash: Hash) -> anyhow::Result<Self> {
        Self::from_rpc_read_at(rpc, hash, 0, None).await
    }

    async fn from_rpc_read_at(
        rpc: &RpcClient,
        hash: Hash,
        offset: u64,
        len: Option<usize>,
    ) -> anyhow::Result<Self> {
        let stream = rpc
            .server_streaming(ReadAtRequest { hash, offset, len })
            .await?;
        let mut stream = flatten(stream);

        let (size, is_complete) = match stream.next().await {
            Some(Ok(ReadAtResponse::Entry { size, is_complete })) => (size, is_complete),
            Some(Err(err)) => return Err(err),
            Some(Ok(_)) => return Err(anyhow!("Expected header frame, but got data frame")),
            None => return Err(anyhow!("Expected header frame, but RPC stream was dropped")),
        };

        let stream = stream.map(|item| match item {
            Ok(ReadAtResponse::Data { chunk }) => Ok(chunk),
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

    use anyhow::Context as _;
    use iroh_blobs::hashseq::HashSeq;
    use iroh_net::NodeId;
    use rand::RngCore;
    use testresult::TestResult;
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
                .blobs()
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
            .blobs()
            .create_collection(collection, SetTagOption::Auto, tags)
            .await?;

        let collections: Vec<_> = client.blobs().list_collections()?.try_collect().await?;

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
        let tags: Vec<_> = client.tags().list().await?.try_collect().await?;
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
            .blobs()
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
        let res = client.blobs().read_to_bytes(hash).await?;
        assert_eq!(&res, &buf[..]);

        // Read at smaller than blob_get_chunk_size
        let res = client.blobs().read_at_to_bytes(hash, 0, Some(100)).await?;
        assert_eq!(res.len(), 100);
        assert_eq!(&res[..], &buf[0..100]);

        let res = client.blobs().read_at_to_bytes(hash, 20, Some(120)).await?;
        assert_eq!(res.len(), 120);
        assert_eq!(&res[..], &buf[20..140]);

        // Read at equal to blob_get_chunk_size
        let res = client
            .blobs()
            .read_at_to_bytes(hash, 0, Some(1024 * 64))
            .await?;
        assert_eq!(res.len(), 1024 * 64);
        assert_eq!(&res[..], &buf[0..1024 * 64]);

        let res = client
            .blobs()
            .read_at_to_bytes(hash, 20, Some(1024 * 64))
            .await?;
        assert_eq!(res.len(), 1024 * 64);
        assert_eq!(&res[..], &buf[20..(20 + 1024 * 64)]);

        // Read at larger than blob_get_chunk_size
        let res = client
            .blobs()
            .read_at_to_bytes(hash, 0, Some(10 + 1024 * 64))
            .await?;
        assert_eq!(res.len(), 10 + 1024 * 64);
        assert_eq!(&res[..], &buf[0..(10 + 1024 * 64)]);

        let res = client
            .blobs()
            .read_at_to_bytes(hash, 20, Some(10 + 1024 * 64))
            .await?;
        assert_eq!(res.len(), 10 + 1024 * 64);
        assert_eq!(&res[..], &buf[20..(20 + 10 + 1024 * 64)]);

        // full length
        let res = client.blobs().read_at_to_bytes(hash, 20, None).await?;
        assert_eq!(res.len(), 1024 * 128 - 20);
        assert_eq!(&res[..], &buf[20..]);

        // size should be total
        let reader = client.blobs().read_at(hash, 0, Some(20)).await?;
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
                .blobs()
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
            .blobs()
            .create_collection(collection, SetTagOption::Auto, tags)
            .await?;

        let collection = client.blobs().get_collection(hash).await?;

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
            .blobs()
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
            .blobs()
            .share(import_outcome.hash, BlobFormat::Raw, Default::default())
            .await?;
        assert_eq!(ticket.hash(), import_outcome.hash);

        let status = client.blobs().status(import_outcome.hash).await?;
        assert_eq!(status, BlobStatus::Complete { size });

        Ok(())
    }

    /// Download a existing blob from oneself
    #[tokio::test]
    async fn test_blob_get_self_existing() -> TestResult<()> {
        let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;
        let node_id = node.node_id();
        let client = node.client();

        let AddOutcome { hash, size, .. } = client.blobs().add_bytes("foo").await?;

        // Direct
        let res = client
            .blobs()
            .download_with_opts(
                hash,
                DownloadOptions {
                    format: BlobFormat::Raw,
                    nodes: vec![node_id.into()],
                    tag: SetTagOption::Auto,
                    mode: DownloadMode::Direct,
                },
            )
            .await?
            .await?;

        assert_eq!(res.local_size, size);
        assert_eq!(res.downloaded_size, 0);

        // Queued
        let res = client
            .blobs()
            .download_with_opts(
                hash,
                DownloadOptions {
                    format: BlobFormat::Raw,
                    nodes: vec![node_id.into()],
                    tag: SetTagOption::Auto,
                    mode: DownloadMode::Queued,
                },
            )
            .await?
            .await?;

        assert_eq!(res.local_size, size);
        assert_eq!(res.downloaded_size, 0);

        Ok(())
    }

    /// Download a missing blob from oneself
    #[tokio::test]
    async fn test_blob_get_self_missing() -> TestResult<()> {
        let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;
        let node_id = node.node_id();
        let client = node.client();

        let hash = Hash::from_bytes([0u8; 32]);

        // Direct
        let res = client
            .blobs()
            .download_with_opts(
                hash,
                DownloadOptions {
                    format: BlobFormat::Raw,
                    nodes: vec![node_id.into()],
                    tag: SetTagOption::Auto,
                    mode: DownloadMode::Direct,
                },
            )
            .await?
            .await;
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string().as_str(),
            "No nodes to download from provided"
        );

        // Queued
        let res = client
            .blobs()
            .download_with_opts(
                hash,
                DownloadOptions {
                    format: BlobFormat::Raw,
                    nodes: vec![node_id.into()],
                    tag: SetTagOption::Auto,
                    mode: DownloadMode::Queued,
                },
            )
            .await?
            .await;
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string().as_str(),
            "No provider nodes found"
        );

        Ok(())
    }

    /// Download a existing collection. Check that things succeed and no download is performed.
    #[tokio::test]
    async fn test_blob_get_existing_collection() -> TestResult<()> {
        let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;
        // We use a nonexisting node id because we just want to check that this succeeds without
        // hitting the network.
        let node_id = NodeId::from_bytes(&[0u8; 32])?;
        let client = node.client();

        let mut collection = Collection::default();
        let mut tags = Vec::new();
        let mut size = 0;
        for value in ["iroh", "is", "cool"] {
            let import_outcome = client.blobs().add_bytes(value).await.context("add bytes")?;
            collection.push(value.to_string(), import_outcome.hash);
            tags.push(import_outcome.tag);
            size += import_outcome.size;
        }

        let (hash, _tag) = client
            .blobs()
            .create_collection(collection, SetTagOption::Auto, tags)
            .await?;

        // load the hashseq and collection header manually to calculate our expected size
        let hashseq_bytes = client.blobs().read_to_bytes(hash).await?;
        size += hashseq_bytes.len() as u64;
        let hashseq = HashSeq::try_from(hashseq_bytes)?;
        let collection_header_bytes = client
            .blobs()
            .read_to_bytes(hashseq.into_iter().next().expect("header to exist"))
            .await?;
        size += collection_header_bytes.len() as u64;

        // Direct
        let res = client
            .blobs()
            .download_with_opts(
                hash,
                DownloadOptions {
                    format: BlobFormat::HashSeq,
                    nodes: vec![node_id.into()],
                    tag: SetTagOption::Auto,
                    mode: DownloadMode::Direct,
                },
            )
            .await?
            .await
            .context("direct (download)")?;

        assert_eq!(res.local_size, size);
        assert_eq!(res.downloaded_size, 0);

        // Queued
        let res = client
            .blobs()
            .download_with_opts(
                hash,
                DownloadOptions {
                    format: BlobFormat::HashSeq,
                    nodes: vec![node_id.into()],
                    tag: SetTagOption::Auto,
                    mode: DownloadMode::Queued,
                },
            )
            .await?
            .await
            .context("queued")?;

        assert_eq!(res.local_size, size);
        assert_eq!(res.downloaded_size, 0);

        Ok(())
    }
}
