use std::{
    io,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::{Future, SinkExt, Stream, StreamExt, TryStreamExt};
use iroh_base::ticket::BlobTicket;
use iroh_bytes::{
    export::ExportProgress,
    format::collection::Collection,
    get::db::DownloadProgress,
    provider::AddProgress,
    store::{ExportFormat, ExportMode, ValidateProgress},
    BlobFormat, Hash, Tag,
};
use iroh_net::NodeAddr;
use portable_atomic::{AtomicU64, Ordering};
use quic_rpc::{client::BoxStreamSync, RpcClient, ServiceConnection};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::warn;

use crate::rpc_protocol::{
    BlobAddPathRequest, BlobAddStreamRequest, BlobAddStreamUpdate, BlobDeleteBlobRequest,
    BlobDownloadRequest, BlobExportRequest, BlobGetCollectionRequest, BlobGetCollectionResponse,
    BlobListCollectionsRequest, BlobListCollectionsResponse, BlobListIncompleteRequest,
    BlobListIncompleteResponse, BlobListRequest, BlobListResponse, BlobReadAtRequest,
    BlobReadAtResponse, BlobValidateRequest, CreateCollectionRequest, CreateCollectionResponse,
    NodeStatusRequest, NodeStatusResponse, ProviderService, SetTagOption, WrapOption,
};

use super::{flatten, Iroh};

/// Iroh blobs client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<ProviderService, C>,
}

impl<'a, C: ServiceConnection<ProviderService>> From<&'a Iroh<C>>
    for &'a RpcClient<ProviderService, C>
{
    fn from(client: &'a Iroh<C>) -> &'a RpcClient<ProviderService, C> {
        &client.blobs.rpc
    }
}

impl<C> Client<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Stream the contents of a a single blob.
    ///
    /// Returns a [`BlobReader`], which can report the size of the blob before reading it.
    pub async fn read(&self, hash: Hash) -> Result<BlobReader> {
        BlobReader::from_rpc_read(&self.rpc, hash).await
    }

    /// Read offset + len from a single blob.
    ///
    /// If `len` is `None` it will read the full blob.
    pub async fn read_at(&self, hash: Hash, offset: u64, len: Option<usize>) -> Result<BlobReader> {
        BlobReader::from_rpc_read_at(&self.rpc, hash, offset, len).await
    }

    /// Read all bytes of single blob.
    ///
    /// This allocates a buffer for the full blob. Use only if you know that the blob you're
    /// reading is small. If not sure, use [`Self::read`] and check the size with
    /// [`BlobReader::size`] before calling [`BlobReader::read_to_bytes`].
    pub async fn read_to_bytes(&self, hash: Hash) -> Result<Bytes> {
        BlobReader::from_rpc_read(&self.rpc, hash)
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
        BlobReader::from_rpc_read_at(&self.rpc, hash, offset, len)
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
    ) -> Result<BlobAddProgress> {
        let stream = self
            .rpc
            .server_streaming(BlobAddPathRequest {
                path,
                in_place,
                tag,
                wrap,
            })
            .await?;
        Ok(BlobAddProgress::new(stream))
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
    ) -> anyhow::Result<BlobAddProgress> {
        const CAP: usize = 1024 * 64; // send 64KB per request by default
        let input = ReaderStream::with_capacity(reader, CAP);
        self.add_stream(input, tag).await
    }

    /// Write a blob by passing a stream of bytes.
    pub async fn add_stream(
        &self,
        input: impl Stream<Item = io::Result<Bytes>> + Send + Unpin + 'static,
        tag: SetTagOption,
    ) -> anyhow::Result<BlobAddProgress> {
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

        Ok(BlobAddProgress::new(progress))
    }

    /// Write a blob by passing bytes.
    pub async fn add_bytes(&self, bytes: impl Into<Bytes>) -> anyhow::Result<BlobAddOutcome> {
        let input = futures::stream::once(futures::future::ready(Ok(bytes.into())));
        self.add_stream(input, SetTagOption::Auto).await?.await
    }

    /// Write a blob by passing bytes, setting an explicit tag name.
    pub async fn add_bytes_named(
        &self,
        bytes: impl Into<Bytes>,
        name: impl Into<Tag>,
    ) -> anyhow::Result<BlobAddOutcome> {
        let input = futures::stream::once(futures::future::ready(Ok(bytes.into())));
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
        Ok(stream.map_err(anyhow::Error::from))
    }

    /// Download a blob from another node and add it to the local database.
    pub async fn download(&self, req: BlobDownloadRequest) -> Result<BlobDownloadProgress> {
        let stream = self.rpc.server_streaming(req).await?;
        Ok(BlobDownloadProgress::new(
            stream.map_err(anyhow::Error::from),
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
    ) -> Result<BlobExportProgress> {
        let req = BlobExportRequest {
            hash,
            path: destination,
            format,
            mode,
        };
        let stream = self.rpc.server_streaming(req).await?;
        Ok(BlobExportProgress::new(stream.map_err(anyhow::Error::from)))
    }

    /// List all complete blobs.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<BlobListResponse>>> {
        let stream = self.rpc.server_streaming(BlobListRequest).await?;
        Ok(flatten(stream))
    }

    /// List all incomplete (partial) blobs.
    pub async fn list_incomplete(
        &self,
    ) -> Result<impl Stream<Item = Result<BlobListIncompleteResponse>>> {
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
    pub async fn list_collections(
        &self,
    ) -> Result<impl Stream<Item = Result<BlobListCollectionsResponse>>> {
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
        ticket_options: ShareTicketOptions,
    ) -> Result<BlobTicket> {
        let NodeStatusResponse { addr, .. } = self.rpc.rpc(NodeStatusRequest).await??;
        let mut node_addr = NodeAddr::new(addr.node_id);
        match ticket_options {
            ShareTicketOptions::RelayAndAddresses => {
                node_addr = node_addr.with_direct_addresses(addr.direct_addresses().copied());
                if let Some(url) = addr.relay_url() {
                    node_addr = node_addr.with_relay_url(url.clone());
                }
            }
            ShareTicketOptions::Relay => {
                if let Some(url) = addr.relay_url() {
                    node_addr = node_addr.with_relay_url(url.clone());
                }
            }
            ShareTicketOptions::Addresses => {
                node_addr = node_addr.with_direct_addresses(addr.direct_addresses().copied());
            }
        }

        let ticket = BlobTicket::new(node_addr, hash, blob_format).expect("correct ticket");

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
}

/// Options when creating a ticket
#[derive(
    Copy, Clone, PartialEq, Eq, Default, Debug, derive_more::Display, derive_more::FromStr,
)]
pub enum ShareTicketOptions {
    /// Include both the relay URL and the direct addresses.
    #[default]
    RelayAndAddresses,
    /// Only include the relay URL.
    Relay,
    /// Only include the direct addresses.
    Addresses,
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
pub struct BlobAddOutcome {
    /// The hash of the blob
    pub hash: Hash,
    /// The format the blob
    pub format: BlobFormat,
    /// The size of the blob
    pub size: u64,
    /// The tag of the blob
    pub tag: Tag,
}

/// Progress stream for blob add operations.
#[derive(derive_more::Debug)]
pub struct BlobAddProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<AddProgress>> + Send + Unpin + 'static>>,
    current_total_size: Arc<AtomicU64>,
}

impl BlobAddProgress {
    fn new(
        stream: (impl Stream<Item = Result<impl Into<AddProgress>, impl Into<anyhow::Error>>>
             + Send
             + Unpin
             + 'static),
    ) -> Self {
        let current_total_size = Arc::new(AtomicU64::new(0));
        let total_size = current_total_size.clone();
        let stream = stream.map(move |item| match item {
            Ok(item) => {
                let item = item.into();
                if let AddProgress::Found { size, .. } = &item {
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
    /// Returns a [`BlobAddOutcome`] which contains a tag, format, hash and a size.
    /// When importing a single blob, this is the hash and size of that blob.
    /// When importing a collection, the hash is the hash of the collection and the size
    /// is the total size of all imported blobs (but excluding the size of the collection blob
    /// itself).
    pub async fn finish(self) -> Result<BlobAddOutcome> {
        self.await
    }
}

impl Stream for BlobAddProgress {
    type Item = Result<AddProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.poll_next_unpin(cx)
    }
}

impl Future for BlobAddProgress {
    type Output = Result<BlobAddOutcome>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(anyhow!("Response stream ended prematurely")))
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    AddProgress::AllDone { hash, format, tag } => {
                        let outcome = BlobAddOutcome {
                            hash,
                            format,
                            tag,
                            size: self.current_total_size.load(Ordering::Relaxed),
                        };
                        return Poll::Ready(Ok(outcome));
                    }
                    AddProgress::Abort(err) => {
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
pub struct BlobDownloadOutcome {
    /// The size of the data we already had locally
    pub local_size: u64,
    /// The size of the data we downloaded from the network
    pub downloaded_size: u64,
    /// Statistics about the download
    pub stats: iroh_bytes::get::Stats,
}

/// Progress stream for blob download operations.
#[derive(derive_more::Debug)]
pub struct BlobDownloadProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<DownloadProgress>> + Send + Unpin + 'static>>,
    current_local_size: Arc<AtomicU64>,
    current_network_size: Arc<AtomicU64>,
}

impl BlobDownloadProgress {
    /// Create a `BlobDownloadProgress` that can help you easily poll the `DownloadProgress` stream from your download until it is finished or errors.
    pub fn new(
        stream: (impl Stream<Item = Result<impl Into<DownloadProgress>, impl Into<anyhow::Error>>>
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
                    DownloadProgress::FoundLocal { size, .. } => {
                        local_size.fetch_add(size.value(), Ordering::Relaxed);
                    }
                    DownloadProgress::Found { size, .. } => {
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
    /// Returns a [`BlobDownloadOutcome`] which contains the size of the content we downloaded and the size of the content we already had locally.
    /// When importing a single blob, this is the size of that blob.
    /// When importing a collection, this is the total size of all imported blobs (but excluding the size of the collection blob itself).
    pub async fn finish(self) -> Result<BlobDownloadOutcome> {
        self.await
    }
}

impl Stream for BlobDownloadProgress {
    type Item = Result<DownloadProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.poll_next_unpin(cx)
    }
}

impl Future for BlobDownloadProgress {
    type Output = Result<BlobDownloadOutcome>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(anyhow!("Response stream ended prematurely")))
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    DownloadProgress::AllDone(stats) => {
                        let outcome = BlobDownloadOutcome {
                            local_size: self.current_local_size.load(Ordering::Relaxed),
                            downloaded_size: self.current_network_size.load(Ordering::Relaxed),
                            stats,
                        };
                        return Poll::Ready(Ok(outcome));
                    }
                    DownloadProgress::Abort(err) => {
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
pub struct BlobExportOutcome {
    /// The total size of the exported data.
    total_size: u64,
}

/// Progress stream for blob export operations.
#[derive(derive_more::Debug)]
pub struct BlobExportProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<ExportProgress>> + Send + Unpin + 'static>>,
    current_total_size: Arc<AtomicU64>,
}

impl BlobExportProgress {
    /// Create a `BlobExportProgress` that can help you easily poll the `ExportProgress` stream from your download until it is finished or errors.
    pub fn new(
        stream: (impl Stream<Item = Result<impl Into<ExportProgress>, impl Into<anyhow::Error>>>
             + Send
             + Unpin
             + 'static),
    ) -> Self {
        let current_total_size = Arc::new(AtomicU64::new(0));
        let total_size = current_total_size.clone();
        let stream = stream.map(move |item| match item {
            Ok(item) => {
                let item = item.into();
                if let ExportProgress::Found { size, .. } = &item {
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
    /// Returns a [`BlobExportOutcome`] which contains the size of the content we exported.
    pub async fn finish(self) -> Result<BlobExportOutcome> {
        self.await
    }
}

impl Stream for BlobExportProgress {
    type Item = Result<ExportProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.poll_next_unpin(cx)
    }
}

impl Future for BlobExportProgress {
    type Output = Result<BlobExportOutcome>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(anyhow!("Response stream ended prematurely")))
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    ExportProgress::AllDone => {
                        let outcome = BlobExportOutcome {
                            total_size: self.current_total_size.load(Ordering::Relaxed),
                        };
                        return Poll::Ready(Ok(outcome));
                    }
                    ExportProgress::Abort(err) => {
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
pub struct BlobReader {
    size: u64,
    response_size: u64,
    is_complete: bool,
    #[debug("StreamReader")]
    stream: tokio_util::io::StreamReader<BoxStreamSync<'static, io::Result<Bytes>>, Bytes>,
}

impl BlobReader {
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

    pub(crate) async fn from_rpc_read<C: ServiceConnection<ProviderService>>(
        rpc: &RpcClient<ProviderService, C>,
        hash: Hash,
    ) -> anyhow::Result<Self> {
        Self::from_rpc_read_at(rpc, hash, 0, None).await
    }

    async fn from_rpc_read_at<C: ServiceConnection<ProviderService>>(
        rpc: &RpcClient<ProviderService, C>,
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

impl AsyncRead for BlobReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl Stream for BlobReader {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).get_pin_mut().poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.get_ref().size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Context as _;
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
            let BlobListCollectionsResponse {
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
