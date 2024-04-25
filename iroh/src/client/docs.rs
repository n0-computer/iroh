use std::{
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};
use iroh_base::{key::PublicKey, node_addr::AddrInfoOptions};
use iroh_bytes::{export::ExportProgress, store::ExportMode, Hash};
use iroh_net::NodeAddr;
use iroh_sync::{
    actor::OpenState,
    store::{DownloadPolicy, Query},
    AuthorId, CapabilityKind, ContentStatus, NamespaceId, PeerIdBytes, RecordIdentifier,
};
use portable_atomic::{AtomicBool, Ordering};
use quic_rpc::{message::RpcMsg, RpcClient, ServiceConnection};
use serde::{Deserialize, Serialize};

use crate::{
    rpc_protocol::{
        DocCloseRequest, DocCreateRequest, DocDelRequest, DocDelResponse, DocDropRequest,
        DocExportFileRequest, DocGetDownloadPolicyRequest, DocGetExactRequest, DocGetManyRequest,
        DocGetSyncPeersRequest, DocImportFileRequest, DocImportProgress, DocImportRequest,
        DocLeaveRequest, DocListRequest, DocOpenRequest, DocSetDownloadPolicyRequest,
        DocSetHashRequest, DocSetRequest, DocShareRequest, DocStartSyncRequest, DocStatusRequest,
        DocSubscribeRequest, ProviderService, ShareMode,
    },
    sync_engine::SyncEvent,
    ticket::DocTicket,
};

use super::{blobs::BlobReader, flatten};

/// Iroh docs client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<ProviderService, C>,
}

impl<C> Client<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Create a new document.
    pub async fn create(&self) -> Result<Doc<C>> {
        let res = self.rpc.rpc(DocCreateRequest {}).await??;
        let doc = Doc::new(self.rpc.clone(), res.id);
        Ok(doc)
    }

    /// Delete a document from the local node.
    ///
    /// This is a destructive operation. Both the document secret key and all entries in the
    /// document will be permanently deleted from the node's storage. Content blobs will be deleted
    /// through garbage collection unless they are referenced from another document or tag.
    pub async fn drop_doc(&self, doc_id: NamespaceId) -> Result<()> {
        self.rpc.rpc(DocDropRequest { doc_id }).await??;
        Ok(())
    }

    /// Import a document from a ticket and join all peers in the ticket.
    pub async fn import(&self, ticket: DocTicket) -> Result<Doc<C>> {
        let res = self.rpc.rpc(DocImportRequest(ticket)).await??;
        let doc = Doc::new(self.rpc.clone(), res.doc_id);
        Ok(doc)
    }

    /// List all documents.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<(NamespaceId, CapabilityKind)>>> {
        let stream = self.rpc.server_streaming(DocListRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| (res.id, res.capability)))
    }

    /// Get a [`Doc`] client for a single document. Return None if the document cannot be found.
    pub async fn open(&self, id: NamespaceId) -> Result<Option<Doc<C>>> {
        self.rpc.rpc(DocOpenRequest { doc_id: id }).await??;
        let doc = Doc::new(self.rpc.clone(), id);
        Ok(Some(doc))
    }
}

/// Document handle
#[derive(Debug, Clone)]
pub struct Doc<C: ServiceConnection<ProviderService>>(Arc<DocInner<C>>);

impl<C: ServiceConnection<ProviderService>> PartialEq for Doc<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl<C: ServiceConnection<ProviderService>> Eq for Doc<C> {}

#[derive(Debug)]
struct DocInner<C: ServiceConnection<ProviderService>> {
    id: NamespaceId,
    rpc: RpcClient<ProviderService, C>,
    closed: AtomicBool,
    rt: tokio::runtime::Handle,
}

impl<C> Drop for DocInner<C>
where
    C: ServiceConnection<ProviderService>,
{
    fn drop(&mut self) {
        let doc_id = self.id;
        let rpc = self.rpc.clone();
        self.rt.spawn(async move {
            rpc.rpc(DocCloseRequest { doc_id }).await.ok();
        });
    }
}

impl<C> Doc<C>
where
    C: ServiceConnection<ProviderService>,
{
    fn new(rpc: RpcClient<ProviderService, C>, id: NamespaceId) -> Self {
        Self(Arc::new(DocInner {
            rpc,
            id,
            closed: AtomicBool::new(false),
            rt: tokio::runtime::Handle::current(),
        }))
    }

    async fn rpc<M>(&self, msg: M) -> Result<M::Response>
    where
        M: RpcMsg<ProviderService>,
    {
        let res = self.0.rpc.rpc(msg).await?;
        Ok(res)
    }

    /// Get the document id of this doc.
    pub fn id(&self) -> NamespaceId {
        self.0.id
    }

    /// Close the document.
    pub async fn close(&self) -> Result<()> {
        self.0.closed.store(true, Ordering::Release);
        self.rpc(DocCloseRequest { doc_id: self.id() }).await??;
        Ok(())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.0.closed.load(Ordering::Acquire) {
            Err(anyhow!("document is closed"))
        } else {
            Ok(())
        }
    }

    /// Set the content of a key to a byte array.
    pub async fn set_bytes(
        &self,
        author_id: AuthorId,
        key: impl Into<Bytes>,
        value: impl Into<Bytes>,
    ) -> Result<Hash> {
        self.ensure_open()?;
        let res = self
            .rpc(DocSetRequest {
                doc_id: self.id(),
                author_id,
                key: key.into(),
                value: value.into(),
            })
            .await??;
        Ok(res.entry.content_hash())
    }

    /// Set an entries on the doc via its key, hash, and size.
    pub async fn set_hash(
        &self,
        author_id: AuthorId,
        key: impl Into<Bytes>,
        hash: Hash,
        size: u64,
    ) -> Result<()> {
        self.ensure_open()?;
        self.rpc(DocSetHashRequest {
            doc_id: self.id(),
            author_id,
            key: key.into(),
            hash,
            size,
        })
        .await??;
        Ok(())
    }

    /// Add an entry from an absolute file path
    pub async fn import_file(
        &self,
        author: AuthorId,
        key: Bytes,
        path: impl AsRef<Path>,
        in_place: bool,
    ) -> Result<DocImportFileProgress> {
        self.ensure_open()?;
        let stream = self
            .0
            .rpc
            .server_streaming(DocImportFileRequest {
                doc_id: self.id(),
                author_id: author,
                path: path.as_ref().into(),
                key,
                in_place,
            })
            .await?;
        Ok(DocImportFileProgress::new(stream))
    }

    /// Export an entry as a file to a given absolute path.
    pub async fn export_file(
        &self,
        entry: Entry,
        path: impl AsRef<Path>,
        mode: ExportMode,
    ) -> Result<DocExportFileProgress> {
        self.ensure_open()?;
        let stream = self
            .0
            .rpc
            .server_streaming(DocExportFileRequest {
                entry: entry.0,
                path: path.as_ref().into(),
                mode,
            })
            .await?;
        Ok(DocExportFileProgress::new(stream))
    }

    /// Delete entries that match the given `author` and key `prefix`.
    ///
    /// This inserts an empty entry with the key set to `prefix`, effectively clearing all other
    /// entries whose key starts with or is equal to the given `prefix`.
    ///
    /// Returns the number of entries deleted.
    pub async fn del(&self, author_id: AuthorId, prefix: impl Into<Bytes>) -> Result<usize> {
        self.ensure_open()?;
        let res = self
            .rpc(DocDelRequest {
                doc_id: self.id(),
                author_id,
                prefix: prefix.into(),
            })
            .await??;
        let DocDelResponse { removed } = res;
        Ok(removed)
    }

    /// Get an entry for a key and author.
    ///
    /// Optionally also get the entry if it is empty (i.e. a deletion marker).
    pub async fn get_exact(
        &self,
        author: AuthorId,
        key: impl AsRef<[u8]>,
        include_empty: bool,
    ) -> Result<Option<Entry>> {
        self.ensure_open()?;
        let res = self
            .rpc(DocGetExactRequest {
                author,
                key: key.as_ref().to_vec().into(),
                doc_id: self.id(),
                include_empty,
            })
            .await??;
        Ok(res.entry.map(|entry| entry.into()))
    }

    /// Get entries.
    pub async fn get_many(
        &self,
        query: impl Into<Query>,
    ) -> Result<impl Stream<Item = Result<Entry>>> {
        self.ensure_open()?;
        let stream = self
            .0
            .rpc
            .server_streaming(DocGetManyRequest {
                doc_id: self.id(),
                query: query.into(),
            })
            .await?;
        Ok(flatten(stream).map_ok(|res| res.entry.into()))
    }

    /// Get a single entry.
    pub async fn get_one(&self, query: impl Into<Query>) -> Result<Option<Entry>> {
        self.get_many(query).await?.next().await.transpose()
    }

    /// Share this document with peers over a ticket.
    pub async fn share(
        &self,
        mode: ShareMode,
        addr_options: AddrInfoOptions,
    ) -> anyhow::Result<DocTicket> {
        self.ensure_open()?;
        let res = self
            .rpc(DocShareRequest {
                doc_id: self.id(),
                mode,
                addr_options,
            })
            .await??;
        Ok(res.0)
    }

    /// Start to sync this document with a list of peers.
    pub async fn start_sync(&self, peers: Vec<NodeAddr>) -> Result<()> {
        self.ensure_open()?;
        let _res = self
            .rpc(DocStartSyncRequest {
                doc_id: self.id(),
                peers,
            })
            .await??;
        Ok(())
    }

    /// Stop the live sync for this document.
    pub async fn leave(&self) -> Result<()> {
        self.ensure_open()?;
        let _res = self.rpc(DocLeaveRequest { doc_id: self.id() }).await??;
        Ok(())
    }

    /// Subscribe to events for this document.
    pub async fn subscribe(&self) -> anyhow::Result<impl Stream<Item = anyhow::Result<LiveEvent>>> {
        self.ensure_open()?;
        let stream = self
            .0
            .rpc
            .server_streaming(DocSubscribeRequest { doc_id: self.id() })
            .await?;
        Ok(flatten(stream)
            .map_ok(|res| res.event.into())
            .map_err(Into::into))
    }

    /// Get status info for this document
    pub async fn status(&self) -> anyhow::Result<OpenState> {
        self.ensure_open()?;
        let res = self.rpc(DocStatusRequest { doc_id: self.id() }).await??;
        Ok(res.status)
    }

    /// Set the download policy for this document
    pub async fn set_download_policy(&self, policy: DownloadPolicy) -> Result<()> {
        self.rpc(DocSetDownloadPolicyRequest {
            doc_id: self.id(),
            policy,
        })
        .await??;
        Ok(())
    }

    /// Get the download policy for this document
    pub async fn get_download_policy(&self) -> Result<DownloadPolicy> {
        let res = self
            .rpc(DocGetDownloadPolicyRequest { doc_id: self.id() })
            .await??;
        Ok(res.policy)
    }

    /// Get sync peers for this document
    pub async fn get_sync_peers(&self) -> Result<Option<Vec<PeerIdBytes>>> {
        let res = self
            .rpc(DocGetSyncPeersRequest { doc_id: self.id() })
            .await??;
        Ok(res.peers)
    }
}

impl<'a, C: ServiceConnection<ProviderService>> From<&'a Doc<C>>
    for &'a RpcClient<ProviderService, C>
{
    fn from(doc: &'a Doc<C>) -> &'a RpcClient<ProviderService, C> {
        &doc.0.rpc
    }
}

/// A single entry in a [`Doc`].
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Entry(iroh_sync::Entry);

impl From<iroh_sync::Entry> for Entry {
    fn from(value: iroh_sync::Entry) -> Self {
        Self(value)
    }
}

impl From<iroh_sync::SignedEntry> for Entry {
    fn from(value: iroh_sync::SignedEntry) -> Self {
        Self(value.into())
    }
}

impl Entry {
    /// Get the [`RecordIdentifier`] for this entry.
    pub fn id(&self) -> &RecordIdentifier {
        self.0.id()
    }

    /// Get the [`AuthorId`] of this entry.
    pub fn author(&self) -> AuthorId {
        self.0.author()
    }

    /// Get the [`struct@Hash`] of the content data of this record.
    pub fn content_hash(&self) -> Hash {
        self.0.content_hash()
    }

    /// Get the length of the data addressed by this record's content hash.
    pub fn content_len(&self) -> u64 {
        self.0.content_len()
    }

    /// Get the key of this entry.
    pub fn key(&self) -> &[u8] {
        self.0.key()
    }

    /// Get the timestamp of this entry.
    pub fn timestamp(&self) -> u64 {
        self.0.timestamp()
    }

    /// Read the content of an [`Entry`] as a streaming [`BlobReader`].
    ///
    /// You can pass either a [`Doc`] or the `Iroh` client by reference as `client`.
    pub async fn content_reader<C>(
        &self,
        client: impl Into<&RpcClient<ProviderService, C>>,
    ) -> Result<BlobReader>
    where
        C: ServiceConnection<ProviderService>,
    {
        BlobReader::from_rpc_read(client.into(), self.content_hash()).await
    }

    /// Read all content of an [`Entry`] into a buffer.
    ///
    /// You can pass either a [`Doc`] or the `Iroh` client by reference as `client`.
    pub async fn content_bytes<C>(
        &self,
        client: impl Into<&RpcClient<ProviderService, C>>,
    ) -> Result<Bytes>
    where
        C: ServiceConnection<ProviderService>,
    {
        BlobReader::from_rpc_read(client.into(), self.content_hash())
            .await?
            .read_to_bytes()
            .await
    }
}

/// Events informing about actions of the live sync progress.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, strum::Display)]
pub enum LiveEvent {
    /// A local insertion.
    InsertLocal {
        /// The inserted entry.
        entry: Entry,
    },
    /// Received a remote insert.
    InsertRemote {
        /// The peer that sent us the entry.
        from: PublicKey,
        /// The inserted entry.
        entry: Entry,
        /// If the content is available at the local node
        content_status: ContentStatus,
    },
    /// The content of an entry was downloaded and is now available at the local node
    ContentReady {
        /// The content hash of the newly available entry content
        hash: Hash,
    },
    /// We have a new neighbor in the swarm.
    NeighborUp(PublicKey),
    /// We lost a neighbor in the swarm.
    NeighborDown(PublicKey),
    /// A set-reconciliation sync finished.
    SyncFinished(SyncEvent),
}

impl From<crate::sync_engine::LiveEvent> for LiveEvent {
    fn from(event: crate::sync_engine::LiveEvent) -> LiveEvent {
        match event {
            crate::sync_engine::LiveEvent::InsertLocal { entry } => Self::InsertLocal {
                entry: entry.into(),
            },
            crate::sync_engine::LiveEvent::InsertRemote {
                from,
                entry,
                content_status,
            } => Self::InsertRemote {
                from,
                content_status,
                entry: entry.into(),
            },
            crate::sync_engine::LiveEvent::ContentReady { hash } => Self::ContentReady { hash },
            crate::sync_engine::LiveEvent::NeighborUp(node) => Self::NeighborUp(node),
            crate::sync_engine::LiveEvent::NeighborDown(node) => Self::NeighborDown(node),
            crate::sync_engine::LiveEvent::SyncFinished(details) => Self::SyncFinished(details),
        }
    }
}

/// Progress stream for doc import operations.
#[derive(derive_more::Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct DocImportFileProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<DocImportProgress>> + Send + Unpin + 'static>>,
}

impl DocImportFileProgress {
    fn new(
        stream: (impl Stream<Item = Result<impl Into<DocImportProgress>, impl Into<anyhow::Error>>>
             + Send
             + Unpin
             + 'static),
    ) -> Self {
        let stream = stream.map(|item| match item {
            Ok(item) => Ok(item.into()),
            Err(err) => Err(err.into()),
        });
        Self {
            stream: Box::pin(stream),
        }
    }

    /// Finish writing the stream, ignoring all intermediate progress events.
    ///
    /// Returns a [`DocImportFileOutcome`] which contains a tag, key, and hash and the size of the
    /// content.
    pub async fn finish(mut self) -> Result<DocImportFileOutcome> {
        let mut entry_size = 0;
        let mut entry_hash = None;
        while let Some(msg) = self.next().await {
            match msg? {
                DocImportProgress::Found { size, .. } => {
                    entry_size = size;
                }
                DocImportProgress::AllDone { key } => {
                    let hash = entry_hash
                        .context("expected DocImportProgress::IngestDone event to occur")?;
                    let outcome = DocImportFileOutcome {
                        hash,
                        key,
                        size: entry_size,
                    };
                    return Ok(outcome);
                }
                DocImportProgress::Abort(err) => return Err(err.into()),
                DocImportProgress::Progress { .. } => {}
                DocImportProgress::IngestDone { hash, .. } => {
                    entry_hash = Some(hash);
                }
            }
        }
        Err(anyhow!("Response stream ended prematurely"))
    }
}

/// Outcome of a [`Doc::import_file`] operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocImportFileOutcome {
    /// The hash of the entry's content
    pub hash: Hash,
    /// The size of the entry
    pub size: u64,
    /// The key of the entry
    pub key: Bytes,
}

impl Stream for DocImportFileProgress {
    type Item = Result<DocImportProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.poll_next_unpin(cx)
    }
}

/// Progress stream for doc export operations.
#[derive(derive_more::Debug)]
pub struct DocExportFileProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<ExportProgress>> + Send + Unpin + 'static>>,
}
impl DocExportFileProgress {
    fn new(
        stream: (impl Stream<Item = Result<impl Into<ExportProgress>, impl Into<anyhow::Error>>>
             + Send
             + Unpin
             + 'static),
    ) -> Self {
        let stream = stream.map(|item| match item {
            Ok(item) => Ok(item.into()),
            Err(err) => Err(err.into()),
        });
        Self {
            stream: Box::pin(stream),
        }
    }
    /// Iterate through the export progress stream, returning when the stream has completed.

    /// Returns a [`DocExportFileOutcome`] which contains a file path the data was written to and the size of the content.
    pub async fn finish(mut self) -> Result<DocExportFileOutcome> {
        let mut total_size = 0;
        let mut path = None;
        while let Some(msg) = self.next().await {
            match msg? {
                ExportProgress::Found { size, outpath, .. } => {
                    total_size = size.value();
                    path = Some(outpath);
                }
                ExportProgress::AllDone => {
                    let path = path.context("expected ExportProgress::Found event to occur")?;
                    let outcome = DocExportFileOutcome {
                        size: total_size,
                        path,
                    };
                    return Ok(outcome);
                }
                ExportProgress::Done { .. } => {}
                ExportProgress::Abort(err) => return Err(anyhow!(err)),
                ExportProgress::Progress { .. } => {}
            }
        }
        Err(anyhow!("Response stream ended prematurely"))
    }
}

/// Outcome of a [`Doc::export_file`] operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocExportFileOutcome {
    /// The size of the entry
    size: u64,
    /// The path to which the entry was saved
    path: PathBuf,
}

impl Stream for DocExportFileProgress {
    type Item = Result<ExportProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.poll_next_unpin(cx)
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn test_drop_doc_client_sync() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;

        let client = node.client();
        let doc = client.docs.create().await?;

        let res = std::thread::spawn(move || {
            drop(doc);
            drop(node);
        });

        tokio::task::spawn_blocking(move || res.join().map_err(|e| anyhow::anyhow!("{:?}", e)))
            .await??;

        Ok(())
    }

    #[tokio::test]
    async fn test_doc_import_export() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;

        // create temp file
        let temp_dir = tempfile::tempdir().context("tempdir")?;

        let in_root = temp_dir.path().join("in");
        tokio::fs::create_dir_all(in_root.clone())
            .await
            .context("create dir all")?;
        let out_root = temp_dir.path().join("out");

        let path = in_root.join("test");

        let size = 100;
        let mut buf = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut buf);
        let mut file = tokio::fs::File::create(path.clone())
            .await
            .context("create file")?;
        file.write_all(&buf.clone()).await.context("write_all")?;
        file.flush().await.context("flush")?;

        // create doc & author
        let client = node.client();
        let doc = client.docs.create().await.context("doc create")?;
        let author = client.authors.create().await.context("author create")?;

        // import file
        let import_outcome = doc
            .import_file(
                author,
                crate::util::fs::path_to_key(path.clone(), None, Some(in_root))?,
                path,
                true,
            )
            .await
            .context("import file")?
            .finish()
            .await
            .context("import finish")?;

        // export file
        let entry = doc
            .get_one(Query::author(author).key_exact(import_outcome.key))
            .await
            .context("get one")?
            .unwrap();
        let key = entry.key().to_vec();
        let export_outcome = doc
            .export_file(
                entry,
                crate::util::fs::key_to_path(key, None, Some(out_root))?,
                ExportMode::Copy,
            )
            .await
            .context("export file")?
            .finish()
            .await
            .context("export finish")?;

        let got_bytes = tokio::fs::read(export_outcome.path)
            .await
            .context("tokio read")?;
        assert_eq!(buf, got_bytes);

        Ok(())
    }
}
