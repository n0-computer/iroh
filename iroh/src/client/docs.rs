//! API for document management.

use std::{
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use derive_more::{Display, FromStr};
use futures_lite::{Stream, StreamExt};
use iroh_base::{key::PublicKey, node_addr::AddrInfoOptions, rpc::RpcError};
use iroh_blobs::{export::ExportProgress, store::ExportMode, Hash};
use iroh_docs::{
    actor::OpenState,
    store::{DownloadPolicy, Query},
    AuthorId, Capability, CapabilityKind, ContentStatus, DocTicket, NamespaceId, PeerIdBytes,
    RecordIdentifier,
};
use iroh_net::NodeAddr;
use portable_atomic::{AtomicBool, Ordering};
use quic_rpc::message::RpcMsg;
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};

use crate::rpc_protocol::{
    DocCloseRequest, DocCreateRequest, DocDelRequest, DocDelResponse, DocDropRequest,
    DocExportFileRequest, DocGetDownloadPolicyRequest, DocGetExactRequest, DocGetManyRequest,
    DocGetSyncPeersRequest, DocImportFileRequest, DocImportRequest, DocLeaveRequest,
    DocListRequest, DocOpenRequest, DocSetDownloadPolicyRequest, DocSetHashRequest, DocSetRequest,
    DocShareRequest, DocStartSyncRequest, DocStatusRequest, DocSubscribeRequest, RpcService,
};

#[doc(inline)]
pub use iroh_docs::engine::{Origin, SyncEvent, SyncReason};

use super::{blobs, flatten, RpcClient};

/// Iroh docs client.
#[derive(Debug, Clone, RefCast)]
#[repr(transparent)]
pub struct Client {
    pub(super) rpc: RpcClient,
}

impl Client {
    /// Create a new document.
    pub async fn create(&self) -> Result<Doc> {
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

    /// Import a document from a namespace capability.
    ///
    /// This does not start sync automatically. Use [`Doc::start_sync`] to start sync.
    pub async fn import_namespace(&self, capability: Capability) -> Result<Doc> {
        let res = self.rpc.rpc(DocImportRequest { capability }).await??;
        let doc = Doc::new(self.rpc.clone(), res.doc_id);
        Ok(doc)
    }

    /// Import a document from a ticket and join all peers in the ticket.
    pub async fn import(&self, ticket: DocTicket) -> Result<Doc> {
        let DocTicket { capability, nodes } = ticket;
        let doc = self.import_namespace(capability).await?;
        doc.start_sync(nodes).await?;
        Ok(doc)
    }

    /// Import a document from a ticket, create a subscription stream and join all peers in the ticket.
    ///
    /// Returns the [`Doc`] and a [`Stream`] of [`LiveEvent`]s
    ///
    /// The subscription stream is created before the sync is started, so the first call to this
    /// method after starting the node is guaranteed to not miss any sync events.
    pub async fn import_and_subscribe(
        &self,
        ticket: DocTicket,
    ) -> Result<(Doc, impl Stream<Item = anyhow::Result<LiveEvent>>)> {
        let DocTicket { capability, nodes } = ticket;
        let res = self.rpc.rpc(DocImportRequest { capability }).await??;
        let doc = Doc::new(self.rpc.clone(), res.doc_id);
        let events = doc.subscribe().await?;
        doc.start_sync(nodes).await?;
        Ok((doc, events))
    }

    /// List all documents.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<(NamespaceId, CapabilityKind)>>> {
        let stream = self.rpc.server_streaming(DocListRequest {}).await?;
        Ok(flatten(stream).map(|res| res.map(|res| (res.id, res.capability))))
    }

    /// Get a [`Doc`] client for a single document. Return None if the document cannot be found.
    pub async fn open(&self, id: NamespaceId) -> Result<Option<Doc>> {
        self.rpc.rpc(DocOpenRequest { doc_id: id }).await??;
        let doc = Doc::new(self.rpc.clone(), id);
        Ok(Some(doc))
    }
}

/// Document handle
#[derive(Debug, Clone)]
pub struct Doc(Arc<DocInner>);

impl PartialEq for Doc {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl Eq for Doc {}

#[derive(Debug)]
struct DocInner {
    id: NamespaceId,
    rpc: RpcClient,
    closed: AtomicBool,
    rt: tokio::runtime::Handle,
}

impl Drop for DocInner {
    fn drop(&mut self) {
        let doc_id = self.id;
        let rpc = self.rpc.clone();
        if !self.closed.swap(true, Ordering::Relaxed) {
            self.rt.spawn(async move {
                rpc.rpc(DocCloseRequest { doc_id }).await.ok();
            });
        }
    }
}

impl Doc {
    fn new(rpc: RpcClient, id: NamespaceId) -> Self {
        Self(Arc::new(DocInner {
            rpc,
            id,
            closed: AtomicBool::new(false),
            rt: tokio::runtime::Handle::current(),
        }))
    }

    async fn rpc<M>(&self, msg: M) -> Result<M::Response>
    where
        M: RpcMsg<RpcService>,
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
        if !self.0.closed.swap(true, Ordering::Relaxed) {
            self.rpc(DocCloseRequest { doc_id: self.id() }).await??;
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.0.closed.load(Ordering::Relaxed) {
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
    ) -> Result<ImportFileProgress> {
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
        Ok(ImportFileProgress::new(stream))
    }

    /// Export an entry as a file to a given absolute path.
    pub async fn export_file(
        &self,
        entry: Entry,
        path: impl AsRef<Path>,
        mode: ExportMode,
    ) -> Result<ExportFileProgress> {
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
        Ok(ExportFileProgress::new(stream))
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
        Ok(flatten(stream).map(|res| res.map(|res| res.entry.into())))
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
            .try_server_streaming(DocSubscribeRequest { doc_id: self.id() })
            .await?;
        Ok(stream.map(|res| match res {
            Ok(res) => Ok(res.event.into()),
            Err(err) => Err(err.into()),
        }))
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

impl<'a> From<&'a Doc> for &'a RpcClient {
    fn from(doc: &'a Doc) -> &'a RpcClient {
        &doc.0.rpc
    }
}

/// A single entry in a [`Doc`].
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Entry(iroh_docs::Entry);

impl From<iroh_docs::Entry> for Entry {
    fn from(value: iroh_docs::Entry) -> Self {
        Self(value)
    }
}

impl From<iroh_docs::SignedEntry> for Entry {
    fn from(value: iroh_docs::SignedEntry) -> Self {
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

    /// Read the content of an [`Entry`] as a streaming [`blobs::Reader`].
    ///
    /// You can pass either a [`Doc`] or the `Iroh` client by reference as `client`.
    pub async fn content_reader(&self, client: impl Into<&RpcClient>) -> Result<blobs::Reader> {
        blobs::Reader::from_rpc_read(client.into(), self.content_hash()).await
    }

    /// Read all content of an [`Entry`] into a buffer.
    ///
    /// You can pass either a [`Doc`] or the `Iroh` client by reference as `client`.
    pub async fn content_bytes(&self, client: impl Into<&RpcClient>) -> Result<Bytes> {
        blobs::Reader::from_rpc_read(client.into(), self.content_hash())
            .await?
            .read_to_bytes()
            .await
    }
}

/// Progress messages for an doc import operation
///
/// An import operation involves computing the outboard of a file, and then
/// either copying or moving the file into the database, then setting the author, hash, size, and tag of that
/// file as an entry in the doc.
#[derive(Debug, Serialize, Deserialize)]
pub enum ImportProgress {
    /// An item was found with name `name`, from now on referred to via `id`
    Found {
        /// A new unique id for this entry.
        id: u64,
        /// The name of the entry.
        name: String,
        /// The size of the entry in bytes.
        size: u64,
    },
    /// We got progress ingesting item `id`.
    Progress {
        /// The unique id of the entry.
        id: u64,
        /// The offset of the progress, in bytes.
        offset: u64,
    },
    /// We are done adding `id` to the data store and the hash is `hash`.
    IngestDone {
        /// The unique id of the entry.
        id: u64,
        /// The hash of the entry.
        hash: Hash,
    },
    /// We are done setting the entry to the doc
    AllDone {
        /// The key of the entry
        key: Bytes,
    },
    /// We got an error and need to abort.
    ///
    /// This will be the last message in the stream.
    Abort(RpcError),
}

/// Intended capability for document share tickets
#[derive(Serialize, Deserialize, Debug, Clone, Display, FromStr)]
pub enum ShareMode {
    /// Read-only access
    Read,
    /// Write access
    Write,
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
    /// All pending content is now ready.
    ///
    /// This event signals that all queued content downloads from the last sync run have either
    /// completed or failed.
    ///
    /// It will only be emitted after a [`Self::SyncFinished`] event, never before.
    ///
    /// Receiving this event does not guarantee that all content in the document is available. If
    /// blobs failed to download, this event will still be emitted after all operations completed.
    PendingContentReady,
}

impl From<crate::docs::engine::LiveEvent> for LiveEvent {
    fn from(event: crate::docs::engine::LiveEvent) -> LiveEvent {
        match event {
            crate::docs::engine::LiveEvent::InsertLocal { entry } => Self::InsertLocal {
                entry: entry.into(),
            },
            crate::docs::engine::LiveEvent::InsertRemote {
                from,
                entry,
                content_status,
            } => Self::InsertRemote {
                from,
                content_status,
                entry: entry.into(),
            },
            crate::docs::engine::LiveEvent::ContentReady { hash } => Self::ContentReady { hash },
            crate::docs::engine::LiveEvent::NeighborUp(node) => Self::NeighborUp(node),
            crate::docs::engine::LiveEvent::NeighborDown(node) => Self::NeighborDown(node),
            crate::docs::engine::LiveEvent::SyncFinished(details) => Self::SyncFinished(details),
            crate::docs::engine::LiveEvent::PendingContentReady => Self::PendingContentReady,
        }
    }
}

/// Progress stream for [`Doc::import_file`].
#[derive(derive_more::Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct ImportFileProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<ImportProgress>> + Send + Unpin + 'static>>,
}

impl ImportFileProgress {
    fn new(
        stream: (impl Stream<Item = Result<impl Into<ImportProgress>, impl Into<anyhow::Error>>>
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
    /// Returns a [`ImportFileOutcome`] which contains a tag, key, and hash and the size of the
    /// content.
    pub async fn finish(mut self) -> Result<ImportFileOutcome> {
        let mut entry_size = 0;
        let mut entry_hash = None;
        while let Some(msg) = self.next().await {
            match msg? {
                ImportProgress::Found { size, .. } => {
                    entry_size = size;
                }
                ImportProgress::AllDone { key } => {
                    let hash = entry_hash
                        .context("expected DocImportProgress::IngestDone event to occur")?;
                    let outcome = ImportFileOutcome {
                        hash,
                        key,
                        size: entry_size,
                    };
                    return Ok(outcome);
                }
                ImportProgress::Abort(err) => return Err(err.into()),
                ImportProgress::Progress { .. } => {}
                ImportProgress::IngestDone { hash, .. } => {
                    entry_hash = Some(hash);
                }
            }
        }
        Err(anyhow!("Response stream ended prematurely"))
    }
}

/// Outcome of a [`Doc::import_file`] operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFileOutcome {
    /// The hash of the entry's content
    pub hash: Hash,
    /// The size of the entry
    pub size: u64,
    /// The key of the entry
    pub key: Bytes,
}

impl Stream for ImportFileProgress {
    type Item = Result<ImportProgress>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

/// Progress stream for [`Doc::export_file`].
#[derive(derive_more::Debug)]
pub struct ExportFileProgress {
    #[debug(skip)]
    stream: Pin<Box<dyn Stream<Item = Result<ExportProgress>> + Send + Unpin + 'static>>,
}
impl ExportFileProgress {
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

    /// Returns a [`ExportFileOutcome`] which contains a file path the data was written to and the size of the content.
    pub async fn finish(mut self) -> Result<ExportFileOutcome> {
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
                    let outcome = ExportFileOutcome {
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
pub struct ExportFileOutcome {
    /// The size of the entry
    size: u64,
    /// The path to which the entry was saved
    path: PathBuf,
}

impl Stream for ExportFileProgress {
    type Item = Result<ExportProgress>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
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
        let doc = client.docs().create().await?;

        let res = std::thread::spawn(move || {
            drop(doc);
            drop(node);
        });

        tokio::task::spawn_blocking(move || res.join().map_err(|e| anyhow::anyhow!("{:?}", e)))
            .await??;

        Ok(())
    }

    /// Test that closing a doc does not close other instances.
    #[tokio::test]
    async fn test_doc_close() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let node = crate::node::Node::memory().spawn().await?;
        let author = node.authors().default().await?;
        // open doc two times
        let doc1 = node.docs().create().await?;
        let doc2 = node.docs().open(doc1.id()).await?.expect("doc to exist");
        // close doc1 instance
        doc1.close().await?;
        // operations on doc1 now fail.
        assert!(doc1.set_bytes(author, "foo", "bar").await.is_err());
        // dropping doc1 will close the doc if not already closed
        // wait a bit because the close-on-drop spawns a task for which we cannot track completion.
        drop(doc1);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // operations on doc2 still succeed
        doc2.set_bytes(author, "foo", "bar").await?;
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
        let doc = client.docs().create().await.context("doc create")?;
        let author = client.authors().create().await.context("author create")?;

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
