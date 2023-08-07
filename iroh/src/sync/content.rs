use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use bytes::Bytes;
use iroh_bytes::util::Hash;
use iroh_io::{AsyncSliceReader, AsyncSliceReaderExt};
use iroh_metrics::{inc, inc_by};
use iroh_net::{tls::PeerId, MagicEndpoint};
use iroh_sync::{
    store::{self, Store as _},
    sync::{Author, InsertOrigin, Namespace, OnInsertCallback, PeerIdBytes, Replica, SignedEntry},
};
use tokio::io::AsyncRead;

use super::metrics::Metrics;
use crate::{
    database::flat::{writable::WritableFileDatabase, Database},
    download::Downloader,
};

#[derive(Debug, Copy, Clone)]
pub enum DownloadMode {
    Always,
    Manual,
}

#[derive(Debug, Clone)]
pub struct DocStore {
    replicas: store::fs::Store,
    blobs: BlobStore,
    local_author: Arc<Author>,
}

const REPLICA_DB_NAME: &str = "replica.db";

impl DocStore {
    pub fn new(blobs: BlobStore, author: Author, storage_path: PathBuf) -> Result<Self> {
        let replicas = store::fs::Store::new(storage_path.join(REPLICA_DB_NAME))?;

        Ok(Self {
            replicas,
            local_author: Arc::new(author),
            blobs,
        })
    }

    pub async fn create_or_open(
        &self,
        namespace: Namespace,
        download_mode: DownloadMode,
    ) -> Result<Doc<store::fs::Store>> {
        let replica = match self.replicas.get_replica(&namespace.id())? {
            Some(replica) => replica,
            None => self.replicas.new_replica(namespace)?,
        };

        let doc = Doc::new(
            replica,
            self.blobs.clone(),
            self.local_author.clone(),
            download_mode,
        );
        Ok(doc)
    }

    pub async fn handle_connection(&self, conn: quinn::Connecting) -> anyhow::Result<()> {
        crate::sync::handle_connection(conn, self.replicas.clone()).await
    }

    pub fn store(&self) -> &store::fs::Store {
        &self.replicas
    }
}

/// A replica with a [`BlobStore`] for contents.
///
/// This will also download missing content from peers.
///
/// TODO: Currently content is only downloaded from the author of a entry.
/// We want to try other peers if the author is offline (or always).
/// We'll need some heuristics which peers to try.
///
/// TODO: remove
#[derive(Clone, Debug)]
pub struct Doc<S: store::Store> {
    replica: Replica<S::Instance>,
    blobs: BlobStore,
    local_author: Arc<Author>,
}

impl<S: store::Store> Doc<S> {
    pub fn new(
        replica: Replica<S::Instance>,
        blobs: BlobStore,
        local_author: Arc<Author>,
        download_mode: DownloadMode,
    ) -> Self {
        let doc = Self {
            replica,
            blobs,
            local_author,
        };

        // If download mode is set to always download:
        // setup on_insert callback to trigger download on remote insert
        if let DownloadMode::Always = download_mode {
            let doc_clone = doc.clone();
            doc.replica
                .on_insert(Box::new(move |origin, entry| match origin {
                    InsertOrigin::Sync(peer) => {
                        doc_clone.download_content_from_author_and_other_peer(&entry, peer);
                    }
                    InsertOrigin::Local => {}
                }));
        }

        // Collect metrics
        doc.replica.on_insert(Box::new(move |origin, entry| {
            let size = entry.entry().record().content_len();
            match origin {
                InsertOrigin::Local => {
                    inc!(Metrics, new_entries_local);
                    inc_by!(Metrics, new_entries_local_size, size);
                }
                InsertOrigin::Sync(_) => {
                    inc!(Metrics, new_entries_remote);
                    inc_by!(Metrics, new_entries_remote_size, size);
                }
            }
        }));

        doc
    }

    pub fn on_insert(&self, callback: OnInsertCallback) {
        self.replica.on_insert(callback);
    }

    pub fn replica(&self) -> &Replica<S::Instance> {
        &self.replica
    }

    pub fn local_author(&self) -> &Author {
        &self.local_author
    }

    pub async fn insert_bytes(
        &self,
        key: impl AsRef<[u8]>,
        content: Bytes,
    ) -> anyhow::Result<(Hash, u64)> {
        let (hash, len) = self.blobs.put_bytes(content).await?;
        self.replica
            .insert(key, &self.local_author, hash, len)
            .map_err(Into::into)?;
        Ok((hash, len))
    }

    pub async fn insert_reader(
        &self,
        key: impl AsRef<[u8]>,
        content: impl AsyncRead + Unpin,
    ) -> anyhow::Result<(Hash, u64)> {
        let (hash, len) = self.blobs.put_reader(content).await?;
        self.replica
            .insert(key, &self.local_author, hash, len)
            .map_err(Into::into)?;
        Ok((hash, len))
    }

    pub async fn insert_from_file(
        &self,
        key: impl AsRef<[u8]>,
        file_path: impl AsRef<Path>,
    ) -> anyhow::Result<(Hash, u64)> {
        let reader = tokio::fs::File::open(&file_path).await?;
        self.insert_reader(&key, reader).await
    }

    pub fn download_content_from_author_and_other_peer(
        &self,
        entry: &SignedEntry,
        other_peer: Option<PeerIdBytes>,
    ) {
        let author_peer_id = PeerId::from_bytes(entry.entry().id().author().as_bytes())
            .expect("failed to convert author to peer id");

        let mut peers = vec![author_peer_id];

        if let Some(other_peer) = other_peer {
            let other_peer_id =
                PeerId::from_bytes(&other_peer).expect("failed to convert author to peer id");
            if other_peer_id != peers[0] {
                peers.push(other_peer_id);
            }
        }

        let hash = *entry.entry().record().content_hash();
        self.blobs.start_download(hash, peers);
    }

    pub async fn get_content_bytes(&self, entry: &SignedEntry) -> Option<Bytes> {
        let hash = entry.entry().record().content_hash();
        self.blobs.get_bytes(hash).await.ok().flatten()
    }

    pub async fn get_content_reader(&self, entry: &SignedEntry) -> Option<impl AsyncSliceReader> {
        let hash = entry.entry().record().content_hash();
        self.blobs.get_reader(hash).await.ok().flatten()
    }
}

/// A blob database that can download missing blobs from peers.
///
/// Blobs can be inserted either from bytes or by downloading from peers.
/// Downloads can be started and will be tracked in the blobstore.
/// New blobs will be saved as files with a filename based on their hash.
///
/// TODO: This is similar to what is used in the iroh provider.
/// Unify once we know how the APIs should look like.
#[derive(Debug, Clone)]
pub struct BlobStore {
    db: WritableFileDatabase,
    downloader: Downloader,
}
impl BlobStore {
    pub async fn new(
        rt: iroh_bytes::util::runtime::Handle,
        data_path: PathBuf,
        endpoint: MagicEndpoint,
    ) -> anyhow::Result<Self> {
        let db = WritableFileDatabase::new(data_path).await?;
        let downloader = Downloader::new(rt, endpoint, db.clone());
        Ok(Self { db, downloader })
    }

    pub async fn save(&self) -> io::Result<()> {
        self.db.save().await
    }

    pub fn db(&self) -> &Database {
        self.db.db()
    }

    pub fn start_download(&self, hash: Hash, peers: Vec<PeerId>) {
        if !self.db.has(&hash) {
            self.downloader.push(hash, peers);
        }
    }

    pub async fn get_bytes(&self, hash: &Hash) -> anyhow::Result<Option<Bytes>> {
        self.downloader.finished(hash).await;
        let Some(entry) = self.db().get(hash) else {
            return Ok(None)
        };
        let bytes = entry.data_reader().await?.read_to_end().await?;
        Ok(Some(bytes))
    }

    pub async fn get_reader(&self, hash: &Hash) -> anyhow::Result<Option<impl AsyncSliceReader>> {
        self.downloader.finished(hash).await;
        let Some(entry) = self.db().get(hash) else {
            return Ok(None)
        };
        let reader = entry.data_reader().await?;
        Ok(Some(reader))
    }

    pub async fn put_bytes(&self, data: Bytes) -> anyhow::Result<(Hash, u64)> {
        self.db.put_bytes(data).await
    }

    pub async fn put_reader(&self, data: impl AsyncRead + Unpin) -> anyhow::Result<(Hash, u64)> {
        self.db.put_reader(data).await
    }
}
