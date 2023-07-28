use std::{
    collections::{HashMap, VecDeque},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::Result;
use bytes::Bytes;
use futures::{
    future::{BoxFuture, LocalBoxFuture, Shared},
    stream::FuturesUnordered,
    FutureExt,
};
use iroh_bytes::util::Hash;
use iroh_gossip::net::util::Dialer;
use iroh_io::{AsyncSliceReader, AsyncSliceReaderExt};
use iroh_metrics::{inc, inc_by};
use iroh_net::{tls::PeerId, MagicEndpoint};
use iroh_sync::{
    store::{self, Store as _},
    sync::{Author, InsertOrigin, Namespace, OnInsertCallback, PeerIdBytes, Replica, SignedEntry},
};
use tokio::{io::AsyncRead, sync::oneshot};
use tokio_stream::StreamExt;
use tracing::{debug, error, warn};

use super::metrics::Metrics;
use crate::database::flat::{writable::WritableFileDatabase, Database};

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
            self.downloader.start_download(hash, peers);
        }
    }

    pub async fn get_bytes(&self, hash: &Hash) -> anyhow::Result<Option<Bytes>> {
        self.downloader.wait_for_download(hash).await;
        let Some(entry) = self.db().get(hash) else {
            return Ok(None)
        };
        let bytes = entry.data_reader().await?.read_to_end().await?;
        Ok(Some(bytes))
    }

    pub async fn get_reader(&self, hash: &Hash) -> anyhow::Result<Option<impl AsyncSliceReader>> {
        self.downloader.wait_for_download(hash).await;
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

pub type DownloadReply = oneshot::Sender<Option<(Hash, u64)>>;
pub type DownloadFuture = Shared<BoxFuture<'static, Option<(Hash, u64)>>>;

#[derive(Debug)]
pub struct DownloadRequest {
    hash: Hash,
    peers: Vec<PeerId>,
    reply: DownloadReply,
}

/// A download queue
///
/// Spawns a background task that handles connecting to peers and performing get requests.
///
/// TODO: Queued downloads are pushed into an unbounded channel. Maybe make it bounded instead.
/// We want the start_download() method to be sync though because it is used
/// from sync on_insert callbacks on the replicas.
/// TODO: Move to iroh-bytes or replace with corresponding feature from iroh-bytes once available
#[derive(Debug, Clone)]
pub struct Downloader {
    pending_downloads: Arc<Mutex<HashMap<Hash, DownloadFuture>>>,
    to_actor_tx: flume::Sender<DownloadRequest>,
}

impl Downloader {
    pub fn new(
        rt: iroh_bytes::util::runtime::Handle,
        endpoint: MagicEndpoint,
        blobs: WritableFileDatabase,
    ) -> Self {
        let (tx, rx) = flume::bounded(64);
        // spawn the actor on a local pool
        // the local pool is required because WritableFileDatabase::download_single
        // returns a future that is !Send
        rt.local_pool().spawn_pinned(move || async move {
            let mut actor = DownloadActor::new(endpoint, blobs, rx);
            if let Err(err) = actor.run().await {
                error!("download actor failed with error {err:?}");
            }
        });
        Self {
            pending_downloads: Arc::new(Mutex::new(HashMap::new())),
            to_actor_tx: tx,
        }
    }

    pub fn wait_for_download(&self, hash: &Hash) -> DownloadFuture {
        match self.pending_downloads.lock().unwrap().get(hash) {
            Some(fut) => fut.clone(),
            None => futures::future::ready(None).boxed().shared(),
        }
    }

    pub fn start_download(&self, hash: Hash, peers: Vec<PeerId>) {
        let (reply, reply_rx) = oneshot::channel();
        let req = DownloadRequest { hash, peers, reply };
        if self.pending_downloads.lock().unwrap().get(&hash).is_none() {
            let pending_downloads = self.pending_downloads.clone();
            let fut = async move {
                let res = reply_rx.await;
                pending_downloads.lock().unwrap().remove(&hash);
                res.ok().flatten()
            };
            self.pending_downloads
                .lock()
                .unwrap()
                .insert(hash, fut.boxed().shared());
        }
        // TODO: this is potentially blocking inside an async call. figure out a better solution
        if let Err(err) = self.to_actor_tx.send(req) {
            warn!("download actor dropped: {err}");
        }
    }
}

type PendingDownloadsFutures =
    FuturesUnordered<LocalBoxFuture<'static, (PeerId, Hash, anyhow::Result<Option<(Hash, u64)>>)>>;

#[derive(Debug)]
pub struct DownloadActor {
    dialer: Dialer,
    db: WritableFileDatabase,
    conns: HashMap<PeerId, quinn::Connection>,
    replies: HashMap<Hash, VecDeque<DownloadReply>>,
    pending_download_futs: PendingDownloadsFutures,
    queue: DownloadQueue,
    rx: flume::Receiver<DownloadRequest>,
}
impl DownloadActor {
    fn new(
        endpoint: MagicEndpoint,
        db: WritableFileDatabase,
        rx: flume::Receiver<DownloadRequest>,
    ) -> Self {
        Self {
            rx,
            db,
            dialer: Dialer::new(endpoint),
            replies: Default::default(),
            conns: Default::default(),
            pending_download_futs: Default::default(),
            queue: Default::default(),
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                req = self.rx.recv_async() => match req {
                    Err(_) => return Ok(()),
                    Ok(req) => self.on_download_request(req).await
                },
                (peer, conn) = self.dialer.next() => match conn {
                    Ok(conn) => {
                        debug!("connection to {peer} established");
                        self.conns.insert(peer, conn);
                        self.on_peer_ready(peer);
                    },
                    Err(err) => self.on_peer_fail(&peer, err),
                },
                Some((peer, hash, res)) = self.pending_download_futs.next() => match res {
                    Ok(Some((hash, size))) => {
                        self.queue.on_success(hash, peer);
                        self.reply(hash, Some((hash, size)));
                        self.on_peer_ready(peer);
                    }
                    Ok(None) => {
                        self.on_not_found(&peer, hash);
                        self.on_peer_ready(peer);
                    }
                    Err(err) => self.on_peer_fail(&peer, err),
                }
            }
        }
    }

    fn reply(&mut self, hash: Hash, res: Option<(Hash, u64)>) {
        for reply in self.replies.remove(&hash).into_iter().flatten() {
            reply.send(res).ok();
        }
    }

    fn on_peer_fail(&mut self, peer: &PeerId, err: anyhow::Error) {
        warn!("download from {peer} failed: {err}");
        for hash in self.queue.on_peer_fail(peer) {
            self.reply(hash, None);
        }
        self.conns.remove(peer);
    }

    fn on_not_found(&mut self, peer: &PeerId, hash: Hash) {
        self.queue.on_not_found(hash, *peer);
        if self.queue.has_no_candidates(&hash) {
            self.reply(hash, None);
        }
    }

    fn on_peer_ready(&mut self, peer: PeerId) {
        if let Some(hash) = self.queue.try_next_for_peer(peer) {
            self.start_download_unchecked(peer, hash);
        } else {
            self.conns.remove(&peer);
        }
    }

    fn start_download_unchecked(&mut self, peer: PeerId, hash: Hash) {
        let conn = self.conns.get(&peer).unwrap().clone();
        let blobs = self.db.clone();
        let fut = async move {
            let start = Instant::now();
            let res = blobs.download_single(conn, hash).await;
            // record metrics
            let elapsed = start.elapsed().as_millis();
            match &res {
                Ok(Some((_hash, len))) => {
                    inc!(Metrics, downloads_success);
                    inc_by!(Metrics, download_bytes_total, *len);
                    inc_by!(Metrics, download_time_total, elapsed as u64);
                }
                Ok(None) => inc!(Metrics, downloads_notfound),
                Err(_) => inc!(Metrics, downloads_error),
            }
            (peer, hash, res)
        };
        self.pending_download_futs.push(fut.boxed_local());
    }

    async fn on_download_request(&mut self, req: DownloadRequest) {
        let DownloadRequest { peers, hash, reply } = req;
        if self.db.has(&hash) {
            let size = self.db.get_size(&hash).await.unwrap();
            reply.send(Some((hash, size))).ok();
            return;
        }
        self.replies.entry(hash).or_default().push_back(reply);
        for peer in peers {
            self.queue.push_candidate(hash, peer);
            // TODO: Don't dial all peers instantly.
            if self.conns.get(&peer).is_none() && !self.dialer.is_pending(&peer) {
                self.dialer.queue_dial(peer, &iroh_bytes::protocol::ALPN);
            }
        }
    }
}

#[derive(Debug, Default)]
struct DownloadQueue {
    candidates_by_hash: HashMap<Hash, VecDeque<PeerId>>,
    candidates_by_peer: HashMap<PeerId, VecDeque<Hash>>,
    running_by_hash: HashMap<Hash, PeerId>,
    running_by_peer: HashMap<PeerId, Hash>,
}

impl DownloadQueue {
    pub fn push_candidate(&mut self, hash: Hash, peer: PeerId) {
        self.candidates_by_hash
            .entry(hash)
            .or_default()
            .push_back(peer);
        self.candidates_by_peer
            .entry(peer)
            .or_default()
            .push_back(hash);
    }

    pub fn try_next_for_peer(&mut self, peer: PeerId) -> Option<Hash> {
        let mut next = None;
        for (idx, hash) in self.candidates_by_peer.get(&peer)?.iter().enumerate() {
            if !self.running_by_hash.contains_key(hash) {
                next = Some((idx, *hash));
                break;
            }
        }
        if let Some((idx, hash)) = next {
            self.running_by_hash.insert(hash, peer);
            self.running_by_peer.insert(peer, hash);
            self.candidates_by_peer.get_mut(&peer).unwrap().remove(idx);
            if let Some(peers) = self.candidates_by_hash.get_mut(&hash) {
                peers.retain(|p| p != &peer);
            }
            self.ensure_no_empty(hash, peer);
            return Some(hash);
        } else {
            None
        }
    }

    pub fn has_no_candidates(&self, hash: &Hash) -> bool {
        self.candidates_by_hash.get(hash).is_none() && self.running_by_hash.get(&hash).is_none()
    }

    pub fn on_success(&mut self, hash: Hash, peer: PeerId) -> Option<(PeerId, Hash)> {
        let peer2 = self.running_by_hash.remove(&hash);
        debug_assert_eq!(peer2, Some(peer));
        self.running_by_peer.remove(&peer);
        self.try_next_for_peer(peer).map(|hash| (peer, hash))
    }

    pub fn on_peer_fail(&mut self, peer: &PeerId) -> Vec<Hash> {
        let mut failed = vec![];
        for hash in self
            .candidates_by_peer
            .remove(peer)
            .map(|hashes| hashes.into_iter())
            .into_iter()
            .flatten()
        {
            if let Some(peers) = self.candidates_by_hash.get_mut(&hash) {
                peers.retain(|p| p != peer);
                if peers.is_empty() && self.running_by_hash.get(&hash).is_none() {
                    failed.push(hash);
                }
            }
        }
        if let Some(hash) = self.running_by_peer.remove(&peer) {
            self.running_by_hash.remove(&hash);
            if self.candidates_by_hash.get(&hash).is_none() {
                failed.push(hash);
            }
        }
        failed
    }

    pub fn on_not_found(&mut self, hash: Hash, peer: PeerId) {
        let peer2 = self.running_by_hash.remove(&hash);
        debug_assert_eq!(peer2, Some(peer));
        self.running_by_peer.remove(&peer);
        self.ensure_no_empty(hash, peer);
    }

    fn ensure_no_empty(&mut self, hash: Hash, peer: PeerId) {
        if self
            .candidates_by_peer
            .get(&peer)
            .map_or(false, |hashes| hashes.is_empty())
        {
            self.candidates_by_peer.remove(&peer);
        }
        if self
            .candidates_by_hash
            .get(&hash)
            .map_or(false, |peers| peers.is_empty())
        {
            self.candidates_by_hash.remove(&hash);
        }
    }
}

#[cfg(test)]
mod test {}
