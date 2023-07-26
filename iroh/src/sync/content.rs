use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use futures::{
    future::{BoxFuture, LocalBoxFuture, Shared},
    stream::FuturesUnordered,
    FutureExt,
};
use iroh_bytes::util::Hash;
use iroh_gossip::net::util::Dialer;
use iroh_io::{AsyncSliceReader, AsyncSliceReaderExt};
use iroh_net::{tls::PeerId, MagicEndpoint};
use iroh_sync::sync::{
    Author, InsertOrigin, Namespace, NamespaceId, OnInsertCallback, Replica, ReplicaStore,
    SignedEntry,
};
use tokio::{
    io::AsyncRead,
    sync::{mpsc, oneshot},
};
use tokio_stream::StreamExt;
use tracing::{debug, error, warn};

use crate::database::flat::{writable::WritableFileDatabase, Database};

#[derive(Debug, Copy, Clone)]
pub enum DownloadMode {
    Always,
    Manual,
}

#[derive(Debug, Clone)]
pub struct DocStore {
    replicas: ReplicaStore,
    blobs: BlobStore,
    local_author: Arc<Author>,
    storage_path: PathBuf,
}

impl DocStore {
    pub fn new(blobs: BlobStore, author: Author, storage_path: PathBuf) -> Self {
        Self {
            replicas: ReplicaStore::default(),
            local_author: Arc::new(author),
            storage_path,
            blobs,
        }
    }

    pub async fn create_or_open(
        &self,
        namespace: Namespace,
        download_mode: DownloadMode,
    ) -> anyhow::Result<Doc> {
        let path = self.replica_path(namespace.id());
        let replica = if path.exists() {
            let bytes = tokio::fs::read(path).await?;
            self.replicas.open_replica(&bytes)?
        } else {
            self.replicas.new_replica(namespace)
        };

        let doc = Doc::new(
            replica,
            self.blobs.clone(),
            self.local_author.clone(),
            download_mode,
        );
        Ok(doc)
    }

    pub async fn save(&self, doc: &Doc) -> anyhow::Result<()> {
        let replica_path = self.replica_path(&doc.replica().namespace());
        tokio::fs::create_dir_all(replica_path.parent().unwrap()).await?;
        let bytes = doc.replica().to_bytes()?;
        tokio::fs::write(replica_path, bytes).await?;
        Ok(())
    }

    fn replica_path(&self, namespace: &NamespaceId) -> PathBuf {
        self.storage_path.join(hex::encode(namespace.as_bytes()))
    }

    pub async fn handle_connection(&self, conn: quinn::Connecting) -> anyhow::Result<()> {
        crate::sync::handle_connection(conn, self.replicas.clone()).await
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
pub struct Doc {
    replica: Replica,
    blobs: BlobStore,
    local_author: Arc<Author>,
}

impl Doc {
    pub fn new(
        replica: Replica,
        blobs: BlobStore,
        local_author: Arc<Author>,
        download_mode: DownloadMode,
    ) -> Self {
        let doc = Self {
            replica,
            blobs,
            local_author,
        };
        if let DownloadMode::Always = download_mode {
            let doc2 = doc.clone();
            doc.replica.on_insert(Box::new(move |origin, entry| {
                if matches!(origin, InsertOrigin::Sync) {
                    doc2.download_content_fron_author(&entry);
                }
            }));
        }
        doc
    }

    pub fn on_insert(&self, callback: OnInsertCallback) {
        self.replica.on_insert(callback);
    }

    pub fn replica(&self) -> &Replica {
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
        self.replica.insert(key, &self.local_author, hash, len);
        Ok((hash, len))
    }

    pub async fn insert_reader(
        &self,
        key: impl AsRef<[u8]>,
        content: impl AsyncRead + Unpin,
    ) -> anyhow::Result<(Hash, u64)> {
        let (hash, len) = self.blobs.put_reader(content).await?;
        self.replica.insert(key, &self.local_author, hash, len);
        Ok((hash, len))
    }

    pub fn download_content_fron_author(&self, entry: &SignedEntry) {
        let hash = *entry.entry().record().content_hash();
        let peer_id = PeerId::from_bytes(entry.entry().id().author().as_bytes())
            .expect("failed to convert author to peer id");
        self.blobs.start_download(hash, peer_id);
    }

    pub async fn get_content_bytes(&self, entry: &SignedEntry) -> Option<Bytes> {
        let hash = entry.entry().record().content_hash();
        let bytes = self.blobs.get_bytes(hash).await.ok().flatten();
        bytes
    }
    pub async fn get_content_reader(&self, entry: &SignedEntry) -> Option<impl AsyncSliceReader> {
        let hash = entry.entry().record().content_hash();
        let bytes = self.blobs.get_reader(hash).await.ok().flatten();
        bytes
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
        &self.db.db()
    }

    pub fn start_download(&self, hash: Hash, peer: PeerId) {
        if !self.db.has(&hash) {
            self.downloader.start_download(hash, peer);
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
    peer: PeerId,
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
    to_actor_tx: mpsc::UnboundedSender<DownloadRequest>,
}

impl Downloader {
    pub fn new(
        rt: iroh_bytes::util::runtime::Handle,
        endpoint: MagicEndpoint,
        blobs: WritableFileDatabase,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
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

    pub fn start_download(&self, hash: Hash, peer: PeerId) {
        let (reply, reply_rx) = oneshot::channel();
        let req = DownloadRequest { hash, peer, reply };
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
        if let Err(err) = self.to_actor_tx.send(req) {
            warn!("download actor dropped: {err}");
        }
    }
}

#[derive(Debug)]
pub struct DownloadActor {
    dialer: Dialer,
    db: WritableFileDatabase,
    conns: HashMap<PeerId, quinn::Connection>,
    replies: HashMap<Hash, VecDeque<DownloadReply>>,
    peer_hashes: HashMap<PeerId, VecDeque<Hash>>,
    hash_peers: HashMap<Hash, HashSet<PeerId>>,
    pending_downloads: FuturesUnordered<
        LocalBoxFuture<'static, (PeerId, Hash, anyhow::Result<Option<(Hash, u64)>>)>,
    >,
    rx: mpsc::UnboundedReceiver<DownloadRequest>,
}
impl DownloadActor {
    fn new(
        endpoint: MagicEndpoint,
        db: WritableFileDatabase,
        rx: mpsc::UnboundedReceiver<DownloadRequest>,
    ) -> Self {
        Self {
            rx,
            db,
            dialer: Dialer::new(endpoint),
            replies: Default::default(),
            conns: Default::default(),
            pending_downloads: Default::default(),
            peer_hashes: Default::default(),
            hash_peers: Default::default(),
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                req = self.rx.recv() => match req {
                    None => return Ok(()),
                    Some(req) => self.on_download_request(req).await
                },
                (peer, conn) = self.dialer.next() => match conn {
                    Ok(conn) => {
                        debug!("connection to {peer} established");
                        self.conns.insert(peer, conn);
                        self.on_peer_ready(peer);
                    },
                    Err(err) => self.on_peer_fail(&peer, err),
                },
                Some((peer, hash, res)) = self.pending_downloads.next() => match res {
                    Ok(Some((hash, size))) => {
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
            reply.send(res.clone()).ok();
        }
    }

    fn on_peer_fail(&mut self, peer: &PeerId, err: anyhow::Error) {
        warn!("download from {peer} failed: {err}");
        for hash in self.peer_hashes.remove(&peer).into_iter().flatten() {
            self.on_not_found(peer, hash);
        }
        self.conns.remove(&peer);
    }

    fn on_not_found(&mut self, peer: &PeerId, hash: Hash) {
        if let Some(peers) = self.hash_peers.get_mut(&hash) {
            peers.remove(&peer);
            if peers.is_empty() {
                self.reply(hash, None);
                self.hash_peers.remove(&hash);
            }
        }
    }

    fn on_peer_ready(&mut self, peer: PeerId) {
        if let Some(hash) = self
            .peer_hashes
            .get_mut(&peer)
            .map(|hashes| hashes.pop_front())
            .flatten()
        {
            let conn = self.conns.get(&peer).unwrap().clone();
            let blobs = self.db.clone();
            let fut = async move { (peer, hash, blobs.download_single(conn, hash).await) };
            self.pending_downloads.push(fut.boxed_local());
        } else {
            self.conns.remove(&peer);
            self.peer_hashes.remove(&peer);
        }
    }

    async fn on_download_request(&mut self, req: DownloadRequest) {
        let DownloadRequest { peer, hash, reply } = req;
        if self.db.has(&hash) {
            let size = self.db.get_size(&hash).await.unwrap();
            reply.send(Some((hash, size))).ok();
            return;
        }
        debug!("queue download {hash} from {peer}");
        self.replies.entry(hash).or_default().push_back(reply);
        self.hash_peers.entry(hash).or_default().insert(peer);
        self.peer_hashes.entry(peer).or_default().push_back(hash);
        if self.conns.get(&peer).is_none() && !self.dialer.is_pending(&peer) {
            self.dialer.queue_dial(peer, &iroh_bytes::protocol::ALPN);
        }
    }
}
