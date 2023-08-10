//! Download queue

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

#[cfg(feature = "metrics")]
use std::time::Instant;

use anyhow::anyhow;
use futures::{
    future::{BoxFuture, LocalBoxFuture, Shared},
    stream::FuturesUnordered,
    FutureExt,
};
use iroh_bytes::{
    baomap::{MapEntry, Store as BaoStore},
    util::{progress::IgnoreProgressSender, Hash},
};
use iroh_gossip::net::util::Dialer;
#[cfg(feature = "metrics")]
use iroh_metrics::{inc, inc_by};
use iroh_net::{tls::PeerId, MagicEndpoint};
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::{debug, error, warn};

#[cfg(feature = "metrics")]
use crate::metrics::Metrics;

/// Future for the completion of a download request
pub type DownloadFuture = Shared<BoxFuture<'static, Option<(Hash, u64)>>>;

/// A download queue for iroh-bytes
///
/// Spawns a background task that handles connecting to peers and performing get requests.
///
// TODO: Support retries and backoff - become a proper queue...
// TODO: Download requests send via synchronous flume::Sender::send. Investigate if we want async
// here. We currently use [`Downloader::push`] from [`iroh_sync::Replica::on_insert`] callbacks,
// which are sync, thus we need a sync method on the Downloader to push new download requests.
// TODO: Support collections, likely become generic over C: CollectionParser
#[derive(Debug, Clone)]
pub struct Downloader {
    pending_downloads: Arc<Mutex<HashMap<Hash, DownloadFuture>>>,
    to_actor_tx: flume::Sender<DownloadRequest>,
}

impl Downloader {
    /// Create a new downloader
    pub fn new<B: BaoStore>(
        rt: iroh_bytes::util::runtime::Handle,
        endpoint: MagicEndpoint,
        db: B,
    ) -> Self {
        let (tx, rx) = flume::bounded(64);
        // spawn the actor on a local pool
        // the local pool is required because WritableFileDatabase::download_single
        // returns a future that is !Send
        rt.local_pool().spawn_pinned(move || async move {
            let mut actor = DownloadActor::new(endpoint, db, rx);
            if let Err(err) = actor.run().await {
                error!("download actor failed with error {err:?}");
            }
        });
        Self {
            pending_downloads: Arc::new(Mutex::new(HashMap::new())),
            to_actor_tx: tx,
        }
    }

    /// Add a new download request to the download queue.
    ///
    /// Note: This method takes only [`PeerId`]s and will attempt to connect to those peers. For
    /// this to succeed, you need to add addresses for these peers to the magic endpoint's
    /// addressbook yourself. See [`MagicEndpoint::add_known_addrs`].
    pub fn push(&self, hash: Hash, peers: Vec<PeerId>) {
        let (reply, reply_rx) = oneshot::channel();
        let req = DownloadRequest { hash, peers, reply };

        // TODO: this is potentially blocking inside an async call. figure out a better solution
        if let Err(err) = self.to_actor_tx.send(req) {
            warn!("download actor dropped: {err}");
        }

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
    }

    /// Returns a future that completes once the blob for `hash` has been downloaded, or all queued
    /// requests for that blob have failed.
    ///
    /// NOTE: This does not start the download itself. Use [`Self::push`] for that.
    pub fn finished(&self, hash: &Hash) -> DownloadFuture {
        match self.pending_downloads.lock().unwrap().get(hash) {
            Some(fut) => fut.clone(),
            None => futures::future::ready(None).boxed().shared(),
        }
    }
}

type DownloadReply = oneshot::Sender<Option<(Hash, u64)>>;
type PendingDownloadsFutures =
    FuturesUnordered<LocalBoxFuture<'static, (PeerId, Hash, anyhow::Result<Option<u64>>)>>;

#[derive(Debug)]
struct DownloadRequest {
    hash: Hash,
    peers: Vec<PeerId>,
    reply: DownloadReply,
}

#[derive(Debug)]
struct DownloadActor<B> {
    dialer: Dialer,
    db: B,
    conns: HashMap<PeerId, quinn::Connection>,
    replies: HashMap<Hash, VecDeque<DownloadReply>>,
    pending_download_futs: PendingDownloadsFutures,
    queue: DownloadQueue,
    rx: flume::Receiver<DownloadRequest>,
}
impl<B: BaoStore> DownloadActor<B> {
    fn new(endpoint: MagicEndpoint, db: B, rx: flume::Receiver<DownloadRequest>) -> Self {
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
                        debug!(peer = ?peer, "connection established");
                        self.conns.insert(peer, conn);
                        self.on_peer_ready(peer);
                    },
                    Err(err) => self.on_peer_fail(&peer, err),
                },
                Some((peer, hash, res)) = self.pending_download_futs.next() => match res {
                    Ok(Some(size)) => {
                        self.queue.on_success(hash, peer);
                        self.reply(hash, Some((hash, size)));
                        self.on_peer_ready(peer);
                    }
                    Ok(None) => {
                        // TODO: This case is currently never reached, because iroh::get::get_blob
                        // doesn't return an option but only a result, with no way (AFAICS) to discern
                        // between connection error and not found.
                        // self.on_not_found(&peer, hash);
                        // self.on_peer_ready(peer);
                        unreachable!()
                    }
                    Err(_err) => {
                        self.on_not_found(&peer, hash);
                        self.on_peer_ready(peer);
                        // TODO: In case of connection errors or similar we want to call
                        // on_peer_fail to not continue downloading from this peer.
                        // Currently however a "not found" is also an error, thus calling
                        // on_peer_fail would stop trying to get other hashes from this peer.
                        // This likely needs fixing in iroh::get::get to have a meaningful error to
                        // see if the connection failed or if it's just a "not found".
                        // self.on_peer_fail(&peer, err),
                    }
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
        warn!("download from {peer} failed: {err:?}");
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
            debug!(peer = ?peer, hash = ?hash, "on_peer_ready: get next");
            self.start_download_unchecked(peer, hash);
        } else {
            debug!(peer = ?peer, "on_peer_ready: nothing left, disconnect");
            self.conns.remove(&peer);
        }
    }

    fn start_download_unchecked(&mut self, peer: PeerId, hash: Hash) {
        let conn = self.conns.get(&peer).unwrap().clone();
        let db = self.db.clone();
        let progress_sender = IgnoreProgressSender::default();

        let fut = async move {
            debug!(peer = ?peer, hash = ?hash, "start download");

            #[cfg(feature = "metrics")]
            let start = Instant::now();

            // TODO: None for not found instead of error
            let res = crate::get::get_blob(&db, conn, &hash, progress_sender).await;
            let res = res.and_then(|_stats| {
                db.get(&hash)
                    .ok_or_else(|| anyhow!("downloaded blob not found in store"))
                    .map(|entry| Some(entry.size()))
            });
            debug!(peer = ?peer, hash = ?hash, "finish download: {res:?}");

            // record metrics
            #[cfg(feature = "metrics")]
            {
                let elapsed = start.elapsed().as_millis();
                match &res {
                    Ok(Some(len)) => {
                        inc!(Metrics, downloads_success);
                        inc_by!(Metrics, download_bytes_total, *len);
                        inc_by!(Metrics, download_time_total, elapsed as u64);
                    }
                    Ok(None) => inc!(Metrics, downloads_notfound),
                    Err(_) => inc!(Metrics, downloads_error),
                }
            }

            (peer, hash, res)
        };
        self.pending_download_futs.push(fut.boxed_local());
    }

    async fn on_download_request(&mut self, req: DownloadRequest) {
        let DownloadRequest { peers, hash, reply } = req;
        if let Some(entry) = self.db.get(&hash) {
            let size = entry.size();
            reply.send(Some((hash, size))).ok();
            return;
        }
        self.replies.entry(hash).or_default().push_back(reply);
        for peer in peers {
            debug!(peer = ?peer, hash = ?hash, "queue download");
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
            Some(hash)
        } else {
            None
        }
    }

    pub fn has_no_candidates(&self, hash: &Hash) -> bool {
        self.candidates_by_hash.get(hash).is_none() && self.running_by_hash.get(hash).is_none()
    }

    /// Mark a download as successfull.
    pub fn on_success(&mut self, hash: Hash, peer: PeerId) {
        let peer2 = self.running_by_hash.remove(&hash);
        debug_assert_eq!(peer2, Some(peer));
        self.running_by_peer.remove(&peer);
        self.candidates_by_hash.remove(&hash);
        for hashes in self.candidates_by_peer.values_mut() {
            hashes.retain(|h| h != &hash);
        }
        self.ensure_no_empty(hash, peer);
    }

    /// To be called when a peer failed (i.e. disconnected).
    ///
    /// Returns a list of hashes that have no other peers queue. Those hashes should thus be
    /// considered failed.
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
        if let Some(hash) = self.running_by_peer.remove(peer) {
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
