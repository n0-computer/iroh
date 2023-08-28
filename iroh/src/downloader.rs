//! Handle downloading blobs and collections concurrently and from multiple peers.
//!
//! The [`Service`] interacts with five main components to this end.
//! - [`Dialer`]: Used to queue opening connection to peers we need perform downloads.
//! - [`AvailabilityRegistry`]: Where the downloader obtains information about peers that could be
//!   used to perform a download.
//! - [`Store`]: Where data is stored.
//! - [`CollectionParser`]: Used by the [`GetRequest`] associated logic to identify blobs encoding
//!   collections.
//!
//! Once a download request is recevied, the logic is as follows:
//! 1. The [`AvailabilityRegistry`] is queried for peers. From these peers some are selected
//!    priorizing connected peers with lower number of active requests. If no useful peer is
//!    connected, or useful connected peers have no capacity to perform the request, a connection
//!    attempt is started using the [`Dialer`].
//! 2. The download is queued for processing at a later time. Downloads are not performed right
//!    away. Instead, they are initially delayed to allow the peer to obtain the data itself, and
//!    to wait for the new connection to be established if necessary.
//! 3. Once a request is ready to be sent after a delay (initial or for a retry), the preferred
//!    peer is used if available. The request is now considered active.
//!
//! Concurrency is limited in different ways:
//! - *Total number of active request:* This is a way to prevent a self DoS by overwhelming our own
//!   bandwith capacity. This is a best effort heuristic since it doesn't take into account how
//!   much data we are actually requesting ort receiving.
//! - *Total number of connected peers:* Peer connections are kept for a longer time than they are
//!   strictly needed since it's likely they will be usefull soon again.
//! - *Requests per peer*: to avoid overwhelming peers with requests, the number of concurrent
//!   requests to a single peer is also limited.

#![allow(clippy::all, unused, missing_docs)]

use std::{
    collections::{hash_map::Entry, HashMap},
    task::Poll::{Pending, Ready},
};

use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use iroh_bytes::{
    baomap::{range_collections::RangeSet2, Store},
    collection::CollectionParser,
    protocol::{RangeSpec, RangeSpecSeq},
    Hash,
};
use iroh_gossip::net::util::Dialer;
use iroh_net::key::PublicKey;
use tokio::sync::{mpsc, oneshot};
use tokio_util::{sync::CancellationToken, time::delay_queue};
use tracing::{debug, error, info, trace, warn};

/// Download identifier.
// Mainly for readability.
pub type Id = u64;

pub trait AvailabilityRegistry {
    type CandidateIter<'a>: Iterator<Item = &'a PublicKey>
    where
        Self: 'a;
    fn get_candidates(&self, hash: &Hash) -> Self::CandidateIter<'_>;
}

/// Concurrency limits for the [`Service`].
#[derive(Debug)]
pub struct ConcurrencyLimits {
    /// Maximum number of requests the service performs concurrently.
    max_concurrent_requests: usize,
    /// Maximum number of requests performed by a single peer concurrently.
    max_concurrent_requests_per_peer: usize,
    /// Maximum number of open connections the service maintains.
    max_open_connections: usize,
}

/// Download requests the [`Downloader`] handles.
#[derive(Debug)]
pub enum Download {
    /// Download a single blob entirely.
    Blob {
        /// Blob to be downloaded.
        hash: Hash,
    },
    /// Download ranges of a blob.
    BlobRanges {
        /// Blob to be downloaded.
        hash: Hash,
        /// Ranges to be downloaded from this blob.
        range_set: RangeSpec,
    },
    /// Download a collection entirely.
    Collection {
        /// Blob to be downloaded.
        hash: Hash,
    },
    /// Download ranges of a collection.
    CollectionRanges {
        /// Blob to be downloaded.
        hash: Hash,
        /// Sequence of ranges to be downloaded from this collection.
        range_set_seq: RangeSpecSeq,
    },
}

impl Download {
    /// Get the requested hash.
    const fn hash(&self) -> &Hash {
        match self {
            Download::Blob { hash }
            | Download::BlobRanges { hash, .. }
            | Download::Collection { hash }
            | Download::CollectionRanges { hash, .. } => hash,
        }
    }

    /// Get the ranges this download is requesting.
    fn ranges(&self) -> RangeSpecSeq {
        match self {
            Download::Blob { .. } => RangeSpecSeq::from_ranges([RangeSet2::all()]),
            Download::BlobRanges { range_set, .. } => {
                RangeSpecSeq::from_ranges([range_set.to_chunk_ranges()])
            }
            Download::Collection { hash } => RangeSpecSeq::all(),
            Download::CollectionRanges {
                hash,
                range_set_seq,
            } => range_set_seq.clone(),
        }
    }
}

// TODO(@divma): mot likely drop this. Useful for now
#[derive(Debug)]
pub enum DownloadResult {
    Success,
    Failed,
}

/// Kind of sources that canm be used to perform a download.
// TODO(@divma): likely we will end up using only onme of these. Curiously, I'm not sure which is
// more ilkely
#[derive(Debug)]
pub enum Source {
    /// Perform the download from any available source.
    ///
    /// Sources can be added via [`Downloader::add_source`] with [`DownloadHandle::id`].
    // TODO(@divma): do we want to add an optional initial source?
    // - we want. Maybe this saves a subsequent, awkward call to `add_source`
    // - we don't want. Whatever discovery mechanism we have will be asked and the optional initial
    // source should be registered there. If the sources registry has no peer for this download
    // then the download fails without more retries. Reasoning behind this would be that there is
    // no way to know when to check again for sources for this download.
    // both options sound likely/reasonable
    Available,
    /// Perform the download only from sources registered for the request.
    ///
    /// Sources can be added via [`Downloader::add_source`] with [`DownloadHandle::id`].
    Specific {
        // TODO(@divma): what are we supposed to call this now?
        source_key: PublicKey,
    },
}

/// Handle to interact with a download request.
#[derive(Debug)]
pub struct DownloadHandle {
    /// Id used to identify the request in the [`Downloader`].
    id: u64,
    /// Receiver to retrieve the return value of this download.
    receiver: oneshot::Receiver<DownloadResult>,
}

impl std::future::Future for DownloadHandle {
    type Output = DownloadResult;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll::*;
        // make it easier on holders of the handle to poll the result, removing the receiver error
        // from the middle
        match self.receiver.poll_unpin(cx) {
            Ready(Ok(result)) => Ready(result),
            Ready(Err(_recv_err)) => Ready(DownloadResult::Failed),
            Pending => Pending,
        }
    }
}

#[derive(Debug)]
pub struct Downloader;

#[derive(Debug)]
struct DownloadInfo {
    /// Kind of download we are performing. This maintains the intent as registerd with the
    /// downloader.
    // NOTE: this is useful and necessary because the wire request associated to a download will be
    // different in different instants depending on what local data we already have
    kind: Download,
    /// How many times can this request be attempted again before declearing it failed.
    // TODO(@divma): we likely want to distinguish between io/transport errors and unexpected
    // conditions/miss-behaviours such as the source not having the requested data, decoding
    // errors, etc. Transport errors could allow for more attempts than serious errors such as the
    // source sending that that can't be decoded, or not having the requested data.
    remaining_retries: u8,
    /// oneshot to return the download result back to the requester.
    // TODO(@divma): download futures return the id of the intent they belong to so that it can be
    // removed afterwards.
    // problem with this is that a download future could relate to multiple intents. And in the
    // future one intent can have multiple download futures if we paralelize large collection
    // downloads.
    sender: oneshot::Sender<DownloadResult>,
}

enum Message {
    Start {
        kind: Download,
        id: Id,
        sender: oneshot::Sender<DownloadResult>,
    },
    Cancel {
        id: Id,
    },
}

/// Information about a request.
#[derive(Debug)]
struct RequestInfo {
    /// Ids of intents ([`Download`]) associated with this request.
    intents: Vec<Id>,
    /// State of the request.
    state: RequestState,
}

#[derive(derive_more::Debug)]
enum RequestState {
    /// Request has not yet started.
    Scheduled {
        /// Key to manage the delay associated with this scheduled request.
        #[debug(skip)]
        delay_key: delay_queue::Key,
        /// If this attempt was scheduled with a known potential peer, this is stored here to
        /// prevent another query to the [`AvailabilityRegistry`].
        next_peer: Option<PublicKey>,
    },
    /// Request is underway.
    Active {
        /// Token used to cancel the future doing the request.
        #[debug(skip)]
        cancellation: CancellationToken,
    },
}

/// Information about a connected peer.
#[derive(derive_more::Debug)]
struct PeerInfo {
    /// Connection to this peer.
    #[debug(skip)]
    connection: quinn::Connection,
    /// Number of active requests this peer is performing for us.
    // TODO(@divma): unsure if we want to keep track of the specific ids for this requests
    active_requests: usize,
    /// Number of requests scheduled for this peer.
    scheduled_requests: usize,
}
impl PeerInfo {
    fn new(connection: quinn::Connection) -> PeerInfo {
        PeerInfo {
            connection,
            active_requests: 0,
            scheduled_requests: 0,
        }
    }
}

/// Type of future that performs a download request.
type DownloadFut = BoxFuture<'static, (Hash, RangeSpecSeq, DownloadResult)>;

#[derive(Debug)]
struct Service<S, C, R> {
    /// The store to which data is downloaded.
    store: S,
    /// Parser to idenfity blobs encoding collections.
    collection_parser: C,
    /// Registry to query for peers that we believe have the data we are looking for.
    availabiliy_registry: R,
    /// Dialer to get connections for required peers.
    dialer: Dialer,
    /// Limits to concurrent tasks handled by the service.
    concurrency_limits: ConcurrencyLimits,
    /// Channel to receive messages from the service's handle.
    msg_rx: mpsc::Receiver<Message>,
    /// Available peers to use and their relevant information.
    peers: HashMap<PublicKey, PeerInfo>,
    /// Download requests as received by the [`Downloader`]. These requests might be underway or
    /// pending.
    registered_intents: HashMap<Id, DownloadInfo>,
    /// Requests performed for download intents. Two download requests can produce the same
    /// request. This map allows deduplication of efforts. These requests might be underway or
    /// pending.
    current_requests: HashMap<(Hash, RangeSpecSeq), RequestInfo>,
    /// Queue of scheduled requests.
    scheduled_requests: delay_queue::DelayQueue<(Hash, RangeSpecSeq)>,
    /// Downloads underway.
    in_progress_downloads: FuturesUnordered<DownloadFut>,
}

impl<S: Store, C: CollectionParser, R: AvailabilityRegistry> Service<S, C, R> {
    fn new(
        store: S,
        collection_parser: C,
        availabiliy_registry: R,
        endpoint: iroh_net::MagicEndpoint,
        concurrency_limits: ConcurrencyLimits,
        msg_rx: mpsc::Receiver<Message>,
    ) -> Self {
        let dialer = Dialer::new(endpoint);
        Service {
            store,
            collection_parser,
            availabiliy_registry,
            dialer,
            concurrency_limits,
            msg_rx,
            peers: HashMap::default(),
            registered_intents: HashMap::default(),
            current_requests: HashMap::default(),
            scheduled_requests: delay_queue::DelayQueue::default(),
            in_progress_downloads: FuturesUnordered::default(),
        }
    }

    async fn run(mut self) {
        loop {
            // check if we have capacity to dequeue another scheduled request
            let at_capacity = self.at_request_capacity();
            tokio::select! {
                (peer, conn_result) = self.dialer.next() => {
                    self.on_connection_ready(peer, conn_result);
                }
                maybe_msg = self.msg_rx.recv() => {
                    match maybe_msg {
                        Some(msg) => self.handle_message(msg),
                        None => return self.shutdown(),
                    }
                }
                Some((hash, ranges, result)) = self.in_progress_downloads.next() => {
                    self.on_download_completed(hash, ranges, result);
                }
                Some(expired) = self.scheduled_requests.next(), if !at_capacity => {
                    let (hash, ranges) = expired.into_inner();
                    self.on_scheduled_request_ready(hash, ranges);
                }
            }
        }
    }

    /// Handle receiving a [`Message`].
    fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Start { kind, id, sender } => self.handle_start_download(kind, id, sender),
            Message::Cancel { id } => self.handle_cancel_download(id),
        }
    }

    /// Handle a [`Message::Start`].
    ///
    /// This will not start the download right away. Instead, if this intent maps to a request that
    /// already exists, it will be registered with it. If the request is new it will be scheduled.
    fn handle_start_download(
        &mut self,
        kind: Download,
        id: Id,
        sender: oneshot::Sender<DownloadResult>,
    ) {
        // map this intent to a download request.
        let download_key = (*kind.hash(), kind.ranges());

        // register the intent
        let remaining_retries = 3; // TODO(@divma): we can receive a number of retries if we want or even a strategy
        let intent_info = DownloadInfo {
            kind,
            remaining_retries,
            sender,
        };
        self.registered_intents.insert(id, intent_info);

        // check if there is already a download request for this and what state it is
        match self.current_requests.entry(download_key) {
            Entry::Occupied(mut entry) => {
                // the associated request already exists for another intent, register it
                entry.get_mut().intents.push(id);
                let (hash, ranges) = entry.key();
                let info = entry.get();
                trace!(%hash, ?ranges, ?info, "intent registered with existing request");
            }
            Entry::Vacant(mut entry) => {
                // TODO(@divma): we could also receive an initial delay, or make it part of the
                // (re)try strategy

                // since this request is new, schedule it
                let timeout = std::time::Duration::from_millis(300);
                let delay_key = self.scheduled_requests.insert(entry.key().clone(), timeout);
                let (hash, ranges) = entry.key();
                debug!(%hash, ?ranges, "new request scheduled");

                let intents = vec![id];

                let candidates = self.availabiliy_registry.get_candidates(hash);
                //
                // TODO(@divma): query the AvailabilityRegistry
                let state = RequestState::Scheduled {
                    delay_key,
                    next_peer: None,
                };
                entry.insert(RequestInfo { intents, state });
            }
        }
    }

    fn get_best_candidates(&self, hash: &Hash) -> Option<PublicKey> {
        let mut candidates = self
            .availabiliy_registry
            .get_candidates(hash)
            .filter_map(|peer| {
                match self.peers.get(peer) {
                    Some(info)
                        if info.active_requests
                            >= self.concurrency_limits.max_concurrent_requests_per_peer =>
                    {
                        // filter out peers that do not have capacity under current concurrency limits
                        None
                    }
                    Some(info) => Some((peer, Some(info.active_requests))),
                    None => Some((peer, None)),
                }
            })
            .collect::<Vec<_>>();
        // sort candidates
    }

    /// Cancels the download request.
    ///
    /// This removes the registerd download intent and, depending on it's state, it will either
    /// remove it from the scheduled requests, or cancel the future.
    fn handle_cancel_download(&mut self, id: Id) {
        // remove the intent first
        let Some(DownloadInfo { kind, .. }) = self.registered_intents.remove(&id) else {
            // unlikely scenario to occur but this is reachable in a race between a download being
            // finished and the requester cancelling it before polling the result
            debug!(%id, "intent to cancel no longer present");
            return;
        };

        // get the hash and ranges this intent maps to
        let download_key = (*kind.hash(), kind.ranges());
        let Entry::Occupied(mut occupied_entry) = self.current_requests.entry(download_key) else {
            unreachable!("registered intents have an associated request")
        };

        // remove the intent from the associated request
        let intents = &mut occupied_entry.get_mut().intents;
        let intent_position = intents
            .iter()
            .position(|&intent_id| intent_id == id)
            .expect("associated request contains intent id");
        intents.remove(intent_position);

        // if this was the last intent associated with the request, cancel it or remove it from the
        // schedule queue accordingly
        if intents.is_empty() {
            let ((hash, ranges), info) = occupied_entry.remove_entry();
            debug!(%hash, ?ranges, ?info, "request cancelled");
            match info.state {
                RequestState::Scheduled { delay_key, .. } => {
                    self.scheduled_requests.remove(&delay_key);
                }
                RequestState::Active { cancellation } => {
                    cancellation.cancel();
                }
            }
        }
    }

    async fn poll_schedulled(&mut self) {
        let download_key = self.scheduled_requests.next().await.unwrap().into_inner();
        let RequestInfo { intents, state } = self.current_requests.get_mut(&download_key).unwrap();
        let cancellation = CancellationToken::new();
        *state = match state {
            RequestState::Scheduled { .. } => RequestState::Active { cancellation },
            RequestState::Active { .. } => unreachable!("request was scheduled"),
        };

        // TODO(@divma): needs
        // - connection
        // - sender whatever that it
        // crate::get::get(db, collection_parser, conn, hash, recursive, sender)
    }

    fn on_connection_ready(&mut self, peer: PublicKey, result: anyhow::Result<quinn::Connection>) {
        match result {
            Ok(connection) => {
                trace!(%peer, "connected to peer");
                let peer_info = PeerInfo::new(connection);
                self.peers.insert(peer, peer_info);
            }
            Err(err) => {
                debug!(%peer, %err, "connection to peer failed")
            }
        }
    }

    fn on_download_completed(&mut self, hash: Hash, ranges: RangeSpecSeq, result: DownloadResult) {
        // TODO(@divma): either send the result or handle the retries
    }

    fn on_scheduled_request_ready(&mut self, hash: Hash, ranges: RangeSpecSeq) {
        // TODO(@divma): get the request's next peer, get the connection, add the download future
    }

    /// Returns whether the service is at capcity to perform another concurrent request.
    fn at_request_capacity(&self) -> bool {
        self.in_progress_downloads.len() >= self.concurrency_limits.max_concurrent_requests
    }

    fn shutdown(mut self) {
        // TODO(@divma):
        // cancel opening connections
        // cancel download futures
    }
}
