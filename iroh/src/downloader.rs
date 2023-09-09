//! Handle downloading blobs and collections concurrently and from peers.
//!
//! The [`Downloader`] interacts with four main components to this end.
//! - [`Dialer`]: Used to queue opening connections to peers we need to perform downloads.
//! - [`ProviderMap`]: Where the downloader obtains information about peers that could be
//!   used to perform a download.
//! - [`Store`]: Where data is stored.
//! - [`CollectionParser`]: Used by the Get state machine logic to identify blobs encoding
//!   collections.
//!
//! Once a download request is received, the logic is as follows:
//! 1. The [`ProviderMap`] is queried for peers. From these peers some are selected
//!    prioritizing connected peers with lower number of active requests. If no useful peer is
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
//!   bandwidth capacity. This is a best effort heuristic since it doesn't take into account how
//!   much data we are actually requesting or receiving.
//! - *Total number of connected peers:* Peer connections are kept for a longer time than they are
//!   strictly needed since it's likely they will be useful soon again.
//! - *Requests per peer*: to avoid overwhelming peers with requests, the number of concurrent
//!   requests to a single peer is also limited.

use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    num::NonZeroUsize,
};

use futures::{future::LocalBoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use iroh_bytes::{
    baomap::{range_collections::RangeSet2, Store},
    collection::CollectionParser,
    protocol::RangeSpecSeq,
    Hash,
};
use iroh_net::{key::PublicKey, MagicEndpoint};
use tokio::sync::{mpsc, oneshot};
use tokio_util::{sync::CancellationToken, time::delay_queue};
use tracing::{debug, trace};

use self::get::FailureAction;

mod get;
mod io_getter;
mod test;

/// Delay added to a request when it's first received.
const INITIAL_REQUEST_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
/// Number of retries initially assigned to a request.
const INITIAL_RETRY_COUNT: u8 = 4;
/// Duration for which we keep peers connected after they were last useful to us.
const IDLE_PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Capacity of the channel used to comunicate between the [`Downloader`] and the [`Service`].
const SERVICE_CHANNEL_CAPACITY: usize = 120;

/// Download identifier.
// Mainly for readability.
pub type Id = u64;

/// Trait modeling a dialer. This allows for IO-less testing.
pub trait Dialer:
    futures::Stream<Item = (PublicKey, anyhow::Result<Self::Connection>)> + Unpin
{
    /// Type of connections returned by the Dialer.
    type Connection: Clone;
    /// Dial a peer.
    fn queue_dial(&mut self, peer_id: PublicKey);
    /// Get the number of dialing peers.
    fn pending_count(&self) -> usize;
    /// Check if a peer is being dialed.
    fn is_pending(&self, peer: &PublicKey) -> bool;
}

/// Future of a get request.
type GetFut = LocalBoxFuture<'static, Result<(), FailureAction>>;

/// Trait modelling performing a single request over a connection. This allows for IO-less testing.
pub trait Getter {
    /// Type of connections the Getter requires to perform a download.
    type Connection;
    /// Return a future that performs the download using the given connection.
    fn get(&mut self, kind: DownloadKind, conn: Self::Connection) -> GetFut;
}

/// Concurrency limits for the [`Downloader`].
#[derive(Debug)]
pub struct ConcurrencyLimits {
    /// Maximum number of requests the service performs concurrently.
    pub max_concurrent_requests: usize,
    /// Maximum number of requests performed by a single peer concurrently.
    pub max_concurrent_requests_per_peer: usize,
    /// Maximum number of open connections the service maintains.
    pub max_open_connections: usize,
}

impl Default for ConcurrencyLimits {
    fn default() -> Self {
        // these numbers should be checked against a running node and might depend on platform
        ConcurrencyLimits {
            max_concurrent_requests: 50,
            max_concurrent_requests_per_peer: 4,
            max_open_connections: 100,
        }
    }
}

impl ConcurrencyLimits {
    fn at_requests_capacity(&self, active_requests: usize) -> bool {
        active_requests >= self.max_concurrent_requests
    }

    fn peer_at_request_capacity(&self, active_peer_requests: usize) -> bool {
        active_peer_requests >= self.max_concurrent_requests_per_peer
    }

    fn at_connections_capacity(&self, active_connections: usize) -> bool {
        active_connections >= self.max_open_connections
    }
}

/// Download requests the [`Downloader`] handles.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DownloadKind {
    /// Download a single blob entirely.
    Blob {
        /// Blob to be downloaded.
        hash: Hash,
    },
    /// Download a collection entirely.
    Collection {
        /// Blob to be downloaded.
        hash: Hash,
    },
}

impl DownloadKind {
    /// Get the requested hash.
    const fn hash(&self) -> &Hash {
        match self {
            DownloadKind::Blob { hash } | DownloadKind::Collection { hash } => hash,
        }
    }

    /// Get the ranges this download is requesting.
    // NOTE: necessary to extend downloads to support ranges of blobs ranges of collections.
    #[allow(dead_code)]
    fn ranges(&self) -> RangeSpecSeq {
        match self {
            DownloadKind::Blob { .. } => RangeSpecSeq::from_ranges([RangeSet2::all()]),
            DownloadKind::Collection { .. } => RangeSpecSeq::all(),
        }
    }
}

// TODO(@divma): do we care about failure reason? do we care about success data reporting?
type DownloadResult = Result<(), ()>;

/// Handle to interact with a download request.
#[derive(Debug)]
pub struct DownloadHandle {
    /// Id used to identify the request in the [`Downloader`].
    id: u64,
    /// Kind of download.
    kind: DownloadKind,
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
            Ready(Err(_recv_err)) => Ready(Err(())),
            Pending => Pending,
        }
    }
}

/// Handle for the download services.
#[derive(Debug)]
pub struct Downloader {
    /// Next id to use for a download intent.
    next_id: Id,
    /// Channel to communicate with the service.
    msg_tx: mpsc::Sender<Message>,
}

impl Downloader {
    /// Create a new Downloader.
    pub async fn new<S, C>(
        store: S,
        collection_parser: C,
        endpoint: MagicEndpoint,
        rt: iroh_bytes::util::runtime::Handle,
    ) -> Self
    where
        S: Store,
        C: CollectionParser,
    {
        let (msg_tx, msg_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
        let dialer = iroh_gossip::net::util::Dialer::new(endpoint);

        let create_future = move || {
            let concurrency_limits = ConcurrencyLimits::default();
            let getter = io_getter::IoGetter {
                store,
                collection_parser,
            };

            let service = Service::new(getter, dialer, concurrency_limits, msg_rx);

            service.run()
        };
        rt.local_pool().spawn_pinned(create_future);
        Self { next_id: 0, msg_tx }
    }
    /// Queue a download.
    pub async fn queue(&mut self, kind: DownloadKind, peers: Vec<PublicKey>) -> DownloadHandle {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let (sender, receiver) = oneshot::channel();
        let handle = DownloadHandle {
            id,
            kind: kind.clone(),
            receiver,
        };
        let msg = Message::Queue {
            kind,
            id,
            sender,
            peers,
        };
        // if this fails polling the handle will fail as well since the sender side of the oneshot
        // will be dropped
        if let Err(send_err) = self.msg_tx.send(msg).await {
            let msg = send_err.0;
            debug!(?msg, "download not sent");
        }
        handle
    }

    /// Cancel a download.
    // NOTE: receiving the handle ensures an intent can't be cancelled twice
    pub async fn cancel(&mut self, handle: DownloadHandle) {
        let DownloadHandle {
            id,
            kind,
            receiver: _,
        } = handle;
        let msg = Message::Cancel { id, kind };
        if let Err(send_err) = self.msg_tx.send(msg).await {
            let msg = send_err.0;
            debug!(?msg, "cancel not sent");
        }
    }

    /// Declare that certains peers can be used to download a hash.
    pub async fn peers_have(&mut self, hash: Hash, peers: Vec<PublicKey>) {
        let msg = Message::PeersHave { hash, peers };
        if let Err(send_err) = self.msg_tx.send(msg).await {
            let msg = send_err.0;
            debug!(?msg, "peers have not sent")
        }
    }
}

/// Messages the service can receive.
#[derive(derive_more::Debug)]
enum Message {
    /// Queue a download intent.
    Queue {
        kind: DownloadKind,
        id: Id,
        #[debug(skip)]
        sender: oneshot::Sender<DownloadResult>,
        peers: Vec<PublicKey>,
    },
    /// Cancel an intent. The associated request will be cancelled when the last intent is
    /// cancelled.
    Cancel { id: Id, kind: DownloadKind },
    /// Declare that peers have certains hash and can be used for downloading. This feeds the [`ProviderMap`].
    PeersHave { hash: Hash, peers: Vec<PublicKey> },
}

/// Information about a request being processed.
#[derive(derive_more::Debug)]
struct ActiveRequestInfo {
    /// Ids of intents associated with this request.
    #[debug("{:?}", intents.keys().collect::<Vec<_>>())]
    intents: HashMap<Id, oneshot::Sender<DownloadResult>>,
    /// How many times can this request be retried.
    remaining_retries: u8,
    /// Token used to cancel the future doing the request.
    #[debug(skip)]
    cancellation: CancellationToken,
    /// Peer doing this request attempt.
    peer: PublicKey,
}

/// Information about a request that has not started.
#[derive(derive_more::Debug)]
struct PendingRequestInfo {
    /// Ids of intents associated with this request.
    #[debug("{:?}", intents.keys().collect::<Vec<_>>())]
    intents: HashMap<Id, oneshot::Sender<DownloadResult>>,
    /// How many times can this request be retried.
    remaining_retries: u8,
    /// Key to manage the delay associated with this scheduled request.
    #[debug(skip)]
    delay_key: delay_queue::Key,
    /// If this attempt was scheduled with a known potential peer, this is stored here to
    /// prevent another query to the [`ProviderMap`].
    next_peer: Option<PublicKey>,
}

/// State of the connection to this peer.
#[derive(derive_more::Debug)]
struct ConnectionInfo<Conn> {
    /// Connection to this peer.
    ///
    /// If this peer was deemed unusable by a request, this will be set to `None`. As a
    /// consequence, when evaluating peers for a download, this peer will not be considered.
    /// Since peers are kept for a longer time that they are strictly necessary, this acts as a
    /// temporary ban.
    #[debug(skip)]
    conn: Option<Conn>,
    /// State of this peer.
    state: PeerState,
}

impl<Conn> ConnectionInfo<Conn> {
    /// Create a new idle peer.
    fn new_idle(connection: Conn, drop_key: delay_queue::Key) -> Self {
        ConnectionInfo {
            conn: Some(connection),
            state: PeerState::Idle { drop_key },
        }
    }

    /// Count of active requests for the peer.
    fn active_requests(&self) -> usize {
        match self.state {
            PeerState::Busy { active_requests } => active_requests.get(),
            PeerState::Idle { .. } => 0,
        }
    }
}

/// State of a connected peer.
#[derive(derive_more::Debug)]
enum PeerState {
    /// Peer is handling at least one request.
    Busy {
        #[debug("{}", active_requests.get())]
        active_requests: NonZeroUsize,
    },
    /// Peer is idle.
    Idle {
        #[debug(skip)]
        drop_key: delay_queue::Key,
    },
}

/// Type of future that performs a download request.
type DownloadFut = LocalBoxFuture<'static, (DownloadKind, Result<(), FailureAction>)>;

#[derive(Debug)]
struct Service<G: Getter, D: Dialer> {
    /// The getter performs individual requests.
    getter: G,
    /// Map to query for peers that we believe have the data we are looking for.
    providers: ProviderMap,
    /// Dialer to get connections for required peers.
    dialer: D,
    /// Limits to concurrent tasks handled by the service.
    concurrency_limits: ConcurrencyLimits,
    /// Channel to receive messages from the service's handle.
    msg_rx: mpsc::Receiver<Message>,
    /// Peers available to use and their relevant information.
    peers: HashMap<PublicKey, ConnectionInfo<D::Connection>>,
    /// Queue to manage dropping keys.
    goodbye_peer_queue: delay_queue::DelayQueue<PublicKey>,
    /// Requests performed for download intents. Two download requests can produce the same
    /// request. This map allows deduplication of efforts.
    current_requests: HashMap<DownloadKind, ActiveRequestInfo>,
    /// Downloads underway.
    in_progress_downloads: FuturesUnordered<DownloadFut>,
    /// Requests scheduled to be downloaded at a later time.
    scheduled_requests: HashMap<DownloadKind, PendingRequestInfo>,
    /// Queue of scheduled requests.
    scheduled_request_queue: delay_queue::DelayQueue<DownloadKind>,
}

impl<G: Getter<Connection = D::Connection>, D: Dialer> Service<G, D> {
    fn new(
        getter: G,
        dialer: D,
        concurrency_limits: ConcurrencyLimits,
        msg_rx: mpsc::Receiver<Message>,
    ) -> Self {
        Service {
            getter,
            providers: ProviderMap::default(),
            dialer,
            concurrency_limits,
            msg_rx,
            peers: HashMap::default(),
            goodbye_peer_queue: delay_queue::DelayQueue::default(),
            current_requests: HashMap::default(),
            in_progress_downloads: FuturesUnordered::default(),
            scheduled_requests: HashMap::default(),
            scheduled_request_queue: delay_queue::DelayQueue::default(),
        }
    }

    /// Main loop for the service.
    async fn run(mut self) {
        loop {
            // check if we have capacity to dequeue another scheduled request
            let at_capacity = self
                .concurrency_limits
                .at_requests_capacity(self.in_progress_downloads.len());

            tokio::select! {
                Some((peer, conn_result)) = self.dialer.next() => {
                    trace!("tick: connection ready");
                    self.on_connection_ready(peer, conn_result);
                }
                maybe_msg = self.msg_rx.recv() => {
                    trace!(msg=?maybe_msg, "tick: message received");
                    match maybe_msg {
                        Some(msg) => self.handle_message(msg),
                        None => return self.shutdown().await,
                    }
                }
                Some((kind, result)) = self.in_progress_downloads.next() => {
                    trace!("tick: download completed");
                    self.on_download_completed(kind, result);
                }
                Some(expired) = self.scheduled_request_queue.next(), if !at_capacity => {
                    trace!("tick: scheduled request ready");
                    let kind = expired.into_inner();
                    let request_info = self.scheduled_requests.remove(&kind).expect("is registered");
                    self.on_scheduled_request_ready(kind, request_info);
                }
                Some(expired) = self.goodbye_peer_queue.next() => {
                    let peer = expired.into_inner();
                    self.peers.remove(&peer);
                    trace!(%peer, "tick: goodbye peer");
                }
            }
            #[cfg(test)]
            self.check_invariants();
        }
    }

    /// Handle receiving a [`Message`].
    fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Queue {
                kind,
                id,
                sender,
                peers,
            } => self.handle_queue_new_download(kind, id, sender, peers),
            Message::Cancel { id, kind } => self.handle_cancel_download(id, kind),
            Message::PeersHave { hash, peers } => self.handle_peers_have(hash, peers),
        }
    }

    /// Handle a [`Message::Queue`].
    ///
    /// If this intent maps to a request that already exists, it will be registered with it. If the
    /// request is new it will be scheduled.
    fn handle_queue_new_download(
        &mut self,
        kind: DownloadKind,
        id: Id,
        sender: oneshot::Sender<DownloadResult>,
        peers: Vec<PublicKey>,
    ) {
        self.providers.add_peers(*kind.hash(), &peers);
        if let Some(info) = self.current_requests.get_mut(&kind) {
            // this intent maps to a download that already exists, simply register it
            info.intents.insert(id, sender);
            // increasing the retries by one accounts for multiple intents for the same request in
            // a conservative way
            info.remaining_retries += 1;
            return trace!(?kind, ?info, "intent registered with active request");
        }

        let needs_peer = self
            .scheduled_requests
            .get(&kind)
            .map(|info| info.next_peer.is_none())
            .unwrap_or(true);

        let next_peer = needs_peer
            .then(|| self.get_best_candidate(kind.hash()))
            .flatten();

        // if we are here this request is not active, check if it needs to be scheduled
        match self.scheduled_requests.get_mut(&kind) {
            Some(info) => {
                info.intents.insert(id, sender);
                // pre-emptively get a peer if we don't already have one
                if info.next_peer.is_none() {
                    info.next_peer = next_peer
                }
                // increasing the retries by one accounts for multiple intents for the same request in
                // a conservative way
                info.remaining_retries += 1;
                trace!(?kind, ?info, "intent registered with scheduled request");
            }
            None => {
                let intents = HashMap::from([(id, sender)]);
                self.schedule_request(kind, INITIAL_RETRY_COUNT, next_peer, intents)
            }
        }
    }

    /// Gets the best candidate for a download.
    ///
    /// Peers are selected prioritizing those with an open connection and with capacity for another
    /// request, followed by peers we are currently dialing with capacity for another request.
    /// Lastly, peers not connected and not dialing are considered.
    ///
    /// If the selected candidate is not connected and we have capacity for another connection, a
    /// dial is queued.
    fn get_best_candidate(&mut self, hash: &Hash) -> Option<PublicKey> {
        /// Model the state of peers found in the candidates
        #[derive(PartialEq, Eq, Clone, Copy)]
        enum ConnState {
            Dialing,
            Connected(usize),
            NotConnected,
        }

        impl Ord for ConnState {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                // define the order of preference between candidates as follows:
                // - prefer connected peers to dialing ones
                // - prefer dialing peers to not connected ones
                // - prefer peers with less active requests when connected
                use std::cmp::Ordering::*;
                match (self, other) {
                    (ConnState::Dialing, ConnState::Dialing) => Equal,
                    (ConnState::Dialing, ConnState::Connected(_)) => Less,
                    (ConnState::Dialing, ConnState::NotConnected) => Greater,
                    (ConnState::NotConnected, ConnState::Dialing) => Less,
                    (ConnState::NotConnected, ConnState::Connected(_)) => Less,
                    (ConnState::NotConnected, ConnState::NotConnected) => Equal,
                    (ConnState::Connected(_), ConnState::Dialing) => Greater,
                    (ConnState::Connected(_), ConnState::NotConnected) => Greater,
                    (ConnState::Connected(a), ConnState::Connected(b)) => match a.cmp(b) {
                        Less => Greater, // less preferable if greater number of requests
                        Equal => Equal,  // no preference
                        Greater => Less, // more preferable if less number of requests
                    },
                }
            }
        }

        impl PartialOrd for ConnState {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        // first collect suitable candidates
        let mut candidates = self
            .providers
            .get_candidates(hash)
            .filter_map(|peer| {
                if let Some(info) = self.peers.get(peer) {
                    info.conn.as_ref()?;
                    let req_count = info.active_requests();
                    // filter out peers at capacity
                    let has_capacity = !self.concurrency_limits.peer_at_request_capacity(req_count);
                    has_capacity.then_some((peer, ConnState::Connected(req_count)))
                } else if self.dialer.is_pending(peer) {
                    Some((peer, ConnState::Dialing))
                } else {
                    Some((peer, ConnState::NotConnected))
                }
            })
            .collect::<Vec<_>>();

        candidates.sort_unstable_by_key(|peer_and_state| peer_and_state.1 /* state */);

        // this is our best peer, check if we need to dial it
        let (peer, state) = candidates.pop()?;

        if let ConnState::NotConnected = state {
            if !self.at_connections_capacity() {
                // peer is not connected, not dialing and concurrency limits allow another connection
                debug!(%peer, "dialing peer");
                self.dialer.queue_dial(*peer);
                Some(*peer)
            } else {
                trace!(%peer, "required peer not dialed to maintain concurrency limits");
                None
            }
        } else {
            Some(*peer)
        }
    }

    /// Cancels the download request.
    ///
    /// This removes the registered download intent and, depending on its state, it will either
    /// remove it from the scheduled requests, or cancel the future.
    fn handle_cancel_download(&mut self, id: Id, kind: DownloadKind) {
        if let Entry::Occupied(mut occupied_entry) = self.current_requests.entry(kind.clone()) {
            // remove the intent from the associated request
            let intents = &mut occupied_entry.get_mut().intents;
            intents.remove(&id);
            // if this was the last intent associated with the request cancel it
            if intents.is_empty() {
                occupied_entry.remove().cancellation.cancel();
            }
        } else if let Entry::Occupied(mut occupied_entry) = self.scheduled_requests.entry(kind) {
            // remove the intent from the associated request
            let intents = &mut occupied_entry.get_mut().intents;
            intents.remove(&id);
            // if this was the last intent associated with the request remove it from the schedule
            // queue
            if intents.is_empty() {
                let delay_key = occupied_entry.remove().delay_key;
                self.scheduled_request_queue.remove(&delay_key);
            }
        }
    }

    /// Handle a [`Message::PeersHave`].
    fn handle_peers_have(&mut self, hash: Hash, peers: Vec<PublicKey>) {
        // check if this still needed
        if self.is_needed(hash) {
            self.providers.add_peers(hash, &peers);
        }
    }

    /// Checks if this hash is needed.
    fn is_needed(&self, hash: Hash) -> bool {
        let as_blob = DownloadKind::Blob { hash };
        let as_collection = DownloadKind::Collection { hash };
        self.current_requests.contains_key(&as_blob)
            || self.scheduled_requests.contains_key(&as_blob)
            || self.current_requests.contains_key(&as_collection)
            || self.scheduled_requests.contains_key(&as_collection)
    }

    /// Handle receiving a new connection.
    fn on_connection_ready(&mut self, peer: PublicKey, result: anyhow::Result<D::Connection>) {
        match result {
            Ok(connection) => {
                trace!(%peer, "connected to peer");
                let drop_key = self.goodbye_peer_queue.insert(peer, IDLE_PEER_TIMEOUT);
                self.peers
                    .insert(peer, ConnectionInfo::new_idle(connection, drop_key));
            }
            Err(err) => {
                debug!(%peer, %err, "connection to peer failed")
            }
        }
    }

    fn on_download_completed(&mut self, kind: DownloadKind, result: Result<(), FailureAction>) {
        // first remove the request
        let info = self
            .current_requests
            .remove(&kind)
            .expect("request was active");

        // update the active requests for this peer
        let ActiveRequestInfo {
            intents,
            peer,
            mut remaining_retries,
            ..
        } = info;

        let peer_info = self.peers.get_mut(&peer).expect("peer is connected");
        peer_info.state = match &peer_info.state {
            PeerState::Busy { active_requests } => {
                match NonZeroUsize::new(active_requests.get() - 1) {
                    Some(active_requests) => PeerState::Busy { active_requests },
                    None => {
                        // last request of the peer was this one
                        let drop_key = self.goodbye_peer_queue.insert(peer, IDLE_PEER_TIMEOUT);
                        PeerState::Idle { drop_key }
                    }
                }
            }
            PeerState::Idle { .. } => unreachable!("peer was busy"),
        };

        let hash = *kind.hash();

        match result {
            Ok(()) => {
                debug!(%peer, ?kind, "download completed");
                for sender in intents.into_values() {
                    let _ = sender.send(Ok(()));
                }
            }
            Err(FailureAction::AbortRequest(reason)) => {
                debug!(%peer, ?kind, %reason, "aborting request");
                for sender in intents.into_values() {
                    let _ = sender.send(Err(()));
                }
            }
            Err(FailureAction::DropPeer(reason)) => {
                debug!(%peer, ?kind, %reason, "peer will be dropped");
                if let Some(_connection) = peer_info.conn.take() {
                    // TODO(@divma): this will fail open streams, do we want this?
                    // connection.close(..)
                }
            }
            Err(FailureAction::RetryLater(reason)) => {
                // check if the download can be retried
                if remaining_retries > 0 {
                    debug!(%peer, ?kind, %reason, "download attempt failed");
                    remaining_retries -= 1;
                    let next_peer = self.get_best_candidate(kind.hash());
                    self.schedule_request(kind, remaining_retries, next_peer, intents);
                } else {
                    debug!(%peer, ?kind, %reason, "download failed");
                    for sender in intents.into_values() {
                        let _ = sender.send(Err(()));
                    }
                }
            }
        }

        if !self.is_needed(hash) {
            self.providers.remove(hash)
        }
    }

    /// A scheduled request is ready to be processed.
    ///
    /// The peer that was initially selected is used if possible. Otherwise we try to get a new
    /// peer
    fn on_scheduled_request_ready(&mut self, kind: DownloadKind, info: PendingRequestInfo) {
        let PendingRequestInfo {
            intents,
            mut remaining_retries,
            next_peer,
            ..
        } = info;

        // first try with the peer that was initially assigned
        if let Some((peer, conn)) = next_peer.and_then(|peer| {
            self.get_peer_connection_for_download(&peer)
                .map(|conn| (peer, conn))
        }) {
            return self.start_download(kind, peer, conn, remaining_retries, intents);
        }

        // we either didn't have a peer or the peer is busy or dialing. In any case try to get
        // another peer
        let next_peer = match self.get_best_candidate(kind.hash()) {
            None => None,
            Some(peer) => {
                // optimistically check if the peer could do the request right away
                match self.get_peer_connection_for_download(&peer) {
                    Some(conn) => {
                        return self.start_download(kind, peer, conn, remaining_retries, intents)
                    }
                    None => Some(peer),
                }
            }
        };

        // we tried to get a peer to perform this request but didn't get one, so now this attempt
        // is failed
        if remaining_retries > 0 {
            remaining_retries -= 1;
            self.schedule_request(kind, remaining_retries, next_peer, intents);
        } else {
            // request can't be retried
            for sender in intents.into_values() {
                let _ = sender.send(Err(()));
            }
            debug!(?kind, "download ran out of attempts")
        }
    }

    /// Start downloading from the given peer.
    fn start_download(
        &mut self,
        kind: DownloadKind,
        peer: PublicKey,
        conn: D::Connection,
        remaining_retries: u8,
        intents: HashMap<Id, oneshot::Sender<DownloadResult>>,
    ) {
        debug!(%peer, ?kind, "starting download");
        let cancellation = CancellationToken::new();
        let info = ActiveRequestInfo {
            intents,
            remaining_retries,
            cancellation,
            peer,
        };
        let cancellation = info.cancellation.clone();
        self.current_requests.insert(kind.clone(), info);

        let get = self.getter.get(kind.clone(), conn);
        let fut = async move {
            // TODO(@divma): timeout?
            let res = tokio::select! {
                _ = cancellation.cancelled() => Err(get::FailureAction::AbortRequest(anyhow::anyhow!("cancelled"))),
                res = get => res
            };

            (kind, res)
        };

        self.in_progress_downloads.push(fut.boxed_local());
    }

    /// Schedule a request for later processing.
    fn schedule_request(
        &mut self,
        kind: DownloadKind,
        remaining_retries: u8,
        next_peer: Option<PublicKey>,
        intents: HashMap<Id, oneshot::Sender<DownloadResult>>,
    ) {
        // this is simply INITIAL_REQUEST_DELAY * attempt_num where attempt_num (as an ordinal
        // number) is maxed at INITIAL_RETRY_COUNT
        let delay = INITIAL_REQUEST_DELAY
            * (INITIAL_RETRY_COUNT.saturating_sub(remaining_retries) as u32 + 1);
        let delay_key = self.scheduled_request_queue.insert(kind.clone(), delay);

        let info = PendingRequestInfo {
            intents,
            remaining_retries,
            delay_key,
            next_peer,
        };
        debug!(?kind, ?info, "request scheduled");
        self.scheduled_requests.insert(kind, info);
    }

    /// Gets the [`quinn::Connection`] for a peer if it's connected an has capacity for another
    /// request. In this case, the count of active requests for the peer is incremented.
    fn get_peer_connection_for_download(&mut self, peer: &PublicKey) -> Option<D::Connection> {
        let info = self.peers.get_mut(peer)?;
        let connection = info.conn.as_ref()?;
        // check if the peer can be sent another request
        match &mut info.state {
            PeerState::Busy { active_requests } => {
                if !self
                    .concurrency_limits
                    .peer_at_request_capacity(active_requests.get())
                {
                    *active_requests = active_requests.saturating_add(1);
                    Some(connection.clone())
                } else {
                    None
                }
            }
            PeerState::Idle { drop_key } => {
                // peer is no longer idle
                self.goodbye_peer_queue.remove(drop_key);
                info.state = PeerState::Busy {
                    active_requests: NonZeroUsize::new(1).expect("clearly non zero"),
                };
                Some(connection.clone())
            }
        }
    }

    /// Check if we have maxed our connection capacity.
    fn at_connections_capacity(&self) -> bool {
        self.concurrency_limits
            .at_connections_capacity(self.connections_count())
    }

    /// Get the total number of connected and dialing peers.
    fn connections_count(&self) -> usize {
        let connected_peers = self
            .peers
            .values()
            .filter(|info| info.conn.is_some())
            .count();
        let dialing_peers = self.dialer.pending_count();
        connected_peers + dialing_peers
    }

    async fn shutdown(self) {
        debug!("shutting down");
        // TODO(@divma): how to make sure the download futures end gracefully?
    }
}

/// Map of potential providers for a hash.
#[derive(Default, Debug)]
struct ProviderMap {
    /// Candidates to download a hash.
    candidates: HashMap<Hash, HashSet<PublicKey>>,
}

struct ProviderIter<'a> {
    inner: Option<std::collections::hash_set::Iter<'a, PublicKey>>,
}

impl<'a> Iterator for ProviderIter<'a> {
    type Item = &'a PublicKey;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.as_mut().and_then(|iter| iter.next())
    }
}

impl ProviderMap {
    /// Get candidates to download this hash.
    fn get_candidates(&self, hash: &Hash) -> impl Iterator<Item = &PublicKey> {
        let inner = self.candidates.get(hash).map(|peer_set| peer_set.iter());
        ProviderIter { inner }
    }

    /// Register peers for a hash. Should only be done for hashes we care to download.
    fn add_peers(&mut self, hash: Hash, peers: &[PublicKey]) {
        self.candidates.entry(hash).or_default().extend(peers)
    }

    /// Signal the registry that this hash is no longer of interest.
    fn remove(&mut self, hash: Hash) {
        self.candidates.remove(&hash);
    }
}

impl Dialer for iroh_gossip::net::util::Dialer {
    type Connection = quinn::Connection;

    fn queue_dial(&mut self, peer_id: PublicKey) {
        self.queue_dial(peer_id, &iroh_bytes::protocol::ALPN)
    }

    fn pending_count(&self) -> usize {
        self.pending_count()
    }

    fn is_pending(&self, peer: &PublicKey) -> bool {
        self.is_pending(peer)
    }
}
