//! Handle downloading blobs and collections concurrently and from nodes.
//!
//! The [`Downloader`] interacts with four main components to this end.
//! - [`Dialer`]: Used to queue opening connections to nodes we need to perform downloads.
//! - [`ProviderMap`]: Where the downloader obtains information about nodes that could be
//!   used to perform a download.
//! - [`Store`]: Where data is stored.
//!
//! Once a download request is received, the logic is as follows:
//! 1. The [`ProviderMap`] is queried for nodes. From these nodes some are selected
//!    prioritizing connected nodes with lower number of active requests. If no useful node is
//!    connected, or useful connected nodes have no capacity to perform the request, a connection
//!    attempt is started using the [`Dialer`].
//! 2. The download is queued for processing at a later time. Downloads are not performed right
//!    away. Instead, they are initially delayed to allow the node to obtain the data itself, and
//!    to wait for the new connection to be established if necessary.
//! 3. Once a request is ready to be sent after a delay (initial or for a retry), the preferred
//!    node is used if available. The request is now considered active.
//!
//! Concurrency is limited in different ways:
//! - *Total number of active request:* This is a way to prevent a self DoS by overwhelming our own
//!   bandwidth capacity. This is a best effort heuristic since it doesn't take into account how
//!   much data we are actually requesting or receiving.
//! - *Total number of connected nodes:* Peer connections are kept for a longer time than they are
//!   strictly needed since it's likely they will be useful soon again.
//! - *Requests per node*: to avoid overwhelming nodes with requests, the number of concurrent
//!   requests to a single node is also limited.

use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use bao_tree::ChunkRanges;
use futures::{future::LocalBoxFuture, FutureExt, StreamExt};
use iroh_bytes::{protocol::RangeSpecSeq, store::Store, Hash, HashAndFormat, TempTag};
use iroh_net::{MagicEndpoint, NodeId};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, time::delay_queue};
use tracing::{debug, error_span, trace, warn, Instrument};

mod get;
mod invariants;
mod test;

/// Delay added to a request when it's first received.
const INITIAL_REQUEST_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
/// Number of retries initially assigned to a request.
const INITIAL_RETRY_COUNT: u8 = 4;
/// Duration for which we keep nodes connected after they were last useful to us.
const IDLE_PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Capacity of the channel used to comunicate between the [`Downloader`] and the [`Service`].
const SERVICE_CHANNEL_CAPACITY: usize = 128;

/// Download identifier.
// Mainly for readability.
pub type Id = u64;

/// Trait modeling a dialer. This allows for IO-less testing.
pub trait Dialer:
    futures::Stream<Item = (NodeId, anyhow::Result<Self::Connection>)> + Unpin
{
    /// Type of connections returned by the Dialer.
    type Connection: Clone;
    /// Dial a node.
    fn queue_dial(&mut self, node_id: NodeId);
    /// Get the number of dialing nodes.
    fn pending_count(&self) -> usize;
    /// Check if a node is being dialed.
    fn is_pending(&self, node: &NodeId) -> bool;
}

/// Signals what should be done with the request when it fails.
#[derive(Debug)]
pub enum FailureAction {
    /// An error ocurred that prevents the request from being retried at all.
    AbortRequest(anyhow::Error),
    /// An error occurred that suggests the node should not be used in general.
    DropPeer(anyhow::Error),
    /// An error occurred in which neither the node nor the request are at fault.
    RetryLater(anyhow::Error),
}

/// Future of a get request.
type GetFut = LocalBoxFuture<'static, Result<TempTag, FailureAction>>;

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
    /// Maximum number of requests performed by a single node concurrently.
    pub max_concurrent_requests_per_node: usize,
    /// Maximum number of open connections the service maintains.
    pub max_open_connections: usize,
}

impl Default for ConcurrencyLimits {
    fn default() -> Self {
        // these numbers should be checked against a running node and might depend on platform
        ConcurrencyLimits {
            max_concurrent_requests: 50,
            max_concurrent_requests_per_node: 4,
            max_open_connections: 25,
        }
    }
}

impl ConcurrencyLimits {
    /// Checks if the maximum number of concurrent requests has been reached.
    fn at_requests_capacity(&self, active_requests: usize) -> bool {
        active_requests >= self.max_concurrent_requests
    }

    /// Checks if the maximum number of concurrent requests per node has been reached.
    fn node_at_request_capacity(&self, active_node_requests: usize) -> bool {
        active_node_requests >= self.max_concurrent_requests_per_node
    }

    /// Checks if the maximum number of connections has been reached.
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
    /// Download a sequence of hashes entirely.
    HashSeq {
        /// Hash sequence to be downloaded.
        hash: Hash,
    },
}

impl DownloadKind {
    /// Get the requested hash.
    const fn hash(&self) -> &Hash {
        match self {
            DownloadKind::Blob { hash } | DownloadKind::HashSeq { hash } => hash,
        }
    }

    /// Get the requested hash and format.
    fn hash_and_format(&self) -> HashAndFormat {
        match self {
            DownloadKind::Blob { hash } => HashAndFormat::raw(*hash),
            DownloadKind::HashSeq { hash } => HashAndFormat::hash_seq(*hash),
        }
    }

    /// Get the ranges this download is requesting.
    // NOTE: necessary to extend downloads to support ranges of blobs ranges of collections.
    #[allow(dead_code)]
    fn ranges(&self) -> RangeSpecSeq {
        match self {
            DownloadKind::Blob { .. } => RangeSpecSeq::from_ranges([ChunkRanges::all()]),
            DownloadKind::HashSeq { .. } => RangeSpecSeq::all(),
        }
    }
}

// For readability. In the future we might care about some data reporting on a successful download
// or kind of failure in the error case.
type DownloadResult = anyhow::Result<TempTag>;

/// Handle to interact with a download request.
#[derive(Debug)]
pub struct DownloadHandle {
    /// Id used to identify the request in the [`Downloader`].
    id: Id,
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
            Ready(Err(recv_err)) => Ready(Err(anyhow::anyhow!("oneshot error: {recv_err}"))),
            Pending => Pending,
        }
    }
}

/// Handle for the download services.
#[derive(Clone, Debug)]
pub struct Downloader {
    /// Next id to use for a download intent.
    next_id: Arc<AtomicU64>,
    /// Channel to communicate with the service.
    msg_tx: mpsc::Sender<Message>,
}

impl Downloader {
    /// Create a new Downloader.
    pub fn new<S>(store: S, endpoint: MagicEndpoint, rt: iroh_bytes::util::runtime::Handle) -> Self
    where
        S: Store,
    {
        let me = endpoint.peer_id().fmt_short();
        let (msg_tx, msg_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
        let dialer = iroh_gossip::net::util::Dialer::new(endpoint);

        let create_future = move || {
            let concurrency_limits = ConcurrencyLimits::default();
            let getter = get::IoGetter { store };

            let service = Service::new(getter, dialer, concurrency_limits, msg_rx);

            service.run().instrument(error_span!("downloader", %me))
        };
        rt.local_pool().spawn_pinned(create_future);
        Self {
            next_id: Arc::new(AtomicU64::new(0)),
            msg_tx,
        }
    }

    /// Queue a download.
    pub async fn queue(&mut self, kind: DownloadKind, nodes: Vec<NodeInfo>) -> DownloadHandle {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

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
            nodes,
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

    /// Declare that certains nodes can be used to download a hash.
    pub async fn nodes_have(&mut self, hash: Hash, nodes: Vec<NodeInfo>) {
        let msg = Message::PeersHave { hash, nodes };
        if let Err(send_err) = self.msg_tx.send(msg).await {
            let msg = send_err.0;
            debug!(?msg, "nodes have not been sent")
        }
    }
}

/// A node and its role with regard to a hash.
#[derive(Debug, Clone, Copy)]
pub struct NodeInfo {
    node_id: NodeId,
    role: Role,
}

impl NodeInfo {
    /// Create a new [`PeerInfo`] from its parts.
    pub fn new(node_id: NodeId, role: Role) -> Self {
        Self { node_id, role }
    }
}

impl From<(NodeId, Role)> for NodeInfo {
    fn from((node_id, role): (NodeId, Role)) -> Self {
        Self { node_id, role }
    }
}

/// The role of a node with regard to a download intent.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    /// We have information that this node has the requested blob.
    Provider,
    /// We do not have information if this node has the requested blob.
    Candidate,
}

impl PartialOrd for Role {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Role {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Role::Provider, Role::Provider) => std::cmp::Ordering::Equal,
            (Role::Candidate, Role::Candidate) => std::cmp::Ordering::Equal,
            (Role::Provider, Role::Candidate) => std::cmp::Ordering::Greater,
            (Role::Candidate, Role::Provider) => std::cmp::Ordering::Less,
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
        nodes: Vec<NodeInfo>,
    },
    /// Cancel an intent. The associated request will be cancelled when the last intent is
    /// cancelled.
    Cancel { id: Id, kind: DownloadKind },
    /// Declare that nodes have certains hash and can be used for downloading. This feeds the [`ProviderMap`].
    PeersHave { hash: Hash, nodes: Vec<NodeInfo> },
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
    node: NodeId,
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
    /// If this attempt was scheduled with a known potential node, this is stored here to
    /// prevent another query to the [`ProviderMap`].
    next_node: Option<NodeId>,
}

/// State of the connection to this node.
#[derive(derive_more::Debug)]
struct ConnectionInfo<Conn> {
    /// Connection to this node.
    ///
    /// If this node was deemed unusable by a request, this will be set to `None`. As a
    /// consequence, when evaluating nodes for a download, this node will not be considered.
    /// Since nodes are kept for a longer time that they are strictly necessary, this acts as a
    /// temporary ban.
    #[debug(skip)]
    conn: Option<Conn>,
    /// State of this node.
    state: PeerState,
}

impl<Conn> ConnectionInfo<Conn> {
    /// Create a new idle node.
    fn new_idle(connection: Conn, drop_key: delay_queue::Key) -> Self {
        ConnectionInfo {
            conn: Some(connection),
            state: PeerState::Idle { drop_key },
        }
    }

    /// Count of active requests for the node.
    fn active_requests(&self) -> usize {
        match self.state {
            PeerState::Busy { active_requests } => active_requests.get(),
            PeerState::Idle { .. } => 0,
        }
    }
}

/// State of a connected node.
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

/// Type that is returned from a download request.
type DownloadRes = (DownloadKind, Result<TempTag, FailureAction>);

#[derive(Debug)]
struct Service<G: Getter, D: Dialer> {
    /// The getter performs individual requests.
    getter: G,
    /// Map to query for nodes that we believe have the data we are looking for.
    providers: ProviderMap,
    /// Dialer to get connections for required nodes.
    dialer: D,
    /// Limits to concurrent tasks handled by the service.
    concurrency_limits: ConcurrencyLimits,
    /// Channel to receive messages from the service's handle.
    msg_rx: mpsc::Receiver<Message>,
    /// Peers available to use and their relevant information.
    nodes: HashMap<NodeId, ConnectionInfo<D::Connection>>,
    /// Queue to manage dropping nodes.
    goodbye_nodes_queue: delay_queue::DelayQueue<NodeId>,
    /// Requests performed for download intents. Two download requests can produce the same
    /// request. This map allows deduplication of efforts.
    current_requests: HashMap<DownloadKind, ActiveRequestInfo>,
    /// Downloads underway.
    in_progress_downloads: JoinSet<DownloadRes>,
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
            nodes: HashMap::default(),
            goodbye_nodes_queue: delay_queue::DelayQueue::default(),
            current_requests: HashMap::default(),
            in_progress_downloads: Default::default(),
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
                Some((node, conn_result)) = self.dialer.next() => {
                    trace!("tick: connection ready");
                    self.on_connection_ready(node, conn_result);
                }
                maybe_msg = self.msg_rx.recv() => {
                    trace!(msg=?maybe_msg, "tick: message received");
                    match maybe_msg {
                        Some(msg) => self.handle_message(msg),
                        None => return self.shutdown().await,
                    }
                }
                Some(res) = self.in_progress_downloads.join_next() => {
                    match res {
                        Ok((kind, result)) => {
                            trace!("tick: download completed");
                            self.on_download_completed(kind, result);
                        }
                        Err(e) => {
                            warn!("download issue: {:?}", e);
                        }
                    }
                }
                Some(expired) = self.scheduled_request_queue.next(), if !at_capacity => {
                    trace!("tick: scheduled request ready");
                    let kind = expired.into_inner();
                    let request_info = self.scheduled_requests.remove(&kind).expect("is registered");
                    self.on_scheduled_request_ready(kind, request_info);
                }
                Some(expired) = self.goodbye_nodes_queue.next() => {
                    let node = expired.into_inner();
                    self.nodes.remove(&node);
                    trace!(%node, "tick: goodbye node");
                }
            }
            #[cfg(any(test, debug_assertions))]
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
                nodes,
            } => self.handle_queue_new_download(kind, id, sender, nodes),
            Message::Cancel { id, kind } => self.handle_cancel_download(id, kind),
            Message::PeersHave { hash, nodes } => self.handle_nodes_have(hash, nodes),
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
        nodes: Vec<NodeInfo>,
    ) {
        self.providers.add_nodes(*kind.hash(), &nodes);
        if let Some(info) = self.current_requests.get_mut(&kind) {
            // this intent maps to a download that already exists, simply register it
            info.intents.insert(id, sender);
            // increasing the retries by one accounts for multiple intents for the same request in
            // a conservative way
            info.remaining_retries += 1;
            return trace!(?kind, ?info, "intent registered with active request");
        }

        let needs_node = self
            .scheduled_requests
            .get(&kind)
            .map(|info| info.next_node.is_none())
            .unwrap_or(true);

        let next_node = needs_node
            .then(|| self.get_best_candidate(kind.hash()))
            .flatten();

        // if we are here this request is not active, check if it needs to be scheduled
        match self.scheduled_requests.get_mut(&kind) {
            Some(info) => {
                info.intents.insert(id, sender);
                // pre-emptively get a node if we don't already have one
                match (info.next_node, next_node) {
                    // We did not yet have next node, but have a node now.
                    (None, Some(next_node)) => {
                        info.next_node = Some(next_node);
                    }
                    (Some(_old_next_node), Some(_next_node)) => {
                        unreachable!("invariant: info.next_node must be none because checked above with needs_node")
                    }
                    _ => {}
                }

                // increasing the retries by one accounts for multiple intents for the same request in
                // a conservative way
                info.remaining_retries += 1;
                trace!(?kind, ?info, "intent registered with scheduled request");
            }
            None => {
                let intents = HashMap::from([(id, sender)]);
                self.schedule_request(kind, INITIAL_RETRY_COUNT, next_node, intents)
            }
        }
    }

    /// Gets the best candidate for a download.
    ///
    /// Peers are selected prioritizing those with an open connection and with capacity for another
    /// request, followed by nodes we are currently dialing with capacity for another request.
    /// Lastly, nodes not connected and not dialing are considered.
    ///
    /// If the selected candidate is not connected and we have capacity for another connection, a
    /// dial is queued.
    fn get_best_candidate(&mut self, hash: &Hash) -> Option<NodeId> {
        /// Model the state of nodes found in the candidates
        #[derive(PartialEq, Eq, Clone, Copy)]
        enum ConnState {
            Dialing,
            Connected(usize),
            NotConnected,
        }

        impl Ord for ConnState {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                // define the order of preference between candidates as follows:
                // - prefer connected nodes to dialing ones
                // - prefer dialing nodes to not connected ones
                // - prefer nodes with less active requests when connected
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
            .filter_map(|(node_id, role)| {
                let node = NodeInfo::new(*node_id, *role);
                if let Some(info) = self.nodes.get(node_id) {
                    info.conn.as_ref()?;
                    let req_count = info.active_requests();
                    // filter out nodes at capacity
                    let has_capacity = !self.concurrency_limits.node_at_request_capacity(req_count);
                    has_capacity.then_some((node, ConnState::Connected(req_count)))
                } else if self.dialer.is_pending(node_id) {
                    Some((node, ConnState::Dialing))
                } else {
                    Some((node, ConnState::NotConnected))
                }
            })
            .collect::<Vec<_>>();

        // Sort candidates by:
        // * Role (Providers > Candidates)
        // * ConnState (Connected > Dialing > NotConnected)
        candidates.sort_unstable_by_key(|(NodeInfo { role, .. }, state)| (*role, *state));

        // this is our best node, check if we need to dial it
        let (node, state) = candidates.pop()?;

        if let ConnState::NotConnected = state {
            if !self.at_connections_capacity() {
                // node is not connected, not dialing and concurrency limits allow another connection
                debug!(node = %node.node_id, "dialing node");
                self.dialer.queue_dial(node.node_id);
                Some(node.node_id)
            } else {
                trace!(node = %node.node_id, "required node not dialed to maintain concurrency limits");
                None
            }
        } else {
            Some(node.node_id)
        }
    }

    /// Cancels the download request.
    ///
    /// This removes the registered download intent and, depending on its state, it will either
    /// remove it from the scheduled requests, or cancel the future.
    fn handle_cancel_download(&mut self, id: Id, kind: DownloadKind) {
        let hash = *kind.hash();
        let mut download_removed = false;
        if let Entry::Occupied(mut occupied_entry) = self.current_requests.entry(kind.clone()) {
            // remove the intent from the associated request
            let intents = &mut occupied_entry.get_mut().intents;
            intents.remove(&id);
            // if this was the last intent associated with the request cancel it
            if intents.is_empty() {
                download_removed = true;
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
                download_removed = true;
            }
        }

        if download_removed && !self.is_needed(hash) {
            self.providers.remove(hash)
        }
    }

    /// Handle a [`Message::PeersHave`].
    fn handle_nodes_have(&mut self, hash: Hash, nodes: Vec<NodeInfo>) {
        // check if this still needed
        if self.is_needed(hash) {
            self.providers.add_nodes(hash, &nodes);
        }
    }

    /// Checks if this hash is needed.
    fn is_needed(&self, hash: Hash) -> bool {
        let as_blob = DownloadKind::Blob { hash };
        let as_hash_seq = DownloadKind::HashSeq { hash };
        self.current_requests.contains_key(&as_blob)
            || self.scheduled_requests.contains_key(&as_blob)
            || self.current_requests.contains_key(&as_hash_seq)
            || self.scheduled_requests.contains_key(&as_hash_seq)
    }

    /// Check if this hash is currently being downloaded.
    fn is_current_request(&self, hash: Hash) -> bool {
        let as_blob = DownloadKind::Blob { hash };
        let as_hash_seq = DownloadKind::HashSeq { hash };
        self.current_requests.contains_key(&as_blob)
            || self.current_requests.contains_key(&as_hash_seq)
    }

    /// Remove a hash from the scheduled queue.
    fn unschedule(&mut self, hash: Hash) -> Option<(DownloadKind, PendingRequestInfo)> {
        let as_blob = DownloadKind::Blob { hash };
        let as_hash_seq = DownloadKind::HashSeq { hash };
        let info = match self.scheduled_requests.remove(&as_blob) {
            Some(req) => Some(req),
            None => self.scheduled_requests.remove(&as_hash_seq),
        };
        if let Some(info) = info {
            let kind = self.scheduled_request_queue.remove(&info.delay_key);
            let kind = kind.into_inner();
            Some((kind, info))
        } else {
            None
        }
    }

    /// Handle receiving a new connection.
    fn on_connection_ready(&mut self, node: NodeId, result: anyhow::Result<D::Connection>) {
        match result {
            Ok(connection) => {
                trace!(%node, "connected to node");
                let drop_key = self.goodbye_nodes_queue.insert(node, IDLE_PEER_TIMEOUT);
                self.nodes
                    .insert(node, ConnectionInfo::new_idle(connection, drop_key));
                self.on_node_ready(node);
            }
            Err(err) => {
                debug!(%node, %err, "connection to node failed")
            }
        }
    }

    /// Called after the connection to a node is established, and after finishing a download.
    ///
    /// Starts the next provider hash download, if there is one.
    fn on_node_ready(&mut self, node: NodeId) {
        // Get the next provider hash for this node.
        let Some(hash) = self.providers.get_next_provider_hash_for_node(&node) else {
            return;
        };

        if self.is_current_request(hash) {
            return;
        }

        let Some(conn) = self.get_node_connection_for_download(&node) else {
            return;
        };

        let Some((kind, info)) = self.unschedule(hash) else {
            debug_assert!(
                false,
                "invalid state: expected {hash:?} to be scheduled, but it wasn't"
            );
            return;
        };

        let PendingRequestInfo {
            intents,
            remaining_retries,
            ..
        } = info;

        self.start_download(kind, node, conn, remaining_retries, intents);
    }

    fn on_download_completed(
        &mut self,
        kind: DownloadKind,
        result: Result<TempTag, FailureAction>,
    ) {
        // first remove the request
        let info = self
            .current_requests
            .remove(&kind)
            .expect("request was active");

        // update the active requests for this node
        let ActiveRequestInfo {
            intents,
            node,
            mut remaining_retries,
            ..
        } = info;

        let node_info = self
            .nodes
            .get_mut(&node)
            .expect("node exists in the mapping");
        node_info.state = match &node_info.state {
            PeerState::Busy { active_requests } => {
                match NonZeroUsize::new(active_requests.get() - 1) {
                    Some(active_requests) => PeerState::Busy { active_requests },
                    None => {
                        // last request of the node was this one
                        let drop_key = self.goodbye_nodes_queue.insert(node, IDLE_PEER_TIMEOUT);
                        PeerState::Idle { drop_key }
                    }
                }
            }
            PeerState::Idle { .. } => unreachable!("node was busy"),
        };

        let hash = *kind.hash();

        let node_ready = match result {
            Ok(tt) => {
                debug!(%node, ?kind, "download completed");
                for sender in intents.into_values() {
                    let _ = sender.send(Ok(tt.clone()));
                }
                true
            }
            Err(FailureAction::AbortRequest(reason)) => {
                debug!(%node, ?kind, %reason, "aborting request");
                for sender in intents.into_values() {
                    let _ = sender.send(Err(anyhow::anyhow!("request aborted")));
                }
                true
            }
            Err(FailureAction::DropPeer(reason)) => {
                debug!(%node, ?kind, %reason, "node will be dropped");
                if let Some(_connection) = node_info.conn.take() {
                    // TODO(@divma): this will fail open streams, do we want this?
                    // connection.close(..)
                }
                false
            }
            Err(FailureAction::RetryLater(reason)) => {
                // check if the download can be retried
                if remaining_retries > 0 {
                    debug!(%node, ?kind, %reason, "download attempt failed");
                    remaining_retries -= 1;
                    let next_node = self.get_best_candidate(kind.hash());
                    self.schedule_request(kind, remaining_retries, next_node, intents);
                } else {
                    warn!(%node, ?kind, %reason, "download failed");
                    for sender in intents.into_values() {
                        let _ = sender.send(Err(anyhow::anyhow!("download ran out of attempts")));
                    }
                }
                false
            }
        };

        if !self.is_needed(hash) {
            self.providers.remove(hash)
        }
        if node_ready {
            self.on_node_ready(node);
        }
    }

    /// A scheduled request is ready to be processed.
    ///
    /// The node that was initially selected is used if possible. Otherwise we try to get a new
    /// node
    fn on_scheduled_request_ready(&mut self, kind: DownloadKind, info: PendingRequestInfo) {
        let PendingRequestInfo {
            intents,
            mut remaining_retries,
            next_node,
            ..
        } = info;

        // first try with the node that was initially assigned
        if let Some((node_id, conn)) = next_node.and_then(|node_id| {
            self.get_node_connection_for_download(&node_id)
                .map(|conn| (node_id, conn))
        }) {
            return self.start_download(kind, node_id, conn, remaining_retries, intents);
        }

        // we either didn't have a node or the node is busy or dialing. In any case try to get
        // another node
        let next_node = match self.get_best_candidate(kind.hash()) {
            None => None,
            Some(node_id) => {
                // optimistically check if the node could do the request right away
                match self.get_node_connection_for_download(&node_id) {
                    Some(conn) => {
                        return self.start_download(kind, node_id, conn, remaining_retries, intents)
                    }
                    None => Some(node_id),
                }
            }
        };

        // we tried to get a node to perform this request but didn't get one, so now this attempt
        // is failed
        if remaining_retries > 0 {
            remaining_retries -= 1;
            self.schedule_request(kind, remaining_retries, next_node, intents);
        } else {
            // check if this hash is needed in some form, otherwise remove it from providers
            let hash = *kind.hash();
            if !self.is_needed(hash) {
                self.providers.remove(hash)
            }
            // request can't be retried
            for sender in intents.into_values() {
                let _ = sender.send(Err(anyhow::anyhow!("download ran out of attempts")));
            }
            debug!(?kind, "download ran out of attempts")
        }
    }

    /// Start downloading from the given node.
    fn start_download(
        &mut self,
        kind: DownloadKind,
        node: NodeId,
        conn: D::Connection,
        remaining_retries: u8,
        intents: HashMap<Id, oneshot::Sender<DownloadResult>>,
    ) {
        debug!(%node, ?kind, "starting download");
        let cancellation = CancellationToken::new();
        let info = ActiveRequestInfo {
            intents,
            remaining_retries,
            cancellation,
            node,
        };
        let cancellation = info.cancellation.clone();
        self.current_requests.insert(kind.clone(), info);

        let get = self.getter.get(kind.clone(), conn);
        let fut = async move {
            // NOTE: it's an open question if we should do timeouts at this point. Considerations from @Frando:
            // > at this stage we do not know the size of the download, so the timeout would have
            // > to be so large that it won't be useful for non-huge downloads. At the same time,
            // > this means that a super slow node would block a download from succeeding for a long
            // > time, while faster nodes could be readily available.
            // As a conclusion, timeouts should be added only after downloads are known to be bounded
            let res = tokio::select! {
                _ = cancellation.cancelled() => Err(FailureAction::AbortRequest(anyhow::anyhow!("cancelled"))),
                res = get => res
            };

            (kind, res)
        };

        self.in_progress_downloads.spawn_local(fut);
    }

    /// Schedule a request for later processing.
    fn schedule_request(
        &mut self,
        kind: DownloadKind,
        remaining_retries: u8,
        next_node: Option<NodeId>,
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
            next_node,
        };
        debug!(?kind, ?info, "request scheduled");
        self.scheduled_requests.insert(kind, info);
    }

    /// Gets the [`Dialer::Connection`] for a node if it's connected and has capacity for another
    /// request. In this case, the count of active requests for the node is incremented.
    fn get_node_connection_for_download(&mut self, node: &NodeId) -> Option<D::Connection> {
        let info = self.nodes.get_mut(node)?;
        let connection = info.conn.as_ref()?;
        // check if the node can be sent another request
        match &mut info.state {
            PeerState::Busy { active_requests } => {
                if !self
                    .concurrency_limits
                    .node_at_request_capacity(active_requests.get())
                {
                    *active_requests = active_requests.saturating_add(1);
                    Some(connection.clone())
                } else {
                    None
                }
            }
            PeerState::Idle { drop_key } => {
                // node is no longer idle
                self.goodbye_nodes_queue.remove(drop_key);
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

    /// Get the total number of connected and dialing nodes.
    fn connections_count(&self) -> usize {
        let connected_nodes = self
            .nodes
            .values()
            .filter(|info| info.conn.is_some())
            .count();
        let dialing_nodes = self.dialer.pending_count();
        connected_nodes + dialing_nodes
    }

    #[allow(clippy::unused_async)]
    async fn shutdown(self) {
        debug!("shutting down");
        // TODO(@divma): how to make sure the download futures end gracefully?
    }
}

/// Map of potential providers for a hash.
#[derive(Default, Debug)]
pub struct ProviderMap {
    /// Candidates to download a hash.
    candidates: HashMap<Hash, HashMap<NodeId, Role>>,
    /// Ordered list of provider hashes per node.
    ///
    /// I.e. blobs we assume the node can provide.
    provider_hashes_by_node: HashMap<NodeId, VecDeque<Hash>>,
}

struct ProviderIter<'a> {
    inner: Option<std::collections::hash_map::Iter<'a, NodeId, Role>>,
}

impl<'a> Iterator for ProviderIter<'a> {
    type Item = (&'a NodeId, &'a Role);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.as_mut().and_then(|iter| iter.next())
    }
}

impl ProviderMap {
    /// Get candidates to download this hash.
    fn get_candidates(&self, hash: &Hash) -> impl Iterator<Item = (&NodeId, &Role)> {
        let inner = self.candidates.get(hash).map(|nodes| nodes.iter());
        ProviderIter { inner }
    }

    /// Register nodes for a hash. Should only be done for hashes we care to download.
    fn add_nodes(&mut self, hash: Hash, nodes: &[NodeInfo]) {
        let entry = self.candidates.entry(hash).or_default();
        for node in nodes {
            entry
                .entry(node.node_id)
                .and_modify(|role| *role = (*role).max(node.role))
                .or_insert(node.role);
            if let Role::Provider = node.role {
                self.provider_hashes_by_node
                    .entry(node.node_id)
                    .or_default()
                    .push_back(hash);
            }
        }
    }

    /// Get the next provider hash for a node.
    ///
    /// I.e. get the next hash that was added with [`PeerRole::Provider`] for this node.
    fn get_next_provider_hash_for_node(&mut self, node: &NodeId) -> Option<Hash> {
        let hash = self
            .provider_hashes_by_node
            .get(node)
            .and_then(|hashes| hashes.front())
            .copied();
        if let Some(hash) = hash {
            self.move_hash_to_back(node, hash);
        }
        hash
    }

    /// Signal the registry that this hash is no longer of interest.
    fn remove(&mut self, hash: Hash) {
        if let Some(nodes) = self.candidates.remove(&hash) {
            for node in nodes.keys() {
                if let Some(hashes) = self.provider_hashes_by_node.get_mut(node) {
                    hashes.retain(|h| *h != hash);
                }
            }
        }
    }

    /// Move a hash to the back of the provider queue for a node.
    fn move_hash_to_back(&mut self, node: &NodeId, hash: Hash) {
        let hashes = self.provider_hashes_by_node.get_mut(node);
        if let Some(hashes) = hashes {
            debug_assert_eq!(hashes.front(), Some(&hash));
            if !hashes.is_empty() {
                hashes.rotate_left(1);
            }
        }
    }
}

impl Dialer for iroh_gossip::net::util::Dialer {
    type Connection = quinn::Connection;

    fn queue_dial(&mut self, node_id: NodeId) {
        self.queue_dial(node_id, &iroh_bytes::protocol::ALPN)
    }

    fn pending_count(&self) -> usize {
        self.pending_count()
    }

    fn is_pending(&self, node: &NodeId) -> bool {
        self.is_pending(node)
    }
}
