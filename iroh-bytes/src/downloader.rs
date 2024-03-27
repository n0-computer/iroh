//! Handle downloading blobs and collections concurrently and from nodes.
//!
//! The [`Downloader`] interacts with four main components to this end.
//! - [`Dialer`]: Used to queue opening connections to nodes we need to perform downloads.
//! - `ProviderMap`: Where the downloader obtains information about nodes that could be
//!   used to perform a download.
//! - [`Store`]: Where data is stored.
//!
//! Once a download request is received, the logic is as follows:
//! 1. The `ProviderMap` is queried for nodes. From these nodes some are selected
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
    collections::{hash_map::Entry, HashMap, HashSet},
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use futures::{future::LocalBoxFuture, FutureExt, StreamExt};
use hashlink::LinkedHashSet;
use iroh_base::hash::{BlobFormat, Hash, HashAndFormat};
use iroh_net::{MagicEndpoint, NodeAddr, NodeId};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, task::LocalPoolHandle, time::delay_queue};
use tracing::{debug, error_span, trace, warn, Instrument};

use crate::{
    get::{db::DownloadProgress, Stats},
    store::Store,
    util::{progress::ProgressSender, SetTagOption},
    Tag, TempTag,
};

mod get;
mod invariants;
mod progress;
mod test;

use self::progress::{BroadcastProgressSender, ProgressSubscriber, ProgressTracker};

// TODO: In which cases should we retry downloads?
// /// Number of retries for connecting to a node.
// const INITIAL_RETRY_COUNT: u8 = 4;
// /// Initial delay when reconnecting to a node.
// const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Duration for which we keep nodes connected after they were last useful to us.
const IDLE_PEER_TIMEOUT: Duration = Duration::from_secs(10);
/// Capacity of the channel used to communicate between the [`Downloader`] and the [`Service`].
const SERVICE_CHANNEL_CAPACITY: usize = 128;

/// Identifier for a download intent.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Display)]
pub struct IntentId(pub u64);

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
    /// The request was cancelled by us.
    Cancelled,
    /// An error ocurred that prevents the request from being retried at all.
    AbortRequest(anyhow::Error),
    /// An error occurred that suggests the node should not be used in general.
    DropPeer(anyhow::Error),
    /// An error occurred in which neither the node nor the request are at fault.
    RetryLater(anyhow::Error),
}

/// Future of a get request.
type GetFut = LocalBoxFuture<'static, InternalDownloadResult>;

/// Trait modelling performing a single request over a connection. This allows for IO-less testing.
pub trait Getter {
    /// Type of connections the Getter requires to perform a download.
    type Connection;
    /// Return a future that performs the download using the given connection.
    fn get(
        &mut self,
        kind: DownloadKind,
        conn: Self::Connection,
        progress_sender: BroadcastProgressSender,
    ) -> GetFut;
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
    /// Maximum number of nodes to dial concurrently for a single request.
    pub max_concurrent_dials_per_hash: usize,
}

impl Default for ConcurrencyLimits {
    fn default() -> Self {
        // these numbers should be checked against a running node and might depend on platform
        ConcurrencyLimits {
            max_concurrent_requests: 50,
            max_concurrent_requests_per_node: 4,
            max_open_connections: 25,
            max_concurrent_dials_per_hash: 5,
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

    /// Checks if the maximum number of concurrent dials per hash has been reached.
    fn at_dials_per_hash_capacity(&self, concurrent_dials: usize) -> bool {
        concurrent_dials >= self.max_concurrent_dials_per_hash
    }
}

/// A download request.
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    kind: DownloadKind,
    nodes: Vec<NodeAddr>,
    tag: Option<SetTagOption>,
    progress: Option<ProgressSubscriber>,
}

impl DownloadRequest {
    /// Create a new download request.
    ///
    /// The blob will be auto-tagged after the download to prevent it from being garbage collected.
    pub fn new(
        resource: impl Into<DownloadKind>,
        nodes: impl IntoIterator<Item = impl Into<NodeAddr>>,
    ) -> Self {
        Self {
            kind: resource.into(),
            nodes: nodes.into_iter().map(|n| n.into()).collect(),
            tag: Some(SetTagOption::Auto),
            progress: None,
        }
    }

    /// Create a new untagged download request.
    ///
    /// The blob will not be tagged, so only use this if the blob is already protected from garbage
    /// collection through other means.
    pub fn untagged(
        resource: HashAndFormat,
        nodes: impl IntoIterator<Item = impl Into<NodeAddr>>,
    ) -> Self {
        let mut r = Self::new(resource, nodes);
        r.tag = None;
        r
    }

    /// Set a tag to apply to the blob after download.
    pub fn tag(mut self, tag: SetTagOption) -> Self {
        self.tag = Some(tag);
        self
    }

    /// Pass a progress sender to receive progress updates.
    pub fn progress_sender(mut self, sender: ProgressSubscriber) -> Self {
        self.progress = Some(sender);
        self
    }
}

/// The kind of resource to download.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy, derive_more::From, derive_more::Into)]
pub struct DownloadKind(HashAndFormat);

impl DownloadKind {
    /// Get the hash of this download
    pub const fn hash(&self) -> Hash {
        self.0.hash
    }

    /// Get the format of this download
    pub const fn format(&self) -> BlobFormat {
        self.0.format
    }

    /// Get the [`HashAndFormat`] pair of this download
    pub const fn hash_and_format(&self) -> HashAndFormat {
        self.0
    }

    /// Short format string for this download
    pub fn fmt_short(&self) -> String {
        format!("{}:{:?}", self.0.hash.fmt_short(), self.0.format)
    }
}

// For readability. In the future we might care about some data reporting on a successful download
// or kind of failure in the error case.
type ExternalDownloadResult = Result<Stats, DownloadError>;

// The outcome of a single get transfer operation.
type InternalDownloadResult = Result<Stats, FailureAction>;

/// Error returned when a kind could not be downloaded.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DownloadError {
    /// Failed to download from any provider
    #[error("Failed to download kind")]
    DownloadFailed,
    /// The download was cancelled by us
    #[error("Download cancelled by us")]
    Cancelled,
    /// No provider nodes found
    #[error("No provider nodes found")]
    NoProviders,
    /// Failed to receive response from service.
    #[error("Failed to receive response from download service")]
    ActorClosed,
}

/// Handle to interact with a download request.
#[derive(Debug)]
pub struct DownloadHandle {
    /// Id used to identify the request in the [`Downloader`].
    id: IntentId,
    /// Kind of download.
    kind: DownloadKind,
    /// Receiver to retrieve the return value of this download.
    receiver: oneshot::Receiver<ExternalDownloadResult>,
}

impl std::future::Future for DownloadHandle {
    type Output = ExternalDownloadResult;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll::*;
        // make it easier on holders of the handle to poll the result, removing the receiver error
        // from the middle
        match self.receiver.poll_unpin(cx) {
            Ready(Ok(result)) => Ready(result),
            Ready(Err(_recv_err)) => Ready(Err(DownloadError::ActorClosed)),
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
    pub fn new<S>(store: S, endpoint: MagicEndpoint, rt: LocalPoolHandle) -> Self
    where
        S: Store,
    {
        let me = endpoint.node_id().fmt_short();
        let (msg_tx, msg_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
        let dialer = iroh_net::dialer::Dialer::new(endpoint);

        let create_future = move || {
            let concurrency_limits = ConcurrencyLimits::default();
            let getter = get::IoGetter {
                store: store.clone(),
            };

            let service = Service::new(store, getter, dialer, concurrency_limits, msg_rx);

            service.run().instrument(error_span!("downloader", %me))
        };
        rt.spawn_pinned(create_future);
        Self {
            next_id: Arc::new(AtomicU64::new(0)),
            msg_tx,
        }
    }

    /// Queue a download.
    pub async fn queue(&self, request: DownloadRequest) -> DownloadHandle {
        // let kind = kind.into();
        let kind = request.kind;
        let intent_id = IntentId(self.next_id.fetch_add(1, Ordering::SeqCst));
        let (sender, receiver) = oneshot::channel();
        let handle = DownloadHandle {
            id: intent_id,
            kind,
            receiver,
        };
        let msg = Message::Queue {
            on_finish: sender,
            request,
            intent_id,
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
    pub async fn cancel(&self, handle: DownloadHandle) {
        let DownloadHandle {
            id,
            kind,
            receiver: _,
        } = handle;
        let msg = Message::CancelIntent { id, kind };
        if let Err(send_err) = self.msg_tx.send(msg).await {
            let msg = send_err.0;
            debug!(?msg, "cancel not sent");
        }
    }

    /// Declare that certains nodes can be used to download a hash.
    ///
    /// Note that this does not start a download, but only provides new nodes to already queued
    /// downloads. Use [`Self::queue`] to queue a download.
    pub async fn nodes_have(&mut self, hash: Hash, nodes: Vec<NodeId>) {
        let msg = Message::NodesHave { hash, nodes };
        if let Err(send_err) = self.msg_tx.send(msg).await {
            let msg = send_err.0;
            debug!(?msg, "nodes have not been sent")
        }
    }
}

/// Messages the service can receive.
#[derive(derive_more::Debug)]
enum Message {
    /// Queue a download intent.
    Queue {
        request: DownloadRequest,
        #[debug(skip)]
        on_finish: oneshot::Sender<ExternalDownloadResult>,
        intent_id: IntentId,
    },
    /// Add information about a node.
    NodesHave { hash: Hash, nodes: Vec<NodeId> },
    /// Cancel an intent. The associated request will be cancelled when the last intent is
    /// cancelled.
    CancelIntent { id: IntentId, kind: DownloadKind },
}

#[derive(derive_more::Debug)]
struct IntentCallbacks {
    #[debug("oneshot::Sender<DownloadResult>")]
    on_finish: oneshot::Sender<ExternalDownloadResult>,
    on_progress: Option<ProgressSubscriber>,
}

/// Information about a request.
#[derive(Debug)]
struct RequestInfo {
    intents: HashSet<IntentId>,
    tags: TagSet,
}

impl RequestInfo {
    pub fn new(intent: IntentId, tag: Option<SetTagOption>) -> Self {
        let mut tags = TagSet::default();
        if let Some(tag) = tag {
            tags.insert(tag);
        }
        Self {
            intents: [intent].into_iter().collect(),
            tags,
        }
    }
}

/// Information about a request in progress.
#[derive(derive_more::Debug)]
struct ActiveRequestInfo {
    /// Token used to cancel the future doing the request.
    #[debug(skip)]
    cancellation: CancellationToken,
    /// Peer doing this request attempt.
    node: NodeId,
    /// Temporary tag to protect the partial blob from being garbage collected.
    temp_tag: TempTag,
}

/// State of the connection to this node.
#[derive(derive_more::Debug)]
struct ConnectionInfo<Conn> {
    /// Connection to this node.
    #[debug(skip)]
    conn: Conn,
    /// State of this node.
    state: ConnectedState,
}

impl<Conn> ConnectionInfo<Conn> {
    /// Create a new idle node.
    fn new_idle(connection: Conn, drop_key: delay_queue::Key) -> Self {
        ConnectionInfo {
            conn: connection,
            state: ConnectedState::Idle { drop_key },
        }
    }

    /// Count of active requests for the node.
    fn active_requests(&self) -> usize {
        match self.state {
            ConnectedState::Busy { active_requests } => active_requests.get(),
            ConnectedState::Idle { .. } => 0,
        }
    }
}

/// State of a connected node.
#[derive(derive_more::Debug)]
enum ConnectedState {
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

#[derive(Debug)]
enum NodeState<'a, Conn> {
    Connected(&'a ConnectionInfo<Conn>),
    Dialing,
    Disconnected,
}

#[derive(Debug)]
struct Service<G: Getter, D: Dialer, DB: Store> {
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
    /// Active connections
    nodes: HashMap<NodeId, ConnectionInfo<D::Connection>>,
    /// Queue to manage dropping nodes.
    goodbye_nodes_queue: delay_queue::DelayQueue<NodeId>,
    /// Queue of pending downloads.
    queue: LinkedHashSet<DownloadKind>,
    /// Information about pending and active requests
    requests: HashMap<DownloadKind, RequestInfo>,
    /// State of running downloads
    active_requests: HashMap<DownloadKind, ActiveRequestInfo>,
    /// Tasks for currently running transfers.
    in_progress_downloads: JoinSet<(DownloadKind, InternalDownloadResult)>,
    /// Progress tracker
    progress_tracker: ProgressTracker,
    /// Registered intents with progress senders and result callbacks.
    intents: HashMap<IntentId, IntentCallbacks>,
    db: DB,
}
impl<DB: Store, G: Getter<Connection = D::Connection>, D: Dialer> Service<G, D, DB> {
    fn new(
        db: DB,
        getter: G,
        dialer: D,
        concurrency_limits: ConcurrencyLimits,
        msg_rx: mpsc::Receiver<Message>,
    ) -> Self {
        Service {
            getter,
            dialer,
            msg_rx,
            concurrency_limits,
            nodes: Default::default(),
            providers: Default::default(),
            requests: Default::default(),
            goodbye_nodes_queue: delay_queue::DelayQueue::default(),
            active_requests: Default::default(),
            in_progress_downloads: Default::default(),
            progress_tracker: ProgressTracker::new(),
            intents: Default::default(),
            queue: Default::default(),
            db,
        }
    }

    /// Main loop for the service.
    async fn run(mut self) {
        loop {
            trace!("wait for tick");
            tokio::select! {
                Some((node, conn_result)) = self.dialer.next() => {
                    trace!(node=%node.fmt_short(), "tick: connection ready");
                    self.on_connection_ready(node, conn_result);
                }
                maybe_msg = self.msg_rx.recv() => {
                    trace!(msg=?maybe_msg, "tick: message received");
                    match maybe_msg {
                        Some(msg) => self.handle_message(msg).await,
                        None => return self.shutdown().await,
                    }
                }
                Some(res) = self.in_progress_downloads.join_next(), if !self.in_progress_downloads.is_empty() => {
                    match res {
                        Ok((kind, result)) => {
                            trace!(kind=%kind.fmt_short(), "tick: transfer completed");
                            self.on_download_completed(kind, result).await;
                        }
                        Err(err) => {
                            warn!(?err, "transfer task paniced");
                        }
                    }
                }
                Some(expired) = self.goodbye_nodes_queue.next() => {
                    let node = expired.into_inner();
                    self.nodes.remove(&node);
                    trace!(node=%node.fmt_short(), "tick: goodbye node");
                }
            }

            self.process_head();

            #[cfg(any(test, debug_assertions))]
            self.check_invariants();
        }
    }

    /// Handle receiving a [`Message`].
    ///
    // This is called in the actor loop, and only async because subscribing to an existing transfer
    // sends the initial state.
    async fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Queue {
                request,
                on_finish,
                intent_id,
            } => {
                self.handle_queue_new_download(request, intent_id, on_finish)
                    .await
            }
            Message::CancelIntent { id, kind } => self.handle_cancel_download(id, kind).await,
            Message::NodesHave { hash, nodes } => self
                .providers
                .add_nodes_if_hash_exists(hash, nodes.iter().cloned()),
        }
    }

    /// Handle a [`Message::Queue`].
    ///
    /// If this intent maps to a request that already exists, it will be registered with it. If the
    /// request is new it will be scheduled.
    async fn handle_queue_new_download(
        &mut self,
        request: DownloadRequest,
        intent_id: IntentId,
        on_finish: oneshot::Sender<ExternalDownloadResult>,
    ) {
        let DownloadRequest {
            kind,
            nodes,
            tag,
            progress,
        } = request;
        debug!(kind=%kind.fmt_short(), nodes=?nodes.iter().map(|n| n.node_id.fmt_short()).collect::<Vec<_>>(), "queue intent");
        self.providers
            .add_hash_with_nodes(kind.hash(), nodes.iter().map(|n| n.node_id));
        let intent_callbacks = IntentCallbacks {
            on_finish,
            on_progress: progress,
        };
        self.requests
            .entry(kind)
            .and_modify(|info| {
                info.intents.insert(intent_id);
                if let Some(tag) = &tag {
                    info.tags.insert(tag.clone());
                }
            })
            .or_insert_with(|| RequestInfo::new(intent_id, tag));

        if self.active_requests.contains_key(&kind) {
            // the transfer is already running, so attach the progress sender
            if let Some(on_progress) = &intent_callbacks.on_progress {
                // this is async because it send the current state over the progress channel.
                if let Err(err) = self
                    .progress_tracker
                    .subscribe(kind, on_progress.clone())
                    .await
                {
                    debug!(?err, kind=%kind.fmt_short(), "failed to subscribe progress sender to transfer");
                }
            }
        } else {
            // the transfer is not yet running, so add to queue.
            // this is a noop if the transfer is already queued.
            self.queue.insert(kind);
        }
        // store the download intent
        self.intents.insert(intent_id, intent_callbacks);
    }

    /// Cancels the download request.
    ///
    /// This removes the registered download intent and, depending on its state, it will either
    /// remove it from the scheduled requests, or cancel the future.o send abort message on progress sender
    ///
    /// The method is async because it will send a final abort event on the progress sender.
    async fn handle_cancel_download(&mut self, intent_id: IntentId, kind: DownloadKind) {
        let mut no_more_intents = false;
        if let Entry::Occupied(mut occupied_entry) = self.requests.entry(kind) {
            let intents = &mut occupied_entry.get_mut().intents;
            intents.remove(&intent_id);
            if intents.is_empty() {
                no_more_intents = true;
                occupied_entry.remove();
            }
        }

        if let Some(callbacks) = self.intents.remove(&intent_id) {
            callbacks.on_finish.send(Err(DownloadError::Cancelled)).ok();
            if let Some(sender) = callbacks.on_progress {
                self.progress_tracker.unsubscribe(&kind, &sender);
                sender
                    .send(DownloadProgress::Abort(
                        anyhow::Error::from(DownloadError::Cancelled).into(),
                    ))
                    .await
                    .ok();
            }
        }

        if no_more_intents {
            if let Entry::Occupied(occupied_entry) = self.active_requests.entry(kind) {
                occupied_entry.remove().cancellation.cancel();
            } else {
                self.queue.remove(&kind);
            }
            self.providers.remove_hash(&kind.hash());
        }
    }

    /// Handle receiving a new connection.
    fn on_connection_ready(&mut self, node: NodeId, result: anyhow::Result<D::Connection>) {
        match result {
            Ok(connection) => {
                trace!(node=%node.fmt_short(), "connected to node");
                let drop_key = self.goodbye_nodes_queue.insert(node, IDLE_PEER_TIMEOUT);
                self.nodes
                    .insert(node, ConnectionInfo::new_idle(connection, drop_key));
            }
            Err(err) => {
                debug!(%node, %err, "connection to node failed")
            }
        }
    }

    async fn on_download_completed(&mut self, kind: DownloadKind, result: InternalDownloadResult) {
        // first remove the request
        let active_request_info = self
            .active_requests
            .remove(&kind)
            .expect("request was active");

        // get general request info
        let request_info = self.requests.remove(&kind).expect("request was active");

        let ActiveRequestInfo { node, temp_tag, .. } = active_request_info;

        // get node info
        let node_info = self
            .nodes
            .get_mut(&node)
            .expect("node exists in the mapping");

        let (keep_node, _retry_node) = match &result {
            Ok(_) => {
                debug!(kind=%kind.fmt_short(), node=%node.fmt_short(), "transfer finished");
                (true, false)
            }
            Err(FailureAction::Cancelled) => {
                debug!(kind=%kind.fmt_short(), node=%node.fmt_short(), "download cancelled");
                (true, false)
            }
            Err(FailureAction::AbortRequest(reason)) => {
                debug!(kind=%kind.fmt_short(), node=%node.fmt_short(), %reason, "aborting request");
                (true, false)
            }
            Err(FailureAction::DropPeer(reason)) => {
                debug!(kind=%kind.fmt_short(), node=%node.fmt_short(), %reason, "node will be dropped");
                (false, false)
            }
            Err(FailureAction::RetryLater(reason)) => {
                debug!(kind=%kind.fmt_short(), node=%node.fmt_short(), %reason, "download failed but retry later");
                // TODO: How do we want to actually do retries?
                // Right now they are skipped (same as abort request)
                (true, true)
            }
        };

        if keep_node {
            // TODO: Handle retries somehow.
            // if retry_node { ..}
            self.providers.remove_hash_from_node(&kind.hash(), &node);
            // update node busy/idle state
            node_info.state = match &node_info.state {
                ConnectedState::Busy { active_requests } => {
                    match NonZeroUsize::new(active_requests.get() - 1) {
                        Some(active_requests) => ConnectedState::Busy { active_requests },
                        None => {
                            // last request of the node was this one, switch to idle
                            let drop_key = self.goodbye_nodes_queue.insert(node, IDLE_PEER_TIMEOUT);
                            ConnectedState::Idle { drop_key }
                        }
                    }
                }
                ConnectedState::Idle { .. } => unreachable!("node was busy"),
            };
        } else {
            // this drops the connection, thus disconnects
            self.nodes.remove(&node);
            self.providers.remove_node(&node);
        }

        let finalize =
            result.is_ok() || self.providers.get_candidates(&kind.hash()).next().is_none();

        if finalize {
            let result = result.map_err(|_| DownloadError::DownloadFailed);
            if result.is_ok() {
                request_info.tags.apply(&self.db, kind.0).await.ok();
            }
            drop(temp_tag);
            self.finalize_download(kind, request_info.intents, result);
        } else {
            // reinsert the download at the front of the queue to try from the next node
            self.requests.insert(kind, request_info);
            self.queue.insert(kind);
            self.queue.to_front(&kind);
        }
    }

    /// Finalize a download.
    ///
    /// This triggers the intent return channels, and removes the download from the progress tracker
    /// and provider map.
    fn finalize_download(
        &mut self,
        kind: DownloadKind,
        intents: HashSet<IntentId>,
        result: ExternalDownloadResult,
    ) {
        self.progress_tracker.remove(&kind);
        self.providers.remove_hash(&kind.hash());
        let intents = intents.into_iter().flat_map(|id| self.intents.remove(&id));
        let result = result.map_err(|_| DownloadError::DownloadFailed);
        for intent in intents {
            intent.on_finish.send(result.clone()).ok();
        }
    }

    /// Start the next downloads, or dial nodes, if limits permit and the queue is non-empty.
    ///
    /// This is called after all actions. If there is nothing to do, it will return cheaply.
    /// Otherwise, we will check the next hash in the queue, and:
    /// * start the transfer if we are connected to a provider and limits are ok
    /// * or, connect to a provider, if there is one we are not dialing yet and limits are ok
    /// * or, disconnect an idle node if it would allow us to connect to a provider,
    /// * or, if our limits are reached, do nothing for now
    fn process_head(&mut self) {
        // start as many queued downloads as allowed by the request limits.
        loop {
            // if queue empty: break.
            let Some(kind) = self.queue.front().cloned() else {
                break;
            };

            let next_step = self.next_step(&kind);
            trace!(kind=%kind.fmt_short(), ?next_step, "check queue head");

            match next_step {
                // We are waiting either for dialing to finish, or for a full node to finish a
                // transfer, so nothing to do for us at the moment.
                NextStep::Wait => break,
                NextStep::StartTransfer(node) => {
                    let _ = self.queue.pop_front();
                    debug!(kind=%kind.fmt_short(), node=%node.fmt_short(), "start transfer");
                    self.start_download(kind, node);
                }
                NextStep::Dial(node) => {
                    debug!(node=%node.fmt_short(), kind=%kind.fmt_short(), "dial node");
                    self.dialer.queue_dial(node);
                }
                NextStep::DialAfterIdleDisconnect(node, key) => {
                    let expired = self.goodbye_nodes_queue.remove(&key);
                    let expired_node = expired.into_inner();
                    debug!(node=%expired_node.fmt_short(), "disconnect idle node to make room for next connection");
                    let info = self.nodes.remove(&expired_node);
                    debug_assert!(
                        matches!(
                            info,
                            Some(ConnectionInfo {
                                state: ConnectedState::Idle { .. },
                                ..
                            })
                        ),
                        "node picked from goodbye queue to be idle"
                    );
                    debug!(node=%node.fmt_short(), kind=%kind.fmt_short(), "dial node");
                    self.dialer.queue_dial(node);
                }
                NextStep::OutOfProviders => {
                    debug!(kind=%kind.fmt_short(), "abort download: out of providers");
                    let _ = self.queue.pop_front();
                    let info = self.requests.remove(&kind).expect("queued downloads exist");
                    self.finalize_download(kind, info.intents, Err(DownloadError::NoProviders));
                }
            }
        }
    }

    fn next_step(&self, kind: &DownloadKind) -> NextStep {
        if self
            .concurrency_limits
            .at_requests_capacity(self.active_requests.len())
        {
            return NextStep::Wait;
        };

        let mut candidates = self.providers.get_candidates(&kind.hash()).peekable();
        if candidates.peek().is_none() {
            return NextStep::OutOfProviders;
        }

        let mut available = vec![];
        let mut currently_dialing = 0;
        let mut has_exhausted = false;
        let mut next_to_dial = None;
        for node in candidates {
            match self.node_state(node) {
                NodeState::Connected(info) => {
                    let active_requests = info.active_requests();
                    if self
                        .concurrency_limits
                        .node_at_request_capacity(active_requests)
                    {
                        has_exhausted = true;
                    } else {
                        available.push((node, active_requests));
                    }
                }
                NodeState::Dialing => {
                    currently_dialing += 1;
                }
                NodeState::Disconnected => {
                    if next_to_dial.is_none() {
                        next_to_dial = Some(node);
                    }
                }
            }
        }

        let has_dialing = currently_dialing > 0;

        if !available.is_empty() {
            available.sort_unstable_by_key(|(_node, req_count)| *req_count);
            let (node, _) = available.last().expect("just checked");
            NextStep::StartTransfer(**node)
        } else if let Some(node) = next_to_dial {
            let at_dial_capacity = has_dialing
                && self
                    .concurrency_limits
                    .at_dials_per_hash_capacity(currently_dialing);
            let at_connections_capacity = self.at_connections_capacity();

            if !at_connections_capacity && !at_dial_capacity {
                NextStep::Dial(*node)
            } else if at_connections_capacity
                && !at_dial_capacity
                && !self.goodbye_nodes_queue.is_empty()
            {
                let key = self.goodbye_nodes_queue.peek().expect("just checked");
                NextStep::DialAfterIdleDisconnect(*node, key)
            } else {
                NextStep::Wait
            }
        } else if has_exhausted || has_dialing {
            NextStep::Wait
        } else {
            NextStep::OutOfProviders
        }
    }

    /// Start downloading from the given node.
    ///
    /// Panics if hash is not in self.requests or node is not in self.nodes.
    fn start_download(&mut self, kind: DownloadKind, node: NodeId) {
        let node_info = self.nodes.get_mut(&node).expect("node exists");
        let request_info = self.requests.get(&kind).expect("hash exists");

        // create a progress sender and subscribe all intents to the progress sender
        let subscribers = request_info
            .intents
            .iter()
            .flat_map(|id| self.intents.get(id))
            .flat_map(|state| state.on_progress.clone());
        let progress_sender = self.progress_tracker.create(kind, subscribers);

        // create the active request state
        let cancellation = CancellationToken::new();
        let temp_tag = self.db.temp_tag(kind.0);
        let state = ActiveRequestInfo {
            cancellation: cancellation.clone(),
            node,
            temp_tag,
        };
        let conn = node_info.conn.clone();
        let get_fut = self.getter.get(kind, conn, progress_sender);
        let fut = async move {
            // NOTE: it's an open question if we should do timeouts at this point. Considerations from @Frando:
            // > at this stage we do not know the size of the download, so the timeout would have
            // > to be so large that it won't be useful for non-huge downloads. At the same time,
            // > this means that a super slow node would block a download from succeeding for a long
            // > time, while faster nodes could be readily available.
            // As a conclusion, timeouts should be added only after downloads are known to be bounded
            let res = tokio::select! {
                _ = cancellation.cancelled() => Err(FailureAction::Cancelled),
                res = get_fut => res
            };
            trace!("transfer finished");

            (kind, res)
        }
        .instrument(error_span!("transfer", node=%node.fmt_short(), kind=%kind.fmt_short()));
        node_info.state = match &node_info.state {
            ConnectedState::Busy { active_requests } => ConnectedState::Busy {
                active_requests: active_requests.saturating_add(1),
            },
            ConnectedState::Idle { drop_key } => {
                self.goodbye_nodes_queue.remove(drop_key);
                ConnectedState::Busy {
                    active_requests: NonZeroUsize::new(1).expect("clearly non zero"),
                }
            }
        };
        self.active_requests.insert(kind, state);
        self.in_progress_downloads.spawn_local(fut);
    }

    fn node_state<'a>(&'a self, node: &NodeId) -> NodeState<'a, D::Connection> {
        if let Some(info) = self.nodes.get(node) {
            NodeState::Connected(info)
        } else if self.dialer.is_pending(node) {
            NodeState::Dialing
        } else {
            NodeState::Disconnected
        }
    }

    /// Check if we have maxed our connection capacity.
    fn at_connections_capacity(&self) -> bool {
        self.concurrency_limits
            .at_connections_capacity(self.connections_count())
    }

    /// Get the total number of connected and dialing nodes.
    fn connections_count(&self) -> usize {
        let connected_nodes = self.nodes.values().count();
        let dialing_nodes = self.dialer.pending_count();
        connected_nodes + dialing_nodes
    }

    #[allow(clippy::unused_async)]
    async fn shutdown(self) {
        debug!("shutting down");
        // TODO(@divma): how to make sure the download futures end gracefully?
    }
}

#[derive(Debug)]
enum NextStep {
    StartTransfer(NodeId),
    Dial(NodeId),
    DialAfterIdleDisconnect(NodeId, delay_queue::Key),
    Wait,
    OutOfProviders,
}

/// Map of potential providers for a hash.
#[derive(Default, Debug)]
struct ProviderMap {
    hash_node: HashMap<Hash, HashSet<NodeId>>,
    node_hash: HashMap<NodeId, HashSet<Hash>>,
}

impl ProviderMap {
    /// Get candidates to download this hash.
    pub fn get_candidates(&self, hash: &Hash) -> impl Iterator<Item = &NodeId> {
        self.hash_node
            .get(hash)
            .map(|nodes| nodes.iter())
            .into_iter()
            .flatten()
    }

    /// Register nodes for a hash. Should only be done for hashes we care to download.
    fn add_hash_with_nodes(&mut self, hash: Hash, nodes: impl Iterator<Item = NodeId>) {
        let hash_entry = self.hash_node.entry(hash).or_default();
        for node in nodes {
            hash_entry.insert(node);
            let node_entry = self.node_hash.entry(node).or_default();
            node_entry.insert(hash);
        }
    }

    /// Register nodes for a hash, but only if the hash is already in our queue.
    fn add_nodes_if_hash_exists(&mut self, hash: Hash, nodes: impl Iterator<Item = NodeId>) {
        if let Some(hash_entry) = self.hash_node.get_mut(&hash) {
            for node in nodes {
                hash_entry.insert(node);
                let node_entry = self.node_hash.entry(node).or_default();
                node_entry.insert(hash);
            }
        }
    }

    /// Signal the registry that this hash is no longer of interest.
    fn remove_hash(&mut self, hash: &Hash) {
        if let Some(nodes) = self.hash_node.remove(hash) {
            for node in nodes {
                if let Some(hashes) = self.node_hash.get_mut(&node) {
                    hashes.remove(hash);
                    if hashes.is_empty() {
                        self.node_hash.remove(&node);
                    }
                }
            }
        }
    }

    fn remove_node(&mut self, node: &NodeId) {
        if let Some(hashes) = self.node_hash.remove(node) {
            for hash in hashes {
                if let Some(nodes) = self.hash_node.get_mut(&hash) {
                    nodes.remove(node);
                    if nodes.is_empty() {
                        self.hash_node.remove(&hash);
                    }
                }
            }
        }
    }

    fn remove_hash_from_node(&mut self, hash: &Hash, node: &NodeId) {
        if let Some(nodes) = self.hash_node.get_mut(hash) {
            nodes.remove(node);
            if nodes.is_empty() {
                self.remove_hash(hash);
            }
        }
        if let Some(hashes) = self.node_hash.get_mut(node) {
            hashes.remove(hash);
            if hashes.is_empty() {
                self.remove_node(node);
            }
        }
    }
}

/// Helper struct to merge multiple tags for a blob.
#[derive(Debug, Default)]
struct TagSet {
    auto: bool,
    named: Vec<Tag>,
}

impl TagSet {
    /// Insert a new tag into the set.
    pub fn insert(&mut self, tag: SetTagOption) {
        match tag {
            SetTagOption::Auto => self.auto = true,
            SetTagOption::Named(tag) => {
                if !self.named.iter().any(|t| t == &tag) {
                    self.named.push(tag)
                }
            }
        }
    }

    /// Convert the [`TagSet`] into a list of [`SetTagOption`].
    pub fn into_tags(self) -> impl Iterator<Item = SetTagOption> {
        self.auto
            .then_some(SetTagOption::Auto)
            .into_iter()
            .chain(self.named.into_iter().map(SetTagOption::Named))
    }

    /// Apply the tags in the [`TagSet`] to the database.
    pub async fn apply<D: Store>(
        self,
        db: &D,
        hash_and_format: HashAndFormat,
    ) -> std::io::Result<()> {
        let tags = self.into_tags();
        for tag in tags {
            match tag {
                SetTagOption::Named(tag) => {
                    db.set_tag(tag, Some(hash_and_format)).await?;
                }
                SetTagOption::Auto => {
                    db.create_tag(hash_and_format).await?;
                }
            }
        }
        Ok(())
    }
}

impl Dialer for iroh_net::dialer::Dialer {
    type Connection = quinn::Connection;

    fn queue_dial(&mut self, node_id: NodeId) {
        self.queue_dial(node_id, crate::protocol::ALPN)
    }

    fn pending_count(&self) -> usize {
        self.pending_count()
    }

    fn is_pending(&self, node: &NodeId) -> bool {
        self.is_pending(node)
    }
}
