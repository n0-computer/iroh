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
    fmt,
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
    util::{progress::ProgressSender, SetTagOption, TagSet},
    TempTag,
};

mod get;
mod invariants;
mod progress;
mod test;

use self::progress::{BroadcastProgressSender, ProgressSubscriber, ProgressTracker};

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
    ///
    /// Note that this limit is not strictly enforced, and not checked in
    /// [`Service::check_invariants`]. A certain hash can exceed this limit in a valid way if some
    /// of its providers are dialed for another hash. However, once the limit is reached,
    /// no new dials will be initiated for the hash.
    fn at_dials_per_hash_capacity(&self, concurrent_dials: usize) -> bool {
        concurrent_dials >= self.max_concurrent_dials_per_hash
    }
}

/// Configuration for retry behavior of the [`Downloader`].
#[derive(Debug)]
pub struct RetryConfig {
    /// Maximum number of retry attempts for a node that failed to dial or failed with IO errors.
    pub max_retries_per_node: u32,
    /// The initial delay to wait before retrying a node. On subsequent failures, the retry delay
    /// will be multiplied with the number of failed retries.
    pub initial_retry_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries_per_node: 6,
            initial_retry_delay: Duration::from_millis(500),
        }
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

    /// Switch from [`BlobFormat::Raw`] to [`BlobFormat::HashSeq`] and vice-versa.
    fn with_format_switched(&self) -> Self {
        let format = match self.format() {
            BlobFormat::Raw => BlobFormat::HashSeq,
            BlobFormat::HashSeq => BlobFormat::Raw,
        };
        Self(HashAndFormat::new(self.hash(), format))
    }
}

impl fmt::Display for DownloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:?}", self.0.hash.fmt_short(), self.0.format)
    }
}

/// The result of a download request, as returned to the application code.
type ExternalDownloadResult = Result<Stats, DownloadError>;

/// The result of a download request, as used in this module.
type InternalDownloadResult = Result<Stats, FailureAction>;

/// Error returned when a download could not be completed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DownloadError {
    /// Failed to download from any provider
    #[error("Failed to complete download")]
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
    /// Create a new Downloader with the default [`ConcurrencyLimits`] and [`RetryConfig`].
    pub fn new<S>(store: S, endpoint: MagicEndpoint, rt: LocalPoolHandle) -> Self
    where
        S: Store,
    {
        Self::with_config(store, endpoint, rt, Default::default(), Default::default())
    }

    /// Create a new Downloader with custom [`ConcurrencyLimits`] and [`RetryConfig`].
    pub fn with_config<S>(
        store: S,
        endpoint: MagicEndpoint,
        rt: LocalPoolHandle,
        concurrency_limits: ConcurrencyLimits,
        retry_config: RetryConfig,
    ) -> Self
    where
        S: Store,
    {
        let me = endpoint.node_id().fmt_short();
        let (msg_tx, msg_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);
        let dialer = iroh_net::dialer::Dialer::new(endpoint);

        let create_future = move || {
            let getter = get::IoGetter {
                store: store.clone(),
            };

            let service = Service::new(
                store,
                getter,
                dialer,
                concurrency_limits,
                retry_config,
                msg_rx,
            );

            service.run().instrument(error_span!("downloader", %me))
        };
        rt.spawn_pinned(create_future);
        Self {
            next_id: Arc::new(AtomicU64::new(0)),
            msg_tx,
        }
    }

    /// Queue a download.
    pub async fn queue(&self, request: impl Into<DownloadRequest>) -> DownloadHandle {
        let request = request.into();
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
    /// Declare that nodes have a certain hash and can be used for downloading.
    NodesHave { hash: Hash, nodes: Vec<NodeId> },
    /// Cancel an intent. The associated request will be cancelled when the last intent is
    /// cancelled.
    CancelIntent { id: IntentId, kind: DownloadKind },
}

#[derive(derive_more::Debug)]
struct IntentHandlers {
    #[debug("oneshot::Sender<DownloadResult>")]
    on_finish: oneshot::Sender<ExternalDownloadResult>,
    on_progress: Option<ProgressSubscriber>,
}

/// Information about a request.
#[derive(Debug, Default)]
struct RequestInfo {
    /// Registered intents with progress senders and result callbacks.
    intents: HashMap<IntentId, IntentHandlers>,
    /// Tags requested for the blob to be created once the download finishes.
    tags: TagSet,
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

#[derive(Debug, Default)]
struct RetryState {
    /// How many times did we retry this node?
    retry_count: u32,
    /// Whether the node is currently queued for retry.
    retry_is_queued: bool,
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

    /// Returns `true` if the node is currently idle.
    fn is_idle(&self) -> bool {
        matches!(self.state, ConnectedState::Idle { .. })
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
    WaitForRetry,
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
    /// Configuration for retry behavior.
    retry_config: RetryConfig,
    /// Channel to receive messages from the service's handle.
    msg_rx: mpsc::Receiver<Message>,
    /// Connected nodes
    connected_nodes: HashMap<NodeId, ConnectionInfo<D::Connection>>,
    /// Nodes for which we track retries
    retrying_nodes: HashMap<NodeId, RetryState>,
    /// Delay queue for retrying failed nodes
    retry_nodes_queue: delay_queue::DelayQueue<NodeId>,
    /// Delay queue for dropping idle nodes
    goodbye_nodes_queue: delay_queue::DelayQueue<NodeId>,
    /// Queue of pending downloads.
    queue: Queue,
    /// Information about pending and active requests
    requests: HashMap<DownloadKind, RequestInfo>,
    /// State of running downloads
    active_requests: HashMap<DownloadKind, ActiveRequestInfo>,
    /// Tasks for currently running transfers.
    in_progress_downloads: JoinSet<(DownloadKind, InternalDownloadResult)>,
    /// Progress tracker
    progress_tracker: ProgressTracker,
    /// The [`Store`] where tags are saved after a download completes.
    db: DB,
}
impl<DB: Store, G: Getter<Connection = D::Connection>, D: Dialer> Service<G, D, DB> {
    fn new(
        db: DB,
        getter: G,
        dialer: D,
        concurrency_limits: ConcurrencyLimits,
        retry_config: RetryConfig,
        msg_rx: mpsc::Receiver<Message>,
    ) -> Self {
        Service {
            getter,
            dialer,
            msg_rx,
            concurrency_limits,
            retry_config,
            connected_nodes: Default::default(),
            retrying_nodes: Default::default(),
            providers: Default::default(),
            requests: Default::default(),
            retry_nodes_queue: delay_queue::DelayQueue::default(),
            goodbye_nodes_queue: delay_queue::DelayQueue::default(),
            active_requests: Default::default(),
            in_progress_downloads: Default::default(),
            progress_tracker: ProgressTracker::new(),
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
                            trace!(%kind, "tick: transfer completed");
                            self.on_download_completed(kind, result).await;
                        }
                        Err(err) => {
                            warn!(?err, "transfer task panicked");
                        }
                    }
                }
                Some(expired) = self.retry_nodes_queue.next() => {
                    let node = expired.into_inner();
                    trace!(node=%node.fmt_short(), "tick: retry node");
                    self.on_retry_wait_elapsed(node);
                }
                Some(expired) = self.goodbye_nodes_queue.next() => {
                    let node = expired.into_inner();
                    trace!(node=%node.fmt_short(), "tick: goodbye node");
                    self.remove_node(node, "idle_disconnect");
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
            Message::NodesHave { hash, nodes } => {
                let updated = self
                    .providers
                    .add_nodes_if_hash_exists(hash, nodes.iter().cloned());
                if updated {
                    self.queue.unpark_hash(hash);
                }
            }
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
        debug!(%kind, nodes=?nodes.iter().map(|n| n.node_id.fmt_short()).collect::<Vec<_>>(), "queue intent");

        // store the download intent
        let intent_handlers = IntentHandlers {
            on_finish,
            on_progress: progress,
        };

        // early exit if no providers.
        if nodes.is_empty() && self.providers.get_candidates(&kind.hash()).next().is_none() {
            self.finalize_download(
                kind,
                [(intent_id, intent_handlers)].into(),
                Err(DownloadError::NoProviders),
            );
            return;
        }

        // add the nodes to the provider map
        let updated = self
            .providers
            .add_hash_with_nodes(kind.hash(), nodes.iter().map(|n| n.node_id));

        // queue the transfer (if not running) or attach to transfer progress (if already running)
        if self.active_requests.contains_key(&kind) {
            // the transfer is already running, so attach the progress sender
            if let Some(on_progress) = &intent_handlers.on_progress {
                // this is async because it sends the current state over the progress channel
                if let Err(err) = self
                    .progress_tracker
                    .subscribe(kind, on_progress.clone())
                    .await
                {
                    debug!(?err, %kind, "failed to subscribe progress sender to transfer");
                }
            }
        } else {
            // the transfer is not running.
            if updated && self.queue.is_parked(&kind) {
                // the transfer is on hold for pending retries, and we added new nodes, so move back to queue.
                self.queue.unpark(&kind);
            } else if !self.queue.contains(&kind) {
                // the transfer is not yet queued: add to queue.
                self.queue.insert(kind);
            }
        }

        // store the request info
        let request_info = self.requests.entry(kind).or_default();
        request_info.intents.insert(intent_id, intent_handlers);
        if let Some(tag) = &tag {
            request_info.tags.insert(tag.clone());
        }
    }

    /// Cancels a download intent.
    ///
    /// This removes the intent from the list of intents for the `kind`. If the removed intent was
    /// the last one for the `kind`, this means that the download is no longer needed. In this
    /// case, the `kind` will be removed from the list of pending downloads - and, if the download was
    /// already started, the download task will be cancelled.
    ///
    /// The method is async because it will send a final abort event on the progress sender.
    async fn handle_cancel_download(&mut self, intent_id: IntentId, kind: DownloadKind) {
        let Entry::Occupied(mut occupied_entry) = self.requests.entry(kind) else {
            warn!(%kind, %intent_id, "cancel download called for unknown download");
            return;
        };

        let request_info = occupied_entry.get_mut();
        if let Some(handlers) = request_info.intents.remove(&intent_id) {
            handlers.on_finish.send(Err(DownloadError::Cancelled)).ok();

            if let Some(sender) = handlers.on_progress {
                self.progress_tracker.unsubscribe(&kind, &sender);
                sender
                    .send(DownloadProgress::Abort(
                        anyhow::Error::from(DownloadError::Cancelled).into(),
                    ))
                    .await
                    .ok();
            }
        }

        if request_info.intents.is_empty() {
            occupied_entry.remove();
            if let Entry::Occupied(occupied_entry) = self.active_requests.entry(kind) {
                occupied_entry.remove().cancellation.cancel();
            } else {
                self.queue.remove(&kind);
            }
            self.remove_kind_from_provider_map(&kind);
        }
    }

    /// Handle receiving a new connection.
    fn on_connection_ready(&mut self, node: NodeId, result: anyhow::Result<D::Connection>) {
        match result {
            Ok(connection) => {
                trace!(node=%node.fmt_short(), "connected to node");
                let drop_key = self.goodbye_nodes_queue.insert(node, IDLE_PEER_TIMEOUT);
                self.connected_nodes
                    .insert(node, ConnectionInfo::new_idle(connection, drop_key));
            }
            Err(err) => {
                debug!(%node, %err, "connection to node failed");
                self.retry_node(node);
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
            .connected_nodes
            .get_mut(&node)
            .expect("node exists in the mapping");

        let node_action = match &result {
            Ok(_) => {
                debug!(%kind, node=%node.fmt_short(), "transfer finished");
                NodeAction::Keep
            }
            Err(FailureAction::Cancelled) => {
                debug!(%kind, node=%node.fmt_short(), "download cancelled");
                NodeAction::Keep
            }
            Err(FailureAction::AbortRequest(reason)) => {
                debug!(%kind, node=%node.fmt_short(), %reason, "aborting request");
                NodeAction::Keep
            }
            Err(FailureAction::DropPeer(reason)) => {
                debug!(%kind, node=%node.fmt_short(), %reason, "node will be dropped");
                NodeAction::Drop
            }
            Err(FailureAction::RetryLater(reason)) => {
                debug!(%kind, node=%node.fmt_short(), %reason, "download failed but retry later");
                NodeAction::RetryLater
            }
        };

        match node_action {
            NodeAction::Keep => {
                // clear retry state if operation was successful
                if result.is_ok() {
                    self.retrying_nodes.remove(&node);
                }
                // cleanup provider map
                if !self.queue.contains(&kind.with_format_switched()) {
                    self.providers.remove_hash_from_node(&kind.hash(), &node);
                }
                // update node busy/idle state
                node_info.state = match &node_info.state {
                    ConnectedState::Busy { active_requests } => {
                        match NonZeroUsize::new(active_requests.get() - 1) {
                            Some(active_requests) => ConnectedState::Busy { active_requests },
                            None => {
                                // last request of the node was this one, switch to idle
                                let drop_key =
                                    self.goodbye_nodes_queue.insert(node, IDLE_PEER_TIMEOUT);
                                ConnectedState::Idle { drop_key }
                            }
                        }
                    }
                    ConnectedState::Idle { .. } => unreachable!("node was busy"),
                };
            }
            NodeAction::RetryLater => self.retry_node(node),
            NodeAction::Drop => self.remove_node(node, "explicit_drop"),
        }

        let finalize = result.is_ok() || !self.providers.has_candidates(&kind.hash());

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
            self.queue.insert_front(kind);
        }
    }

    /// Finalize a download.
    ///
    /// This triggers the intent return channels, and removes the download from the progress tracker
    /// and provider map.
    fn finalize_download(
        &mut self,
        kind: DownloadKind,
        intents: HashMap<IntentId, IntentHandlers>,
        result: ExternalDownloadResult,
    ) {
        self.progress_tracker.remove(&kind);
        self.remove_kind_from_provider_map(&kind);
        let result = result.map_err(|_| DownloadError::DownloadFailed);
        for (_id, handlers) in intents.into_iter() {
            handlers.on_finish.send(result.clone()).ok();
        }
    }

    fn on_retry_wait_elapsed(&mut self, node: NodeId) {
        let Some(state) = self.retrying_nodes.get_mut(&node) else {
            warn!(node=%node.fmt_short(), "expected node from retry queue to be in retrying_nodes, but isn't");
            return;
        };
        let Some(hashes) = self.providers.node_hash.get(&node) else {
            self.remove_node(node, "obsolete_after_retry");
            return;
        };
        state.retry_is_queued = false;
        for hash in hashes {
            self.queue.unpark_hash(*hash);
        }
    }

    /// Start the next downloads, or dial nodes, if limits permit and the queue is non-empty.
    ///
    /// This is called after all actions. If there is nothing to do, it will return cheaply.
    /// Otherwise, we will check the next hash in the queue, and:
    /// * start the transfer if we are connected to a provider and limits are ok
    /// * or, connect to a provider, if there is one we are not dialing yet and limits are ok
    /// * or, disconnect an idle node if it would allow us to connect to a provider,
    /// * or, if all providers are waiting for retry, park the download
    /// * or, if our limits are reached, do nothing for now
    ///
    /// The download requests will only be popped from the queue once we either start the transfer
    /// from a connected node [`NextStep::StartTransfer`], or if we abort the download on
    /// [`NextStep::OutOfProviders`]. In all other cases, the request is kept at the top of the
    /// queue, so the next call to [`Self::process_head`] will evaluate the situation again - and
    /// so forth, until either [`NextStep::StartTransfer`] or [`NextStep::OutOfProviders`] is
    /// reached.
    fn process_head(&mut self) {
        // start as many queued downloads as allowed by the request limits.
        loop {
            let Some(kind) = self.queue.front().cloned() else {
                break;
            };

            let next_step = self.next_step(&kind);
            trace!(%kind, ?next_step, "process_head");

            match next_step {
                NextStep::Wait => break,
                NextStep::StartTransfer(node) => {
                    let _ = self.queue.pop_front();
                    debug!(%kind, node=%node.fmt_short(), "start transfer");
                    self.start_download(kind, node);
                }
                NextStep::Dial(node) => {
                    debug!(%kind, node=%node.fmt_short(), "dial node");
                    self.dialer.queue_dial(node);
                }
                NextStep::DialQueuedDisconnect(node, key) => {
                    let idle_node = self.goodbye_nodes_queue.remove(&key).into_inner();
                    let info = self.connected_nodes.remove(&idle_node);
                    debug_assert!(
                        info.map(|i| i.is_idle()).unwrap_or(false),
                        "node picked from goodbye queue to be idle"
                    );
                    debug!(%kind, node=%node.fmt_short(), idle_node=%idle_node.fmt_short(), "dial node, disconnect idle node)");
                    self.dialer.queue_dial(node);
                }
                NextStep::Park => {
                    debug!(%kind, "park download: all providers waiting for retry");
                    self.queue.park_front();
                }
                NextStep::OutOfProviders => {
                    debug!(%kind, "abort download: out of providers");
                    let _ = self.queue.pop_front();
                    let info = self.requests.remove(&kind).expect("queued downloads exist");
                    self.finalize_download(kind, info.intents, Err(DownloadError::NoProviders));
                }
            }
        }
    }

    fn retry_node(&mut self, node: NodeId) {
        self.connected_nodes.remove(&node);
        let retry_state = self.retrying_nodes.entry(node).or_default();
        retry_state.retry_count += 1;
        if retry_state.retry_count <= self.retry_config.max_retries_per_node {
            // node can be retried
            debug!(node=%node.fmt_short(), retry_count=retry_state.retry_count, "queue retry");
            let timeout = self.retry_config.initial_retry_delay * retry_state.retry_count;
            self.retry_nodes_queue.insert(node, timeout);
            retry_state.retry_is_queued = true;
        } else {
            // node is dead
            self.remove_node(node, "retries_exceeded");
        }
    }

    /// Calculate the next step needed to proceed the download for `kind`.
    ///
    /// This is called once `kind` has reached the head of the queue, see [`Self::process_head`].
    /// It can be called repeatedly, and does nothing on itself, only calculate what *should* be
    /// done next.
    ///
    /// See [`NextStep`] for details on the potential next steps returned from this method.
    fn next_step(&self, kind: &DownloadKind) -> NextStep {
        // If the total requests capacity is reached, we have to wait until an active request
        // completes.
        if self
            .concurrency_limits
            .at_requests_capacity(self.active_requests.len())
        {
            return NextStep::Wait;
        };

        let mut candidates = self.providers.get_candidates(&kind.hash()).peekable();
        // If we have no provider candidates for this download, there's nothing else we can do.
        if candidates.peek().is_none() {
            return NextStep::OutOfProviders;
        }

        // Track if there is provider node to which we are connected and which is not at its request capacity.
        // If there are more than one, take the one with the least amount of running transfers.
        let mut best_connected: Option<(NodeId, usize)> = None;
        // Track if there is a disconnected provider node to which we can potentially connect.
        let mut next_to_dial = None;
        // Track the number of provider nodes that are currently being dialed.
        let mut currently_dialing = 0;
        // Track if we have at least one provider node which is currently at its request capacity.
        // If this is the case, we will never return [`NextStep::OutOfProviders`] but [`NextStep::Wait`]
        // instead, because we can still try that node once it has finished its work.
        let mut has_exhausted_provider = false;
        // Track if we have at least one provider node that is currently in the retry queue.
        let mut has_retrying_provider = false;

        for node in candidates {
            match self.node_state(node) {
                NodeState::Connected(info) => {
                    let active_requests = info.active_requests();
                    if self
                        .concurrency_limits
                        .node_at_request_capacity(active_requests)
                    {
                        has_exhausted_provider = true;
                    } else {
                        best_connected = Some(match best_connected.take() {
                            Some(old) if old.1 <= active_requests => old,
                            _ => (*node, active_requests),
                        });
                    }
                }
                NodeState::Dialing => {
                    currently_dialing += 1;
                }
                NodeState::WaitForRetry => {
                    has_retrying_provider = true;
                }
                NodeState::Disconnected => {
                    if next_to_dial.is_none() {
                        next_to_dial = Some(node);
                    }
                }
            }
        }

        let has_dialing = currently_dialing > 0;

        // If we have a connected provider node with free slots, use it!
        if let Some((node, _active_requests)) = best_connected {
            NextStep::StartTransfer(node)
        }
        // If we have a node which could be dialed: Check capacity and act accordingly.
        else if let Some(node) = next_to_dial {
            // We check if the dial capacity for this hash is exceeded: We only start new dials for
            // the hash if we are below the limit.
            //
            // If other requests trigger dials for providers of this hash, the limit may be
            // exceeded, but then we just don't start further dials and wait until one completes.
            let at_dial_capacity = has_dialing
                && self
                    .concurrency_limits
                    .at_dials_per_hash_capacity(currently_dialing);
            // Check if we reached the global connection limit.
            let at_connections_capacity = self.at_connections_capacity();

            // All slots are free: We can dial our candidate.
            if !at_connections_capacity && !at_dial_capacity {
                NextStep::Dial(*node)
            }
            // The hash has free dial capacity, but the global connection capacity is reached.
            // But if we have idle nodes, we will disconnect the longest idling node, and then dial our
            // candidate.
            else if at_connections_capacity
                && !at_dial_capacity
                && !self.goodbye_nodes_queue.is_empty()
            {
                let key = self.goodbye_nodes_queue.peek().expect("just checked");
                NextStep::DialQueuedDisconnect(*node, key)
            }
            // No dial capacity, and no idling nodes: We have to wait until capacity is freed up.
            else {
                NextStep::Wait
            }
        }
        // If we have pending dials to candidates, or connected candidates which are busy
        // with other work: Wait for one of these to become available.
        else if has_exhausted_provider || has_dialing {
            NextStep::Wait
        }
        // All providers are in the retry queue: Park this request until they can be tried again.
        else if has_retrying_provider {
            NextStep::Park
        }
        // We have no candidates left: Nothing more to do.
        else {
            NextStep::OutOfProviders
        }
    }

    /// Start downloading from the given node.
    ///
    /// Panics if hash is not in self.requests or node is not in self.nodes.
    fn start_download(&mut self, kind: DownloadKind, node: NodeId) {
        let node_info = self.connected_nodes.get_mut(&node).expect("node exists");
        let request_info = self.requests.get(&kind).expect("hash exists");

        // create a progress sender and subscribe all intents to the progress sender
        let subscribers = request_info
            .intents
            .values()
            .flat_map(|state| state.on_progress.clone());
        let progress_sender = self.progress_tracker.track(kind, subscribers);

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
        .instrument(error_span!("transfer", %kind, node=%node.fmt_short()));
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

    fn remove_node(&mut self, node: NodeId, reason: &'static str) {
        debug!(node = %node.fmt_short(), %reason, "remove node");
        self.connected_nodes.remove(&node);
        self.retrying_nodes.remove(&node);
        self.providers.remove_node(&node);
    }

    fn node_state<'a>(&'a self, node: &NodeId) -> NodeState<'a, D::Connection> {
        if let Some(info) = self.connected_nodes.get(node) {
            NodeState::Connected(info)
        } else if self.dialer.is_pending(node) {
            NodeState::Dialing
        } else {
            match self.retrying_nodes.get(node) {
                Some(state) if state.retry_is_queued => NodeState::WaitForRetry,
                _ => NodeState::Disconnected,
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
        let connected_nodes = self.connected_nodes.values().count();
        let dialing_nodes = self.dialer.pending_count();
        connected_nodes + dialing_nodes
    }

    /// Remove a `kind` from the [`ProviderMap`], but only if [`Self::queue`] does not contain the
    /// hash at all, even with the other [`BlobFormat`].
    fn remove_kind_from_provider_map(&mut self, kind: &DownloadKind) {
        if !self.queue.contains_hash(kind.hash()) {
            self.providers.remove_hash(&kind.hash());
        }
    }

    #[allow(clippy::unused_async)]
    async fn shutdown(self) {
        debug!("shutting down");
        // TODO(@divma): how to make sure the download futures end gracefully?
    }
}

/// The next step needed to continue a download.
///
/// See [`Service::next_step`] for details.
#[derive(Debug)]
enum NextStep {
    /// Provider connection is ready, initiate the transfer.
    StartTransfer(NodeId),
    /// Start to dial `NodeId`.
    ///
    /// This means: We have no non-exhausted connection to a provider node, but a free connection slot
    /// and a provider node we are not yet connected to.
    Dial(NodeId),
    /// Start to dial `NodeId`, but first disconnect the idle node behind [`delay_queue::Key`] in
    /// [`Service::goodbye_nodes_queue`] to free up a connection slot.
    DialQueuedDisconnect(NodeId, delay_queue::Key),
    /// Resource limits are exhausted, do nothing for now and wait until a slot frees up.
    Wait,
    /// All providers are currently in a retry timeout. Park the download aside, and move
    /// to the next download in the queue.
    Park,
    /// We have tried all available providers. There is nothing else to do.
    OutOfProviders,
}

#[derive(Debug)]
enum NodeAction {
    Keep,
    Drop,
    RetryLater,
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

    /// Whether we have any candidates to download this hash.
    pub fn has_candidates(&self, hash: &Hash) -> bool {
        self.hash_node
            .get(hash)
            .map(|nodes| !nodes.is_empty())
            .unwrap_or(false)
    }

    /// Register nodes for a hash. Should only be done for hashes we care to download.
    ///
    /// Returns `true` if new providers were added.
    fn add_hash_with_nodes(&mut self, hash: Hash, nodes: impl Iterator<Item = NodeId>) -> bool {
        let mut updated = false;
        let hash_entry = self.hash_node.entry(hash).or_default();
        for node in nodes {
            updated |= hash_entry.insert(node);
            let node_entry = self.node_hash.entry(node).or_default();
            node_entry.insert(hash);
        }
        updated
    }

    /// Register nodes for a hash, but only if the hash is already in our queue.
    ///
    /// Returns `true` if a new node was added.
    fn add_nodes_if_hash_exists(
        &mut self,
        hash: Hash,
        nodes: impl Iterator<Item = NodeId>,
    ) -> bool {
        let mut updated = false;
        if let Some(hash_entry) = self.hash_node.get_mut(&hash) {
            for node in nodes {
                updated |= hash_entry.insert(node);
                let node_entry = self.node_hash.entry(node).or_default();
                node_entry.insert(hash);
            }
        }
        updated
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

/// The queue of requested downloads.
///
/// This manages two datastructures:
/// * The main queue, a FIFO queue where each item can only appear once.
///   New downloads are pushed to the back of the queue, and the next download to process is popped
///   from the front.
/// * The parked set, a hash set. Items can be moved from the main queue into the parked set.
///   Parked items will not be popped unless they are moved back into the main queue.
#[derive(Debug, Default)]
struct Queue {
    main: LinkedHashSet<DownloadKind>,
    parked: HashSet<DownloadKind>,
}

impl Queue {
    /// Peek at the front element of the main queue.
    pub fn front(&self) -> Option<&DownloadKind> {
        self.main.front()
    }

    #[cfg(any(test, debug_assertions))]
    pub fn iter_parked(&self) -> impl Iterator<Item = &DownloadKind> {
        self.parked.iter()
    }

    #[cfg(any(test, debug_assertions))]
    pub fn iter(&self) -> impl Iterator<Item = &DownloadKind> {
        self.main.iter().chain(self.parked.iter())
    }

    /// Returns `true` if either the main queue or the parked set contain a download.
    pub fn contains(&self, kind: &DownloadKind) -> bool {
        self.main.contains(kind) || self.parked.contains(kind)
    }

    /// Returns `true` if either the main queue or the parked set contain a download for a hash.
    pub fn contains_hash(&self, hash: Hash) -> bool {
        let as_raw = HashAndFormat::raw(hash).into();
        let as_hash_seq = HashAndFormat::hash_seq(hash).into();
        self.contains(&as_raw) || self.contains(&as_hash_seq)
    }

    /// Returns `true` if a download is in the parked set.
    pub fn is_parked(&self, kind: &DownloadKind) -> bool {
        self.parked.contains(kind)
    }

    /// Insert an element at the back of the main queue.
    pub fn insert(&mut self, kind: DownloadKind) {
        if !self.main.contains(&kind) {
            self.main.insert(kind);
        }
    }

    /// Insert an element at the front of the main queue.
    pub fn insert_front(&mut self, kind: DownloadKind) {
        if !self.main.contains(&kind) {
            self.main.insert(kind);
        }
        self.main.to_front(&kind);
    }

    /// Dequeue the first download of the main queue.
    pub fn pop_front(&mut self) -> Option<DownloadKind> {
        self.main.pop_front()
    }

    /// Move the front item of the main queue into the parked set.
    pub fn park_front(&mut self) {
        if let Some(item) = self.pop_front() {
            self.parked.insert(item);
        }
    }

    /// Move a download from the parked set to the front of the main queue.
    pub fn unpark(&mut self, kind: &DownloadKind) {
        if self.parked.remove(kind) {
            self.main.insert(*kind);
            self.main.to_front(kind);
        }
    }

    /// Move any download for a hash from the parked set to the main queue.
    pub fn unpark_hash(&mut self, hash: Hash) {
        let as_raw = HashAndFormat::raw(hash).into();
        let as_hash_seq = HashAndFormat::hash_seq(hash).into();
        self.unpark(&as_raw);
        self.unpark(&as_hash_seq);
    }

    /// Remove a download from both the main queue and the parked set.
    pub fn remove(&mut self, kind: &DownloadKind) -> bool {
        self.main.remove(kind) || self.parked.remove(kind)
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
