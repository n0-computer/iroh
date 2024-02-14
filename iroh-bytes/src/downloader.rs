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
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::{get::Stats, store::Store};
use futures::{future::LocalBoxFuture, FutureExt, StreamExt};
use iroh_base::timer::Timers;
use iroh_net::{MagicEndpoint, NodeId};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, task::LocalPoolHandle};
use tracing::{debug, error_span, trace, warn, Instrument};

mod get;
mod invariants;
mod progress;
mod state;
mod test;

use self::{
    progress::{BroadcastProgressSender, ProgressSubscriber, ProgressTracker},
    state::{
        ConcurrencyLimits, InEvent, IntentId, OutEvent, State, Timer, TransferId, TransferInfo,
    },
};

pub use self::progress::TransferState;
pub use self::state::{NodeHints, Resource, ResourceHints};

/// Number of retries initially assigned to a request.
const INITIAL_RETRY_COUNT: u8 = 4;
/// Duration for which we keep nodes connected after they were last useful to us.
const IDLE_PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Capacity of the channel used to comunicate between the [`Downloader`] and the [`Service`].
const SERVICE_CHANNEL_CAPACITY: usize = 128;
const PROGRESS_CHANNEL_CAP: usize = 1024;

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
    /// The peer doesn't have the requested content
    NotFound,
    /// We cancelled the transfer.
    Cancelled,
}

/// Future of a get request.
type GetFut = LocalBoxFuture<'static, Result<DownloadOutcome, FailureAction>>;

/// Trait modelling performing a single request over a connection. This allows for IO-less testing.
pub trait Getter {
    /// Type of connections the Getter requires to perform a download.
    type Connection;
    /// Return a future that performs the download using the given connection.
    fn get(
        &mut self,
        kind: Resource,
        conn: Self::Connection,
        progress_sender: BroadcastProgressSender,
    ) -> GetFut;
}

/// The outcome of a download operation.
type DownloadOutcome = Stats;
// For readability. In the future we might care about some data reporting on a successful download
// or kind of failure in the error case.
type DownloadResult = Result<DownloadOutcome, DownloadError>;

/// Type that is returned from a download request.
type DownloadRes = (TransferId, Result<DownloadOutcome, FailureAction>);

/// Error returned when a resource could not be downloaded.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DownloadError {
    /// Failed to download from any provider
    #[error("Failed to download resource")]
    DownloadFailed,
    /// Failed to receive response from service.
    #[error("Failed to receive response from download service")]
    ActorDied,
}

/// Handle to interact with a download request.
#[derive(Debug)]
pub struct DownloadHandle {
    /// Id used to identify the request in the [`Downloader`].
    id: IntentId,
    /// Kind of download.
    resource: Resource,
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
            Ready(Err(_recv_err)) => Ready(Err(DownloadError::ActorDied)),
            Pending => Pending,
        }
    }
}

/// A sender for progress events
// pub type DownloadProgressSender = flume::Sender<DownloadProgress>;

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
            let getter = get::IoGetter { store };

            let service = Service::new(getter, dialer, concurrency_limits, msg_rx);

            service.run().instrument(error_span!("downloader", %me))
        };
        rt.spawn_pinned(create_future);
        Self {
            next_id: Arc::new(AtomicU64::new(0)),
            msg_tx,
        }
    }

    /// Queue a download.
    pub async fn queue(
        &mut self,
        resource: Resource,
        hints: ResourceHints,
        on_progress: Option<ProgressSubscriber>,
    ) -> DownloadHandle {
        let id = IntentId(self.next_id.fetch_add(1, Ordering::SeqCst));

        let (sender, receiver) = oneshot::channel();
        let handle = DownloadHandle {
            id,
            resource,
            receiver,
        };
        let msg = Message::QueueResource {
            resource,
            intent: id,
            on_finish: sender,
            hints,
            on_progress,
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
            resource,
            receiver: _,
        } = handle;
        let msg = Message::CancelIntent {
            intent: id,
            resource,
        };
        if let Err(send_err) = self.msg_tx.send(msg).await {
            let msg = send_err.0;
            debug!(?msg, "cancel not sent");
        }
    }

    /// Declare that certains nodes can be used to download a hash.
    pub async fn add_node(&mut self, node: NodeId, hints: NodeHints) {
        let msg = Message::AddNodeHints { node, hints };
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
    QueueResource {
        resource: Resource,
        intent: IntentId,
        #[debug(skip)]
        on_finish: oneshot::Sender<DownloadResult>,
        hints: ResourceHints,
        on_progress: Option<ProgressSubscriber>,
    },
    /// Add information about a node.
    AddNodeHints { node: NodeId, hints: NodeHints },
    /// Cancel an intent. The associated request will be cancelled when the last intent is
    /// cancelled.
    CancelIntent {
        intent: IntentId,
        resource: Resource,
    },
}

#[derive(Debug)]
struct IntentData {
    on_finish: oneshot::Sender<DownloadResult>,
    on_progress: Option<ProgressSubscriber>,
}

#[derive(Debug)]
struct Service<G: Getter, D: Dialer> {
    /// The getter performs individual requests.
    getter: G,
    /// Dialer to get connections for required nodes.
    dialer: D,
    /// Channel to receive messages from the service's handle.
    msg_rx: mpsc::Receiver<Message>,
    /// Active connections
    conns: HashMap<NodeId, D::Connection>,
    /// Registered intents with progress senders and result callbacks.
    intents: HashMap<IntentId, IntentData>,
    /// Cancellation tokens for currently running transfers.
    transfer_controllers: HashMap<TransferId, TransferController>,
    /// Tasks for currently running transfers.
    transfer_tasks: JoinSet<DownloadRes>,
    /// State
    state: State,
    /// Timers
    timers: Timers<Timer>,
    /// Progress tracker
    progress_tracker: ProgressTracker,
}

#[derive(Debug)]
struct TransferController {
    cancel: CancellationToken,
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
            dialer,
            msg_rx,
            intents: Default::default(),
            transfer_controllers: HashMap::default(),
            transfer_tasks: Default::default(),
            state: State::new(concurrency_limits),
            timers: Default::default(),
            conns: Default::default(),
            progress_tracker: ProgressTracker::new(PROGRESS_CHANNEL_CAP),
        }
    }

    /// Main loop for the service.
    async fn run(mut self) {
        loop {
            tokio::select! {
                Some((node, conn_result)) = self.dialer.next() => {
                    trace!("tick: connection ready");
                    self.on_connection_ready(node, conn_result);
                }
                maybe_msg = self.msg_rx.recv() => {
                    trace!(msg=?maybe_msg, "tick: message received");
                    match maybe_msg {
                        Some(msg) => self.handle_message(msg).await,
                        None => return self.shutdown().await,
                    }
                }
                Some(res) = self.transfer_tasks.join_next(), if !self.transfer_tasks.is_empty() => {
                    match res {
                        Ok((transfer_id, result)) => {
                            trace!("tick: download completed");
                            self.on_transfer_fut_ready(transfer_id, result);
                        }
                        Err(e) => {
                            warn!("transfer task join error: {:?}", e);
                        }
                    }
                }
                drain = self.timers.wait_and_drain() => {
                    trace!("tick: timer ready");
                    for (_instant, timer) in drain {
                        self.state.handle(InEvent::TimerExpired { timer });
                    }
                }
                _ = self.progress_tracker.recv() => {}
            }

            self.perform_actions();
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
            Message::QueueResource {
                resource,
                hints,
                intent,
                on_finish,
                on_progress,
            } => {
                // if the resource is currently being transferred, attach progress
                if let Some(on_progress) = &on_progress {
                    if let Some(transfer_id) = self.state.active_transfer_for_resource(&resource) {
                        self.progress_tracker
                            .subscribe(transfer_id, on_progress.clone())
                            .await;
                    }
                }

                // inform state about the newly queued resource
                self.state.handle(InEvent::AddResource {
                    resource,
                    hints,
                    intent,
                });

                // store the intent to later pass result and/or progress
                let state = IntentData {
                    on_finish,
                    on_progress,
                };
                self.intents.insert(intent, state);
            }
            Message::AddNodeHints { node, hints } => {
                self.state.handle(InEvent::AddNode { node, hints });
            }
            Message::CancelIntent { intent, resource } => {
                self.state
                    .handle(InEvent::CancelIntent { resource, intent });
            }
        }
    }

    fn perform_actions(&mut self) {
        let actions = self.state.events();
        // TODO: Can we avoid the alloc? We have a mutable borrow on state...
        let actions: Vec<_> = actions.collect();
        for action in actions.into_iter() {
            debug!("perform action: {action:?}");
            match action {
                OutEvent::StartTransfer { info, intents } => self.start_transfer(info, intents),
                OutEvent::StartConnect(node) => self.dialer.queue_dial(node),
                OutEvent::RegisterTimer(duration, timer) => self.timers.insert(
                    Instant::now()
                        .checked_add(duration)
                        .expect("duration is too long"),
                    timer,
                ),
                OutEvent::DropConnection(node) => {
                    let _ = self.conns.remove(&node);
                }
                OutEvent::CancelTransfer(id) => {
                    self.on_cancel(id);
                }
                OutEvent::TransferFinished {
                    transfer_id,
                    resource,
                    intents,
                    outcome,
                } => {
                    let outcome = outcome.map_err(|()| DownloadError::DownloadFailed);
                    self.on_transfer_finished(transfer_id, resource, intents, outcome);
                }
            }
        }
    }

    fn on_cancel(&mut self, transfer_id: TransferId) {
        let Some(transfer) = self.transfer_controllers.get(&transfer_id) else {
            warn!(?transfer_id, "cancelled download not in current_requests");
            debug_assert!(false, "cancelled download not in current_requests");
            return;
        };
        transfer.cancel.cancel();
    }

    /// Handle receiving a new connection.
    fn on_connection_ready(&mut self, node: NodeId, result: anyhow::Result<D::Connection>) {
        match result {
            Ok(connection) => {
                trace!(%node, "connected to node");
                self.conns.insert(node, connection);
                self.state.handle(InEvent::NodeConnected { node });
            }
            Err(err) => {
                debug!(%node, %err, "connection to node failed");
                self.state.handle(InEvent::NodeFailed { node });
            }
        }
    }

    fn on_transfer_fut_ready(
        &mut self,
        id: TransferId,
        result: Result<DownloadOutcome, FailureAction>,
    ) {
        // remove the cancellation token
        self.transfer_controllers.remove(&id);
        match result {
            Ok(outcome) => {
                // The transfer is finished, finalize and remove.
                self.state.handle(InEvent::TransferReady { id, outcome });
            }
            Err(failure) => {
                // The transfer failed. Inform state but do not remove yet because there's still a
                // possiblity for it to succeed. It will be removed in on_cancel.
                self.state.handle(InEvent::TransferFailed { id, failure });
            }
        }
    }

    fn on_transfer_finished(
        &mut self,
        transfer_id: TransferId,
        _resource: Resource,
        intent_ids: impl IntoIterator<Item = IntentId>,
        res: DownloadResult,
    ) {
        let intents = intent_ids
            .into_iter()
            .flat_map(|id| self.intents.remove(&id));
        for state in intents {
            let _ = state.on_finish.send(res.clone());
        }
        self.progress_tracker.remove(transfer_id);
    }

    /// Start downloading from the given node.
    fn start_transfer(&mut self, transfer: TransferInfo, intents: Vec<IntentId>) {
        let TransferInfo { id, resource, node } = transfer;
        debug!(?id, node = %node.fmt_short(), ?resource, "starting download");
        let cancellation = CancellationToken::new();
        let Some(conn) = self.conns.get(&node) else {
            warn!(?transfer, "starting download while node not connected");
            return;
        };

        // create a progress sender and subscribe all intents to the progress sender
        let subscribers = intents
            .into_iter()
            .flat_map(|id| self.intents.get(&id))
            .flat_map(|state| state.on_progress.clone());
        let progress_sender =
            self.progress_tracker
                .insert_with_subscribers(id, resource.hash(), subscribers);

        let state = TransferController {
            cancel: cancellation.clone(),
        };
        let get_fut = self.getter.get(resource, conn.clone(), progress_sender);
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

            (id, res)
        };
        self.transfer_controllers.insert(id, state);
        self.transfer_tasks.spawn_local(fut);
    }

    #[allow(clippy::unused_async)]
    async fn shutdown(self) {
        debug!("shutting down");
        // TODO(@divma): how to make sure the download futures end gracefully?
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
