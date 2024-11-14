use std::{collections::HashMap, future::Future, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use futures_buffered::join_all;
use futures_lite::{future::Boxed, StreamExt};
use futures_util::{FutureExt, TryFutureExt};
use iroh_net::{
    endpoint::{get_remote_node_id, Connection, ConnectionError},
    Endpoint, NodeId,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::{AbortHandle, JoinSet},
};
use tokio_stream::{wrappers::ReceiverStream, StreamMap};
use tokio_util::{either::Either, sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, error_span, instrument, trace, warn, Instrument, Span};

use super::actor::ActorHandle;
use crate::{
    interest::Interests,
    net::{
        establish, prepare_channels, terminate_gracefully, ChannelStreams, ConnHandle, ALPN,
        ERROR_CODE_DUPLICATE_CONN, ERROR_CODE_SHUTDOWN,
    },
    proto::wgps::AccessChallenge,
    session::{
        intents::{EventKind, EventReceiver, Intent},
        Error, InitialTransmission, Role, SessionEvent, SessionHandle, SessionInit, SessionUpdate,
    },
};

/// Timeout at shutdown after which we abort connections that failed to terminate gracefully.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Customize what to do with incoming connections.
///
/// You can use [`AcceptOpts::default`] to instantiate with the default behavior:
/// * Accept all incoming connections, and submit interest in everything we have
/// * Do not track events for sessions created from incoming connections for which we did not
///   signal a specific interest ourselves as well
///
/// Use [`Self::accept_custom`] to customize which sessions to accept, and which interests to
/// submit.
///
/// Use [`Self::track_events`] to receive events for sessions we accepted.
#[derive(derive_more::Debug, Default)]
pub struct AcceptOpts {
    #[debug("{:?}", accept_cb.as_ref().map(|_| "_"))]
    accept_cb: Option<AcceptCb>,
    track_events: Option<mpsc::Sender<(NodeId, EventKind)>>,
}

impl AcceptOpts {
    /// Registers a callback to determine the fate of incoming connections.
    ///
    /// The callback gets the connecting peer's [`NodeId`] as argument, and must return a future
    /// that resolves to `None` or Some(`[SessionInit]`).
    /// When returning `None`, the session will not be  accepted.
    /// When returning a `SessionInit`, the session will be accepted with these interests.
    ///
    /// The default behavior, if not registering a callback, is to accept all incoming connections with
    /// interests in everything we have and in live session mode.
    pub fn accept_custom<F, Fut>(mut self, cb: F) -> Self
    where
        F: Fn(NodeId) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<SessionInit>> + Send + 'static,
    {
        let cb = Box::new(move |peer: NodeId| {
            let fut: Boxed<Option<SessionInit>> = Box::pin((cb)(peer));
            fut
        });
        self.accept_cb = Some(cb);
        self
    }

    /// Registers an event channel for events from accepted connections.
    ///
    /// If called, the passed [`mpsc::Sender`] will receive all events emitted from session
    /// intents for incoming connections. The corresponding [`mpsc::Receiver`] **must** then be
    /// received from in a loop. The session will be blocked from proceeding if the receiver is not
    /// able to process events fast enough.
    ///
    /// If not called, events from session intents for incoming connections will be dropped.
    pub fn track_events(mut self, sender: mpsc::Sender<(NodeId, EventKind)>) -> Self {
        self.track_events = Some(sender);
        self
    }
}

/// Input commands for the [`PeerManager`] actor.
#[derive(derive_more::Debug)]
pub(super) enum Input {
    SubmitIntent {
        peer: NodeId,
        intent: Intent,
    },
    HandleConnection {
        #[debug("Connection")]
        conn: Connection,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

type AcceptCb = Box<dyn Fn(NodeId) -> Boxed<Option<SessionInit>> + Send + Sync + 'static>;

/// Manages incoming and outgoing connections.
#[derive(Debug)]
pub(super) struct PeerManager {
    actor: ActorHandle,
    endpoint: Endpoint,
    inbox: mpsc::Receiver<Input>,
    session_events_rx: StreamMap<NodeId, ReceiverStream<SessionEvent>>,
    peers: HashMap<NodeId, PeerInfo>,
    accept_handlers: AcceptHandlers,
    conn_tasks: JoinSet<(NodeId, ConnStep)>,
    shutting_down: bool,
}

impl PeerManager {
    pub(super) fn new(
        actor_handle: ActorHandle,
        endpoint: Endpoint,
        inbox: mpsc::Receiver<Input>,
        accept_opts: AcceptOpts,
    ) -> Self {
        PeerManager {
            endpoint: endpoint.clone(),
            actor: actor_handle,
            inbox,
            session_events_rx: Default::default(),
            peers: Default::default(),
            accept_handlers: AcceptHandlers::new(accept_opts),
            conn_tasks: Default::default(),
            shutting_down: false,
        }
    }

    pub(super) async fn run(mut self) -> Result<(), Error> {
        // A timeout that initially is always-pending. Once we initiate shutdown, it is set to an actual timeout,
        // to not wait forever for graceful termination.
        let shutdown_timeout = Either::Left(std::future::pending::<()>());
        tokio::pin!(shutdown_timeout);
        let mut shutdown_reply = None;

        loop {
            tokio::select! {
                Some(input) = self.inbox.recv(), if !self.shutting_down => {
                    trace!(?input, "tick: inbox");
                    match input {
                        Input::SubmitIntent { peer, intent } => self.submit_intent(peer, intent).await,
                        Input::HandleConnection { conn } => self.handle_connection(conn).await,
                        Input::Shutdown { reply } => {
                            self.init_shutdown().await;
                            if self.conn_tasks.is_empty() {
                                reply.send(()).ok();
                                break;
                            } else {
                                shutdown_reply = Some(reply);
                                shutdown_timeout.set(Either::Right(tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT)));
                            }
                        }
                    }
                }
                Some((peer, event)) = self.session_events_rx.next(), if !self.session_events_rx.is_empty() => {
                    trace!(peer=%peer.fmt_short(), ?event, "tick: session event");
                    self.handle_session_event(peer, event);
                }
                Some(res) = self.conn_tasks.join_next(), if !self.conn_tasks.is_empty() => {
                    trace!(active=self.conn_tasks.len(), "tick: conn task joined");
                    match res {
                        Err(err) if err.is_cancelled() => continue,
                        Err(err) => Err(err).context("conn task panicked")?,
                        Ok((peer, out)) => self.handle_conn_output(peer, out).await?,
                    }
                    if self.shutting_down && self.conn_tasks.is_empty() {
                        debug!("all connections gracefully terminated");
                        break;
                    }
                }
                _ = &mut shutdown_timeout => {
                    trace!("tick: shutdown timeout");
                    debug!(
                        remaining=self.conn_tasks.len(),
                        "terminating all connections timed out, abort remaining connections"
                    );
                    // TODO: We do not catch panics here.
                    self.conn_tasks.shutdown().await;
                    break;
                }
                else => break,
            }
        }
        if let Some(reply) = shutdown_reply {
            reply.send(()).ok();
        }
        Ok(())
    }

    /// Handle a new incoming connection.
    async fn handle_connection(&mut self, conn: Connection) {
        let peer = match get_remote_node_id(&conn) {
            Ok(peer) => peer,
            Err(err) => {
                debug!("ignore incoming connection (failed to get remote node id: {err})");
                return;
            }
        };

        let Some(intent) = self.accept_handlers.accept(peer).await else {
            debug!("ignore incoming connection (accept handler returned none)");
            return;
        };
        let peer_info = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerInfo::new(peer));

        debug!(peer = %peer.fmt_short(), our_state=%peer_info.conn_state, "incoming connection");

        let accept_conn = match peer_info.conn_state {
            ConnState::None => true,
            ConnState::Establishing {
                ref mut our_dial, ..
            } => match our_dial {
                // No dial but already establishing a previous incoming connection
                None => {
                    debug!("ignore incoming connection (already accepting)");
                    conn.close(ERROR_CODE_DUPLICATE_CONN, b"duplicate-already-accepting");
                    false
                }
                // We are dialing also: abort one of the conns
                Some(cancel_dial) => {
                    if peer > self.endpoint.node_id() {
                        debug!("incoming connection for a peer we are dialing and their connection wins, abort dial");
                        cancel_dial.cancel();
                        true
                    } else {
                        debug!("ignore incoming connection (already dialing and ours wins)");
                        conn.close(ERROR_CODE_DUPLICATE_CONN, b"duplicate-our-dial-wins");
                        false
                    }
                }
            },
            ConnState::Active { .. } => {
                debug!("ignore incoming connection (already active)");
                conn.close(ERROR_CODE_DUPLICATE_CONN, b"duplicate-already-active");
                false
            }
            ConnState::Terminating { .. } => true,
        };
        if accept_conn {
            debug!(peer=%peer.fmt_short(), "accept connection");
            peer_info.push_intent(intent).await;

            // Start connection establish task.
            let our_nonce = AccessChallenge::generate();
            let fut = async move {
                let res = establish(&conn, Role::Betty, our_nonce).await;
                let res = res.map(|(initial_transmission, channel_streams)| Established {
                    channel_streams,
                    initial_transmission,
                    conn,
                    our_role: Role::Betty,
                });
                ConnStep::Established(res)
            };
            let abort_handle = spawn_conn_task(&mut self.conn_tasks, peer_info, fut);
            peer_info.conn_state = ConnState::Establishing {
                our_dial: None,
                abort_handle,
            };
        }
    }

    async fn submit_intent(&mut self, peer: NodeId, intent: Intent) {
        let peer_info = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerInfo::new(peer));

        debug!(peer=%peer.fmt_short(), state=%peer_info.conn_state, "submit intent");
        if !peer_info.push_intent(intent).await {
            self.connect_if_inactive(peer);
        }
    }

    fn connect_if_inactive(&mut self, peer: NodeId) {
        let peer_info = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerInfo::new(peer));
        if matches!(peer_info.conn_state, ConnState::None) {
            let our_nonce = AccessChallenge::generate();
            let endpoint = self.endpoint.clone();
            let cancel_dial = CancellationToken::new();
            let cancel_dial2 = cancel_dial.clone();
            // Future that dials and establishes the connection. Can be cancelled for simultaneous connection.
            let fut = async move {
                debug!("connecting");
                let conn = tokio::select! {
                    res = endpoint.connect(peer, ALPN) => res,
                    _ = cancel_dial.cancelled() => {
                        debug!("dial cancelled during dial");
                        return Err(ConnectionError::LocallyClosed.into());
                    }
                }?;
                let (initial_transmission, channel_streams) = tokio::select! {
                    res = establish(&conn, Role::Alfie, our_nonce) => res?,
                    _ = cancel_dial.cancelled() => {
                        debug!("dial cancelled during establish");
                        conn.close(ERROR_CODE_DUPLICATE_CONN, b"duplicate-your-dial-wins");
                        return Err(ConnectionError::LocallyClosed.into());
                    },
                };
                Ok(Established {
                    conn,
                    initial_transmission,
                    channel_streams,
                    our_role: Role::Alfie,
                })
            }
            .map(ConnStep::Established);
            let abort_handle = spawn_conn_task(&mut self.conn_tasks, peer_info, fut);
            peer_info.conn_state = ConnState::Establishing {
                our_dial: Some(cancel_dial2),
                abort_handle,
            };
        }
    }

    #[instrument("conn", skip_all, fields(peer=%peer.fmt_short()))]
    fn handle_session_event(&mut self, peer: NodeId, event: SessionEvent) {
        match event {
            SessionEvent::Established => {}
            SessionEvent::Complete {
                result,
                senders,
                mut remaining_intents,
                we_cancelled: _,
            } => {
                debug!(error=?result.err(), remaining_intents=remaining_intents.len(), "session complete");

                // Close the channel senders. This will cause our send loops to close,
                // which in turn causes the receive loops of the other peer to close.
                senders.close_all();

                let Some(peer_info) = self.peers.get_mut(&peer) else {
                    warn!("got session complete event for unknown peer");
                    return;
                };

                peer_info.pending_intents.append(&mut remaining_intents);
                peer_info.session_state = SessionState::None;

                if peer_info.conn_state.is_none() && peer_info.pending_intents.is_empty() {
                    self.peers.remove(&peer);
                } else if peer_info.conn_state.is_none() {
                    self.connect_if_inactive(peer);
                }
                trace!("entering closing state");
            }
        }
    }

    #[instrument("conn", skip_all, fields(peer=%peer.fmt_short()))]
    async fn handle_conn_output(&mut self, peer: NodeId, out: ConnStep) -> Result<()> {
        let peer_info = self
            .peers
            .get_mut(&peer)
            .context("got conn task output for unknown peer")?;
        match out {
            ConnStep::Established(Err(err)) => {
                debug!(current_state=%peer_info.conn_state, "conn task failed while establishing: {err:#?}");
                match err.downcast_ref() {
                    Some(ConnectionError::LocallyClosed) => {
                        // We cancelled the connection, nothing to do.
                        debug!("connection was cancelled by us");
                    }
                    Some(ConnectionError::ApplicationClosed(reason))
                        if reason.error_code == ERROR_CODE_DUPLICATE_CONN =>
                    {
                        debug!(
                        "connection was cancelled by the remote: simultaneous connection and their's wins"
                    );
                        if matches!(
                            &peer_info.conn_state,
                            ConnState::Establishing {
                                our_dial: Some(_),
                                ..
                            },
                        ) {
                            peer_info.conn_state = ConnState::None;
                        }
                        // if our_role != peer_info.our_role {
                        //     // TODO: setup a timeout to kill intents if the other conn doesn't make it.
                        //     debug!("we are still waiting for their connection to arrive");
                        // }
                    }
                    _ => {
                        peer_info.conn_state = ConnState::None;
                        match &peer_info.session_state {
                            SessionState::None => {
                                println!("Error: {err:#}");
                                peer_info
                                    .abort_pending_intents(err.context("failed while establishing"))
                                    .await;
                                self.peers.remove(&peer);
                            }
                            SessionState::Active { .. } => {
                                // An establishing connection failed while an old session was still not terminated.
                                // We log the error and keep waiting for the session to terminate. This does not happen usually but can due to timings.
                                warn!("establish failed while session still not closed");
                            }
                        }
                    }
                }
            }
            ConnStep::Established(Ok(Established {
                our_role,
                conn,
                initial_transmission,
                channel_streams,
            })) => {
                let SessionState::None = peer_info.session_state else {
                    unreachable!("session must be inactive when connection establishes");
                };

                let intents = std::mem::take(&mut peer_info.pending_intents);

                if self.shutting_down {
                    debug!("connection became ready while shutting down, abort");
                    conn.close(ERROR_CODE_SHUTDOWN, b"shutting-down");
                    if !intents.is_empty() {
                        let err = Arc::new(Error::ShuttingDown);
                        join_all(
                            intents
                                .into_iter()
                                .map(|intent| intent.send_abort(err.clone())),
                        )
                        .await;
                    }
                    return Ok(());
                }

                debug!(?our_role, "connection ready: init session");
                let (channels, fut) = prepare_channels(channel_streams)?;
                let conn_handle = ConnHandle {
                    initial_transmission,
                    channels,
                    our_role,
                    peer,
                };
                let session_handle = self.actor.init_session(conn_handle, intents).await?;

                let fut = fut.map_ok(|()| conn).map(ConnStep::Done);
                let abort_handle = spawn_conn_task(&mut self.conn_tasks, peer_info, fut);

                let SessionHandle {
                    update_tx,
                    event_rx,
                } = session_handle;
                self.session_events_rx
                    .insert(peer, ReceiverStream::new(event_rx));

                peer_info.conn_state = ConnState::Active { abort_handle };
                peer_info.session_state = SessionState::Active { update_tx };
            }
            ConnStep::Done(Ok(conn)) => {
                trace!("connection loop finished");
                let ConnState::Active { .. } = &peer_info.conn_state else {
                    unreachable!("connection state mismatch: Done comes after Active only");
                };
                if let SessionState::Active { .. } = &peer_info.session_state {
                    // TODO: Can this happen?
                    unreachable!(
                        "connection may not terminate gracefully while session is still active"
                    );
                };
                let fut = async move { ConnStep::Closed(terminate_gracefully(conn).await) };
                let abort_handle = spawn_conn_task(&mut self.conn_tasks, peer_info, fut);
                peer_info.conn_state = ConnState::Terminating { abort_handle };
            }
            ConnStep::Done(Err(err)) => {
                let ConnState::Active { .. } = &peer_info.conn_state else {
                    unreachable!("connection state mismatch: Done comes after Active only");
                };
                if let SessionState::Active { update_tx } = &peer_info.session_state {
                    warn!(?err, "connection failed while active");
                    update_tx
                        .send(SessionUpdate::Abort(Error::ConnectionClosed(err)))
                        .await
                        .ok();
                    peer_info.conn_state = ConnState::None;
                } else {
                    debug!(?err, "connection failed while on session is active");
                    peer_info
                        .abort_pending_intents(err.context("failed while active"))
                        .await;
                    self.peers.remove(&peer);
                }
            }
            ConnStep::Closed(res) => {
                debug!(?res, "connection closed");
                match &peer_info.conn_state {
                    ConnState::Terminating { .. } => {
                        peer_info.conn_state = ConnState::None;
                        if !peer_info.pending_intents.is_empty() {
                            debug!("peer has pending intents, reconnect");
                            match res {
                                Ok(()) => self.connect_if_inactive(peer),
                                Err(err) => {
                                    peer_info
                                        .abort_pending_intents(
                                            err.context("failed while closing connection"),
                                        )
                                        .await
                                }
                            }
                        } else if peer_info.session_state.is_none() {
                            debug!("removed peer");
                            self.peers.remove(&peer).expect("just checked");
                        } else {
                            debug!("keeping peer because session still closing");
                        }
                    }
                    ConnState::Establishing { .. } => {
                        debug!("conn is already establishing again");
                    }
                    ConnState::Active { .. } => {
                        debug!("conn is already active again");
                    }
                    ConnState::None => unreachable!("ConnState::Closed may not happen while None"),
                }
            }
        }
        Ok(())
    }

    async fn init_shutdown(&mut self) {
        self.shutting_down = true;
        for peer in self.peers.values() {
            if let ConnState::Establishing { abort_handle, .. } = &peer.conn_state {
                // We are in pending state, which means the session has not yet been started.
                // Hard-abort the task and let the other peer handle the error.
                abort_handle.abort();
            }
            if let SessionState::Active { update_tx } = &peer.session_state {
                // We are in active state. We cancel our session, which leads to graceful connection termination.
                update_tx
                    .send(SessionUpdate::Abort(Error::ShuttingDown))
                    .await
                    .ok();
            }
        }
    }
}

fn spawn_conn_task(
    conn_tasks: &mut JoinSet<(NodeId, ConnStep)>,
    peer_info: &PeerInfo,
    fut: impl Future<Output = ConnStep> + Send + 'static,
) -> AbortHandle {
    let node_id = peer_info.node_id;
    let fut = fut
        .map(move |res| (node_id, res))
        .instrument(peer_info.span.clone());
    conn_tasks.spawn(fut)
}

#[derive(Debug)]
struct PeerInfo {
    node_id: NodeId,
    span: Span,
    pending_intents: Vec<Intent>,
    conn_state: ConnState,
    session_state: SessionState,
}

impl PeerInfo {
    /// Returns `true` if the intent was pushed into the session channel and `false` if it was added to the pending intent list.
    async fn push_intent(&mut self, intent: Intent) -> bool {
        match &self.session_state {
            SessionState::None => {
                self.pending_intents.push(intent);
                false
            }
            SessionState::Active { update_tx } => {
                if let Err(err) = update_tx.send(SessionUpdate::SubmitIntent(intent)).await {
                    debug!("failed to submit intent into active session, queue in peer state");
                    if let SessionUpdate::SubmitIntent(intent) = err.0 {
                        self.pending_intents.push(intent);
                    }
                    false
                } else {
                    trace!("intent sent to session");
                    true
                }
            }
        }
    }

    async fn abort_pending_intents(&mut self, err: anyhow::Error) {
        let err = Arc::new(Error::Net(err));
        join_all(
            self.pending_intents
                .drain(..)
                .map(|intent| intent.send_abort(err.clone())),
        )
        .await;
    }
}

#[derive(Debug, Default, strum::Display)]
enum SessionState {
    #[default]
    None,
    Active {
        update_tx: mpsc::Sender<SessionUpdate>,
    },
}

impl SessionState {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

#[derive(Debug, Default, strum::Display)]
enum ConnState {
    #[default]
    None,
    Establishing {
        our_dial: Option<CancellationToken>,
        abort_handle: AbortHandle,
    },
    Active {
        abort_handle: AbortHandle,
    },
    Terminating {
        abort_handle: AbortHandle,
    },
}

impl ConnState {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl PeerInfo {
    fn new(peer: NodeId) -> Self {
        Self {
            node_id: peer,
            span: error_span!("conn", peer=%peer.fmt_short()),
            session_state: Default::default(),
            conn_state: Default::default(),
            pending_intents: Default::default(),
        }
    }
}

#[derive(Debug)]
struct Established {
    our_role: Role,
    conn: Connection,
    initial_transmission: InitialTransmission,
    channel_streams: ChannelStreams,
}

#[derive(derive_more::Debug, strum::Display)]
enum ConnStep {
    Established(anyhow::Result<Established>),
    Done(anyhow::Result<Connection>),
    Closed(anyhow::Result<()>),
}

/// The internal handlers for the [`AcceptOpts].
#[derive(derive_more::Debug)]
struct AcceptHandlers {
    #[debug("{:?}", accept_cb.as_ref().map(|_| "_"))]
    accept_cb: Option<AcceptCb>,
    event_forwarder: Option<EventForwarder>,
}

impl AcceptHandlers {
    pub fn new(opts: AcceptOpts) -> Self {
        Self {
            accept_cb: opts.accept_cb,
            event_forwarder: opts.track_events.map(EventForwarder::new),
        }
    }

    pub async fn accept(&self, peer: NodeId) -> Option<Intent> {
        let init = match &self.accept_cb {
            None => Some(SessionInit::continuous(Interests::All)),
            Some(cb) => cb(peer).await,
        };
        let init = init?;

        let intent = match &self.event_forwarder {
            None => Intent::new_detached(init),
            Some(forwarder) => {
                let (intent, handle) = Intent::new(init);
                let (_update_tx, event_rx) = handle.split();
                forwarder.add_intent(peer, event_rx).await;
                intent
            }
        };

        Some(intent)
    }
}

/// Simple event forwarder to combine the intent event receivers for all betty sessions
/// and send to the event sender configured via [`AcceptOpts].
///
/// Runs a forwarding loop in a task. The task is aborted on drop.
#[derive(Debug)]
struct EventForwarder {
    _join_handle: AbortOnDropHandle<()>,
    stream_sender: mpsc::Sender<(NodeId, EventReceiver)>,
}

impl EventForwarder {
    fn new(event_sender: mpsc::Sender<(NodeId, EventKind)>) -> EventForwarder {
        let (stream_sender, mut stream_receiver) = mpsc::channel(16);
        let join_handle = tokio::task::spawn(async move {
            let mut streams = StreamMap::new();
            loop {
                tokio::select! {
                    Some((peer, receiver)) = stream_receiver.recv() => {
                        streams.insert(peer, receiver);
                    },
                    Some((peer, event)) = streams.next() => {
                        if let Err(_receiver_dropped) = event_sender.send((peer, event)).await {
                            break;
                        }
                    },
                    else => break,
                }
            }
        });
        EventForwarder {
            _join_handle: AbortOnDropHandle::new(join_handle),
            stream_sender,
        }
    }

    pub async fn add_intent(&self, peer: NodeId, event_stream: EventReceiver) {
        self.stream_sender.send((peer, event_stream)).await.ok();
    }
}
