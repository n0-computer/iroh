use std::{collections::HashMap, future::Future, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use futures_buffered::join_all;

use futures_lite::{future::Boxed, StreamExt};
use futures_util::{FutureExt, TryFutureExt};
use iroh_net::{
    endpoint::{get_remote_node_id, Connection, ConnectionError},
    util::AbortingJoinHandle,
    Endpoint, NodeId,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::{AbortHandle, JoinSet},
};
use tokio_stream::{wrappers::ReceiverStream, StreamMap};

use tokio_util::{either::Either, sync::CancellationToken};
use tracing::{debug, error_span, instrument, trace, warn, Instrument, Span};

use crate::{
    interest::Interests,
    net::{
        establish, prepare_channels, terminate_gracefully, ChannelStreams, ConnHandle, ALPN,
        ERROR_CODE_DUPLICATE_CONN, ERROR_CODE_FAIL, ERROR_CODE_SHUTDOWN,
    },
    proto::wgps::AccessChallenge,
    session::{
        intents::{EventKind, EventReceiver, Intent},
        Error, InitialTransmission, Role, SessionEvent, SessionHandle, SessionInit, SessionUpdate,
    },
};

use super::actor::ActorHandle;

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
    conn_tasks: JoinSet<(Role, NodeId, Result<ConnStep>)>,
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
                        Ok((our_role, peer, out)) => self.handle_conn_output(our_role, peer, out).await?,
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
            .or_insert_with(|| PeerInfo::new(Role::Betty, peer));

        debug!(peer = %peer.fmt_short(), our_state=%peer_info.state, "incoming connection");

        let accept_conn = match peer_info.state {
            PeerState::None => true,
            PeerState::Pending {
                ref mut cancel_dial,
                ..
            } => match peer_info.our_role {
                Role::Betty => {
                    debug!("ignore incoming connection (already accepting)");
                    conn.close(ERROR_CODE_DUPLICATE_CONN, b"duplicate-already-accepting");
                    false
                }
                Role::Alfie => {
                    if peer > self.endpoint.node_id() {
                        debug!("incoming connection for a peer we are dialing and their connection wins, abort dial");
                        if let Some(cancel_dial) = cancel_dial.take() {
                            cancel_dial.cancel();
                        }
                        true
                    } else {
                        debug!("ignore incoming connection (already dialing and ours wins)");
                        conn.close(ERROR_CODE_DUPLICATE_CONN, b"duplicate-our-dial-wins");
                        false
                    }
                }
            },
            PeerState::Active { .. } => {
                debug!("ignore incoming connection (already active)");
                conn.close(ERROR_CODE_DUPLICATE_CONN, b"duplicate-already-active");
                false
            }
            PeerState::Closing { .. } => true,
        };
        if accept_conn {
            debug!(peer=%peer.fmt_short(), "accept connection");
            // Take any pending intents from the previous state and merge with the new betty intent.
            let mut intents = match peer_info.state {
                PeerState::Pending {
                    ref mut intents, ..
                }
                | PeerState::Closing {
                    ref mut intents, ..
                } => std::mem::take(intents),
                _ => vec![],
            };
            intents.push(intent);
            peer_info.state = PeerState::Pending {
                intents,
                cancel_dial: None,
            };
            peer_info.our_role = Role::Betty;

            // Start connection establish task.
            let our_nonce = AccessChallenge::generate();
            let fut = async move {
                let (initial_transmission, channel_streams) =
                    establish(&conn, Role::Betty, our_nonce).await?;
                Ok(ConnStep::Ready {
                    conn,
                    initial_transmission,
                    channel_streams,
                })
            };
            let abort_handle = spawn_conn_task(&mut self.conn_tasks, peer_info, fut);
            peer_info.abort_handle = Some(abort_handle);
        }
    }

    async fn submit_intent(&mut self, peer: NodeId, intent: Intent) {
        let peer_info = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerInfo::new(Role::Alfie, peer));

        debug!(peer=%peer.fmt_short(), state=%peer_info.state, "submit intent");

        match peer_info.state {
            PeerState::None => {
                let our_nonce = AccessChallenge::generate();
                let endpoint = self.endpoint.clone();
                let cancel_dial = CancellationToken::new();
                let cancel_dial2 = cancel_dial.clone();
                // Future that dials and establishes the connection. Can be cancelled for simultaneous connection.
                let fut = async move {
                    debug!("connecting");
                    let conn = tokio::select! {
                        res = endpoint.connect_by_node_id(peer, ALPN) => res,
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
                    Ok(ConnStep::Ready {
                        conn,
                        initial_transmission,
                        channel_streams,
                    })
                };
                let abort_handle = spawn_conn_task(&mut self.conn_tasks, peer_info, fut);
                peer_info.abort_handle = Some(abort_handle);
                peer_info.state = PeerState::Pending {
                    intents: vec![intent],
                    cancel_dial: Some(cancel_dial2),
                };
            }
            PeerState::Pending {
                ref mut intents, ..
            } => {
                intents.push(intent);
            }
            PeerState::Active {
                ref update_tx,
                ref mut intents_after_close,
                ..
            } => {
                if let Err(err) = update_tx.send(SessionUpdate::SubmitIntent(intent)).await {
                    debug!("failed to submit intent into active session, queue in peer state");
                    if let SessionUpdate::SubmitIntent(intent) = err.0 {
                        intents_after_close.push(intent);
                    }
                } else {
                    trace!("intent sent to session");
                }
            }
            PeerState::Closing {
                intents: ref mut new_intents,
                ..
            } => {
                new_intents.push(intent);
            }
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

                let PeerState::Active {
                    ref mut intents_after_close,
                    ..
                } = peer_info.state
                else {
                    warn!("got session complete event for peer not in active state");
                    return;
                };
                remaining_intents.append(intents_after_close);

                peer_info.state = PeerState::Closing {
                    intents: remaining_intents,
                };
                trace!("entering closing state");
            }
        }
    }

    #[instrument("conn", skip_all, fields(peer=%peer.fmt_short()))]
    async fn handle_conn_output(
        &mut self,
        our_role: Role,
        peer: NodeId,
        out: Result<ConnStep>,
    ) -> Result<()> {
        let peer_info = self
            .peers
            .get_mut(&peer)
            .context("got conn task output for unknown peer")?;
        match out {
            Err(err) => {
                trace!(?our_role, current_state=%peer_info.state, "conn task failed: {err:#?}");
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
                        if our_role != peer_info.our_role {
                            // TODO: setup a timeout to kill intents if the other conn doesn't make it.
                            debug!("we are still waiting for their connection to arrive");
                        }
                    }
                    _ => {
                        let peer = self.peers.remove(&peer).expect("just checked");
                        match peer.state {
                            PeerState::Pending { intents, .. } => {
                                warn!(?err, "connection failed while pending");
                                // If we were still in pending state, terminate all pending intents.
                                let err = Arc::new(Error::Net(err));
                                join_all(
                                    intents
                                        .into_iter()
                                        .map(|intent| intent.send_abort(err.clone())),
                                )
                                .await;
                            }
                            PeerState::Closing { intents } => {
                                debug!(?err, "connection failed to close gracefully");
                                // If we were are in closing state, we still forward the connection error to the intents.
                                // This would be the place where we'd implement retries: instead of aborting the intents, resubmit them.
                                // Right now, we only resubmit intents that were submitted while terminating a session, and only if the session closed gracefully.
                                let err = Arc::new(Error::Net(err));
                                join_all(
                                    intents
                                        .into_iter()
                                        .map(|intent| intent.send_abort(err.clone())),
                                )
                                .await;
                            }
                            PeerState::Active { update_tx, .. } => {
                                warn!(?err, "connection failed while active");
                                update_tx
                                    .send(SessionUpdate::Abort(Error::ConnectionClosed(err)))
                                    .await
                                    .ok();
                            }
                            PeerState::None => {
                                warn!(?err, "connection failed while peer is in None state");
                            }
                        }
                    }
                }
            }
            Ok(ConnStep::Ready {
                conn,
                initial_transmission,
                channel_streams,
            }) => {
                let PeerState::Pending {
                    ref mut intents, ..
                } = &mut peer_info.state
                else {
                    debug!(
                        ?our_role,
                        "got connection ready for peer in non-pending state"
                    );
                    conn.close(ERROR_CODE_FAIL, b"invalid-state");
                    drop(conn);
                    // TODO: unreachable?
                    return Err(anyhow!(
                        "got connection ready for peer in non-pending state"
                    ));
                };

                let intents = std::mem::take(intents);

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

                // TODO: Here we should check again that we are not establishing a duplicate connection.
                debug!(?our_role, "connection ready: init session");
                let (channels, fut) = prepare_channels(channel_streams)?;
                let conn_handle = ConnHandle {
                    initial_transmission,
                    channels,
                    our_role,
                    peer,
                };
                peer_info.our_role = our_role;
                let session_handle = self.actor.init_session(conn_handle, intents).await?;

                let fut = fut.map_ok(move |()| ConnStep::Done { conn });
                let abort_handle = spawn_conn_task(&mut self.conn_tasks, peer_info, fut);

                let SessionHandle {
                    update_tx,
                    event_rx,
                } = session_handle;
                self.session_events_rx
                    .insert(peer, ReceiverStream::new(event_rx));

                peer_info.state = PeerState::Active {
                    update_tx,
                    intents_after_close: vec![],
                };
                peer_info.abort_handle = Some(abort_handle);
            }
            Ok(ConnStep::Done { conn }) => {
                trace!("connection loop finished");
                let fut = async move {
                    terminate_gracefully(&conn).await?;
                    // The connection is fully closed.
                    drop(conn);
                    Ok(ConnStep::Closed)
                };
                let abort_handle = spawn_conn_task(&mut self.conn_tasks, peer_info, fut);
                if let PeerState::Closing { .. } = &peer_info.state {
                    peer_info.abort_handle = Some(abort_handle);
                } else {
                    // TODO: What do we do with the closing abort handle in case we have a new connection already?
                }
            }
            Ok(ConnStep::Closed) => {
                debug!("connection closed gracefully");
                let peer_info = self.peers.remove(&peer).expect("just checked");
                if let PeerState::Closing { intents } = peer_info.state {
                    if !intents.is_empty() {
                        debug!(
                            "resubmitting {} intents that were not yet processed",
                            intents.len()
                        );
                        for intent in intents {
                            self.submit_intent(peer, intent).await;
                        }
                    }
                } else {
                    warn!(state=%peer_info.state, "reached closed step for peer in wrong state");
                }
            }
        }
        Ok(())
    }

    async fn init_shutdown(&mut self) {
        self.shutting_down = true;
        for peer in self.peers.values() {
            match &peer.state {
                PeerState::None => {}
                PeerState::Pending { .. } => {
                    // We are in pending state, which means the session has not yet been started.
                    // Hard-abort the task and let the other peer handle the error.
                    if let Some(abort_handle) = &peer.abort_handle {
                        abort_handle.abort();
                    }
                }
                PeerState::Closing { .. } => {}
                PeerState::Active { update_tx, .. } => {
                    // We are in active state. We cancel our session, which leads to graceful connection termination.
                    update_tx
                        .send(SessionUpdate::Abort(Error::ShuttingDown))
                        .await
                        .ok();
                }
            }
        }
    }
}

fn spawn_conn_task(
    conn_tasks: &mut JoinSet<(Role, NodeId, Result<ConnStep>)>,
    peer_info: &PeerInfo,
    fut: impl Future<Output = Result<ConnStep>> + Send + 'static,
) -> AbortHandle {
    let node_id = peer_info.node_id;
    let our_role = peer_info.our_role;
    let fut = fut
        .map(move |res| (our_role, node_id, res))
        .instrument(peer_info.span.clone());
    conn_tasks.spawn(fut)
}

#[derive(Debug)]
struct PeerInfo {
    node_id: NodeId,
    our_role: Role,
    abort_handle: Option<AbortHandle>,
    state: PeerState,
    span: Span,
}

impl PeerInfo {
    fn new(our_role: Role, peer: NodeId) -> Self {
        Self {
            node_id: peer,
            our_role,
            abort_handle: None,
            state: PeerState::None,
            span: error_span!("conn", peer=%peer.fmt_short()),
        }
    }
}

#[derive(Debug, strum::Display)]
enum PeerState {
    None,
    Pending {
        intents: Vec<Intent>,
        cancel_dial: Option<CancellationToken>,
    },
    Active {
        update_tx: mpsc::Sender<SessionUpdate>,
        /// List of intents that we failed to submit into the session because it is closing.
        intents_after_close: Vec<Intent>,
    },
    Closing {
        intents: Vec<Intent>,
    },
}

#[derive(derive_more::Debug, strum::Display)]
enum ConnStep {
    Ready {
        conn: Connection,
        initial_transmission: InitialTransmission,
        channel_streams: ChannelStreams,
    },
    Done {
        conn: Connection,
    },
    Closed,
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
    _join_handle: AbortingJoinHandle<()>,
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
            _join_handle: join_handle.into(),
            stream_sender,
        }
    }

    pub async fn add_intent(&self, peer: NodeId, event_stream: EventReceiver) {
        self.stream_sender.send((peer, event_stream)).await.ok();
    }
}
