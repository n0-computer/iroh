use std::{collections::HashMap, future::Future, sync::Arc};

use anyhow::{anyhow, Context, Result};
use futures_buffered::join_all;

use futures_lite::{future::Boxed, StreamExt};
use futures_util::FutureExt;
use iroh_net::{
    endpoint::{get_remote_node_id, Connection, VarInt},
    util::AbortingJoinHandle,
    Endpoint, NodeId,
};
use tokio::{
    sync::mpsc,
    task::{AbortHandle, JoinSet},
};
use tokio_stream::{wrappers::ReceiverStream, StreamMap};

use tracing::{debug, trace};

use crate::{
    net::{WillowConn, ALPN},
    proto::sync::AccessChallenge,
    session::{
        intents::{EventKind, Intent},
        Error, Interests, Role, SessionEvent, SessionHandle, SessionInit, SessionUpdate,
    },
};

use super::actor::ActorHandle;

const ERROR_CODE_IGNORE_CONN: VarInt = VarInt::from_u32(1);

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
    /// that resolves to `Option<`[SessionInit]``>`. When returning `None`, the session will not be
    /// accepted. When returning a `SessionInit`, the session will be accepted with these
    /// interests.
    pub fn accept_custom<F, Fut>(mut self, cb: F) -> Self
    where
        F: Fn(NodeId) -> Fut + 'static + Send + Sync,
        Fut: 'static + Send + Future<Output = Option<SessionInit>>,
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
}

type AcceptCb = Box<dyn Fn(NodeId) -> Boxed<Option<SessionInit>> + Send + Sync + 'static>;

#[derive(derive_more::Debug)]
pub(super) struct PeerManager {
    actor: ActorHandle,
    endpoint: Endpoint,
    inbox: mpsc::Receiver<Input>,
    session_events_rx: StreamMap<NodeId, ReceiverStream<SessionEvent>>,
    tasks: JoinSet<(NodeId, Result<WillowConn>)>,
    peers: HashMap<NodeId, PeerState>,
    accept_handlers: AcceptHandlers,
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
            tasks: Default::default(),
            peers: Default::default(),
            accept_handlers: AcceptHandlers::new(accept_opts),
        }
    }

    pub(super) async fn run(mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                Some(input) = self.inbox.recv() => {
                    trace!(?input, "tick: inbox");
                    self.handle_input(input).await;
                }
                Some((session_id, event)) = self.session_events_rx.next(), if !self.session_events_rx.is_empty() => {
                    trace!(?session_id, ?event, "tick: event");
                    self.handle_event(session_id, event);
                }
                Some(res) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    trace!("tick: task joined");
                    match res {
                        Err(err) if err.is_cancelled() => continue,
                        Err(err) => Err(err).context("establish task paniced")?,
                        Ok((_peer, Ok(conn))) => self.on_established(conn).await?,
                        Ok((peer, Err(err))) => self.on_establish_failed(peer, Arc::new(Error::Net(err))).await,
                    }
                }
                else => break,
            }
        }
        Ok(())
    }

    async fn handle_input(&mut self, input: Input) {
        match input {
            Input::SubmitIntent { peer, intent } => self.submit_intent(peer, intent).await,
            Input::HandleConnection { conn } => self.handle_connection(conn).await,
        }
    }

    async fn handle_connection(&mut self, conn: Connection) {
        let peer = match get_remote_node_id(&conn) {
            Ok(node_id) => node_id,
            Err(err) => {
                tracing::debug!("ignore incoming connection (failed to get remote node id: {err})");
                return;
            }
        };
        let me = self.endpoint.node_id();

        match self.peers.get_mut(&peer) {
            None => {
                if let Some(intent) = self.accept_handlers.accept(peer).await {
                    let abort_handle = self.tasks.spawn(
                        WillowConn::betty(conn, me, AccessChallenge::generate())
                            .map(move |res| (peer, res)),
                    );
                    self.peers.insert(
                        peer,
                        PeerState::Pending {
                            our_role: Role::Betty,
                            intents: vec![intent],
                            abort_handle,
                        },
                    );
                }
            }
            Some(PeerState::Pending {
                our_role,
                abort_handle,
                intents,
            }) => {
                if *our_role == Role::Betty {
                    tracing::debug!("ignore incoming connection (already accepting)");
                    conn.close(ERROR_CODE_IGNORE_CONN, b"duplicate-already-accepting");
                } else if me > peer {
                    tracing::debug!(
                        "ignore incoming connection (already dialing and our dial wins)"
                    );
                    conn.close(ERROR_CODE_IGNORE_CONN, b"duplicate-our-dial-wins");
                } else if let Some(intent) = self.accept_handlers.accept(peer).await {
                    // Abort our dial attempt and insert the new abort handle and intent.
                    abort_handle.abort();
                    *abort_handle = self.tasks.spawn(
                        WillowConn::betty(conn, me, AccessChallenge::generate())
                            .map(move |res| (peer, res)),
                    );
                    *our_role = Role::Betty;
                    intents.push(intent);
                }
            }
            Some(PeerState::Active { .. }) => {
                tracing::debug!("ignore incoming connection (already connected)");
                conn.close(ERROR_CODE_IGNORE_CONN, b"duplicate-already-accepting");
            }
        }
    }

    async fn on_establish_failed(&mut self, peer: NodeId, error: Arc<Error>) {
        let Some(peer_state) = self.peers.remove(&peer) else {
            tracing::warn!(?peer, "connection failure for unknown peer");
            return;
        };
        match peer_state {
            PeerState::Pending { intents, .. } => {
                join_all(
                    intents
                        .into_iter()
                        .map(|intent| intent.send_abort(error.clone())),
                )
                .await;
            }
            PeerState::Active { .. } => {
                unreachable!("we never handle connections for active peers")
            }
        };
    }

    async fn on_established(&mut self, conn: WillowConn) -> anyhow::Result<()> {
        let peer = conn.peer;
        let state = self
            .peers
            .remove(&peer)
            .ok_or_else(|| anyhow!("unreachable: on_established called for unknown peer"))?;

        let PeerState::Pending { intents, .. } = state else {
            anyhow::bail!("unreachable: on_established called for peer in wrong state")
        };

        let session_handle = self.actor.init_session(conn, intents).await?;

        let SessionHandle {
            cancel_token: _,
            update_tx,
            event_rx,
        } = session_handle;
        self.session_events_rx
            .insert(peer, ReceiverStream::new(event_rx));
        self.peers.insert(peer, PeerState::Active { update_tx });
        Ok(())
    }

    async fn submit_intent(&mut self, peer: NodeId, intent: Intent) {
        match self.peers.get_mut(&peer) {
            None => {
                let our_nonce = AccessChallenge::generate();
                let abort_handle = self.tasks.spawn({
                    let endpoint = self.endpoint.clone();
                    async move {
                        let conn = endpoint.connect_by_node_id(&peer, ALPN).await?;
                        WillowConn::alfie(conn, endpoint.node_id(), our_nonce).await
                    }
                    .map(move |res| (peer, res))
                });
                let state = PeerState::Pending {
                    intents: vec![intent],
                    abort_handle,
                    our_role: Role::Alfie,
                };
                self.peers.insert(peer, state);
            }
            Some(PeerState::Pending { intents, .. }) => {
                intents.push(intent);
            }
            Some(PeerState::Active { update_tx, .. }) => {
                if let Err(message) = update_tx.send(SessionUpdate::SubmitIntent(intent)).await {
                    let SessionUpdate::SubmitIntent(intent) = message.0;
                    intent.send_abort(Arc::new(Error::ActorFailed)).await;
                }
            }
        };
    }

    fn handle_event(&mut self, peer: NodeId, event: SessionEvent) {
        tracing::info!(?event, "event");
        match event {
            SessionEvent::Established => {}
            SessionEvent::Complete { .. } => {
                let state = self.peers.remove(&peer);
                debug_assert!(matches!(state, Some(PeerState::Active { .. })));
            }
        }
    }
}

#[derive(Debug)]
enum PeerState {
    Pending {
        our_role: Role,
        intents: Vec<Intent>,
        abort_handle: AbortHandle,
    },
    Active {
        update_tx: mpsc::Sender<SessionUpdate>,
    },
}

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

#[derive(Debug)]
struct EventForwarder {
    _join_handle: AbortingJoinHandle<()>,
    stream_sender: mpsc::Sender<(NodeId, ReceiverStream<EventKind>)>,
}

#[derive(Debug)]
struct EventForwarderActor {
    stream_receiver: mpsc::Receiver<(NodeId, ReceiverStream<EventKind>)>,
    streams: StreamMap<NodeId, ReceiverStream<EventKind>>,
    event_sender: mpsc::Sender<(NodeId, EventKind)>,
}

impl EventForwarder {
    fn new(event_sender: mpsc::Sender<(NodeId, EventKind)>) -> EventForwarder {
        let (stream_sender, stream_receiver) = mpsc::channel(16);
        let forwarder = EventForwarderActor {
            stream_receiver,
            streams: Default::default(),
            event_sender,
        };
        let join_handle = tokio::task::spawn(forwarder.run());
        EventForwarder {
            _join_handle: join_handle.into(),
            stream_sender,
        }
    }

    pub async fn add_intent(&self, peer: NodeId, event_stream: ReceiverStream<EventKind>) {
        self.stream_sender.send((peer, event_stream)).await.ok();
    }
}

impl EventForwarderActor {
    async fn run(mut self) {
        loop {
            tokio::select! {
                Some((peer, receiver)) = self.stream_receiver.recv() => {
                    self.streams.insert(peer, receiver);
                },
                Some((peer, event)) = self.streams.next() => {
                    if let Err(_receiver_dropped) = self.event_sender.send((peer, event)).await {
                        break;
                    }
                },
                else => break,
            }
        }
    }
}
