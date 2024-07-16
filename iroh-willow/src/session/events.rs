use std::{
    collections::{hash_map, HashMap, HashSet},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use futures_lite::StreamExt;
use futures_util::FutureExt;
use iroh_net::{
    dialer::Dialer, endpoint::Connection, util::SharedAbortingJoinHandle, Endpoint, NodeId,
};
use tokio::{
    io::Interest,
    sync::{mpsc, oneshot},
    task::{AbortHandle, JoinHandle, JoinSet},
};
use tokio_stream::{wrappers::ReceiverStream, StreamMap, StreamNotifyClose};
use tokio_util::sync::CancellationToken;
use tracing::{error_span, Instrument};

use crate::{
    actor::{Actor, ActorHandle, SessionHandle},
    auth::{Auth, InterestMap},
    net::{setup, ALPN},
    proto::{
        grouping::{Area, AreaOfInterest},
        keys::NamespaceId,
        sync::{ReadAuthorisation, ReadCapability},
    },
    session::{Error, Interests, Role, SessionId, SessionInit, SessionMode, SessionUpdate},
    store::traits::Storage,
};

use super::SessionUpdate::AddInterests;

type NamespaceInterests = HashMap<NamespaceId, HashSet<AreaOfInterest>>;

const COMMAND_CHANNEL_CAP: usize = 128;
const INTENT_UPDATE_CAP: usize = 16;
const INTENT_EVENT_CAP: usize = 64;

#[derive(Debug, Clone)]
pub struct EventSender(pub mpsc::Sender<EventKind>);

impl EventSender {
    pub async fn send(&self, event: EventKind) -> Result<(), Error> {
        self.0
            .send(event)
            .await
            .map_err(|_| Error::InvalidState("session event receiver dropped"))
    }
}

#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub session_id: SessionId,
    pub event: EventKind,
}

impl SessionEvent {
    pub fn new(session_id: SessionId, event: EventKind) -> Self {
        Self { session_id, event }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EventKind {
    CapabilityIntersection {
        namespace: NamespaceId,
        area: Area,
    },
    InterestIntersection {
        namespace: NamespaceId,
        area: AreaOfInterest,
    },
    Reconciled {
        namespace: NamespaceId,
        area: AreaOfInterest,
    },
    ReconciledAll,
    Closed {
        result: Result<(), Arc<Error>>,
    },
}

impl EventKind {
    pub fn namespace(&self) -> Option<NamespaceId> {
        match self {
            EventKind::CapabilityIntersection { namespace, .. } => Some(*namespace),
            EventKind::InterestIntersection { namespace, .. } => Some(*namespace),
            EventKind::Reconciled { namespace, .. } => Some(*namespace),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum IntentUpdate {
    AddInterests(Interests),
    Close,
}

#[derive(Debug)]
pub enum Command {
    SyncWithPeer {
        peer: NodeId,
        init: SessionInit,
        reply: oneshot::Sender<Result<IntentHandle>>,
    },
    HandleConnection {
        conn: Connection,
    },
}

#[derive(Debug, Clone)]
pub struct ManagedHandle {
    actor: ActorHandle,
    command_tx: mpsc::Sender<Command>,
    _task_handle: SharedAbortingJoinHandle<Result<(), String>>,
}

impl ManagedHandle {
    pub fn spawn<S: Storage>(
        endpoint: Endpoint,
        create_store: impl 'static + Send + FnOnce() -> S,
    ) -> Self {
        let me = endpoint.node_id();
        let actor = ActorHandle::spawn(create_store, me);
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAP);
        let peer_manager = PeerManager {
            session_event_rx: Default::default(),
            intent_update_rx: Default::default(),
            command_rx,
            establish_tasks: Default::default(),
            net_tasks: Default::default(),
            actor: actor.clone(),
            peers: Default::default(),
            sessions: Default::default(),
            endpoint: endpoint.clone(),
            dialer: Dialer::new(endpoint),
            next_intent_id: 0,
        };
        let task_handle = tokio::task::spawn(
            async move { peer_manager.run().await.map_err(|err| format!("{err:?}")) }
                .instrument(error_span!("peer_manager", me = me.fmt_short())),
        );
        ManagedHandle {
            actor,
            command_tx,
            _task_handle: task_handle.into(),
        }
    }

    pub async fn handle_connection(&self, conn: Connection) -> Result<()> {
        self.command_tx
            .send(Command::HandleConnection { conn })
            .await?;
        Ok(())
    }

    pub async fn sync_with_peer(&self, peer: NodeId, init: SessionInit) -> Result<IntentHandle> {
        let (reply, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::SyncWithPeer { peer, init, reply })
            .await?;
        reply_rx.await?
    }
}

impl std::ops::Deref for ManagedHandle {
    type Target = ActorHandle;

    fn deref(&self) -> &Self::Target {
        &self.actor
    }
}

type NetTasks = JoinSet<Result<()>>;

type EstablishRes = (NodeId, Result<(NetTasks, SessionHandle)>);

pub type IntentId = (NodeId, u64);

#[derive(derive_more::Debug)]
pub struct PeerManager {
    session_event_rx: StreamMap<SessionId, ReceiverStream<EventKind>>,
    #[debug("StreamMap")]
    intent_update_rx: StreamMap<IntentId, StreamNotifyClose<ReceiverStream<IntentUpdate>>>,
    command_rx: mpsc::Receiver<Command>,
    establish_tasks: JoinSet<EstablishRes>,
    net_tasks: JoinSet<(NodeId, Result<()>)>,

    actor: ActorHandle,
    peers: HashMap<NodeId, PeerState>,
    sessions: HashMap<SessionId, SessionInfo>,
    endpoint: Endpoint,
    dialer: Dialer,
    next_intent_id: u64,
}

impl PeerManager {
    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                Some((session_id, event)) = self.session_event_rx.next(), if !self.session_event_rx.is_empty() => {
                    self.received_event(session_id, event).await;
                }
                Some(((peer, intent_id), event)) = self.intent_update_rx.next(), if !self.intent_update_rx.is_empty() => {
                    if let Some(event) = event {
                        // Received an intent update.
                        if let Err(err) = self.update_intent(peer, intent_id, event).await {
                            tracing::warn!(peer=%peer.fmt_short(), %intent_id, ?err, "failed to update intent");
                        }
                    } else {
                        // The intent update sender was dropped: Cancel the intent.
                        self.cancel_intent(peer, intent_id);
                    }
                }
                Some(command) = self.command_rx.recv() => {
                    self.received_command(command).await;
                }
                Some(res) = self.establish_tasks.join_next(), if !self.establish_tasks.is_empty() => {
                    match res {
                        Err(err) if err.is_cancelled() => continue,
                        Err(err) => Err(err).context("establish task paniced")?,
                        Ok((peer, Ok((tasks, handle)))) => self.on_established(peer, handle, tasks).await?,
                        Ok((peer, Err(err))) => self.remove_peer(peer, Err(Arc::new(Error::Net(err)))).await,
                    }
                }
                Some(res) = self.net_tasks.join_next(), if !self.net_tasks.is_empty() => {
                    match res {
                        Err(err) if err.is_cancelled() => continue,
                        Err(err) => Err(err).context("net task paniced")?,
                        Ok((_peer, Ok(())))=> continue,
                        Ok((peer, Err(err))) => self.on_net_task_failed(peer, err),
                    }
                },
                Some((peer, conn)) = self.dialer.next() => {
                    match conn {
                        Ok(conn) => self.handle_connection(conn, Role::Alfie).await,
                        Err(err) => self.on_dial_fail(peer, err).await,
                    }

                }
                else => break,
            }
        }
        Ok(())
    }

    async fn remove_peer(&mut self, peer: NodeId, result: Result<(), Arc<Error>>) {
        let Some(peer_state) = self.peers.remove(&peer) else {
            tracing::warn!(?peer, "attempted to remove unknown peer");
            return;
        };
        let (intents, session_id) = match peer_state {
            PeerState::Connecting { intents, .. } => {
                self.dialer.abort_dial(&peer);
                (Some(intents), None)
            }
            PeerState::Establishing { intents, .. } => (Some(intents), None),
            PeerState::Active { session_id } => {
                let session = self.sessions.remove(&session_id);
                let intents = session.map(|session| session.intents);
                (intents, Some(session_id))
            }
            PeerState::Placeholder => unreachable!(),
        };
        if let Some(intents) = intents {
            for intent in &intents {
                self.intent_update_rx.remove(&(peer, intent.intent_id));
            }
            let senders = intents.into_iter().map(|intent| intent.event_tx);
            send_all(senders, EventKind::Closed { result }).await;
        }
        if let Some(session_id) = session_id {
            self.session_event_rx.remove(&session_id);
        }
    }

    async fn on_dial_fail(&mut self, peer: NodeId, err: anyhow::Error) {
        let result = Err(Arc::new(Error::Net(err)));
        self.remove_peer(peer, result).await;
    }

    fn session_mut(&mut self, peer: &NodeId) -> Option<&mut SessionInfo> {
        let peer_state = self.peers.get(peer)?;
        match peer_state {
            PeerState::Active { session_id } => self.sessions.get_mut(session_id),
            _ => None,
        }
    }

    fn on_net_task_failed(&mut self, peer: NodeId, err: anyhow::Error) {
        if let Some(session) = self.session_mut(&peer) {
            if session.net_error.is_none() {
                session.net_error = Some(err);
            }
        }
    }

    async fn on_established(
        &mut self,
        peer: NodeId,
        session_handle: SessionHandle,
        mut net_tasks: NetTasks,
    ) -> anyhow::Result<()> {
        let peer_state = self
            .peers
            .get_mut(&peer)
            .ok_or_else(|| anyhow!("unreachable: on_established called for unknown peer"))?;
        let current_state = std::mem::replace(peer_state, PeerState::Placeholder);
        let PeerState::Establishing {
            our_role,
            intents,
            submitted_interests,
            pending_interests,
        } = current_state
        else {
            anyhow::bail!("unreachable: on_established called for peer in wrong state")
        };
        if our_role.is_alfie() && intents.is_empty() {
            session_handle.close();
        }
        let SessionHandle {
            session_id,
            cancel_token,
            update_tx,
            event_rx,
        } = session_handle;
        self.net_tasks.spawn(
            async move { crate::net::join_all(&mut net_tasks).await }.map(move |r| (peer, r)),
        );
        let mut session_info = SessionInfo {
            peer,
            our_role,
            complete_areas: Default::default(),
            submitted_interests,
            intents,
            net_error: None,
            update_tx,
            cancel_token,
        };
        if !pending_interests.is_empty() {
            session_info.push_interests(pending_interests).await?;
        }
        self.sessions.insert(session_id, session_info);
        self.session_event_rx
            .insert(session_id, ReceiverStream::new(event_rx));
        *peer_state = PeerState::Active { session_id };
        Ok(())
    }

    pub async fn sync_with_peer(
        &mut self,
        peer: NodeId,
        init: SessionInit,
    ) -> Result<IntentHandle> {
        let intent_interests = self.actor.resolve_interests(init.interests).await?;
        // TODO: Allow to configure cap?
        let (event_tx, event_rx) = mpsc::channel(INTENT_EVENT_CAP);
        let (update_tx, update_rx) = mpsc::channel(INTENT_UPDATE_CAP);
        let intent_id = {
            let intent_id = self.next_intent_id;
            self.next_intent_id += 1;
            intent_id
        };
        let info = IntentInfo {
            intent_id,
            interests: flatten_interests(&intent_interests),
            mode: init.mode,
            event_tx,
        };
        let handle = IntentHandle {
            event_rx,
            update_tx,
        };
        self.intent_update_rx.insert(
            (peer, intent_id),
            StreamNotifyClose::new(ReceiverStream::new(update_rx)),
        );
        match self.peers.get_mut(&peer) {
            None => {
                self.dialer.queue_dial(peer, ALPN);
                let intents = vec![info];
                let peer_state = PeerState::Connecting {
                    intents,
                    interests: intent_interests,
                };
                self.peers.insert(peer, peer_state);
            }
            Some(state) => match state {
                PeerState::Connecting { intents, interests } => {
                    intents.push(info);
                    merge_interests(interests, intent_interests);
                }
                PeerState::Establishing {
                    intents,
                    pending_interests,
                    ..
                } => {
                    intents.push(info);
                    merge_interests(pending_interests, intent_interests);
                }
                PeerState::Active { session_id, .. } => {
                    let session = self.sessions.get_mut(session_id).expect("session to exist");
                    session.intents.push(info);
                    session.push_interests(intent_interests).await?;
                }
                PeerState::Placeholder => unreachable!(),
            },
        };
        Ok(handle)
    }

    pub async fn update_intent(
        &mut self,
        peer: NodeId,
        intent_id: u64,
        update: IntentUpdate,
    ) -> Result<()> {
        match update {
            IntentUpdate::AddInterests(interests) => {
                let add_interests = self.actor.resolve_interests(interests).await?;
                match self.peers.get_mut(&peer) {
                    None => anyhow::bail!("invalid node id"),
                    Some(peer_state) => match peer_state {
                        PeerState::Connecting { intents, interests } => {
                            let intent_info = intents
                                .iter_mut()
                                .find(|i| i.intent_id == intent_id)
                                .ok_or_else(|| anyhow!("invalid intent id"))?;
                            intent_info.merge_interests(&add_interests);
                            merge_interests(interests, add_interests);
                        }
                        PeerState::Establishing {
                            intents,
                            pending_interests,
                            ..
                        } => {
                            let intent_info = intents
                                .iter_mut()
                                .find(|i| i.intent_id == intent_id)
                                .ok_or_else(|| anyhow!("invalid intent id"))?;
                            intent_info.merge_interests(&add_interests);
                            merge_interests(pending_interests, add_interests);
                        }
                        PeerState::Active { session_id, .. } => {
                            let session =
                                self.sessions.get_mut(session_id).expect("session to exist");
                            let Some(intent_info) = session
                                .intents
                                .iter_mut()
                                .find(|i| i.intent_id == intent_id)
                            else {
                                anyhow::bail!("invalid intent id");
                            };
                            intent_info.merge_interests(&add_interests);
                            session.push_interests(add_interests).await?;
                        }
                        PeerState::Placeholder => unreachable!(),
                    },
                };
            }
            IntentUpdate::Close => {
                self.cancel_intent(peer, intent_id);
            }
        }
        Ok(())
    }

    pub fn cancel_intent(&mut self, peer: NodeId, intent_id: u64) {
        let Some(peer_state) = self.peers.get_mut(&peer) else {
            return;
        };

        self.intent_update_rx.remove(&(peer, intent_id));

        match peer_state {
            PeerState::Connecting { intents, .. } => {
                intents.retain(|intent_info| intent_info.intent_id != intent_id);
                if intents.is_empty() {
                    self.dialer.abort_dial(&peer);
                    self.peers.remove(&peer);
                }
            }
            PeerState::Establishing { intents, .. } => {
                intents.retain(|intent_info| intent_info.intent_id != intent_id);
            }
            PeerState::Active { session_id, .. } => {
                let session = self.sessions.get_mut(session_id).expect("session to exist");
                session
                    .intents
                    .retain(|intent| intent.intent_id != intent_id);
                if session.intents.is_empty() {
                    session.cancel_token.cancel();
                }
            }
            PeerState::Placeholder => unreachable!(),
        }
    }

    pub async fn received_command(&mut self, command: Command) {
        tracing::info!(?command, "command");
        match command {
            Command::SyncWithPeer { peer, init, reply } => {
                let res = self.sync_with_peer(peer, init).await;
                reply.send(res).ok();
            }
            Command::HandleConnection { conn } => {
                self.handle_connection(conn, Role::Betty).await;
            }
        }
    }

    pub async fn received_event(&mut self, session_id: SessionId, event: EventKind) {
        tracing::info!(?event, "event");
        let Some(session) = self.sessions.get_mut(&session_id) else {
            tracing::warn!(?session_id, ?event, "Got event for unknown session");
            return;
        };

        let peer = session.peer;

        if let EventKind::Closed { mut result } = event {
            if result.is_ok() {
                // Inject error from networking tasks.
                if let Some(net_error) = session.net_error.take() {
                    result = Err(Arc::new(Error::Net(net_error)));
                }
            }
            self.remove_peer(peer, result).await;
            return;
        }

        if let EventKind::Reconciled { namespace, area } = &event {
            session
                .complete_areas
                .entry(*namespace)
                .or_default()
                .insert(area.clone());
        }

        let send_futs = session
            .intents
            .iter_mut()
            .map(|intent_info| intent_info.handle_event(&event));
        let send_res = futures_buffered::join_all(send_futs).await;
        let mut removed = 0;
        for (i, res) in send_res.into_iter().enumerate() {
            match res {
                Err(ReceiverDropped) | Ok(false) => {
                    session.intents.remove(i - removed);
                    removed += 1;
                }
                Ok(true) => {}
            }
        }

        // Cancel the session if all intents are gone.
        if session.our_role.is_alfie() && session.intents.is_empty() {
            session.cancel_token.cancel();
        }
    }

    async fn handle_connection(&mut self, conn: Connection, our_role: Role) {
        let peer = match iroh_net::endpoint::get_remote_node_id(&conn) {
            Ok(node_id) => node_id,
            Err(err) => {
                tracing::warn!(?err, "skip connection: failed to get node id");
                return;
            }
        };
        if let Err(err) = self.handle_connection_inner(peer, conn, our_role).await {
            tracing::warn!(?peer, ?err, "failed to establish connection");
            let result = Err(Arc::new(Error::Net(err)));
            self.remove_peer(peer, result).await;
        }
    }

    async fn handle_connection_inner(
        &mut self,
        peer: NodeId,
        conn: Connection,
        our_role: Role,
    ) -> Result<()> {
        let peer_state = self.peers.get_mut(&peer);
        let (interests, mode, intents) = match our_role {
            Role::Alfie => {
                let peer_state = peer_state
                    .ok_or_else(|| anyhow!("got connection for peer without any intents"))?;
                let peer_state = std::mem::replace(peer_state, PeerState::Placeholder);
                match peer_state {
                    PeerState::Placeholder => unreachable!(),
                    PeerState::Active { .. } => {
                        tracing::warn!("got connection for already active peer");
                        return Ok(());
                    }
                    PeerState::Establishing { .. } => {
                        tracing::warn!("got connection for already establishing peer");
                        return Ok(());
                    }
                    PeerState::Connecting { intents, interests } => {
                        let mode = if intents.iter().any(|i| matches!(i.mode, SessionMode::Live)) {
                            SessionMode::Live
                        } else {
                            SessionMode::ReconcileOnce
                        };
                        (interests, mode, intents)
                    }
                }
            }
            Role::Betty => {
                let intents = if let Some(peer_state) = peer_state {
                    let peer_state = std::mem::replace(peer_state, PeerState::Placeholder);
                    match peer_state {
                        PeerState::Placeholder => unreachable!(),
                        PeerState::Active { .. } => {
                            tracing::warn!("got connection for already active peer");
                            return Ok(());
                        }
                        PeerState::Establishing { .. } => {
                            tracing::warn!("got connection for already establishing peer");
                            return Ok(());
                        }
                        PeerState::Connecting { intents, .. } => {
                            // TODO: Decide which conn to use.
                            intents
                        }
                    }
                } else {
                    Default::default()
                };
                let interests = self.actor.resolve_interests(Interests::All).await?;
                (interests, SessionMode::Live, intents)
            }
        };

        let me = self.endpoint.node_id();
        let actor = self.actor.clone();
        let submitted_interests = interests.clone();
        let init = SessionInit {
            mode,
            interests: Interests::Exact(interests),
        };
        let establish_fut = async move {
            let (initial_transmission, channels, tasks) = setup(conn, me, our_role).await?;
            let session_handle = actor
                .init_session(peer, our_role, initial_transmission, channels, init)
                .await?;
            Ok::<_, anyhow::Error>((tasks, session_handle))
        };
        let establish_fut = establish_fut.map(move |res| (peer, res));
        let _task_handle = self.establish_tasks.spawn(establish_fut);
        let peer_state = PeerState::Establishing {
            our_role,
            intents,
            submitted_interests,
            pending_interests: Default::default(),
        };
        self.peers.insert(peer, peer_state);
        Ok(())
    }
}

#[derive(Debug)]
struct SessionInfo {
    peer: NodeId,
    our_role: Role,
    complete_areas: NamespaceInterests,
    submitted_interests: InterestMap,
    intents: Vec<IntentInfo>,
    net_error: Option<anyhow::Error>,
    cancel_token: CancellationToken,
    update_tx: mpsc::Sender<SessionUpdate>,
}

impl SessionInfo {
    async fn push_interests(&mut self, interests: InterestMap) -> Result<()> {
        let new_interests = self.merge_interests(interests);
        self.update_tx
            .send(AddInterests(Interests::Exact(new_interests)))
            .await?;
        Ok(())
    }

    fn merge_interests(&mut self, interests: InterestMap) -> InterestMap {
        let mut new: InterestMap = HashMap::new();
        for (auth, aois) in interests.into_iter() {
            match self.submitted_interests.entry(auth.clone()) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(aois.clone());
                    new.insert(auth, aois);
                }
                hash_map::Entry::Occupied(mut entry) => {
                    let existing = entry.get_mut();
                    for aoi in aois {
                        if !existing.contains(&aoi) {
                            existing.insert(aoi.clone());
                            new.entry(auth.clone()).or_default().insert(aoi);
                        }
                    }
                }
            }
        }
        new
    }
}

#[derive(Debug)]
enum PeerState {
    Connecting {
        intents: Vec<IntentInfo>,
        interests: InterestMap,
    },
    Establishing {
        our_role: Role,
        intents: Vec<IntentInfo>,
        submitted_interests: InterestMap,
        pending_interests: InterestMap,
    },
    Active {
        session_id: SessionId,
    },
    Placeholder,
}

#[derive(Debug)]
pub struct IntentHandle {
    event_rx: mpsc::Receiver<EventKind>,
    update_tx: mpsc::Sender<IntentUpdate>,
}

impl IntentHandle {
    // TODO: impl stream
    pub async fn next(&mut self) -> Option<EventKind> {
        self.event_rx.recv().await
    }

    pub async fn complete(&mut self) -> Result<(), Arc<Error>> {
        loop {
            let event = self
                .event_rx
                .recv()
                .await
                .ok_or_else(|| Arc::new(Error::ActorFailed))?;
            if let EventKind::Closed { result } = event {
                return result;
            }
        }
    }

    pub async fn add_interests(&self, interests: impl Into<Interests>) -> Result<()> {
        self.update_tx
            .send(IntentUpdate::AddInterests(interests.into()))
            .await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.update_tx.send(IntentUpdate::Close).await.ok();
    }
}

#[derive(Debug)]
struct IntentInfo {
    intent_id: u64,
    interests: NamespaceInterests,
    mode: SessionMode,
    event_tx: mpsc::Sender<EventKind>,
}

impl IntentInfo {
    fn merge_interests(&mut self, interests: &InterestMap) {
        for (auth, aois) in interests.iter() {
            self.interests
                .entry(auth.namespace())
                .or_default()
                .extend(aois.clone());
        }
    }

    async fn handle_event(&mut self, event: &EventKind) -> Result<bool, ReceiverDropped> {
        let send = |event: EventKind| async {
            self.event_tx.send(event).await.map_err(|_| ReceiverDropped)
        };

        let stay_alive = match &event {
            EventKind::CapabilityIntersection { namespace, .. } => {
                if self.interests.contains_key(namespace) {
                    send(event.clone()).await?;
                }
                true
            }
            EventKind::InterestIntersection { area, namespace } => {
                if let Some(interests) = self.interests.get(namespace) {
                    let matches = interests
                        .iter()
                        .any(|x| x.area.has_intersection(&area.area));
                    if matches {
                        send(event.clone()).await?;
                    }
                }
                true
            }
            EventKind::Reconciled { area, namespace } => {
                if let Some(interests) = self.interests.get_mut(namespace) {
                    let matches = interests
                        .iter()
                        .any(|x| x.area.has_intersection(&area.area));
                    if matches {
                        send(event.clone()).await?;
                        interests.retain(|x| !area.area.includes_area(&x.area));
                        if interests.is_empty() {
                            send(EventKind::ReconciledAll).await?;
                        }
                    }
                }
                true
            }
            EventKind::Closed { .. } => {
                send(event.clone()).await?;
                false
            }
            EventKind::ReconciledAll => true,
        };
        Ok(stay_alive)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("receiver dropped")]
pub struct ReceiverDropped;

fn merge_interests(a: &mut InterestMap, b: InterestMap) {
    for (cap, aois) in b.into_iter() {
        a.entry(cap).or_default().extend(aois);
    }
}

fn flatten_interests(interests: &InterestMap) -> NamespaceInterests {
    let mut out = NamespaceInterests::new();
    for (cap, aois) in interests {
        out.entry(cap.namespace()).or_default().extend(aois.clone());
    }
    out
}

async fn send_all<T: Clone>(
    senders: impl IntoIterator<Item = impl std::borrow::Borrow<mpsc::Sender<T>>>,
    message: T,
) -> Vec<Result<(), mpsc::error::SendError<T>>> {
    let futs = senders.into_iter().map(|sender| {
        let message = message.clone();
        async move { sender.borrow().send(message).await }
    });
    futures_buffered::join_all(futs).await
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use iroh_net::{Endpoint, NodeAddr, NodeId};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use std::collections::HashMap;

    use super::{EventKind, ManagedHandle, ALPN};
    use crate::{
        actor::ActorHandle,
        auth::{CapSelector, DelegateTo},
        form::{AuthForm, EntryForm, PayloadForm, SubspaceForm, TimestampForm},
        net::run,
        proto::{
            grouping::{Area, AreaOfInterest, ThreeDRange},
            keys::{NamespaceId, NamespaceKind, UserId},
            meadowcap::AccessMode,
            willow::{Entry, InvalidPath, Path},
        },
        session::{Interests, Role, SessionInit, SessionMode},
    };

    fn create_rng(seed: &str) -> ChaCha12Rng {
        let seed = iroh_base::hash::Hash::new(seed);
        rand_chacha::ChaCha12Rng::from_seed(*(seed.as_bytes()))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_manager_two_intents() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = create_rng("peer_manager_two_intents");
        let (
            shutdown,
            namespace,
            (alfie, _alfie_node_id, _alfie_user),
            (betty, betty_node_id, betty_user),
        ) = create_and_setup_two(&mut rng).await?;

        insert(&betty, namespace, betty_user, &[b"foo", b"1"], "foo 1").await?;
        insert(&betty, namespace, betty_user, &[b"bar", b"2"], "bar 2").await?;
        insert(&betty, namespace, betty_user, &[b"bar", b"3"], "bar 3").await?;

        let task_foo = tokio::task::spawn({
            let alfie = alfie.clone();
            async move {
                let path = Path::new(&[b"foo"]).unwrap();

                let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
                let init = SessionInit::new(interests, SessionMode::ReconcileOnce);
                let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::CapabilityIntersection {
                        namespace,
                        area: Area::full(),
                    }
                );

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::InterestIntersection {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::Reconciled {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::Closed { result: Ok(()) }
                );

                assert!(intent.next().await.is_none());
            }
        });

        let task_bar = tokio::task::spawn({
            let alfie = alfie.clone();
            async move {
                let path = Path::new(&[b"bar"]).unwrap();

                let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
                let init = SessionInit::new(interests, SessionMode::ReconcileOnce);

                let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::CapabilityIntersection {
                        namespace,
                        area: Area::full(),
                    }
                );

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::InterestIntersection {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::Reconciled {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::Closed { result: Ok(()) }
                );

                assert!(intent.next().await.is_none());
            }
        });

        task_foo.await.unwrap();
        task_bar.await.unwrap();
        shutdown();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_manager_update_intent() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = create_rng("peer_manager_update_intent");
        let (
            shutdown,
            namespace,
            (alfie, _alfie_node_id, _alfie_user),
            (betty, betty_node_id, betty_user),
        ) = create_and_setup_two(&mut rng).await?;

        insert(&betty, namespace, betty_user, &[b"foo"], "foo 1").await?;
        insert(&betty, namespace, betty_user, &[b"bar"], "bar 1").await?;

        let path = Path::new(&[b"foo"]).unwrap();

        let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
        let init = SessionInit::new(interests, SessionMode::Live);
        let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::CapabilityIntersection {
                namespace,
                area: Area::full(),
            }
        );
        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::InterestIntersection {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );
        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::Reconciled {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );
        assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

        let path = Path::new(&[b"bar"]).unwrap();
        let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
        intent.add_interests(interests).await?;

        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::InterestIntersection {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );
        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::Reconciled {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );

        assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

        intent.close().await;

        assert!(intent.next().await.is_none(),);
        // assert_eq!(
        //     intent.next().await.unwrap(),
        //     EventKind::Closed { result: Ok(()) }
        // );

        shutdown();
        Ok(())
    }

    pub async fn create_and_setup_two(
        rng: &mut rand_chacha::ChaCha12Rng,
    ) -> anyhow::Result<(
        impl Fn(),
        NamespaceId,
        (ManagedHandle, NodeId, UserId),
        (ManagedHandle, NodeId, UserId),
    )> {
        let (alfie, alfie_ep, alfie_addr, alfie_task) = create(rng).await?;
        let (betty, betty_ep, betty_addr, betty_task) = create(rng).await?;

        let betty_node_id = betty_addr.node_id;
        let alfie_node_id = alfie_addr.node_id;
        alfie_ep.add_node_addr(betty_addr)?;
        betty_ep.add_node_addr(alfie_addr)?;

        let (namespace_id, alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;

        let shutdown = move || {
            betty_task.abort();
            alfie_task.abort();
        };
        Ok((
            shutdown,
            namespace_id,
            (alfie, alfie_node_id, alfie_user),
            (betty, betty_node_id, betty_user),
        ))
    }

    pub async fn create(
        rng: &mut rand_chacha::ChaCha12Rng,
    ) -> anyhow::Result<(
        ManagedHandle,
        Endpoint,
        iroh_net::NodeAddr,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    )> {
        let endpoint = Endpoint::builder()
            .secret_key(iroh_net::key::SecretKey::generate_with_rng(rng))
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;
        let node_addr = endpoint.node_addr().await?;
        let payloads = iroh_blobs::store::mem::Store::default();
        let create_store = move || crate::store::memory::Store::new(payloads);
        let handle = ManagedHandle::spawn(endpoint.clone(), create_store);
        let accept_task = tokio::task::spawn({
            let handle = handle.clone();
            let endpoint = endpoint.clone();
            async move {
                while let Some(mut conn) = endpoint.accept().await {
                    let alpn = conn.alpn().await?;
                    if alpn != ALPN {
                        continue;
                    }
                    let conn = conn.await?;
                    handle.handle_connection(conn).await?;
                }
                Ok::<_, anyhow::Error>(())
            }
        });
        Ok((handle, endpoint, node_addr, accept_task))
    }

    async fn setup_and_delegate(
        alfie: &ManagedHandle,
        betty: &ManagedHandle,
    ) -> anyhow::Result<(NamespaceId, UserId, UserId)> {
        let user_alfie = alfie.create_user().await?;
        let user_betty = betty.create_user().await?;

        let namespace_id = alfie
            .create_namespace(NamespaceKind::Owned, user_alfie)
            .await?;

        let cap_for_betty = alfie
            .delegate_caps(
                CapSelector::widest(namespace_id),
                AccessMode::Write,
                DelegateTo::new(user_betty, None),
            )
            .await?;

        betty.import_caps(cap_for_betty).await?;
        Ok((namespace_id, user_alfie, user_betty))
    }

    async fn insert(
        handle: &ManagedHandle,
        namespace_id: NamespaceId,
        user: UserId,
        path: &[&[u8]],
        bytes: impl Into<Bytes>,
    ) -> anyhow::Result<()> {
        let path = Path::new(path)?;
        let entry = EntryForm::new_bytes(namespace_id, path, bytes);
        handle.insert(entry, user).await?;
        Ok(())
    }
}
