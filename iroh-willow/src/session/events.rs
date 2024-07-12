use std::{
    collections::{hash_map, BTreeSet, HashMap},
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
    sync::oneshot,
    task::{AbortHandle, JoinHandle, JoinSet},
};
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
    session::{Error, Interests, Role, SessionId, SessionInit, SessionMode},
    store::traits::Storage,
};

use super::SessionUpdate::AddInterests;

type NamespaceInterests = HashMap<NamespaceId, BTreeSet<AreaOfInterest>>;

const COMMAND_CHANNEL_CAP: usize = 128;

#[derive(Debug, Clone)]
pub struct EventSender {
    session_id: SessionId,
    sender: flume::Sender<SessionEvent>,
}

impl EventSender {
    pub fn new(session_id: SessionId, sender: flume::Sender<SessionEvent>) -> Self {
        Self { session_id, sender }
    }
    pub async fn send(&self, event: EventKind) -> Result<(), Error> {
        self.sender
            .send_async(SessionEvent::new(self.session_id, event))
            .await
            .map_err(|_| Error::InvalidState("session event receiver dropped"))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SessionEvent {
    session_id: SessionId,
    event: EventKind,
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

// #[derive(Debug, Clone)]
// pub struct SyncEvent {
//     peer: NodeId,
//     event: EventKind,
// }

#[derive(Debug)]
pub enum Command {
    SyncWithPeer {
        peer: NodeId,
        init: SessionInit,
        reply: oneshot::Sender<Result<IntentHandle>>,
    },
    UpdateIntent {
        peer: NodeId,
        intent_id: u64,
        add_interests: Interests,
        reply: oneshot::Sender<Result<()>>,
    },
    CancelIntent {
        peer: NodeId,
        intent_id: u64,
    },
    HandleConnection {
        conn: Connection,
    },
}

#[derive(Debug, Clone)]
pub struct ManagedHandle {
    actor: ActorHandle,
    command_tx: flume::Sender<Command>,
    _task_handle: SharedAbortingJoinHandle<Result<(), String>>,
}

impl ManagedHandle {
    pub fn spawn<S: Storage>(
        endpoint: Endpoint,
        create_store: impl 'static + Send + FnOnce() -> S,
    ) -> Self {
        let me = endpoint.node_id();
        let (actor, event_rx) = ActorHandle::spawn_with_events(create_store, me);
        let (command_tx, command_rx) = flume::bounded(COMMAND_CHANNEL_CAP);
        let peer_manager = PeerManager {
            event_rx,
            command_rx,
            command_tx: command_tx.clone(),
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
            .send_async(Command::HandleConnection { conn })
            .await?;
        Ok(())
    }

    pub async fn sync_with_peer(&self, peer: NodeId, init: SessionInit) -> Result<IntentHandle> {
        let (reply, reply_rx) = oneshot::channel();
        self.command_tx
            .send_async(Command::SyncWithPeer { peer, init, reply })
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

type EstablishRes = (NodeId, Result<(JoinSet<Result<()>>, SessionHandle)>);

#[derive(Debug)]
pub struct PeerManager {
    event_rx: flume::Receiver<SessionEvent>,
    command_rx: flume::Receiver<Command>,
    command_tx: flume::Sender<Command>,
    establish_tasks: JoinSet<EstablishRes>,
    net_tasks: JoinSet<(NodeId, Result<()>)>,

    actor: ActorHandle,
    peers: HashMap<NodeId, PeerState>,
    // auth: Auth<S>,
    sessions: HashMap<SessionId, SessionInfo>,
    // intents: HashMap<IntentId, IntentInfo>,
    endpoint: Endpoint,
    dialer: Dialer,
    next_intent_id: u64,
}

#[derive(Debug)]
struct SessionInfo {
    // peer: NodeId,
    our_role: Role,
    complete_areas: NamespaceInterests,
    submitted_interests: InterestMap,
    intents: Vec<IntentInfo>,
    handle: SessionHandle,
    net_error: Option<anyhow::Error>,
}

impl SessionInfo {
    async fn push_interests(&mut self, interests: InterestMap) -> Result<()> {
        let new_interests = self.merge_interests(interests);
        self.handle
            .send_update(AddInterests(Interests::Exact(new_interests)))
            .await?;
        Ok(())
    }
    // TODO: Less clones?
    fn merge_interests(&mut self, interests: InterestMap) -> InterestMap {
        let mut new: InterestMap = HashMap::new();
        for (auth, aois) in interests.into_iter() {
            match self.submitted_interests.entry(auth.clone()) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(aois.clone());
                    new.insert(auth, aois.clone());
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
        // for (namespace, details) in interests.into_iter() {
        //     let namespace = *namespace;
        //     match self.submitted_interests.entry(namespace) {
        //         hash_map::Entry::Vacant(entry) => {
        //             entry.insert(details.clone());
        //             new.insert(namespace, details.clone());
        //         }
        //         hash_map::Entry::Occupied(mut entry) => {
        //             let existing = entry.get_mut();
        //             for aoi in details.aois {
        //                 if !existing.aois.contains(&aoi) {
        //                     existing.aois.insert(aoi.clone());
        //                     new.entry(namespace).or_default().aois.insert(aoi);
        //                 }
        //             }
        //             for auth in details.auths {
        //                 if !existing.auths.contains(&auth) {
        //                     existing.auths.insert(auth.clone());
        //                     new.entry(namespace).or_default().auths.insert(auth);
        //                 }
        //             }
        //         }
        //     }
        // }
    }
}

#[derive(Debug)]
struct IntentInfo {
    // peer: NodeId,
    intent_id: u64,
    interests: NamespaceInterests,
    mode: SessionMode,
    sender: flume::Sender<EventKind>,
}

#[derive(Debug)]
pub struct IntentHandle {
    peer: NodeId,
    intent_id: u64,
    receiver: flume::Receiver<EventKind>,
    sender: flume::Sender<Command>,
}

impl IntentHandle {
    // TODO: impl stream
    pub async fn next(&self) -> Option<EventKind> {
        self.receiver.recv_async().await.ok()
    }

    pub async fn complete(&self) -> Result<(), Arc<Error>> {
        loop {
            let event = self
                .receiver
                .recv_async()
                .await
                .map_err(|_| Arc::new(Error::ActorFailed))?;
            if let EventKind::Closed { result } = event {
                return result;
            }
        }
    }

    pub async fn add_interests(&self, interests: impl Into<Interests>) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.sender
            .send_async(Command::UpdateIntent {
                peer: self.peer,
                intent_id: self.intent_id,
                add_interests: interests.into(),
                reply,
            })
            .await?;
        reply_rx.await?
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
    // Closing {
    //     session_id: SessionId,
    // },
    Placeholder,
}

impl PeerState {
    pub fn into_intents(self) -> Option<Vec<IntentInfo>> {
        match self {
            PeerState::Connecting { intents, .. } => Some(intents),
            PeerState::Establishing { intents, .. } => Some(intents),
            _ => None,
        }
    }
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
            self.sender
                .send_async(event)
                .await
                .map_err(|_| ReceiverDropped)
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

impl PeerManager {
    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                Ok(event) = self.event_rx.recv_async() => {
                    self.received_event(event).await;
                }
                Ok(command) = self.command_rx.recv_async() => {
                    self.received_command(command).await;
                }
                Some(res) = self.establish_tasks.join_next(), if !self.establish_tasks.is_empty() => {
                    let res = match res {
                        Ok(res) => res,
                        Err(err) if err.is_cancelled() => {
                            continue;
                        },
                        Err(err) => Err(err).context("establish task paniced")?,
                    };
                    self.on_established(res).await?;

                }
                Some(res) = self.net_tasks.join_next(), if !self.net_tasks.is_empty() => {
                    match res {
                        Err(err) if err.is_cancelled() => {
                            continue;
                        },
                        Err(err) => Err(err).context("net task paniced")?,
                        Ok((peer, res)) => {
                            if let Err(err) = res {
                                self.on_conn_fail(peer, err);
                            }
                        }
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

    async fn on_dial_fail(&mut self, peer: NodeId, err: anyhow::Error) {
        let Some(peer_state) = self.peers.remove(&peer) else {
            tracing::warn!(?peer, "dialer returned connection error for unknown peer");
            return;
        };
        let PeerState::Connecting { intents, .. } = peer_state else {
            tracing::warn!(
                ?peer,
                "dialer returned connection error for peer in wrong state"
            );
            return;
        };
        let result = Err(Arc::new(Error::Net(err)));
        for intent in intents {
            let result = result.clone();
            intent
                .sender
                .send_async(EventKind::Closed { result })
                .await
                .ok();
        }
    }

    fn session_mut(&mut self, peer: &NodeId) -> Option<&mut SessionInfo> {
        let peer_state = self.peers.get(peer)?;
        match peer_state {
            PeerState::Active { session_id } => self.sessions.get_mut(session_id),
            _ => None,
        }
    }

    fn on_conn_fail(&mut self, peer: NodeId, err: anyhow::Error) {
        if let Some(session) = self.session_mut(&peer) {
            if session.net_error.is_none() {
                session.net_error = Some(err);
            }
        }
    }

    async fn on_established(&mut self, res: EstablishRes) -> anyhow::Result<()> {
        let (peer, res) = res;
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
        match res {
            Ok((mut net_tasks, session_handle)) => {
                if our_role.is_alfie() && intents.is_empty() {
                    session_handle.close();
                }
                let session_id = session_handle.session_id();
                self.net_tasks.spawn(
                    async move { crate::net::join_all(&mut net_tasks).await }
                        .map(move |r| (peer, r)),
                );
                let mut session_info = SessionInfo {
                    our_role,
                    complete_areas: Default::default(),
                    submitted_interests,
                    intents,
                    handle: session_handle,
                    net_error: None,
                };
                if !pending_interests.is_empty() {
                    session_info.push_interests(pending_interests).await?;
                }
                self.sessions.insert(session_id, session_info);
                *peer_state = PeerState::Active { session_id };
            }
            Err(err) => {
                tracing::warn!(?peer, ?err, "establishing session failed");
                let result = Err(Arc::new(Error::Net(err)));
                let senders = intents.into_iter().map(|intent| intent.sender);
                send_all(senders, EventKind::Closed { result }).await;
                self.peers.remove(&peer);
            }
        }
        Ok(())
    }

    pub async fn sync_with_peer(
        &mut self,
        peer: NodeId,
        init: SessionInit,
    ) -> Result<IntentHandle> {
        let intent_interests = self.actor.resolve_interests(init.interests).await?;
        // TODO: Allow to configure cap?
        let (sender, receiver) = flume::bounded(64);
        let intent_id = {
            let intent_id = self.next_intent_id;
            self.next_intent_id += 1;
            intent_id
        };
        let intent_info = IntentInfo {
            intent_id,
            interests: flatten_interests(&intent_interests),
            mode: init.mode,
            sender,
        };
        match self.peers.get_mut(&peer) {
            None => {
                self.dialer.queue_dial(peer, ALPN);
                let intents = vec![intent_info];
                let peer_state = PeerState::Connecting {
                    intents,
                    interests: intent_interests,
                };
                self.peers.insert(peer, peer_state);
            }
            Some(state) => match state {
                PeerState::Connecting { intents, interests } => {
                    intents.push(intent_info);
                    merge_interests(interests, intent_interests);
                }
                PeerState::Establishing {
                    intents,
                    pending_interests,
                    ..
                } => {
                    intents.push(intent_info);
                    merge_interests(pending_interests, intent_interests);
                }
                PeerState::Active { session_id, .. } => {
                    let session = self.sessions.get_mut(session_id).expect("session to exist");
                    session.intents.push(intent_info);
                    session.push_interests(intent_interests).await?;
                }
                PeerState::Placeholder => unreachable!(),
            },
        };
        let handle = IntentHandle {
            peer,
            receiver,
            intent_id,
            sender: self.command_tx.clone(),
        };
        Ok(handle)
    }

    pub async fn update_intent(
        &mut self,
        peer: NodeId,
        intent_id: u64,
        add_interests: Interests,
    ) -> Result<()> {
        let add_interests = self.actor.resolve_interests(add_interests).await?;
        match self.peers.get_mut(&peer) {
            None => anyhow::bail!("invalid node id"),
            Some(peer_state) => match peer_state {
                PeerState::Connecting { intents, interests } => {
                    let Some(intent_info) = intents.iter_mut().find(|i| i.intent_id == intent_id)
                    else {
                        anyhow::bail!("invalid intent id");
                    };
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
                    let session = self.sessions.get_mut(session_id).expect("session to exist");
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
        Ok(())
    }

    pub fn cancel_intent(&mut self, peer: NodeId, intent_id: u64) {
        let Some(peer_state) = self.peers.get_mut(&peer) else {
            return;
        };

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
                    session.handle.close();
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
                // TODO: Cancel intent if reply send fails?
                reply.send(res).ok();
            }
            Command::UpdateIntent {
                peer,
                intent_id,
                add_interests,
                reply,
            } => {
                let res = self.update_intent(peer, intent_id, add_interests).await;
                // TODO: Cancel intent if reply send fails?
                reply.send(res).ok();
            }
            Command::CancelIntent { peer, intent_id } => {
                self.cancel_intent(peer, intent_id);
            }
            Command::HandleConnection { conn } => {
                self.handle_connection(conn, Role::Betty).await;
            }
        }
    }

    pub async fn received_event(&mut self, mut event: SessionEvent) {
        tracing::info!(?event, "event");
        let Some(session) = self.sessions.get_mut(&event.session_id) else {
            tracing::warn!(?event, "Got event for unknown session");
            return;
        };

        let mut is_closed = false;
        match &mut event.event {
            EventKind::Reconciled { namespace, area } => {
                session
                    .complete_areas
                    .entry(*namespace)
                    .or_default()
                    .insert(area.clone());
            }
            EventKind::Closed { result } => {
                is_closed = true;
                if result.is_ok() {
                    // Inject error from networking tasks.
                    if let Some(net_error) = session.net_error.take() {
                        *result = Err(Arc::new(Error::Net(net_error)));
                    }
                }
            }
            _ => {}
        }

        let send_futs = session
            .intents
            .iter_mut()
            .map(|intent_info| intent_info.handle_event(&event.event));
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

        if session.our_role.is_alfie() && session.intents.is_empty() && !is_closed {
            session.handle.close();
        }

        if is_closed {
            debug_assert!(session.intents.is_empty());
            // TODO: Wait for net tasks to terminate?
            self.sessions.remove(&event.session_id);
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
            if let Some(peer_state) = self.peers.remove(&peer) {
                if let Some(intents) = peer_state.into_intents() {
                    let result = Err(Arc::new(Error::Net(err)));
                    let senders = intents.into_iter().map(|intent| intent.sender);
                    send_all(senders, EventKind::Closed { result }).await;
                }
            }
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
                        anyhow::bail!("got connection for already active peer");
                    }
                    PeerState::Establishing { .. } => {
                        anyhow::bail!("got connection for already establishing peer");
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
                            anyhow::bail!("got connection for already active peer");
                        }
                        PeerState::Establishing { .. } => {
                            anyhow::bail!("got connection for already establishing peer");
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
    senders: impl IntoIterator<Item = flume::Sender<T>>,
    message: T,
) -> Vec<Result<(), flume::SendError<T>>> {
    let futs = senders.into_iter().map(|sender| {
        let message = message.clone();
        async move { sender.send_async(message).await }
    });
    futures_buffered::join_all(futs).await
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use iroh_net::{Endpoint, NodeAddr, NodeId};
    use rand::SeedableRng;
    use std::collections::{BTreeMap, BTreeSet, HashMap};

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

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_manager_two_intents() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
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
                let handle = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

                assert_eq!(
                    handle.next().await.unwrap(),
                    EventKind::CapabilityIntersection {
                        namespace,
                        area: Area::full(),
                    }
                );

                assert_eq!(
                    handle.next().await.unwrap(),
                    EventKind::InterestIntersection {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(
                    handle.next().await.unwrap(),
                    EventKind::Reconciled {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(handle.next().await.unwrap(), EventKind::ReconciledAll);

                assert_eq!(
                    handle.next().await.unwrap(),
                    EventKind::Closed { result: Ok(()) }
                );

                assert!(handle.next().await.is_none());
            }
        });

        let task_bar = tokio::task::spawn({
            let alfie = alfie.clone();
            async move {
                let path = Path::new(&[b"bar"]).unwrap();

                let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
                let init = SessionInit::new(interests, SessionMode::ReconcileOnce);

                let handle = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

                assert_eq!(
                    handle.next().await.unwrap(),
                    EventKind::CapabilityIntersection {
                        namespace,
                        area: Area::full(),
                    }
                );

                assert_eq!(
                    handle.next().await.unwrap(),
                    EventKind::InterestIntersection {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(
                    handle.next().await.unwrap(),
                    EventKind::Reconciled {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(handle.next().await.unwrap(), EventKind::ReconciledAll);

                assert_eq!(
                    handle.next().await.unwrap(),
                    EventKind::Closed { result: Ok(()) }
                );

                assert!(handle.next().await.is_none());
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
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
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
        let handle = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

        assert_eq!(
            handle.next().await.unwrap(),
            EventKind::CapabilityIntersection {
                namespace,
                area: Area::full(),
            }
        );

        assert_eq!(
            handle.next().await.unwrap(),
            EventKind::InterestIntersection {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );
        assert_eq!(
            handle.next().await.unwrap(),
            EventKind::Reconciled {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );
        assert_eq!(handle.next().await.unwrap(), EventKind::ReconciledAll);

        let path = Path::new(&[b"bar"]).unwrap();
        let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
        handle.add_interests(interests).await?;

        assert_eq!(
            handle.next().await.unwrap(),
            EventKind::InterestIntersection {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );
        assert_eq!(
            handle.next().await.unwrap(),
            EventKind::Reconciled {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );

        assert_eq!(handle.next().await.unwrap(), EventKind::ReconciledAll);

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
