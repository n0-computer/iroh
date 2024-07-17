use std::{
    collections::{hash_map, HashMap, HashSet},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use futures_buffered::join_all;
use futures_concurrency::future::Join;
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
    session::{
        error::ChannelReceiverDropped,
        intents::{IntentChannels, IntentData, IntentHandle, IntentInfo},
        Error, Interests, Role, SessionId, SessionInit, SessionMode, SessionUpdate,
    },
    store::traits::Storage,
};

const COMMAND_CHANNEL_CAP: usize = 128;

#[derive(Debug, Clone)]
pub struct EventSender(pub mpsc::Sender<SessionEvent>);

impl EventSender {
    pub async fn send(&self, event: SessionEvent) -> Result<(), ChannelReceiverDropped> {
        self.0.send(event).await.map_err(|_| ChannelReceiverDropped)
    }
}

#[derive(Debug)]
pub enum SessionEvent {
    Revealed,
    Complete { result: Result<(), Arc<Error>> },
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
    Abort {
        error: Arc<Error>,
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
pub enum Command {
    SubmitIntent { peer: NodeId, intent: IntentData },
    HandleConnection { conn: Connection },
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
            betty_intent_rx: Default::default(),
            command_rx,
            establish_tasks: Default::default(),
            net_tasks: Default::default(),
            actor: actor.clone(),
            peers: Default::default(),
            endpoint: endpoint.clone(),
            dialer: Dialer::new(endpoint),
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
        // TODO: expose cap
        let (handle, intent) = IntentHandle::new(init);
        self.command_tx
            .send(Command::SubmitIntent { peer, intent })
            .await?;
        Ok(handle)
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

#[derive(derive_more::Debug)]
pub struct PeerManager {
    session_event_rx: StreamMap<NodeId, ReceiverStream<SessionEvent>>,
    betty_intent_rx: StreamMap<NodeId, ReceiverStream<EventKind>>,
    command_rx: mpsc::Receiver<Command>,
    establish_tasks: JoinSet<EstablishRes>,
    net_tasks: JoinSet<(NodeId, Result<()>)>,
    actor: ActorHandle,
    peers: HashMap<NodeId, PeerState>,
    endpoint: Endpoint,
    dialer: Dialer,
}

impl PeerManager {
    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                Some((session_id, event)) = self.session_event_rx.next(), if !self.session_event_rx.is_empty() => {
                    self.received_event(session_id, event).await;
                }
                Some((_session_id, _event)) = self.betty_intent_rx.next(), if !self.betty_intent_rx.is_empty() => {
                    // TODO: Do we want to emit these somewhere?
                    // self.received_event(session_id, event).await;
                }
                Some(command) = self.command_rx.recv() => {
                    self.received_command(command).await;
                }
                Some(res) = self.establish_tasks.join_next(), if !self.establish_tasks.is_empty() => {
                    match res {
                        Err(err) if err.is_cancelled() => continue,
                        Err(err) => Err(err).context("establish task paniced")?,
                        Ok((peer, Ok((tasks, handle)))) => self.on_established(peer, handle, tasks)?,
                        Ok((peer, Err(err))) => self.remove_peer(peer, Err(Arc::new(Error::Net(err)))).await,
                    }
                }
                Some(res) = self.net_tasks.join_next(), if !self.net_tasks.is_empty() => {
                    match res {
                        Err(err) if err.is_cancelled() => continue,
                        Err(err) => Err(err).context("net task paniced")?,
                        Ok((_peer, Ok(())))=> continue,
                        Ok((peer, Err(err))) => {
                            // TODO: Forward to session?
                            tracing::warn!(?peer, ?err, "net task failed");
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

    pub async fn received_command(&mut self, command: Command) {
        tracing::info!(?command, "command");
        match command {
            Command::SubmitIntent { peer, intent } => {
                if let Err(err) = self.submit_intent(peer, intent).await {
                    tracing::warn!("failed to submit intent: {err:?}");
                }
            }
            Command::HandleConnection { conn } => {
                self.handle_connection(conn, Role::Betty).await;
            }
        }
    }

    async fn remove_peer(&mut self, peer: NodeId, result: Result<(), Arc<Error>>) {
        let Some(peer_state) = self.peers.remove(&peer) else {
            tracing::warn!(?peer, "attempted to remove unknown peer");
            return;
        };
        let intents = match peer_state {
            PeerState::Connecting { intents, .. } => {
                self.dialer.abort_dial(&peer);
                Some(intents)
            }
            PeerState::Establishing { intents, .. } => Some(intents),
            PeerState::Active { cancel_token, .. } => {
                cancel_token.cancel();
                None
            }
            PeerState::Placeholder => unreachable!(),
        };
        if let Some(intents) = intents {
            if let Err(error) = result {
                join_all(
                    intents
                        .into_iter()
                        .map(|intent| intent.send_abort(error.clone())),
                )
                .await;
            }
        }
        self.session_event_rx.remove(&peer);
        self.betty_intent_rx.remove(&peer);
    }

    async fn on_dial_fail(&mut self, peer: NodeId, err: anyhow::Error) {
        let result = Err(Arc::new(Error::Net(err)));
        self.remove_peer(peer, result).await;
    }

    fn on_established(
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
            // our_role,
            intents: _,
            betty_catchall_intent,
        } = current_state
        else {
            anyhow::bail!("unreachable: on_established called for peer in wrong state")
        };
        let SessionHandle {
            // session_id,
            cancel_token,
            update_tx,
            event_rx,
        } = session_handle;
        self.net_tasks.spawn(
            async move { crate::net::join_all(&mut net_tasks).await }.map(move |r| (peer, r)),
        );
        self.session_event_rx
            .insert(peer, ReceiverStream::new(event_rx));
        // TODO: submit intents that were submitted while establishing
        // for intent in intents {
        //     update_tx.send(SessionUpdate::SubmitIntent(intent)).await?;
        // }
        if let Some(handle) = betty_catchall_intent {
            self.betty_intent_rx.insert(peer, handle.split().1);
        }
        *peer_state = PeerState::Active {
            // session_id,
            cancel_token,
            update_tx,
            // our_role,
        };
        Ok(())
    }

    pub async fn submit_intent(&mut self, peer: NodeId, intent: IntentData) -> Result<()> {
        match self.peers.get_mut(&peer) {
            None => {
                self.dialer.queue_dial(peer, ALPN);
                let intents = vec![intent];
                let peer_state = PeerState::Connecting { intents };
                self.peers.insert(peer, peer_state);
            }
            Some(state) => match state {
                PeerState::Connecting { intents } => {
                    intents.push(intent);
                }
                PeerState::Establishing { intents, .. } => {
                    intents.push(intent);
                }
                PeerState::Active { update_tx, .. } => {
                    update_tx.send(SessionUpdate::SubmitIntent(intent)).await?;
                }
                PeerState::Placeholder => unreachable!(),
            },
        };
        Ok(())
    }

    pub async fn received_event(&mut self, peer: NodeId, event: SessionEvent) {
        tracing::info!(?event, "event");
        match event {
            SessionEvent::Revealed => {}
            SessionEvent::Complete { result } => {
                self.remove_peer(peer, result).await;
            }
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
        if let Err(err) = self.handle_connection_inner(peer, conn, our_role) {
            tracing::warn!(?peer, ?err, "failed to establish connection");
            let result = Err(Arc::new(Error::Net(err)));
            self.remove_peer(peer, result).await;
        }
    }

    fn handle_connection_inner(
        &mut self,
        peer: NodeId,
        conn: Connection,
        our_role: Role,
    ) -> Result<()> {
        let peer_state = self.peers.get_mut(&peer);
        let (intents, betty_catchall_intent) = match our_role {
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
                    PeerState::Connecting { intents } => (intents, None),
                }
            }
            Role::Betty => {
                let mut intents = if let Some(peer_state) = peer_state {
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
                let all_init = SessionInit::new(Interests::All, SessionMode::Live);
                let (handle, data) = IntentHandle::new(all_init);
                intents.push(data);
                (intents, Some(handle))
            }
        };

        let me = self.endpoint.node_id();
        let actor = self.actor.clone();
        let establish_fut = async move {
            let (initial_transmission, channels, tasks) = setup(conn, me, our_role).await?;
            let session_handle = actor
                .init_session(peer, our_role, initial_transmission, channels, intents)
                .await?;
            Ok::<_, anyhow::Error>((tasks, session_handle))
        };
        let establish_fut = establish_fut.map(move |res| (peer, res));
        let _task_handle = self.establish_tasks.spawn(establish_fut);
        let peer_state = PeerState::Establishing {
            // our_role,
            intents: Vec::new(),
            betty_catchall_intent,
        };
        self.peers.insert(peer, peer_state);
        Ok(())
    }
}

#[derive(Debug)]
enum PeerState {
    Connecting {
        intents: Vec<IntentData>,
    },
    Establishing {
        // our_role: Role,
        intents: Vec<IntentData>,
        betty_catchall_intent: Option<IntentHandle>,
    },
    Active {
        // session_id: SessionId,
        // our_role: Role,
        update_tx: mpsc::Sender<SessionUpdate>,
        cancel_token: CancellationToken,
    },
    Placeholder,
}

#[derive(Debug, thiserror::Error)]
#[error("receiver dropped")]
pub struct ReceiverDropped;

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
        // net::run,
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

                // assert_eq!(
                //     intent.next().await.unwrap(),
                //     EventKind::Closed { result: Ok(()) }
                // );

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

                // assert_eq!(
                //     intent.next().await.unwrap(),
                //     EventKind::Closed { result: Ok(()) }
                // );

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

        println!("start");
        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::CapabilityIntersection {
                namespace,
                area: Area::full(),
            }
        );
        println!("first in!");
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
