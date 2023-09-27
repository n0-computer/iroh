use std::{
    collections::{HashMap, HashSet},
    sync::{atomic::AtomicU64, Arc},
    time::SystemTime,
};

use crate::downloader::{DownloadKind, Downloader, PeerRole};
use anyhow::{anyhow, bail, Context, Result};
use flume::r#async::RecvStream;
use futures::{
    future::{BoxFuture, Shared},
    stream::{BoxStream, FuturesUnordered, StreamExt},
    FutureExt, TryFutureExt,
};
use iroh_bytes::{
    baomap::{self, EntryStatus},
    util::runtime::Handle,
    Hash,
};
use iroh_gossip::{
    net::{Event, Gossip},
    proto::TopicId,
};
use iroh_net::{key::PublicKey, MagicEndpoint, PeerAddr};
use iroh_sync::{
    net::{
        connect_and_sync, handle_connection, AbortReason, AcceptError, AcceptOutcome, ConnectError,
        SyncFinished,
    },
    store,
    sync::{AsyncReplica as Replica, Entry, InsertOrigin, NamespaceId, SignedEntry},
    StateVector,
};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{self, mpsc, oneshot},
    task::JoinError,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, error, trace, trace_span, warn, Instrument};

pub use iroh_sync::ContentStatus;

const CHANNEL_CAP: usize = 8;

/// An iroh-sync operation
///
/// This is the message that is broadcast over iroh-gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    /// A new entry was inserted into the document.
    Put(SignedEntry),
    /// A peer now has content available for a hash.
    ContentReady(Hash),
    /// We synced with another peer, here's the news.
    DidSync(SyncReport),
}

/// Report of a successful sync with the new heads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReport {
    peer: PublicKey,
    namespace: NamespaceId,
    heads: StateVector,
}

#[derive(Debug, Clone)]
enum SyncState {
    None,
    Dialing(CancellationToken),
    Accepting,
    Finished,
    Failed,
}

/// Sync status for a document
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiveStatus {
    /// Whether this document is in the live sync
    pub active: bool,
    /// Number of event listeners registered
    pub subscriptions: u64,
}

#[derive(derive_more::Debug, strum::Display)]
enum ToActor<S: store::Store> {
    Status {
        namespace: NamespaceId,
        s: sync::oneshot::Sender<Option<LiveStatus>>,
    },
    StartSync {
        namespace: NamespaceId,
        peers: Vec<PeerAddr>,
        reply: sync::oneshot::Sender<anyhow::Result<()>>,
    },
    JoinPeers {
        namespace: NamespaceId,
        peers: Vec<PeerAddr>,
    },
    StopSync {
        namespace: NamespaceId,
    },
    Shutdown,
    Subscribe {
        namespace: NamespaceId,
        #[debug("cb")]
        cb: OnLiveEventCallback,
        s: sync::oneshot::Sender<Result<RemovalToken>>,
    },
    Unsubscribe {
        namespace: NamespaceId,
        token: RemovalToken,
        s: sync::oneshot::Sender<bool>,
    },
    HandleConnection {
        conn: quinn::Connecting,
    },
    AcceptSyncRequest {
        namespace: NamespaceId,
        peer: PublicKey,
        reply: sync::oneshot::Sender<AcceptOutcome<S>>,
    },
}

/// Whether to keep a live event callback active.
#[derive(Debug)]
pub enum KeepCallback {
    /// Keep active
    Keep,
    /// Drop this callback
    Drop,
}

/// Callback used for tracking [`LiveEvent`]s.
pub type OnLiveEventCallback =
    Box<dyn Fn(LiveEvent) -> BoxFuture<'static, KeepCallback> + Send + Sync + 'static>;

/// Events informing about actions of the live sync progres.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, strum::Display)]
#[allow(clippy::large_enum_variant)]
pub enum LiveEvent {
    /// A local insertion.
    InsertLocal {
        /// The inserted entry.
        entry: Entry,
    },
    /// Received a remote insert.
    InsertRemote {
        /// The peer that sent us the entry.
        from: PublicKey,
        /// The inserted entry.
        entry: Entry,
        /// If the content is available at the local node
        content_status: ContentStatus,
    },
    /// The content of an entry was downloaded and is now available at the local node
    ContentReady {
        /// The content hash of the newly available entry content
        hash: Hash,
    },
    /// We have a new neighbor in the swarm.
    NeighborUp(PublicKey),
    /// We lost a neighbor in the swarm.
    NeighborDown(PublicKey),
    /// A set-reconciliation sync finished.
    SyncFinished(SyncEvent),
}

fn entry_to_content_status(entry: EntryStatus) -> ContentStatus {
    match entry {
        EntryStatus::Complete => ContentStatus::Complete,
        EntryStatus::Partial => ContentStatus::Incomplete,
        EntryStatus::NotFound => ContentStatus::Missing,
    }
}

/// Handle to a running live sync actor
#[derive(Debug, Clone)]
pub struct LiveSync<S: store::Store> {
    to_actor_tx: mpsc::Sender<ToActor<S>>,
    task: Shared<BoxFuture<'static, Result<(), Arc<JoinError>>>>,
}

impl<S: store::Store> LiveSync<S> {
    /// Start the live sync.
    ///
    /// This spawn a background actor to handle gossip events and forward operations over broadcast
    /// messages.
    pub fn spawn<B: baomap::Store>(
        rt: Handle,
        endpoint: MagicEndpoint,
        replica_store: S,
        gossip: Gossip,
        bao_store: B,
        downloader: Downloader,
    ) -> Self {
        let (to_actor_tx, to_actor_rx) = mpsc::channel(CHANNEL_CAP);
        let me = base32::fmt_short(endpoint.peer_id());
        let mut actor = Actor::new(
            endpoint,
            gossip,
            bao_store,
            downloader,
            replica_store,
            to_actor_rx,
            to_actor_tx.clone(),
        );
        let span = debug_span!("sync", %me);
        let task = rt.main().spawn(async move {
            if let Err(err) = actor.run().instrument(span).await {
                error!("live sync failed: {err:?}");
            }
        });
        let handle = LiveSync {
            to_actor_tx,
            task: task.map_err(Arc::new).boxed().shared(),
        };
        handle
    }

    /// Cancel the live sync.
    pub async fn shutdown(&self) -> Result<()> {
        self.to_actor_tx.send(ToActor::<S>::Shutdown).await?;
        self.task.clone().await?;
        Ok(())
    }

    /// Start to sync a document with a set of peers, also joining the gossip swarm for that
    /// document.
    pub async fn start_sync(&self, namespace: NamespaceId, peers: Vec<PeerAddr>) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.to_actor_tx
            .send(ToActor::<S>::StartSync {
                namespace,
                peers,
                reply,
            })
            .await?;
        reply_rx.await??;
        Ok(())
    }

    /// Join and sync with a set of peers for a document that is already syncing.
    pub async fn join_peers(&self, namespace: NamespaceId, peers: Vec<PeerAddr>) -> Result<()> {
        self.to_actor_tx
            .send(ToActor::<S>::JoinPeers { namespace, peers })
            .await?;
        Ok(())
    }

    /// Stop the live sync for a document.
    ///
    /// This will leave the gossip swarm for this document.
    pub async fn stop_sync(&self, namespace: NamespaceId) -> Result<()> {
        self.to_actor_tx
            .send(ToActor::<S>::StopSync { namespace })
            .await?;
        Ok(())
    }

    /// Subscribes `cb` to events on this `namespace`.
    pub async fn subscribe<F>(&self, namespace: NamespaceId, cb: F) -> Result<RemovalToken>
    where
        F: Fn(LiveEvent) -> BoxFuture<'static, KeepCallback> + Send + Sync + 'static,
    {
        let (s, r) = sync::oneshot::channel();
        self.to_actor_tx
            .send(ToActor::<S>::Subscribe {
                namespace,
                cb: Box::new(cb),
                s,
            })
            .await?;
        let token = r.await??;
        Ok(token)
    }

    /// Unsubscribes `token` to events on this `namespace`.
    /// Returns `true` if a callback was found
    pub async fn unsubscribe(&self, namespace: NamespaceId, token: RemovalToken) -> Result<bool> {
        let (s, r) = sync::oneshot::channel();
        self.to_actor_tx
            .send(ToActor::<S>::Unsubscribe {
                namespace,
                token,
                s,
            })
            .await?;
        let token = r.await?;
        Ok(token)
    }

    /// Get status for a document
    pub async fn status(&self, namespace: NamespaceId) -> Result<Option<LiveStatus>> {
        let (s, r) = sync::oneshot::channel();
        self.to_actor_tx
            .send(ToActor::<S>::Status { namespace, s })
            .await?;
        let status = r.await?;
        Ok(status)
    }

    /// Handle an incoming iroh-sync connection.
    pub async fn handle_connection(&self, conn: quinn::Connecting) -> anyhow::Result<()> {
        self.to_actor_tx
            .send(ToActor::<S>::HandleConnection { conn })
            .await?;
        Ok(())
    }
}

type SyncConnectFut = BoxFuture<
    'static,
    (
        NamespaceId,
        PublicKey,
        SyncReason,
        Result<SyncFinished, ConnectError>,
    ),
>;
type SyncAcceptFut = BoxFuture<'static, Result<SyncFinished, AcceptError>>;

// Currently peers might double-sync in both directions.
struct Actor<S: store::Store, B: baomap::Store> {
    endpoint: MagicEndpoint,
    gossip: Gossip,
    bao_store: B,
    downloader: Downloader,
    replica_store: S,

    /// Set of replicas that we opened for sync or event subscriptions.
    open_replicas: HashSet<NamespaceId>,
    /// Set of replicas that are actively syncing.
    syncing_replicas: HashSet<NamespaceId>,

    /// Events from replicas.
    replica_events: futures::stream::SelectAll<RecvStream<'static, (InsertOrigin, SignedEntry)>>,
    /// Events from gossip.
    gossip_events: BoxStream<'static, Result<(TopicId, Event)>>,

    /// Last state of sync for a replica with a peer.
    sync_state: HashMap<(NamespaceId, PublicKey), SyncState>,

    /// Receiver for actor messages.
    to_actor_rx: mpsc::Receiver<ToActor<S>>,
    /// Send messages to self.
    /// Note: Must not be used in methods called from `Self::run` directly to prevent deadlocks.
    /// Only clone into newly spawned tasks.
    to_actor_tx: mpsc::Sender<ToActor<S>>,

    /// Running sync futures (from connect).
    #[allow(clippy::type_complexity)]
    running_sync_connect: FuturesUnordered<SyncConnectFut>,
    /// Running sync futures (from accept).
    running_sync_accept: FuturesUnordered<SyncAcceptFut>,
    /// Runnning download futures.
    pending_downloads: FuturesUnordered<BoxFuture<'static, Option<(NamespaceId, Hash)>>>,
    /// Running gossip join futures.
    pending_joins: FuturesUnordered<BoxFuture<'static, (NamespaceId, Result<()>)>>,

    /// External subscriptions to replica events.
    event_subscriptions: HashMap<NamespaceId, HashMap<u64, OnLiveEventCallback>>,
    /// Next [`RemovalToken`] for external replica event subscriptions.
    event_removal_id: AtomicU64,
}

/// Token needed to remove inserted callbacks.
#[derive(Debug, Clone, Copy)]
pub struct RemovalToken(u64);

impl<S: store::Store, B: baomap::Store> Actor<S, B> {
    pub fn new(
        endpoint: MagicEndpoint,
        gossip: Gossip,
        bao_store: B,
        downloader: Downloader,
        replica_store: S,
        to_actor_rx: mpsc::Receiver<ToActor<S>>,
        to_actor_tx: mpsc::Sender<ToActor<S>>,
    ) -> Self {
        let gossip_events = gossip.clone().subscribe_all().boxed();

        Self {
            gossip,
            endpoint,
            bao_store,
            downloader,
            replica_store,
            syncing_replicas: Default::default(),
            open_replicas: Default::default(),
            to_actor_rx,
            to_actor_tx,
            sync_state: Default::default(),
            running_sync_connect: Default::default(),
            running_sync_accept: Default::default(),
            pending_joins: Default::default(),
            replica_events: Default::default(),
            gossip_events,
            event_subscriptions: Default::default(),
            event_removal_id: Default::default(),
            pending_downloads: Default::default(),
        }
    }

    async fn run(&mut self) -> Result<()> {
        let res = self.run_inner().await;
        if let Err(err) = self.shutdown().await {
            error!(?err, "Error during shutdown");
        }
        res
    }

    async fn run_inner(&mut self) -> Result<()> {
        let mut i = 0;
        loop {
            i += 1;
            trace!(?i, "tick");
            tokio::select! {
                biased;
                msg = self.to_actor_rx.recv() => {
                    trace!(?i, "tick: to_actor");
                    let msg = msg.context("to_actor closed")?;
                    match msg {
                        // received shutdown signal, or livesync handle was dropped:
                        // break loop and exit
                        ToActor::Shutdown => {
                            break;
                        }
                        ToActor::StartSync { namespace, peers, reply } => {
                            let res = self.start_sync(namespace, peers).await;
                            reply.send(res).ok();
                        },
                        ToActor::StopSync { namespace } => {
                            self.stop_sync(namespace).await?;
                        }
                        ToActor::JoinPeers { namespace, peers } => {
                            self.join_peers(namespace, peers).await?;
                        },
                        ToActor::Subscribe { namespace, cb, s } => {
                            let result = self.subscribe(namespace, cb).await;
                            s.send(result).ok();
                        },
                        ToActor::Unsubscribe { namespace, token, s } => {
                            let result = self.unsubscribe(namespace, token).await;
                            s.send(result).ok();
                        },
                        ToActor::Status { namespace , s } => {
                            let result = self.status(namespace).await;
                            s.send(result).ok();
                        },
                        ToActor::HandleConnection { conn } => {
                             self.handle_connection(conn).await;
                        },
                        ToActor::AcceptSyncRequest { namespace, peer, reply } => {
                            let outcome = self.accept_sync_request(namespace, peer);
                            reply.send(outcome).ok();
                        },
                    };
                }
                // new gossip message
                event = self.gossip_events.next() => {
                    trace!(?i, "tick: gossip_event");
                    let (topic, event) = event.context("gossip_events closed")??;
                    if let Err(err) = self.on_gossip_event(topic, event).await {
                        let namespace: NamespaceId = topic.as_bytes().into();
                        error!(?namespace, ?err, "Failed to process gossip event");
                    }
                },
                event = self.replica_events.next(), if !self.replica_events.is_empty() => {
                    trace!(?i, "tick: replica_event");
                    let (origin, entry) = event.context("replica_events closed")?;
                    let namespace = entry.namespace();
                    if let Err(err) = self.on_replica_event(origin, entry).await {
                        error!(?namespace, ?err, "Failed to process replica event");
                    }
                }
                res = self.running_sync_connect.next(), if !self.running_sync_connect.is_empty() => {
                    trace!(?i, "tick: on_sync_via_connect_finished");
                    let (namespace, peer, reason, res) = res.context("running_sync_connect closed")?;
                    if let Err(err) = self.on_sync_via_connect_finished(namespace, peer, reason, res).await {
                        error!(?namespace, ?err, "Failed to process outgoing sync request");
                    }

                }
                res = self.running_sync_accept.next(), if !self.running_sync_accept.is_empty() => {
                    trace!(?i, "tick: on_sync_via_accept_finished");
                    let res = res.context("running_sync_accept closed")?;
                    if let Err(err) = self.on_sync_via_accept_finished(res).await {
                        error!(?err, "Failed to process incoming sync request");
                    }
                }
                res = self.pending_joins.next(), if !self.pending_joins.is_empty() => {
                    trace!(?i, "tick: pending_joins");
                    let (namespace, res )= res.context("pending_joins closed")?;
                    if let Err(err) = res {
                        error!(?namespace, %err, "failed to join gossip");
                    } else {
                        debug!(?namespace, "joined gossip");
                    }
                    // TODO: maintain some join state
                }
                res = self.pending_downloads.next(), if !self.pending_downloads.is_empty() => {
                    trace!(?i, "tick: pending_downloads");
                    let res = res.context("pending_downloads closed")?;
                    if let Some((namespace, hash)) = res {
                        if let Some(subs) = self.event_subscriptions.get_mut(&namespace) {
                            let event = LiveEvent::ContentReady { hash };
                            notify_all(subs, event).await;
                        }

                        // Inform our neighbors that we have new content ready.
                        let op = Op::ContentReady(hash);
                        let message = postcard::to_stdvec(&op)?.into();
                        self.gossip.broadcast_neighbors(namespace.into(), message).await?;
                    }

                }
            }
        }
        debug!("close (shutdown)");
        Ok(())
    }

    fn set_sync_state(&mut self, namespace: NamespaceId, peer: PublicKey, state: SyncState) {
        self.sync_state.insert((namespace, peer), state);
    }
    fn get_sync_state(&self, namespace: NamespaceId, peer: PublicKey) -> SyncState {
        self.sync_state
            .get(&(namespace, peer))
            .cloned()
            .unwrap_or(SyncState::None)
    }

    fn get_replica_if_syncing(&self, namespace: &NamespaceId) -> Option<Replica<S::Instance>> {
        if !self.syncing_replicas.contains(namespace) {
            None
        } else {
            match self.replica_store.open_replica(namespace) {
                Ok(replica) => replica.map(|r| r.into_async()),
                Err(err) => {
                    warn!("Failed to get previously opened replica from the store: {err:?}");
                    None
                }
            }
        }
    }

    fn sync_with_peer(&mut self, namespace: NamespaceId, peer: PublicKey, reason: SyncReason) {
        let Some(replica) = self.get_replica_if_syncing(&namespace) else {
            return;
        };
        // Do not initiate the sync if we are already syncing or did previously sync successfully.
        // TODO: Track finished time and potentially re-run sync on finished state if enough time
        // passed.
        match self.get_sync_state(namespace, peer) {
            // never run two syncs at the same time
            SyncState::Accepting | SyncState::Dialing(_) => return,
            // always rerun if we failed or did not run yet
            SyncState::Failed | SyncState::None => {}
            // if we finished previously, only re-run if explicitly requested.
            SyncState::Finished => match reason {
                SyncReason::ResyncAfterReport => {}
                _ => return,
            },
        };
        debug!(?namespace, ?peer, ?reason, last_state = ?self.get_sync_state(namespace, peer), "sync[dial]: start");

        let cancel = CancellationToken::new();
        self.set_sync_state(namespace, peer, SyncState::Dialing(cancel.clone()));
        let endpoint = self.endpoint.clone();
        let fut = async move {
            let res = connect_and_sync::<S>(&endpoint, &replica, PeerAddr::new(peer), cancel).await;
            (namespace, peer, reason, res)
        }
        .boxed();
        self.running_sync_connect.push(fut);
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        for namespace in self.open_replicas.drain() {
            self.syncing_replicas.remove(&namespace);
            self.gossip.quit(namespace.into()).await?;
            self.event_subscriptions.remove(&namespace);
            self.replica_store.close_replica(&namespace);
        }
        Ok(())
    }

    async fn status(&mut self, namespace: NamespaceId) -> Option<LiveStatus> {
        let exists = self
            .replica_store
            .open_replica(&namespace)
            .ok()
            .flatten()
            .is_some();
        if !exists {
            return None;
        }
        let active = self.syncing_replicas.contains(&namespace);
        let subscriptions = self
            .event_subscriptions
            .get(&namespace)
            .map(|map| map.len() as u64)
            .unwrap_or(0);
        self.maybe_close_replica(namespace);
        Some(LiveStatus {
            active,
            subscriptions,
        })
    }

    async fn start_sync(&mut self, namespace: NamespaceId, peers: Vec<PeerAddr>) -> Result<()> {
        self.ensure_open(namespace)?;
        self.syncing_replicas.insert(namespace);
        self.join_peers(namespace, peers).await?;
        Ok(())
    }

    /// Open a replica, if not yet in our set of open replicas.
    fn ensure_open(&mut self, namespace: NamespaceId) -> anyhow::Result<()> {
        if !self.open_replicas.contains(&namespace) {
            let Some(replica) = self.replica_store.open_replica(&namespace)? else {
                bail!("Replica not found");
            };

            // setup event subscription.
            let events = replica
                .subscribe()
                .ok_or_else(|| anyhow::anyhow!("trying to subscribe twice to the same replica"))?;
            self.replica_events.push(events.into_stream());

            // setup content status callback
            let bao_store = self.bao_store.clone();
            let content_status_cb =
                Box::new(move |hash| entry_to_content_status(bao_store.contains(&hash)));
            replica.set_content_status_callback(content_status_cb);

            self.open_replicas.insert(namespace);
        }
        Ok(())
    }

    /// Close a replica if we don't need it anymore.
    ///
    /// This closes only if both of the following conditions are met:
    /// * The replica is not in the set of actively synced replicas
    /// * There are no external event subscriptions for this replica
    ///
    /// Closing a replica will remove all event subscriptions.
    fn maybe_close_replica(&mut self, namespace: NamespaceId) {
        if !self.open_replicas.contains(&namespace)
            || self.syncing_replicas.contains(&namespace)
            || self.event_subscriptions.contains_key(&namespace)
        {
            return;
        }
        self.replica_store.close_replica(&namespace);
        self.open_replicas.remove(&namespace);
    }

    async fn subscribe(
        &mut self,
        namespace: NamespaceId,
        cb: OnLiveEventCallback,
    ) -> anyhow::Result<RemovalToken> {
        self.ensure_open(namespace)?;
        let subs = self.event_subscriptions.entry(namespace).or_default();
        let removal_id = self
            .event_removal_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        subs.insert(removal_id, cb);
        Ok(RemovalToken(removal_id))
    }

    /// Returns `true` if a callback was found and removed
    async fn unsubscribe(&mut self, namespace: NamespaceId, token: RemovalToken) -> bool {
        if let Some(subs) = self.event_subscriptions.get_mut(&namespace) {
            let res = subs.remove(&token.0).is_some();
            if subs.is_empty() {
                self.event_subscriptions.remove(&namespace);
            }
            self.maybe_close_replica(namespace);
            return res;
        }

        false
    }

    async fn stop_sync(&mut self, namespace: NamespaceId) -> anyhow::Result<()> {
        if self.syncing_replicas.remove(&namespace) {
            self.gossip.quit(namespace.into()).await?;
            self.sync_state.retain(|(n, _peer), _value| *n != namespace);
            self.maybe_close_replica(namespace);
        }
        Ok(())
    }

    async fn join_peers(
        &mut self,
        namespace: NamespaceId,
        peers: Vec<PeerAddr>,
    ) -> anyhow::Result<()> {
        let peer_ids: Vec<PublicKey> = peers.iter().map(|p| p.peer_id).collect();

        // add addresses of initial peers to our endpoint address book
        for peer in peers.into_iter() {
            let peer_id = peer.peer_id;
            if let Err(err) = self.endpoint.add_peer_addr(peer).await {
                warn!(peer = ?peer_id, "failed to add known addrs: {err:?}");
            }
        }

        // join gossip for the topic to receive and send message
        self.pending_joins.push({
            let peer_ids = peer_ids.clone();
            let gossip = self.gossip.clone();
            async move {
                match gossip.join(namespace.into(), peer_ids).await {
                    Err(err) => (namespace, Err(err)),
                    Ok(fut) => (namespace, fut.await),
                }
            }
            .boxed()
        });

        // trigger initial sync with initial peers
        for peer in peer_ids {
            self.sync_with_peer(namespace, peer, SyncReason::DirectJoin);
        }
        Ok(())
    }

    async fn on_sync_via_connect_finished(
        &mut self,
        namespace: NamespaceId,
        peer: PublicKey,
        reason: SyncReason,
        result: Result<SyncFinished, ConnectError>,
    ) -> Result<()> {
        match result {
            Err(ConnectError::RemoteAbort(AbortReason::AlreadySyncing)) => {
                debug!(
                    ?peer,
                    ?namespace,
                    ?reason,
                    "sync[dial]: remote abort, already syncing"
                );
                Ok(())
            }
            Err(ConnectError::Cancelled) => {
                // In case the remote aborted with already running: do nothing
                debug!(
                    ?peer,
                    ?namespace,
                    ?reason,
                    "sync[dial]: cancelled, already syncing"
                );
                Ok(())
            }
            res => {
                self.on_sync_finished(
                    namespace,
                    peer,
                    Origin::Connect(reason),
                    res.map_err(Into::into),
                )
                .await
            }
        }
    }

    async fn on_sync_via_accept_finished(
        &mut self,
        res: Result<SyncFinished, AcceptError>,
    ) -> Result<()> {
        match res {
            Ok(state) => {
                self.on_sync_finished(state.namespace, state.peer, Origin::Accept, Ok(state))
                    .await
            }
            Err(AcceptError::Abort {
                peer,
                namespace,
                reason,
            }) if reason == AbortReason::AlreadySyncing => {
                // In case we aborted the sync: do nothing (our outgoing sync is in progress)
                debug!(?peer, ?namespace, ?reason, "sync[accept]: aborted by us");
                Ok(())
            }
            Err(err) => {
                // If we have a sync in the other direction going on, do not treat as error.
                if let (Some(peer), Some(namespace)) = (err.peer(), err.namespace()) {
                    self.on_sync_finished(
                        namespace,
                        peer,
                        Origin::Accept,
                        Err(anyhow::Error::from(err)),
                    )
                    .await?;
                    Ok(())
                } else {
                    debug!("sync[accept]: failed {err:?}");
                    Err(err.into())
                }
            }
        }
    }

    async fn on_sync_finished(
        &mut self,
        namespace: NamespaceId,
        peer: PublicKey,
        origin: Origin,
        result: Result<SyncFinished>,
    ) -> Result<()> {
        // debug log the result, warn in case of errors
        match (&origin, &result) {
            (Origin::Accept, Ok(_)) => debug!(?peer, ?namespace, "sync[accept]: done"),
            (Origin::Connect(reason), Ok(_)) => {
                debug!(?peer, ?namespace, ?reason, "sync[dial]: done")
            }
            (Origin::Accept, Err(err)) => warn!(?peer, ?namespace, ?err, "sync[accept]: failed"),
            (Origin::Connect(reason), Err(err)) => {
                warn!(?peer, ?namespace, ?err, ?reason, "sync[dial]: failed")
            }
        }
        let state = match result {
            Ok(_) => SyncState::Finished,
            Err(_) => SyncState::Failed,
        };
        self.set_sync_state(namespace, peer, state);

        // Broadcast a sync report to our neighbors, but only if we received new entries.
        if let Ok(state) = &result {
            if state.progress.entries_recv > 0 {
                let report = SyncReport {
                    peer,
                    namespace,
                    heads: state.progress.state_vector.clone(),
                };
                let op = Op::DidSync(report);
                debug!(?namespace, "broadcast to neighbors: DidSync(peer={peer:?})");
                let msg = postcard::to_stdvec(&op)?;
                // TODO: We should debounce and merge these neighbor announcements likely.
                if let Err(err) = self
                    .gossip
                    .broadcast_neighbors(namespace.into(), msg.into())
                    .await
                {
                    error!(
                        ?namespace,
                        ?err,
                        "Failed to broadcast SyncReport to neighbors"
                    );
                }
            }
        }

        let event = SyncEvent {
            namespace,
            peer,
            origin,
            result: result
                .as_ref()
                .map(|_| ())
                .map_err(|err| format!("{err:?}")),
            finished: SystemTime::now(),
        };
        let subs = self.event_subscriptions.get_mut(&event.namespace);
        if let Some(subs) = subs {
            notify_all(subs, LiveEvent::SyncFinished(event)).await;
        }
        Ok(())
    }

    async fn on_gossip_event(&mut self, topic: TopicId, event: Event) -> Result<()> {
        let namespace: NamespaceId = topic.as_bytes().into();
        let Some(replica) = self.get_replica_if_syncing(&namespace) else {
            return Err(anyhow!("Doc {namespace:?} is not active"));
        };
        match event {
            // We received a gossip message. Try to insert it into our replica.
            Event::Received(msg) => {
                let op: Op = postcard::from_bytes(&msg.content)?;
                match op {
                    Op::Put(entry) => {
                        debug!(peer = ?msg.delivered_from, ?namespace, "received entry via gossip");
                        // Insert the entry into our replica.
                        // If the message was broadcast with neighbor scope, or is received
                        // directly from the author, we assume that the content is available at
                        // that peer. Otherwise we don't.
                        // The download is not triggered here, but in the `on_replica_event`
                        // handler for the `InsertRemote` event.
                        let content_status = match msg.scope.is_direct() {
                            true => ContentStatus::Complete,
                            false => ContentStatus::Missing,
                        };
                        replica
                            .insert_remote_entry(
                                entry,
                                *msg.delivered_from.as_bytes(),
                                content_status,
                            )
                            .await?
                    }
                    Op::ContentReady(hash) => {
                        // Inform the downloader that we now know that this peer has the content
                        // for this hash.
                        self.downloader
                            .peers_have(hash, vec![(msg.delivered_from, PeerRole::Provider).into()])
                            .await;
                    }
                    Op::DidSync(report) => {
                        let peer = msg.delivered_from;
                        if self
                            .replica_store
                            .has_news_for_us(report.namespace, &report.heads)?
                        {
                            debug!(?namespace, ?peer, "Recv SyncReport: have news, sync now");
                            self.sync_with_peer(
                                report.namespace,
                                peer,
                                SyncReason::ResyncAfterReport,
                            );
                        } else {
                            debug!(?namespace, ?peer, "Recv SyncReport: no news, no sync");
                        }
                    }
                }
            }
            // A new neighbor appeared in the gossip swarm. Try to sync with it directly.
            // [Self::sync_with_peer] will check to not resync with peers synced previously in the
            // same session. TODO: Maybe this is too broad and leads to too many sync requests.
            Event::NeighborUp(peer) => {
                debug!(?peer, ?namespace, "neighbor up");
                self.sync_with_peer(namespace, peer, SyncReason::NewNeighbor);
                if let Some(subs) = self.event_subscriptions.get_mut(&namespace) {
                    notify_all(subs, LiveEvent::NeighborUp(peer)).await;
                }
            }
            Event::NeighborDown(peer) => {
                debug!(?peer, ?namespace, "neighbor down");
                if let Some(subs) = self.event_subscriptions.get_mut(&namespace) {
                    notify_all(subs, LiveEvent::NeighborDown(peer)).await;
                }
            }
        }
        Ok(())
    }

    async fn on_replica_event(
        &mut self,
        origin: InsertOrigin,
        signed_entry: SignedEntry,
    ) -> Result<()> {
        let namespace = signed_entry.namespace();
        let topic = TopicId::from_bytes(*namespace.as_bytes());
        let subs = self.event_subscriptions.get_mut(&namespace);
        match origin {
            InsertOrigin::Local => {
                let entry = signed_entry.entry().clone();

                // A new entry was inserted locally. Broadcast a gossip message.
                let op = Op::Put(signed_entry);
                let message = postcard::to_stdvec(&op)?.into();
                debug!(?namespace, "broadcast new entry");
                self.gossip.broadcast(topic, message).await?;

                // Notify subscribers about the event
                if let Some(subs) = subs {
                    let event = LiveEvent::InsertLocal {
                        entry: entry.clone(),
                    };
                    notify_all(subs, event).await;
                }
            }
            InsertOrigin::Sync {
                from: peer_id,
                content_status,
            } => {
                let from = PublicKey::from_bytes(&peer_id)?;
                let entry = signed_entry.entry();
                let hash = entry.record().content_hash();

                // A new entry was inserted from initial sync or gossip. Queue downloading the
                // content.
                let entry_status = self.bao_store.contains(&hash);

                // TODO: Make downloads configurable.
                if matches!(entry_status, EntryStatus::NotFound | EntryStatus::Partial) {
                    let role = match content_status {
                        ContentStatus::Complete => PeerRole::Provider,
                        _ => PeerRole::Candidate,
                    };
                    let handle = self
                        .downloader
                        .queue(DownloadKind::Blob { hash }, vec![(from, role).into()])
                        .await;
                    let fut = async move {
                        // NOTE: this ignores the result for now, simply keeping the option
                        let res = handle.await.ok();
                        res.map(|_| (namespace, hash))
                    }
                    .boxed();
                    self.pending_downloads.push(fut);
                }

                // Notify subscribers about the event
                if let Some(subs) = subs {
                    let event = LiveEvent::InsertRemote {
                        from,
                        entry: entry.clone(),
                        content_status: entry_to_content_status(entry_status),
                    };
                    notify_all(subs, event).await;
                }
            }
        }

        Ok(())
    }

    pub async fn handle_connection(&mut self, conn: quinn::Connecting) {
        let to_actor_tx = self.to_actor_tx.clone();
        let request_replica_cb = move |namespace, peer| {
            let to_actor_tx = to_actor_tx.clone();
            async move {
                let (reply_tx, reply_rx) = oneshot::channel();
                to_actor_tx
                    .send(ToActor::AcceptSyncRequest {
                        namespace,
                        peer,
                        reply: reply_tx,
                    })
                    .await
                    .ok();
                reply_rx.await.map_err(anyhow::Error::from)
            }
            .boxed()
        };
        debug!("sync[accept] incoming connection");
        let fut =
            async move { handle_connection::<S, _, _>(conn, request_replica_cb).await }.boxed();
        self.running_sync_accept.push(fut);
    }

    pub fn accept_sync_request(
        &mut self,
        namespace: NamespaceId,
        peer: PublicKey,
    ) -> AcceptOutcome<S> {
        let Some(replica) = self.get_replica_if_syncing(&namespace) else {
            return Err(AbortReason::NotAvailable);
        };
        match self.get_sync_state(namespace, peer) {
            SyncState::None | SyncState::Failed | SyncState::Finished => {
                self.set_sync_state(namespace, peer, SyncState::Accepting);
                Ok(replica.clone())
            }
            SyncState::Accepting => Err(AbortReason::AlreadySyncing),
            // Incoming sync request while we are dialing ourselves.
            // In this case, compare the binary representations of our and the other node's peer id
            // to deterministically decide which of the two concurrent connections will succeed.
            SyncState::Dialing(cancel) => {
                if peer.as_bytes() > self.endpoint.peer_id().as_bytes() {
                    cancel.cancel();
                    self.set_sync_state(namespace, peer, SyncState::Accepting);
                    Ok(replica.clone())
                } else {
                    Err(AbortReason::AlreadySyncing)
                }
            }
        }
    }
}

/// Outcome of a sync operation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SyncEvent {
    /// Namespace that was synced
    pub namespace: NamespaceId,
    /// Peer we synced with
    pub peer: PublicKey,
    /// Origin of the sync exchange
    pub origin: Origin,
    /// Timestamp when the sync finished
    pub finished: SystemTime,
    /// Result of the sync operation
    pub result: std::result::Result<(), String>,
    // TODO: Track time a sync took
    // duration: Duration,
}

/// Why we started a sync request
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum SyncReason {
    /// Direct join request via API
    DirectJoin,
    /// Peer showed up as new neighbor in the gossip swarm
    NewNeighbor,
    ///
    ResyncAfterReport,
}

/// Why we performed a sync exchange
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Origin {
    /// We initiated the exchange
    Connect(SyncReason),
    /// A peer connected to us and we accepted the exchange
    Accept,
}

async fn notify_all(subs: &mut HashMap<u64, OnLiveEventCallback>, event: LiveEvent) {
    let res = futures::future::join_all(
        subs.iter()
            .map(|(idx, sub)| sub(event.clone()).map(|res| (*idx, res))),
    )
    .await;
    for (idx, res) in res {
        if matches!(res, KeepCallback::Drop) {
            subs.remove(&idx);
        }
    }
}

/// Utilities for working with byte array identifiers
// TODO: copy-pasted from iroh-gossip/src/proto/util.rs
// Unify into iroh-common crate or similar
pub(super) mod base32 {
    /// Convert to a base32 string limited to the first 10 bytes
    pub fn fmt_short(bytes: impl AsRef<[u8]>) -> String {
        let len = bytes.as_ref().len().min(10);
        let mut text = data_encoding::BASE32_NOPAD.encode(&bytes.as_ref()[..len]);
        text.make_ascii_lowercase();
        text
    }
}
