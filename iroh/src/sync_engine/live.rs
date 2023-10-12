#![allow(missing_docs)]

use std::{collections::HashMap, time::SystemTime};

use crate::downloader::{DownloadKind, Downloader, PeerRole};
use anyhow::{Context, Result};
use futures::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
    FutureExt,
};
use iroh_bytes::{
    baomap::{self, EntryStatus},
    Hash,
};
use iroh_gossip::{net::Gossip, proto::TopicId};
use iroh_net::{key::PublicKey, MagicEndpoint, PeerAddr};
use iroh_sync::{
    actor::{ReplicaState, StateUpdate, SyncHandle},
    net::{
        connect_and_sync, handle_connection, AbortReason, AcceptError, AcceptOutcome, ConnectError,
        SyncFinished,
    },
    ContentStatus, Entry, InsertOrigin, NamespaceId, SignedEntry,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{self, mpsc, oneshot};
use tracing::{debug, error, instrument, trace, warn, Instrument, Span};

use super::{entry_to_content_status, gossip::ToGossipActor};

/// An iroh-sync operation
///
/// This is the message that is broadcast over iroh-gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    /// A new entry was inserted into the document.
    Put(SignedEntry),
    /// A peer now has content available for a hash.
    ContentReady(Hash),
}

#[derive(Debug, Clone)]
enum SyncState {
    None,
    Dialing,
    Accepting,
    Finished,
    Failed,
}

/// Sync status for a document
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiveStatus {
    /// Whether this document is in the live sync
    pub state: ReplicaState,
    /// Number of event listeners registered
    pub subscriptions: u64,
}

/// Messages to the sync actor
#[derive(derive_more::Debug, strum::Display)]
pub enum ToLiveActor {
    Status {
        namespace: NamespaceId,
        reply: sync::oneshot::Sender<Option<LiveStatus>>,
    },
    StartSync {
        namespace: NamespaceId,
        peers: Vec<PeerAddr>,
        #[debug("onsehot::Sender")]
        reply: sync::oneshot::Sender<anyhow::Result<()>>,
    },
    JoinPeers {
        namespace: NamespaceId,
        peers: Vec<PeerAddr>,
        #[debug("onsehot::Sender")]
        reply: sync::oneshot::Sender<anyhow::Result<()>>,
    },
    Leave {
        namespace: NamespaceId,
        /// If true removes all active client subscriptions.
        force_remove: bool,
        #[debug("onsehot::Sender")]
        reply: sync::oneshot::Sender<anyhow::Result<()>>,
    },
    Shutdown,
    Subscribe {
        namespace: NamespaceId,
        #[debug("cb")]
        cb: OnLiveEventCallback,
        #[debug("oneshot::Sender")]
        reply: sync::oneshot::Sender<Result<RemovalToken>>,
    },
    Unsubscribe {
        namespace: NamespaceId,
        token: RemovalToken,
        reply: sync::oneshot::Sender<bool>,
    },
    HandleConnection {
        conn: quinn::Connecting,
    },
    AcceptSyncRequest {
        namespace: NamespaceId,
        peer: PublicKey,
        #[debug("oneshot::Sender")]
        reply: sync::oneshot::Sender<AcceptOutcome>,
    },
    NeighborUp {
        namespace: NamespaceId,
        peer: PublicKey,
    },
    NeighborDown {
        namespace: NamespaceId,
        peer: PublicKey,
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
    /// The document was closed. No further events will be emitted.
    Closed,
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
pub struct LiveActor<B: baomap::Store> {
    /// Receiver for actor messages.
    inbox: mpsc::Receiver<ToLiveActor>,
    sync: SyncHandle,
    endpoint: MagicEndpoint,
    gossip: Gossip,
    bao_store: B,
    downloader: Downloader,
    sync_events: flume::Receiver<iroh_sync::Event>,
    /// Last state of sync for a replica with a peer.
    sync_state: HashMap<(NamespaceId, PublicKey), SyncState>,

    /// Send messages to self.
    /// Note: Must not be used in methods called from `Self::run` directly to prevent deadlocks.
    /// Only clone into newly spawned tasks.
    sync_actor_tx: mpsc::Sender<ToLiveActor>,
    gossip_actor_tx: mpsc::Sender<ToGossipActor>,

    /// Running sync futures (from connect).
    #[allow(clippy::type_complexity)]
    running_sync_connect: FuturesUnordered<SyncConnectFut>,
    /// Running sync futures (from accept).
    running_sync_accept: FuturesUnordered<SyncAcceptFut>,
    /// Runnning download futures.
    pending_downloads: FuturesUnordered<BoxFuture<'static, Option<(NamespaceId, Hash)>>>,

    /// External subscriptions to replica events.
    subscriptions: Subscriptions,

    states: HashMap<NamespaceId, ReplicaState>,
}

impl<B: baomap::Store> LiveActor<B> {
    /// Create the live actor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sync: SyncHandle,
        sync_events: flume::Receiver<iroh_sync::Event>,
        endpoint: MagicEndpoint,
        gossip: Gossip,
        bao_store: B,
        downloader: Downloader,
        inbox: mpsc::Receiver<ToLiveActor>,
        sync_actor_tx: mpsc::Sender<ToLiveActor>,
        gossip_actor_tx: mpsc::Sender<ToGossipActor>,
    ) -> Self {
        Self {
            inbox,
            sync,
            sync_events,
            endpoint,
            gossip,
            bao_store,
            downloader,
            sync_actor_tx,
            gossip_actor_tx,
            sync_state: Default::default(),
            running_sync_connect: Default::default(),
            running_sync_accept: Default::default(),
            subscriptions: Default::default(),
            pending_downloads: Default::default(),
            states: Default::default(),
        }
    }

    /// Run the actor loop.
    pub async fn run(&mut self) -> Result<()> {
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
            trace!(?i, "tick wait");
            tokio::select! {
                biased;
                msg = self.inbox.recv() => {
                    let msg = msg.context("to_actor closed")?;
                    trace!(?i, %msg, "tick: to_actor");
                    if !self.on_actor_message(msg).await.context("on_actor_message")? {
                        break;
                    }
                }
                event = self.sync_events.recv_async() => {
                    trace!(?i, "tick: replica_event");
                    let event = event.context("replica_events closed")?;
                    if let Err(err) = self.on_replica_event(event).await {
                        error!(?err, "Failed to process replica event");
                    }
                }
                res = self.running_sync_connect.next(), if !self.running_sync_connect.is_empty() => {
                    trace!(?i, "tick: on_sync_via_connect_finished");
                    let (namespace, peer, reason, res) = res.context("running_sync_connect closed")?;
                    if let Err(err) = self.on_sync_via_connect_finished(namespace, peer, reason, res).await {
                        error!(namespace = %namespace.fmt_short(), ?err, "Failed to process outgoing sync request");
                    }

                }
                res = self.running_sync_accept.next(), if !self.running_sync_accept.is_empty() => {
                    trace!(?i, "tick: on_sync_via_accept_finished");
                    let res = res.context("running_sync_accept closed")?;
                    if let Err(err) = self.on_sync_via_accept_finished(res).await {
                        error!(?err, "Failed to process incoming sync request");
                    }
                }
                res = self.pending_downloads.next(), if !self.pending_downloads.is_empty() => {
                    trace!(?i, "tick: pending_downloads");
                    let res = res.context("pending_downloads closed")?;
                    if let Some((namespace, hash)) = res {
                        let event = LiveEvent::ContentReady { hash };
                        self.subscriptions.send(&namespace, event).await;

                        // Inform our neighbors that we have new content ready.
                        let op = Op::ContentReady(hash);
                        let message = postcard::to_stdvec(&op)?.into();
                        if self.is_syncing(&namespace) {
                            self.gossip.broadcast_neighbors(namespace.into(), message).await?;
                        }
                    }

                }
            }
        }
        debug!("close (shutdown)");
        Ok(())
    }

    async fn on_actor_message(&mut self, msg: ToLiveActor) -> anyhow::Result<bool> {
        match msg {
            ToLiveActor::Shutdown => {
                return Ok(false);
            }
            ToLiveActor::NeighborUp { namespace, peer } => {
                debug!(peer = %peer.fmt_short(), namespace = %namespace.fmt_short(), "neighbor up");
                self.sync_with_peer(namespace, peer, SyncReason::NewNeighbor);
                self.subscriptions
                    .send(&namespace, LiveEvent::NeighborUp(peer))
                    .await;
            }
            ToLiveActor::NeighborDown { namespace, peer } => {
                debug!(peer = %peer.fmt_short(), namespace = %namespace.fmt_short(), "neighbor down");
                self.subscriptions
                    .send(&namespace, LiveEvent::NeighborDown(peer))
                    .await;
            }
            ToLiveActor::StartSync {
                namespace,
                peers,
                reply,
            } => {
                let res = self.start_sync(namespace, peers).await;
                reply.send(res).ok();
            }
            ToLiveActor::Leave {
                namespace,
                force_remove,
                reply,
            } => {
                let res = self.leave(namespace, force_remove).await;
                reply.send(res).ok();
            }
            ToLiveActor::JoinPeers {
                namespace,
                peers,
                reply,
            } => {
                let res = self.join_peers(namespace, peers).await;
                reply.send(res).ok();
            }
            ToLiveActor::Subscribe {
                namespace,
                cb,
                reply,
            } => {
                let result = self.subscribe(namespace, cb).await;
                reply.send(result).ok();
            }
            ToLiveActor::Unsubscribe {
                namespace,
                token,
                reply,
            } => {
                let result = self.unsubscribe(namespace, token).await;
                reply.send(result).ok();
            }
            ToLiveActor::Status { namespace, reply } => {
                let result = self.status(namespace).await;
                reply.send(result).ok();
            }
            ToLiveActor::HandleConnection { conn } => {
                self.handle_connection(conn).await;
            }
            ToLiveActor::AcceptSyncRequest {
                namespace,
                peer,
                reply,
            } => {
                let outcome = self.accept_sync_request(namespace, peer);
                reply.send(outcome).ok();
            }
        };
        Ok(true)
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

    #[instrument("connect", skip_all, fields(peer = %peer.fmt_short(), namespace = %namespace.fmt_short()))]
    fn sync_with_peer(&mut self, namespace: NamespaceId, peer: PublicKey, reason: SyncReason) {
        if !self.is_syncing(&namespace) {
            return;
        }
        // Do not initiate the sync if we are already syncing or did previously sync successfully.
        // TODO: Track finished time and potentially re-run sync on finished state if enough time
        // passed.
        match self.get_sync_state(namespace, peer) {
            // never run two syncs at the same time
            SyncState::Accepting | SyncState::Dialing => return,
            // always rerun if we failed or did not run yet
            SyncState::Failed | SyncState::None => {}
            // if we finished previously, only re-run if explicitly requested.
            SyncState::Finished => return,
        };
        debug!(?reason, last_state = ?self.get_sync_state(namespace, peer), "start");

        self.set_sync_state(namespace, peer, SyncState::Dialing);
        let endpoint = self.endpoint.clone();
        let sync = self.sync.clone();
        let fut = async move {
            let res = connect_and_sync(&endpoint, &sync, namespace, PeerAddr::new(peer)).await;
            (namespace, peer, reason, res)
        }
        .instrument(Span::current())
        .boxed();
        self.running_sync_connect.push(fut);
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        for (namespace, _state) in self.states.drain() {
            self.subscriptions.remove(&namespace);
        }
        self.gossip_actor_tx
            .send(ToGossipActor::Shutdown)
            .await
            .ok();
        self.sync.shutdown().await;
        Ok(())
    }

    async fn status(&mut self, namespace: NamespaceId) -> Option<LiveStatus> {
        let state = self.states.get(&namespace).cloned().unwrap_or_default();
        let subscriptions = self.subscriptions.len(&namespace) as u64;
        Some(LiveStatus {
            state,
            subscriptions,
        })
    }

    async fn start_sync(&mut self, namespace: NamespaceId, mut peers: Vec<PeerAddr>) -> Result<()> {
        // update state to allow sync
        if !self.is_syncing(&namespace) {
            self.update_state(namespace, StateUpdate::with_sync(true))
                .await?;
        }
        // add the peers stored for this document
        match self.sync.get_sync_peers(namespace).await {
            Ok(None) => {
                // no peers for this document
            }
            Ok(Some(known_useful_peers)) => {
                let as_peer_addr = known_useful_peers.into_iter().filter_map(|peer_id_bytes| {
                    // peers are stored as bytes, don't fail the operation if they can't be
                    // decoded: simply ignore the peer
                    match PublicKey::from_bytes(&peer_id_bytes) {
                        Ok(public_key) => Some(PeerAddr::new(public_key)),
                        Err(_signing_error) => {
                            warn!("potential db corruption: peers per doc can't be decoded");
                            None
                        }
                    }
                });
                peers.extend(as_peer_addr);
            }
            Err(e) => {
                // try to continue if peers per doc can't be read since they are not vital for sync
                warn!(%e, "db error reading peers per document")
            }
        }
        self.join_peers(namespace, peers).await?;
        Ok(())
    }

    async fn subscribe(
        &mut self,
        namespace: NamespaceId,
        cb: OnLiveEventCallback,
    ) -> anyhow::Result<RemovalToken> {
        self.update_state(namespace, StateUpdate::with_watch(true))
            .await?;
        Ok(self.subscriptions.subscribe(namespace, cb))
    }

    /// Returns `true` if a callback was found and removed
    async fn unsubscribe(&mut self, namespace: NamespaceId, token: RemovalToken) -> bool {
        if !self.subscriptions.unsubscribe(namespace, token) {
            return false;
        }
        // if there are no more subscriptions, and we are not syncing the replica, disable
        // watch.
        if !self.subscriptions.contains(&namespace) && !self.is_syncing(&namespace) {
            self.update_state(namespace, StateUpdate::with_watch(false))
                .await
                .ok();
        }
        true
    }

    async fn update_state(
        &mut self,
        namespace: NamespaceId,
        mut change: StateUpdate,
    ) -> Result<()> {
        // whenever we enable sync, also enable watch, because we need the events for gossiping
        // changes.
        if let Some(true) = change.sync {
            change.watch = Some(true);
        }
        let state = self.states.get(&namespace).cloned().unwrap_or_default();
        let next_state = state.with_update(change);

        if next_state == state {
            return Ok(());
        }

        // when disabling sync: leave gossip
        if state.sync && !next_state.sync {
            self.gossip_actor_tx
                .send(ToGossipActor::Leave { namespace })
                .await
                .context("gossip actor failure")?;
        }
        // update state of the iroh sync handle
        self.sync
            .update_state(namespace, change)
            .await
            .context("iroh_sync actor failure")?;
        self.states.insert(namespace, next_state);
        Ok(())
    }

    async fn leave(&mut self, namespace: NamespaceId, force_remove: bool) -> anyhow::Result<()> {
        let mut change = StateUpdate::default().sync(false);
        if force_remove {
            self.subscriptions.send(&namespace, LiveEvent::Closed).await;
            self.subscriptions.remove(&namespace);
            change.watch = Some(false);
        }
        self.update_state(namespace, change).await?;
        Ok(())
    }

    async fn join_peers(
        &mut self,
        namespace: NamespaceId,
        peers: Vec<PeerAddr>,
    ) -> anyhow::Result<()> {
        let peer_ids: Vec<PublicKey> = peers.iter().map(|p| p.peer_id).collect();

        // add addresses of peers to our endpoint address book
        for peer in peers.into_iter() {
            let peer_id = peer.peer_id;
            if let Err(err) = self.endpoint.add_peer_addr(peer).await {
                warn!(peer = %peer_id.fmt_short(), "failed to add known addrs: {err:?}");
            }
        }

        // tell gossip to join
        self.gossip_actor_tx
            .send(ToGossipActor::Join {
                namespace,
                peers: peer_ids.clone(),
            })
            .await?;

        // trigger initial sync with initial peers
        for peer in peer_ids {
            self.sync_with_peer(namespace, peer, SyncReason::DirectJoin);
        }
        Ok(())
    }

    #[instrument("connect", skip_all, fields(peer = %peer.fmt_short(), namespace = %namespace.fmt_short()))]
    async fn on_sync_via_connect_finished(
        &mut self,
        namespace: NamespaceId,
        peer: PublicKey,
        reason: SyncReason,
        result: Result<SyncFinished, ConnectError>,
    ) -> Result<()> {
        match result {
            Err(ConnectError::RemoteAbort(AbortReason::AlreadySyncing)) => {
                debug!(?reason, "remote abort, already syncing");
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

    #[instrument("accept", skip_all, fields(peer = %fmt_accept_peer(&res), namespace = %fmt_accept_namespace(&res)))]
    async fn on_sync_via_accept_finished(
        &mut self,
        res: Result<SyncFinished, AcceptError>,
    ) -> Result<()> {
        match res {
            Ok(state) => {
                self.on_sync_finished(state.namespace, state.peer, Origin::Accept, Ok(state))
                    .await
            }
            Err(AcceptError::Abort { reason, .. }) if reason == AbortReason::AlreadySyncing => {
                // In case we aborted the sync: do nothing (our outgoing sync is in progress)
                debug!(?reason, "aborted by us");
                Ok(())
            }
            Err(err) => {
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
                    debug!(?err, "failed before reading the first message");
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
        let state = match result {
            Ok(ref details) => {
                debug!(
                    sent = %details.outcome.num_sent,
                    recv = %details.outcome.num_recv,
                    t_connect = ?details.timings.connect,
                    t_process = ?details.timings.process,
                    "sync finish ok",
                );

                // register the peer as useful for the document
                if let Err(e) = self
                    .sync
                    .register_useful_peer(namespace, *peer.as_bytes())
                    .await
                {
                    debug!(%e, "failed to register peer for document")
                }

                SyncState::Finished
            }
            Err(ref err) => {
                warn!(?origin, ?err, "sync failed");

                SyncState::Failed
            }
        };

        self.set_sync_state(namespace, peer, state);

        if self.subscriptions.contains(&namespace) {
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
            self.subscriptions
                .send(&namespace, LiveEvent::SyncFinished(event))
                .await;
        }
        Ok(())
    }

    fn is_syncing(&self, namespace: &NamespaceId) -> bool {
        self.states.get(namespace).map(|x| x.sync).unwrap_or(false)
    }

    async fn on_replica_event(&mut self, event: iroh_sync::Event) -> Result<()> {
        let iroh_sync::Event::Insert {
            namespace,
            origin,
            entry: signed_entry,
        } = event;
        let topic = TopicId::from_bytes(*namespace.as_bytes());
        match origin {
            InsertOrigin::Local => {
                // A new entry was inserted locally. Broadcast a gossip message.
                if self.is_syncing(&namespace) {
                    let op = Op::Put(signed_entry.clone());
                    let message = postcard::to_stdvec(&op)?.into();
                    self.gossip.broadcast(topic, message).await?;
                }
                // Notify subscribers about the event
                if self.subscriptions.contains(&namespace) {
                    let event = LiveEvent::InsertLocal {
                        entry: signed_entry.entry().clone(),
                    };
                    self.subscriptions.send(&namespace, event).await;
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
                if self.subscriptions.contains(&namespace) {
                    let event = LiveEvent::InsertRemote {
                        from,
                        entry: entry.clone(),
                        content_status: entry_to_content_status(entry_status),
                    };
                    self.subscriptions.send(&namespace, event).await;
                }
            }
        }

        Ok(())
    }

    #[instrument("accept", skip_all)]
    pub async fn handle_connection(&mut self, conn: quinn::Connecting) {
        let to_actor_tx = self.sync_actor_tx.clone();
        let accept_request_cb = move |namespace, peer| {
            let to_actor_tx = to_actor_tx.clone();
            async move {
                let (reply_tx, reply_rx) = oneshot::channel();
                to_actor_tx
                    .send(ToLiveActor::AcceptSyncRequest {
                        namespace,
                        peer,
                        reply: reply_tx,
                    })
                    .await
                    .ok();
                match reply_rx.await {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        warn!(
                            "accept request callback failed to retrieve reply from actor: {err:?}"
                        );
                        AcceptOutcome::Reject(AbortReason::InternalServerError)
                    }
                }
            }
            .boxed()
        };
        debug!("incoming connection");
        let sync = self.sync.clone();
        let fut = async move { handle_connection(sync, conn, accept_request_cb).await }.boxed();
        self.running_sync_accept.push(fut);
    }

    pub fn accept_sync_request(
        &mut self,
        namespace: NamespaceId,
        peer: PublicKey,
    ) -> AcceptOutcome {
        if !self.is_syncing(&namespace) {
            return AcceptOutcome::Reject(AbortReason::NotFound);
        };
        match self.get_sync_state(namespace, peer) {
            SyncState::None | SyncState::Failed | SyncState::Finished => {
                self.set_sync_state(namespace, peer, SyncState::Accepting);
                AcceptOutcome::Allow
            }
            SyncState::Accepting => AcceptOutcome::Reject(AbortReason::AlreadySyncing),
            // Incoming sync request while we are dialing ourselves.
            // In this case, compare the binary representations of our and the other node's peer id
            // to deterministically decide which of the two concurrent connections will succeed.
            SyncState::Dialing => match expected_sync_direction(&self.endpoint.peer_id(), &peer) {
                SyncDirection::Accept => {
                    self.set_sync_state(namespace, peer, SyncState::Accepting);
                    AcceptOutcome::Allow
                }
                SyncDirection::Dial => AcceptOutcome::Reject(AbortReason::AlreadySyncing),
            },
        }
    }
}

#[derive(Debug)]
enum SyncDirection {
    Accept,
    Dial,
}

fn expected_sync_direction(self_peer_id: &PublicKey, other_peer_id: &PublicKey) -> SyncDirection {
    if self_peer_id.as_bytes() > other_peer_id.as_bytes() {
        SyncDirection::Accept
    } else {
        SyncDirection::Dial
    }
}

/// Event emitted when a sync operation completes
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
}

/// Why we performed a sync exchange
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Origin {
    /// We initiated the exchange
    Connect(SyncReason),
    /// A peer connected to us and we accepted the exchange
    Accept,
}

#[derive(Default)]
struct Subscriptions {
    inner: HashMap<NamespaceId, HashMap<u64, OnLiveEventCallback>>,
    /// Next [`RemovalToken`] for external replica event subscriptions.
    event_removal_id: u64,
}
impl Subscriptions {
    fn contains(&self, namespace: &NamespaceId) -> bool {
        self.inner.contains_key(namespace)
    }

    fn len(&self, namespace: &NamespaceId) -> usize {
        self.inner.get(namespace).map(|map| map.len()).unwrap_or(0)
    }

    fn remove(&mut self, namespace: &NamespaceId) {
        self.inner.remove(namespace);
    }

    pub async fn send(&mut self, namespace: &NamespaceId, event: LiveEvent) {
        let Some(subs) = self.inner.get_mut(namespace) else {
            return;
        };
        let futs: Vec<_> = subs
            .iter()
            .map(|(idx, sub)| {
                let fut = sub(event.clone());
                fut.map(move |r| (*idx, r))
            })
            .collect();

        let res = futures::future::join_all(futs).await;

        let to_drop = res
            .into_iter()
            .filter(|res| matches!(res.1, KeepCallback::Drop));
        for (idx, _) in to_drop {
            subs.remove(&idx);
        }
    }

    pub fn subscribe(&mut self, namespace: NamespaceId, cb: OnLiveEventCallback) -> RemovalToken {
        let subs = self.inner.entry(namespace).or_default();
        let removal_id = self.event_removal_id;
        self.event_removal_id += 1;
        subs.insert(removal_id, cb);
        RemovalToken(removal_id)
    }

    /// Returns `true` if a callback was found and removed
    pub fn unsubscribe(&mut self, namespace: NamespaceId, token: RemovalToken) -> bool {
        if let Some(subs) = self.inner.get_mut(&namespace) {
            let res = subs.remove(&token.0).is_some();
            if subs.is_empty() {
                self.inner.remove(&namespace);
            }
            return res;
        }
        false
    }
}

/// Token needed to remove inserted callbacks.
#[derive(Debug, Clone, Copy)]
pub struct RemovalToken(u64);

fn fmt_accept_peer(res: &Result<SyncFinished, AcceptError>) -> String {
    match res {
        Ok(res) => res.peer.fmt_short(),
        Err(err) => err
            .peer()
            .map(|x| x.fmt_short())
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

fn fmt_accept_namespace(res: &Result<SyncFinished, AcceptError>) -> String {
    match res {
        Ok(res) => res.namespace.fmt_short(),
        Err(err) => err
            .namespace()
            .map(|x| x.fmt_short())
            .unwrap_or_else(|| "unknown".to_string()),
    }
}
