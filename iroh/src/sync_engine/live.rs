use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    str::FromStr,
    sync::{atomic::AtomicU64, Arc},
    time::SystemTime,
};

use crate::downloader::{DownloadKind, Downloader};
use anyhow::{anyhow, bail, Result};
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
use iroh_net::{key::PublicKey, MagicEndpoint};
use iroh_sync::{
    net::{connect_and_sync, handle_connection, AcceptOutcome, SyncError},
    store,
    sync::{Entry, InsertOrigin, NamespaceId, Replica, SignedEntry},
};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{self, mpsc, oneshot},
    task::JoinError,
};
use tracing::{debug, error, warn};

const CHANNEL_CAP: usize = 8;

/// The address to connect to a peer
// TODO: Move into iroh-net
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerSource {
    /// The peer id (required)
    pub peer_id: PublicKey,
    /// Socket addresses for this peer (may be empty)
    pub addrs: Vec<SocketAddr>,
    /// Derp region for this peer
    pub derp_region: Option<u16>,
}

impl PeerSource {
    /// Deserializes from bytes.
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        postcard::from_bytes(bytes).map_err(Into::into)
    }
    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard::to_stdvec is infallible")
    }
    /// Create with information gathered from a [`MagicEndpoint`]
    pub async fn from_endpoint(endpoint: &MagicEndpoint) -> anyhow::Result<Self> {
        Ok(Self {
            peer_id: endpoint.peer_id(),
            derp_region: endpoint.my_derp().await,
            addrs: endpoint
                .local_endpoints()
                .await?
                .into_iter()
                .map(|ep| ep.addr)
                .collect(),
        })
    }
}

/// Serializes to base32.
impl fmt::Display for PeerSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = self.to_bytes();
        let mut text = data_encoding::BASE32_NOPAD.encode(&encoded);
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

/// Deserializes from base32.
impl FromStr for PeerSource {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        let slf = Self::from_bytes(&bytes)?;
        Ok(slf)
    }
}

/// An iroh-sync operation
///
/// This is the message that is broadcast over iroh-gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    /// A new entry was inserted into the document.
    Put(SignedEntry),
}

#[derive(Debug)]
enum SyncState {
    Running,
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

#[derive(derive_more::Debug)]
enum ToActor<S: store::Store> {
    Status {
        namespace: NamespaceId,
        s: sync::oneshot::Sender<Option<LiveStatus>>,
    },
    StartSync {
        namespace: NamespaceId,
        peers: Vec<PeerSource>,
        reply: sync::oneshot::Sender<anyhow::Result<()>>,
    },
    JoinPeers {
        namespace: NamespaceId,
        peers: Vec<PeerSource>,
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
#[derive(Serialize, Deserialize, Debug, Clone)]
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
    /// A set-reconciliation sync finished.
    SyncFinished(SyncEvent),
}

/// Availability status of an entry's content bytes
// TODO: Add IsDownloading
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ContentStatus {
    /// Fully available on the local node.
    Complete,
    /// Partially available on the local node.
    Incomplete,
    /// Not available on the local node.
    ///
    /// This currently means either that the content is about to be downloaded, failed to be
    /// downloaded, or was never requested.
    Missing,
}

impl From<EntryStatus> for ContentStatus {
    fn from(value: EntryStatus) -> Self {
        match value {
            EntryStatus::Complete => ContentStatus::Complete,
            EntryStatus::Partial => ContentStatus::Incomplete,
            EntryStatus::NotFound => ContentStatus::Missing,
        }
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
        let mut actor = Actor::new(
            endpoint,
            gossip,
            bao_store,
            downloader,
            replica_store,
            to_actor_rx,
            to_actor_tx.clone(),
        );
        let task = rt.main().spawn(async move {
            if let Err(err) = actor.run().await {
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
    pub async fn start_sync(&self, namespace: NamespaceId, peers: Vec<PeerSource>) -> Result<()> {
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
    pub async fn join_peers(&self, namespace: NamespaceId, peers: Vec<PeerSource>) -> Result<()> {
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
    running_sync_connect:
        FuturesUnordered<BoxFuture<'static, (NamespaceId, PublicKey, SyncReason, Result<()>)>>,
    /// Running sync futures (from accept).
    running_sync_accept: FuturesUnordered<
        BoxFuture<'static, std::result::Result<(NamespaceId, PublicKey), SyncError>>,
    >,
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
        loop {
            tokio::select! {
                biased;
                msg = self.to_actor_rx.recv() => {
                    match msg {
                        // received shutdown signal, or livesync handle was dropped:
                        // break loop and exit
                        Some(ToActor::Shutdown) | None => {
                            self.shutdown().await?;
                            break;
                        }
                        Some(ToActor::StartSync { namespace, peers, reply }) => {
                            let res = self.start_sync(namespace, peers).await;
                            reply.send(res).ok();
                        },
                        Some(ToActor::StopSync { namespace }) => {
                            self.stop_sync(namespace).await?;
                        }
                        Some(ToActor::JoinPeers { namespace, peers }) => {
                            self.join_peers(namespace, peers).await?;
                        },
                        Some(ToActor::Subscribe { namespace, cb, s }) => {
                            let result = self.subscribe(namespace, cb).await;
                            s.send(result).ok();
                        },
                        Some(ToActor::Unsubscribe { namespace, token, s }) => {
                            let result = self.unsubscribe(namespace, token).await;
                            s.send(result).ok();
                        },
                        Some(ToActor::Status { namespace , s }) => {
                            let result = self.status(namespace).await;
                            s.send(result).ok();
                        },
                        Some(ToActor::HandleConnection { conn }) => {
                             self.handle_connection(conn).await;
                        },
                        Some(ToActor::AcceptSyncRequest { namespace, peer, reply }) => {
                            let outcome = self.accept_sync_request(namespace, peer);
                            reply.send(outcome).ok();
                        },
                    };
                }
                // new gossip message
                Some(event) = self.gossip_events.next() => {
                    let (topic, event) = event?;
                    if let Err(err) = self.on_gossip_event(topic, event) {
                        error!("Failed to process gossip event: {err:?}");
                    }
                },
                Some((origin, entry))  = self.replica_events.next() => {
                    if let Err(err) = self.on_replica_event(origin, entry).await {
                        error!("Failed to process replica event: {err:?}");
                    }
                }
                Some((namespace, peer, reason, res)) = self.running_sync_connect.next() => {
                    self.on_sync_via_connect_finished(namespace, peer, reason, res).await;

                }
                Some(res) = self.running_sync_accept.next() => {
                    self.on_sync_via_accept_finished(res).await;
                }
                Some((namespace, res)) = self.pending_joins.next() => {
                    if let Err(err) = res {
                        error!("failed to join gossip for {namespace:?}: {err:?}");
                    } else {
                        debug!("joined gossip for {namespace:?}");
                    }
                    // TODO: maintain some join state
                }
                Some(res) = self.pending_downloads.next() => {
                    if let Some((namespace, hash)) = res {
                        if let Some(subs) = self.event_subscriptions.get_mut(&namespace) {
                            let event = LiveEvent::ContentReady { hash };
                            notify_all(subs, event).await;
                        }
                    }

                }
            }
        }
        Ok(())
    }

    fn get_replica_if_syncing(&self, namespace: &NamespaceId) -> Option<Replica<S::Instance>> {
        if !self.syncing_replicas.contains(namespace) {
            None
        } else {
            match self.replica_store.open_replica(namespace) {
                Ok(replica) => replica,
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
        // Check if we synced and only start sync if not yet synced
        // sync_with_peer is triggered on NeighborUp events, so might trigger repeatedly for the
        // same peers.
        // TODO: Track finished time and potentially re-run sync
        if let Some(_state) = self.sync_state.get(&(namespace, peer)) {
            return;
        };
        debug!(?peer, ?namespace, "start sync (reason: {reason:?})");
        self.sync_state
            .insert((namespace, peer), SyncState::Running);
        let task = {
            let endpoint = self.endpoint.clone();
            let replica = replica.clone();
            async move {
                // TODO: Make sure that the peer is dialable.
                let res = connect_and_sync::<S>(&endpoint, &replica, peer, None, &[]).await;
                (namespace, peer, reason, res)
            }
            .boxed()
        };
        self.running_sync_connect.push(task);
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

    async fn start_sync(&mut self, namespace: NamespaceId, peers: Vec<PeerSource>) -> Result<()> {
        self.ensure_subscription(namespace)?;
        self.syncing_replicas.insert(namespace);
        self.join_peers(namespace, peers).await?;
        Ok(())
    }

    fn ensure_subscription(&mut self, namespace: NamespaceId) -> anyhow::Result<()> {
        if !self.open_replicas.contains(&namespace) {
            let Some(replica) = self.replica_store.open_replica(&namespace)? else {
                bail!("Replica not found");
            };
            let events = replica
                .subscribe()
                .ok_or_else(|| anyhow::anyhow!("trying to subscribe twice to the same replica"))?;
            self.replica_events.push(events.into_stream());
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
        self.ensure_subscription(namespace)?;
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
            self.maybe_close_replica(namespace);
        }
        Ok(())
    }

    async fn join_peers(
        &mut self,
        namespace: NamespaceId,
        peers: Vec<PeerSource>,
    ) -> anyhow::Result<()> {
        let peer_ids: Vec<PublicKey> = peers.iter().map(|p| p.peer_id).collect();

        // add addresses of initial peers to our endpoint address book
        for PeerSource {
            peer_id,
            addrs,
            derp_region,
        } in peers.into_iter()
        {
            if let Err(err) = self
                .endpoint
                .add_peer_addr(iroh_net::PeerAddr {
                    peer_id,
                    addr_info: iroh_net::AddrInfo {
                        derp_region,
                        direct_addresses: addrs,
                    },
                })
                .await
            {
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
        result: Result<()>,
    ) {
        self.on_sync_finished(namespace, peer, Origin::Connect(reason), result)
            .await;
    }

    async fn on_sync_via_accept_finished(
        &mut self,
        res: std::result::Result<(NamespaceId, PublicKey), SyncError>,
    ) {
        match res {
            Ok((namespace, peer)) => {
                self.on_sync_finished(namespace, peer, Origin::Accept, Ok(()))
                    .await;
            }
            Err(err) => {
                if let (Some(peer), Some(namespace)) = (err.peer(), err.namespace()) {
                    self.on_sync_finished(
                        namespace,
                        peer,
                        Origin::Accept,
                        Err(anyhow::Error::from(err)),
                    )
                    .await;
                } else {
                    debug!("sync failed (via accept): {err:?}");
                }
            }
        }
    }

    async fn on_sync_finished(
        &mut self,
        namespace: NamespaceId,
        peer: PublicKey,
        origin: Origin,
        result: anyhow::Result<()>,
    ) {
        debug!(?peer, ?namespace, "sync done (via {origin:?}): {result:?}");
        let state = match result {
            Ok(_) => SyncState::Finished,
            Err(_) => SyncState::Failed,
        };
        self.sync_state.insert((namespace, peer), state);
        let event = SyncEvent {
            namespace,
            peer,
            origin,
            result: result.map_err(|err| format!("{err:?}")),
            finished: SystemTime::now(),
        };
        let subs = self.event_subscriptions.get_mut(&event.namespace);
        if let Some(subs) = subs {
            notify_all(subs, LiveEvent::SyncFinished(event)).await;
        }
    }

    fn on_gossip_event(&mut self, topic: TopicId, event: Event) -> Result<()> {
        let namespace: NamespaceId = topic.as_bytes().into();
        let Some(replica) = self.get_replica_if_syncing(&namespace) else {
            return Err(anyhow!("Doc {namespace:?} is not active"));
        };
        match event {
            // We received a gossip message. Try to insert it into our replica.
            Event::Received(data, prev_peer) => {
                let op: Op = postcard::from_bytes(&data)?;
                match op {
                    Op::Put(entry) => {
                        debug!(peer = ?prev_peer, topic = ?topic, "received entry via gossip");
                        replica.insert_remote_entry(entry, *prev_peer.as_bytes())?
                    }
                }
            }
            // A new neighbor appeared in the gossip swarm. Try to sync with it directly.
            // [Self::sync_with_peer] will check to not resync with peers synced previously in the
            // same session. TODO: Maybe this is too broad and leads to too many sync requests.
            Event::NeighborUp(peer) => {
                self.sync_with_peer(namespace, peer, SyncReason::NewNeighbor);
            }
            _ => {}
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
                debug!(topic = ?topic, "broadcast new entry");
                self.gossip.broadcast(topic, message).await?;

                // Notify subscribers about the event
                if let Some(subs) = subs {
                    let event = LiveEvent::InsertLocal {
                        entry: entry.clone(),
                    };
                    notify_all(subs, event).await;
                }
            }
            InsertOrigin::Sync(peer_id) => {
                let from = PublicKey::from_bytes(&peer_id)?;
                let entry = signed_entry.entry();
                let hash = entry.record().content_hash();

                // A new entry was inserted from initial sync or gossip. Queue downloading the
                // content.
                let entry_status = self.bao_store.contains(&hash);
                if matches!(entry_status, EntryStatus::NotFound) {
                    let handle = self
                        .downloader
                        .queue(DownloadKind::Blob { hash }, vec![from])
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
                        content_status: entry_status.into(),
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
            return AcceptOutcome::NotAvailable;
        };
        let state = self.sync_state.get(&(namespace, peer));
        match state {
            None | Some(SyncState::Failed | SyncState::Finished) => {
                self.sync_state
                    .insert((namespace, peer), SyncState::Running);
                AcceptOutcome::Accept(replica.clone())
            }
            Some(SyncState::Running) => AcceptOutcome::AlreadySyncing,
        }
    }
}

/// Outcome of a sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
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
