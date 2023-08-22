use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    str::FromStr,
    sync::{atomic::AtomicU64, Arc},
};

use crate::{download::Downloader, sync::connect_and_sync};
use anyhow::{anyhow, bail, Result};
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
    store,
    sync::{Entry, InsertOrigin, NamespaceId, Replica, SignedEntry},
};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{self, mpsc},
    task::JoinError,
};
use tracing::{debug, error, info, warn};

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
    Failed(anyhow::Error),
}

#[derive(derive_more::Debug)]
enum ToActor<S: store::Store> {
    StartSync {
        replica: Replica<S::Instance>,
        peers: Vec<PeerSource>,
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
}

/// Callback used for tracking [`LiveEvent`]s.
pub type OnLiveEventCallback =
    Box<dyn Fn(LiveEvent) -> BoxFuture<'static, ()> + Send + Sync + 'static>;

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
        gossip: Gossip,
        bao_store: B,
        downloader: Downloader,
    ) -> Self {
        let (to_actor_tx, to_actor_rx) = mpsc::channel(CHANNEL_CAP);
        let mut actor = Actor::new(endpoint, gossip, bao_store, downloader, to_actor_rx);
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
    pub async fn start_sync(
        &self,
        replica: Replica<S::Instance>,
        peers: Vec<PeerSource>,
    ) -> Result<()> {
        self.to_actor_tx
            .send(ToActor::<S>::StartSync { replica, peers })
            .await?;
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
        F: Fn(LiveEvent) -> BoxFuture<'static, ()> + Send + Sync + 'static,
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
}

// Currently peers might double-sync in both directions.
struct Actor<S: store::Store, B: baomap::Store> {
    endpoint: MagicEndpoint,
    gossip: Gossip,
    bao_store: B,
    downloader: Downloader,

    replicas: HashMap<TopicId, Replica<S::Instance>>,
    replicas_subscription: futures::stream::SelectAll<
        flume::r#async::RecvStream<'static, (InsertOrigin, SignedEntry)>,
    >,
    subscription: BoxStream<'static, Result<(TopicId, Event)>>,
    sync_state: HashMap<(TopicId, PublicKey), SyncState>,

    to_actor_rx: mpsc::Receiver<ToActor<S>>,

    pending_syncs: FuturesUnordered<BoxFuture<'static, (TopicId, PublicKey, Result<()>)>>,
    pending_joins: FuturesUnordered<BoxFuture<'static, (TopicId, Result<()>)>>,

    event_subscriptions: HashMap<TopicId, HashMap<u64, OnLiveEventCallback>>,
    event_removal_id: AtomicU64,

    pending_downloads: FuturesUnordered<BoxFuture<'static, Option<(TopicId, Hash)>>>,
}

/// Token needed to remove inserted callbacks.
#[derive(Debug, Clone)]
pub struct RemovalToken(u64);

impl<S: store::Store, B: baomap::Store> Actor<S, B> {
    pub fn new(
        endpoint: MagicEndpoint,
        gossip: Gossip,
        bao_store: B,
        downloader: Downloader,
        to_actor_rx: mpsc::Receiver<ToActor<S>>,
    ) -> Self {
        let sub = gossip.clone().subscribe_all().boxed();

        Self {
            gossip,
            endpoint,
            bao_store,
            downloader,
            to_actor_rx,
            sync_state: Default::default(),
            pending_syncs: Default::default(),
            pending_joins: Default::default(),
            replicas: Default::default(),
            replicas_subscription: Default::default(),
            subscription: sub,
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
                        Some(ToActor::StartSync { replica, peers }) => self.start_sync(replica, peers).await?,
                        Some(ToActor::StopSync { namespace }) => self.stop_sync(&namespace).await?,
                        Some(ToActor::JoinPeers { namespace, peers }) => self.join_gossip_and_start_initial_sync(&namespace, peers).await?,
                        Some(ToActor::Subscribe { namespace, cb, s }) => {
                            let subscribe_result = self.subscribe(&namespace, cb).await;
                            s.send(subscribe_result).ok();
                        },
                        Some(ToActor::Unsubscribe { namespace, token, s }) => {
                            let result = self.unsubscribe(&namespace, token).await;
                            s.send(result).ok();
                        },
                    }
                }
                // new gossip message
                Some(event) = self.subscription.next() => {
                    let (topic, event) = event?;
                    if let Err(err) = self.on_gossip_event(topic, event) {
                        error!("Failed to process gossip event: {err:?}");
                    }
                },
                Some((origin, entry))  = self.replicas_subscription.next() => {
                    if let Err(err) = self.on_replica_event(origin, entry).await {
                        error!("Failed to process replica event: {err:?}");
                    }
                }
                Some((topic, peer, res)) = self.pending_syncs.next() => {
                    // let (topic, peer, res) = res.context("task sync_with_peer paniced")?;
                    self.on_sync_finished(topic, peer, res);

                }
                Some((topic, res)) = self.pending_joins.next() => {
                    if let Err(err) = res {
                        error!("failed to join {topic:?}: {err:?}");
                    } else {
                        info!("joined sync topic {topic:?}");
                    }
                    // TODO: maintain some join state
                }
                Some(res) = self.pending_downloads.next() => {
                    if let Some((topic, hash)) = res {
                        if let Some(subs) = self.event_subscriptions.get(&topic) {
                            let event = LiveEvent::ContentReady { hash };
                            notify_all(subs, event).await;
                        }
                    }

                }
            }
        }
        Ok(())
    }

    fn sync_with_peer(&mut self, topic: TopicId, peer: PublicKey) {
        let Some(replica) = self.replicas.get(&topic) else {
            return;
        };
        // Check if we synced and only start sync if not yet synced
        // sync_with_peer is triggered on NeighborUp events, so might trigger repeatedly for the
        // same peers.
        // TODO: Track finished time and potentially re-run sync
        if let Some(_state) = self.sync_state.get(&(topic, peer)) {
            return;
        };
        self.sync_state.insert((topic, peer), SyncState::Running);
        let task = {
            let endpoint = self.endpoint.clone();
            let replica = replica.clone();
            async move {
                debug!("init sync with {peer}");
                // TODO: Make sure that the peer is dialable.
                let res = connect_and_sync::<S>(&endpoint, &replica, peer, None, &[]).await;
                debug!("synced with {peer}: {res:?}");
                (topic, peer, res)
            }
            .boxed()
        };
        self.pending_syncs.push(task);
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        for (topic, _replica) in self.replicas.drain() {
            self.event_subscriptions.remove(&topic);
            self.gossip.quit(topic).await?;
        }

        Ok(())
    }

    async fn subscribe(
        &mut self,
        namespace: &NamespaceId,
        cb: OnLiveEventCallback,
    ) -> anyhow::Result<RemovalToken> {
        let topic = TopicId::from_bytes(*namespace.as_bytes());
        if self.replicas.contains_key(&topic) {
            let subs = self.event_subscriptions.entry(topic).or_default();
            let removal_id = self
                .event_removal_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            subs.insert(removal_id, cb);
            let token = RemovalToken(removal_id);
            Ok(token)
        } else {
            bail!("cannot subscribe to unknown replica: {}", namespace);
        }
    }

    /// Returns `true` if a callback was found and removed
    async fn unsubscribe(&mut self, namespace: &NamespaceId, token: RemovalToken) -> bool {
        let topic = TopicId::from_bytes(*namespace.as_bytes());
        if let Some(subs) = self.event_subscriptions.get_mut(&topic) {
            return subs.remove(&token.0).is_some();
        }

        false
    }

    async fn stop_sync(&mut self, namespace: &NamespaceId) -> anyhow::Result<()> {
        let topic = TopicId::from_bytes(*namespace.as_bytes());
        if let Some(_replica) = self.replicas.remove(&topic) {
            self.event_subscriptions.remove(&topic);
            self.gossip.quit(topic).await?;
        }
        Ok(())
    }

    async fn join_gossip_and_start_initial_sync(
        &mut self,
        namespace: &NamespaceId,
        peers: Vec<PeerSource>,
    ) -> anyhow::Result<()> {
        let topic = TopicId::from_bytes(*namespace.as_bytes());
        let peer_ids: Vec<PublicKey> = peers.iter().map(|p| p.peer_id).collect();

        // add addresses of initial peers to our endpoint address book
        for peer in &peers {
            if let Err(err) = self
                .endpoint
                .add_known_addrs(peer.peer_id, peer.derp_region, &peer.addrs)
                .await
            {
                warn!(peer = ?peer.peer_id, "failed to add known addrs: {err:?}");
            }
        }

        // join gossip for the topic to receive and send message
        self.pending_joins.push({
            let peer_ids = peer_ids.clone();
            let gossip = self.gossip.clone();
            async move {
                match gossip.join(topic, peer_ids).await {
                    Err(err) => (topic, Err(err)),
                    Ok(fut) => (topic, fut.await),
                }
            }
            .boxed()
        });

        // trigger initial sync with initial peers
        for peer in peer_ids {
            self.sync_with_peer(topic, peer);
        }
        Ok(())
    }

    async fn start_sync(
        &mut self,
        replica: Replica<S::Instance>,
        peers: Vec<PeerSource>,
    ) -> Result<()> {
        let namespace = replica.namespace();
        let topic = TopicId::from_bytes(*namespace.as_bytes());
        if let std::collections::hash_map::Entry::Vacant(e) = self.replicas.entry(topic) {
            // setup replica insert notifications.
            let events = replica
                .subscribe()
                .ok_or_else(|| anyhow::anyhow!("trying to subscribe twice to the same replica"))?;
            self.replicas_subscription.push(events.into_stream());
            e.insert(replica);
        }

        self.join_gossip_and_start_initial_sync(&namespace, peers)
            .await?;

        Ok(())
    }

    fn on_sync_finished(&mut self, topic: TopicId, peer: PublicKey, res: Result<()>) {
        let state = match res {
            Ok(_) => SyncState::Finished,
            Err(err) => SyncState::Failed(err),
        };
        self.sync_state.insert((topic, peer), state);
    }

    fn on_gossip_event(&mut self, topic: TopicId, event: Event) -> Result<()> {
        let Some(replica) = self.replicas.get(&topic) else {
            return Err(anyhow!("Missing doc for {topic:?}"));
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
                debug!(peer = ?peer, "new neighbor, init sync");
                self.sync_with_peer(topic, peer);
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
        let topic = TopicId::from_bytes(*signed_entry.entry().namespace().as_bytes());
        let subs = self.event_subscriptions.get(&topic);
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
                let hash = *entry.record().content_hash();

                // A new entry was inserted from initial sync or gossip. Queue downloading the
                // content.
                let entry_status = self.bao_store.contains(&hash);
                if matches!(entry_status, EntryStatus::NotFound) {
                    self.downloader.push(hash, vec![from]).await;
                    let fut = self.downloader.finished(&hash).await;
                    let fut = fut
                        .map(move |res| res.map(move |(hash, _len)| (topic, hash)))
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
}

async fn notify_all(subs: &HashMap<u64, OnLiveEventCallback>, event: LiveEvent) {
    futures::future::join_all(subs.values().map(|sub| sub(event.clone()))).await;
}
