#![allow(missing_docs)]

use std::{collections::HashMap, time::SystemTime};

use anyhow::{Context, Result};
use futures::FutureExt;
use iroh_bytes::downloader::{DownloadKind, Downloader, Role};
use iroh_bytes::{store::EntryStatus, Hash};
use iroh_gossip::{net::Gossip, proto::TopicId};
use iroh_net::{key::PublicKey, MagicEndpoint, NodeAddr};
use iroh_sync::{
    actor::{OpenOpts, SyncHandle},
    net::{
        connect_and_sync, handle_connection, AbortReason, AcceptError, AcceptOutcome, ConnectError,
        SyncFinished,
    },
    AuthorHeads, ContentStatus, NamespaceId, SignedEntry,
};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{self, mpsc, oneshot},
    task::JoinSet,
};
use tracing::{debug, error, info, instrument, trace, warn, Instrument, Span};

use super::gossip::ToGossipActor;
use super::state::{NamespaceStates, Origin, SyncReason};

/// An iroh-sync operation
///
/// This is the message that is broadcast over iroh-gossip.
#[derive(Debug, Clone, Serialize, Deserialize, strum::Display)]
pub enum Op {
    /// A new entry was inserted into the document.
    Put(SignedEntry),
    /// A peer now has content available for a hash.
    ContentReady(Hash),
    /// We synced with another peer, here's the news.
    SyncReport(SyncReport),
}

/// Report of a successful sync with the new heads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReport {
    namespace: NamespaceId,
    /// Encoded [`AuthorHeads`]
    heads: Vec<u8>,
}

/// Messages to the sync actor
#[derive(derive_more::Debug, strum::Display)]
pub enum ToLiveActor {
    StartSync {
        namespace: NamespaceId,
        peers: Vec<NodeAddr>,
        #[debug("onsehot::Sender")]
        reply: sync::oneshot::Sender<anyhow::Result<()>>,
    },
    JoinPeers {
        namespace: NamespaceId,
        peers: Vec<NodeAddr>,
        #[debug("onsehot::Sender")]
        reply: sync::oneshot::Sender<anyhow::Result<()>>,
    },
    Leave {
        namespace: NamespaceId,
        kill_subscribers: bool,
        #[debug("onsehot::Sender")]
        reply: sync::oneshot::Sender<anyhow::Result<()>>,
    },
    Shutdown,
    Subscribe {
        namespace: NamespaceId,
        #[debug("sender")]
        sender: flume::Sender<Event>,
        #[debug("oneshot::Sender")]
        reply: sync::oneshot::Sender<Result<()>>,
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

    IncomingSyncReport {
        from: PublicKey,
        report: SyncReport,
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

/// Events informing about actions of the live sync progress.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, strum::Display)]
pub enum Event {
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

type SyncConnectRes = (
    NamespaceId,
    PublicKey,
    SyncReason,
    Result<SyncFinished, ConnectError>,
);
type SyncAcceptRes = Result<SyncFinished, AcceptError>;

// Currently peers might double-sync in both directions.
pub struct LiveActor<B: iroh_bytes::store::Store> {
    /// Receiver for actor messages.
    inbox: mpsc::Receiver<ToLiveActor>,
    sync: SyncHandle,
    endpoint: MagicEndpoint,
    gossip: Gossip,
    bao_store: B,
    downloader: Downloader,
    replica_events_tx: flume::Sender<iroh_sync::Event>,
    replica_events_rx: flume::Receiver<iroh_sync::Event>,

    /// Send messages to self.
    /// Note: Must not be used in methods called from `Self::run` directly to prevent deadlocks.
    /// Only clone into newly spawned tasks.
    sync_actor_tx: mpsc::Sender<ToLiveActor>,
    gossip_actor_tx: mpsc::Sender<ToGossipActor>,

    /// Running sync futures (from connect).
    running_sync_connect: JoinSet<SyncConnectRes>,
    /// Running sync futures (from accept).
    running_sync_accept: JoinSet<SyncAcceptRes>,
    /// Running download futures.
    pending_downloads: JoinSet<Option<(NamespaceId, Hash)>>,

    /// Subscribers to actor events
    subscribers: SubscribersMap,

    /// Sync state per replica and peer
    state: NamespaceStates,
}
impl<B: iroh_bytes::store::Store> LiveActor<B> {
    /// Create the live actor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sync: SyncHandle,
        endpoint: MagicEndpoint,
        gossip: Gossip,
        bao_store: B,
        downloader: Downloader,
        inbox: mpsc::Receiver<ToLiveActor>,
        sync_actor_tx: mpsc::Sender<ToLiveActor>,
        gossip_actor_tx: mpsc::Sender<ToGossipActor>,
    ) -> Self {
        let (replica_events_tx, replica_events_rx) = flume::bounded(1024);
        Self {
            inbox,
            sync,
            replica_events_rx,
            replica_events_tx,
            endpoint,
            gossip,
            bao_store,
            downloader,
            sync_actor_tx,
            gossip_actor_tx,
            running_sync_connect: Default::default(),
            running_sync_accept: Default::default(),
            subscribers: Default::default(),
            pending_downloads: Default::default(),
            state: Default::default(),
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
                event = self.replica_events_rx.recv_async() => {
                    trace!(?i, "tick: replica_event");
                    let event = event.context("replica_events closed")?;
                    if let Err(err) = self.on_replica_event(event).await {
                        error!(?err, "Failed to process replica event");
                    }
                }
                Some(res) = self.running_sync_connect.join_next(), if !self.running_sync_connect.is_empty() => {
                    trace!(?i, "tick: running_sync_connect");
                    let (namespace, peer, reason, res) = res.context("running_sync_connect closed")?;
                    self.on_sync_via_connect_finished(namespace, peer, reason, res).await;

                }
                Some(res) = self.running_sync_accept.join_next(), if !self.running_sync_accept.is_empty() => {
                    trace!(?i, "tick: running_sync_accept");
                    let res = res.context("running_sync_accept closed")?;
                    self.on_sync_via_accept_finished(res).await;
                }
                Some(res) = self.pending_downloads.join_next(), if !self.pending_downloads.is_empty() => {
                    trace!(?i, "tick: pending_downloads");
                    let res = res.context("pending_downloads closed")?;
                    if let Some((namespace, hash)) = res {
                        self.subscribers.send(&namespace, Event::ContentReady { hash }).await;
                        // Inform our neighbors that we have new content ready.
                        self.broadcast_neighbors(namespace, &Op::ContentReady(hash)).await;
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
            ToLiveActor::IncomingSyncReport { from, report } => {
                self.on_sync_report(from, report).await
            }
            ToLiveActor::NeighborUp { namespace, peer } => {
                debug!(peer = %peer.fmt_short(), namespace = %namespace.fmt_short(), "neighbor up");
                self.sync_with_peer(namespace, peer, SyncReason::NewNeighbor);
                self.subscribers
                    .send(&namespace, Event::NeighborUp(peer))
                    .await;
            }
            ToLiveActor::NeighborDown { namespace, peer } => {
                debug!(peer = %peer.fmt_short(), namespace = %namespace.fmt_short(), "neighbor down");
                self.subscribers
                    .send(&namespace, Event::NeighborDown(peer))
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
                kill_subscribers,
                reply,
            } => {
                let res = self.leave(namespace, kill_subscribers).await;
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
                sender,
                reply,
            } => {
                self.subscribers.subscribe(namespace, sender);
                reply.send(Ok(())).ok();
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

    #[instrument("connect", skip_all, fields(peer = %peer.fmt_short(), namespace = %namespace.fmt_short()))]
    fn sync_with_peer(&mut self, namespace: NamespaceId, peer: PublicKey, reason: SyncReason) {
        if !self.state.start_connect(&namespace, peer, reason) {
            return;
        }
        let endpoint = self.endpoint.clone();
        let sync = self.sync.clone();
        let fut = async move {
            let res = connect_and_sync(&endpoint, &sync, namespace, NodeAddr::new(peer)).await;
            (namespace, peer, reason, res)
        }
        .instrument(Span::current());
        self.running_sync_connect.spawn(fut);
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        // cancel all subscriptions
        self.subscribers.clear();
        // shutdown gossip actor
        self.gossip_actor_tx
            .send(ToGossipActor::Shutdown)
            .await
            .ok();
        // shutdown sync thread
        self.sync.shutdown().await;
        Ok(())
    }

    async fn start_sync(&mut self, namespace: NamespaceId, mut peers: Vec<NodeAddr>) -> Result<()> {
        // update state to allow sync
        if !self.state.is_syncing(&namespace) {
            let opts = OpenOpts::default()
                .sync()
                .subscribe(self.replica_events_tx.clone());
            self.sync.open(namespace, opts).await?;
            self.state.insert(namespace);
        }
        // add the peers stored for this document
        match self.sync.get_sync_peers(namespace).await {
            Ok(None) => {
                // no peers for this document
            }
            Ok(Some(known_useful_peers)) => {
                let as_node_addr = known_useful_peers.into_iter().filter_map(|peer_id_bytes| {
                    // peers are stored as bytes, don't fail the operation if they can't be
                    // decoded: simply ignore the peer
                    match PublicKey::from_bytes(&peer_id_bytes) {
                        Ok(public_key) => Some(NodeAddr::new(public_key)),
                        Err(_signing_error) => {
                            warn!("potential db corruption: peers per doc can't be decoded");
                            None
                        }
                    }
                });
                peers.extend(as_node_addr);
            }
            Err(e) => {
                // try to continue if peers per doc can't be read since they are not vital for sync
                warn!(%e, "db error reading peers per document")
            }
        }
        self.join_peers(namespace, peers).await?;
        Ok(())
    }

    async fn leave(
        &mut self,
        namespace: NamespaceId,
        kill_subscribers: bool,
    ) -> anyhow::Result<()> {
        // self.subscribers.remove(&namespace);
        if self.state.remove(&namespace) {
            self.sync.set_sync(namespace, false).await?;
            self.sync
                .unsubscribe(namespace, self.replica_events_tx.clone())
                .await?;
            self.sync.close(namespace).await?;
            self.gossip_actor_tx
                .send(ToGossipActor::Leave { namespace })
                .await
                .context("gossip actor failure")?;
        }
        if kill_subscribers {
            self.subscribers.remove(&namespace);
        }
        Ok(())
    }

    async fn join_peers(
        &mut self,
        namespace: NamespaceId,
        peers: Vec<NodeAddr>,
    ) -> anyhow::Result<()> {
        let peer_ids: Vec<PublicKey> = peers.iter().map(|p| p.node_id).collect();

        // add addresses of peers to our endpoint address book
        for peer in peers.into_iter() {
            let peer_id = peer.node_id;
            if let Err(err) = self.endpoint.add_node_addr(peer) {
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
    ) {
        match result {
            Err(ConnectError::RemoteAbort(AbortReason::AlreadySyncing)) => {
                debug!(?reason, "remote abort, already syncing");
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
    async fn on_sync_via_accept_finished(&mut self, res: Result<SyncFinished, AcceptError>) {
        match res {
            Ok(state) => {
                self.on_sync_finished(state.namespace, state.peer, Origin::Accept, Ok(state))
                    .await
            }
            Err(AcceptError::Abort { reason, .. }) if reason == AbortReason::AlreadySyncing => {
                // In case we aborted the sync: do nothing (our outgoing sync is in progress)
                debug!(?reason, "aborted by us");
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
                    debug!(?err, "failed before reading the first message");
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
    ) {
        match &result {
            Err(ref err) => {
                warn!(?origin, ?err, "sync failed");
            }
            Ok(ref details) => {
                info!(
                    sent = %details.outcome.num_sent,
                    recv = %details.outcome.num_recv,
                    t_connect = ?details.timings.connect,
                    t_process = ?details.timings.process,
                    "sync finished",
                );

                // register the peer as useful for the document
                if let Err(e) = self
                    .sync
                    .register_useful_peer(namespace, *peer.as_bytes())
                    .await
                {
                    debug!(%e, "failed to register peer for document")
                }

                // broadcast a sync report to our neighbors, but only if we received new entries.
                if details.outcome.num_recv > 0 {
                    info!("broadcast sync report to neighbors");
                    match details
                        .outcome
                        .heads_received
                        .encode(Some(iroh_gossip::net::MAX_MESSAGE_SIZE))
                    {
                        Err(err) => warn!(?err, "Failed to encode author heads for sync report"),
                        Ok(heads) => {
                            let report = SyncReport { namespace, heads };
                            self.broadcast_neighbors(namespace, &Op::SyncReport(report))
                                .await;
                        }
                    }
                }
            }
        };

        let result_for_event = match &result {
            Ok(_) => Ok(()),
            Err(err) => Err(err.to_string()),
        };

        let Some((started, resync)) = self.state.finish(&namespace, peer, &origin, result) else {
            return;
        };

        let ev = SyncEvent {
            peer,
            origin,
            result: result_for_event,
            finished: SystemTime::now(),
            started,
        };
        self.subscribers
            .send(&namespace, Event::SyncFinished(ev))
            .await;

        if resync {
            self.sync_with_peer(namespace, peer, SyncReason::Resync);
        }
    }

    async fn broadcast_neighbors(&self, namespace: NamespaceId, op: &Op) {
        if !self.state.is_syncing(&namespace) {
            return;
        }

        let msg = match postcard::to_stdvec(op) {
            Ok(msg) => msg,
            Err(err) => {
                error!(?err, ?op, "Failed to serialize message:");
                return;
            }
        };
        // TODO: We should debounce and merge these neighbor announcements likely.
        if let Err(err) = self
            .gossip
            .broadcast_neighbors(namespace.into(), msg.into())
            .await
        {
            error!(
                namespace = %namespace.fmt_short(),
                %op,
                ?err,
                "Failed to broadcast to neighbors"
            );
        }
    }

    #[instrument("on_sync_report", skip_all, fields(peer = %from.fmt_short(), namespace = %report.namespace.fmt_short()))]
    async fn on_sync_report(&mut self, from: PublicKey, report: SyncReport) {
        let namespace = report.namespace;
        if !self.state.is_syncing(&namespace) {
            return;
        }
        let heads = match AuthorHeads::decode(&report.heads) {
            Ok(heads) => heads,
            Err(err) => {
                warn!(?err, "failed to decode AuthorHeads");
                return;
            }
        };
        match self.sync.has_news_for_us(report.namespace, heads).await {
            Ok(Some(updated_authors)) => {
                info!(%updated_authors, "news reported: sync now");
                self.sync_with_peer(report.namespace, from, SyncReason::SyncReport);
            }
            Ok(None) => {
                debug!("no news reported: nothing to do");
            }
            Err(err) => {
                warn!("sync actor error: {err:?}");
            }
        }
    }

    async fn on_replica_event(&mut self, event: iroh_sync::Event) -> Result<()> {
        match event {
            iroh_sync::Event::LocalInsert { namespace, entry } => {
                let topic = TopicId::from_bytes(*namespace.as_bytes());
                // A new entry was inserted locally. Broadcast a gossip message.
                if self.state.is_syncing(&namespace) {
                    let op = Op::Put(entry.clone());
                    let message = postcard::to_stdvec(&op)?.into();
                    self.gossip.broadcast(topic, message).await?;
                }
            }
            iroh_sync::Event::RemoteInsert {
                namespace,
                entry,
                from,
                should_download,
                remote_content_status,
            } => {
                // A new entry was inserted from initial sync or gossip. Queue downloading the
                // content.
                let hash = entry.content_hash();
                let entry_status = self.bao_store.entry_status(&hash);
                // TODO: Make downloads configurable.
                if matches!(entry_status, EntryStatus::NotFound | EntryStatus::Partial)
                    && should_download
                {
                    let from = PublicKey::from_bytes(&from)?;
                    let role = match remote_content_status {
                        ContentStatus::Complete => Role::Provider,
                        _ => Role::Candidate,
                    };
                    let handle = self
                        .downloader
                        .queue(DownloadKind::Blob { hash }, vec![(from, role).into()])
                        .await;

                    self.pending_downloads.spawn(async move {
                        // NOTE: this ignores the result for now, simply keeping the option
                        let res = handle.await.ok();
                        res.map(|_| (namespace, hash))
                    });
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
        self.running_sync_accept
            .spawn(async move { handle_connection(sync, conn, accept_request_cb).await });
    }

    pub fn accept_sync_request(
        &mut self,
        namespace: NamespaceId,
        peer: PublicKey,
    ) -> AcceptOutcome {
        self.state
            .accept_request(&self.endpoint.node_id(), &namespace, peer)
    }
}

/// Event emitted when a sync operation completes
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SyncEvent {
    /// Peer we synced with
    pub peer: PublicKey,
    /// Origin of the sync exchange
    pub origin: Origin,
    /// Timestamp when the sync started
    pub finished: SystemTime,
    /// Timestamp when the sync finished
    pub started: SystemTime,
    /// Result of the sync operation
    pub result: std::result::Result<(), String>,
}

#[derive(Debug, Default)]
struct SubscribersMap(HashMap<NamespaceId, Subscribers>);

impl SubscribersMap {
    fn subscribe(&mut self, namespace: NamespaceId, sender: flume::Sender<Event>) {
        self.0.entry(namespace).or_default().subscribe(sender);
    }

    async fn send(&mut self, namespace: &NamespaceId, event: Event) -> bool {
        let Some(subscribers) = self.0.get_mut(namespace) else {
            return false;
        };

        if !subscribers.send(event).await {
            self.0.remove(namespace);
        }
        true
    }

    fn remove(&mut self, namespace: &NamespaceId) {
        self.0.remove(namespace);
    }

    fn clear(&mut self) {
        self.0.clear();
    }
}

#[derive(Debug, Default)]
struct Subscribers(Vec<flume::Sender<Event>>);

impl Subscribers {
    fn subscribe(&mut self, sender: flume::Sender<Event>) {
        self.0.push(sender)
    }

    async fn send(&mut self, event: Event) -> bool {
        let futs = self.0.iter().map(|sender| sender.send_async(event.clone()));
        let res = futures::future::join_all(futs).await;
        // reverse the order so removing does not shift remaining indices
        for (i, res) in res.into_iter().enumerate().rev() {
            if res.is_err() {
                self.0.remove(i);
            }
        }
        !self.0.is_empty()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_remove() {
        let pk = PublicKey::from_bytes(&[1; 32]).unwrap();
        let (a_tx, a_rx) = flume::unbounded();
        let (b_tx, b_rx) = flume::unbounded();
        let mut subscribers = Subscribers::default();
        subscribers.subscribe(a_tx);
        subscribers.subscribe(b_tx);
        drop(a_rx);
        drop(b_rx);
        subscribers.send(Event::NeighborUp(pk)).await;
    }
}
