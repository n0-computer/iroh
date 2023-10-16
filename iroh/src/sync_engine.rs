//! Handlers and actors to for live syncing [`iroh_sync`] replicas.
//!
//! [`iroh_sync::Replica`] is also called documents here.

use std::sync::Arc;

use anyhow::Result;
use futures::{
    future::{BoxFuture, FutureExt, Shared},
    Stream, TryStreamExt,
};
use iroh_bytes::{store::EntryStatus, util::runtime::Handle, Hash};
use iroh_gossip::net::Gossip;
use iroh_net::{key::PublicKey, MagicEndpoint, PeerAddr};
use iroh_sync::{
    actor::SyncHandle, store::Store, sync::NamespaceId, ContentStatus, ContentStatusCallback,
    Entry, InsertOrigin,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tracing::{error, error_span, Instrument};

use crate::downloader::Downloader;

mod gossip;
mod live;
pub mod rpc;

use gossip::GossipActor;
use live::{LiveActor, ToLiveActor};

pub use self::live::{Origin, SyncEvent};
pub use iroh_sync::net::SYNC_ALPN;

/// Capacity of the channel for the [`ToLiveActor`] messages.
const ACTOR_CHANNEL_CAP: usize = 64;
/// Capacity for the channels for [`SyncEngine::subscribe`].
const SUBSCRIBE_CHANNEL_CAP: usize = 256;

/// The SyncEngine contains the [`LiveActor`] handle, and keeps a copy of the store and endpoint.
///
/// The RPC methods dealing with documents and sync operate on the `SyncEngine`, with method
/// implementations in [rpc].
#[derive(derive_more::Debug, Clone)]
pub struct SyncEngine<S: Store> {
    pub(crate) rt: Handle,
    pub(crate) endpoint: MagicEndpoint,
    pub(crate) sync: SyncHandle,
    to_live_actor: mpsc::Sender<ToLiveActor>,
    tasks_fut: Shared<BoxFuture<'static, ()>>,
    #[debug("ContentStatusCallback")]
    content_status_cb: ContentStatusCallback,

    // TODO:
    // After the latest refactoring we don't need the store here anymore because all interactions
    // go over the [`SyncHandle`]. Removing the store removes the `S: Store` generic from the
    // `SyncEngine`, in turn removing the `S: Store` generic from [`iroh::node::Node`]. Yay!
    // As this changes the code in many lines, I'd defer it to a follwup.
    _store: S,
}

impl<S: Store> SyncEngine<S> {
    /// Start the sync engine.
    ///
    /// This will spawn background tasks for the [`LiveActor`] and [`GossipActor`],
    /// and a background thread for the [`SyncHandle`].
    pub fn spawn<B: iroh_bytes::store::Store>(
        rt: Handle,
        endpoint: MagicEndpoint,
        gossip: Gossip,
        replica_store: S,
        bao_store: B,
        downloader: Downloader,
    ) -> Self {
        let (live_actor_tx, to_live_actor_recv) = mpsc::channel(ACTOR_CHANNEL_CAP);
        let (to_gossip_actor, to_gossip_actor_recv) = mpsc::channel(ACTOR_CHANNEL_CAP);
        let me = endpoint.peer_id().fmt_short();

        let content_status_cb = {
            let bao_store = bao_store.clone();
            Arc::new(move |hash| entry_to_content_status(bao_store.contains(&hash)))
        };
        let sync = SyncHandle::spawn(
            replica_store.clone(),
            Some(content_status_cb.clone()),
            me.clone(),
        );

        let mut actor = LiveActor::new(
            sync.clone(),
            endpoint.clone(),
            gossip.clone(),
            bao_store,
            downloader.clone(),
            to_live_actor_recv,
            live_actor_tx.clone(),
            to_gossip_actor,
        );
        let mut gossip_actor = GossipActor::new(
            to_gossip_actor_recv,
            sync.clone(),
            gossip,
            downloader,
            live_actor_tx.clone(),
        );
        let live_actor_task = rt.main().spawn(
            async move {
                if let Err(err) = actor.run().await {
                    error!("sync actor failed: {err:?}");
                }
            }
            .instrument(error_span!("sync", %me)),
        );
        let gossip_actor_task = rt.main().spawn(
            async move {
                if let Err(err) = gossip_actor.run().await {
                    error!("gossip recv actor failed: {err:?}");
                }
            }
            .instrument(error_span!("sync", %me)),
        );
        let tasks_fut = async move {
            if let Err(err) = live_actor_task.await {
                error!("Error while joining actor task: {err:?}");
            }
            gossip_actor_task.abort();
            if let Err(err) = gossip_actor_task.await {
                if !err.is_cancelled() {
                    error!("Error while joining gossip recv task task: {err:?}");
                }
            }
        }
        .boxed()
        .shared();

        Self {
            rt,
            endpoint,
            sync,
            to_live_actor: live_actor_tx,
            tasks_fut,
            content_status_cb,
            _store: replica_store,
        }
    }

    /// Start to sync a document.
    ///
    /// If `peers` is non-empty, it will both do an initial set-reconciliation sync with each peer,
    /// and join an iroh-gossip swarm with these peers to receive and broadcast document updates.
    pub async fn start_sync(&self, namespace: NamespaceId, peers: Vec<PeerAddr>) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.to_live_actor
            .send(ToLiveActor::StartSync {
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
        let (reply, reply_rx) = oneshot::channel();
        self.to_live_actor
            .send(ToLiveActor::JoinPeers {
                namespace,
                peers,
                reply,
            })
            .await?;
        reply_rx.await??;
        Ok(())
    }

    /// Stop the live sync for a document and leave the gossip swarm.
    ///
    /// If `kill_subscribers` is true, all existing event subscribers will be dropped. This means
    /// they will receive `None` and no further events in case of rejoining the document.
    pub async fn leave(&self, namespace: NamespaceId, kill_subscribers: bool) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.to_live_actor
            .send(ToLiveActor::Leave {
                namespace,
                kill_subscribers,
                reply,
            })
            .await?;
        reply_rx.await??;
        Ok(())
    }

    /// Subscribe to replica and sync progress events.
    pub fn subscribe(
        &self,
        namespace: NamespaceId,
    ) -> impl Stream<Item = Result<LiveEvent>> + Unpin + 'static {
        let content_status_cb = self.content_status_cb.clone();

        // Create a future that sends channel senders to the respective actors.
        // We clone `self` so that the future does not capture any lifetimes.
        let this = self.clone();
        let fut = async move {
            // Subscribe to insert events from the replica.
            let replica_events = {
                let (s, r) = flume::bounded(SUBSCRIBE_CHANNEL_CAP);
                this.sync.subscribe(namespace, s).await?;
                r.into_stream()
                    .map(move |ev| Ok(LiveEvent::from_replica_event(ev, &content_status_cb)))
            };

            // Subscribe to events from the [`live::Actor`].
            let sync_events = {
                let (s, r) = flume::bounded(SUBSCRIBE_CHANNEL_CAP);
                let (reply, reply_rx) = oneshot::channel();
                this.to_live_actor
                    .send(ToLiveActor::Subscribe {
                        namespace,
                        sender: s,
                        reply,
                    })
                    .await?;
                reply_rx.await??;
                r.into_stream().map(|event| Ok(LiveEvent::from(event)))
            };

            // Merge the two receivers into a single stream.
            let stream = replica_events.merge(sync_events);
            // We need type annotations for the error type here.
            Result::<_, anyhow::Error>::Ok(stream)
        };

        // Flatten the future into a single stream. If the future errors, the error will be
        // returned from the first call to [`Stream::next`].
        // We first pin the future so that the resulting stream is `Unpin`.
        Box::pin(fut).into_stream().try_flatten()
    }

    /// Handle an incoming iroh-sync connection.
    pub async fn handle_connection(&self, conn: quinn::Connecting) -> anyhow::Result<()> {
        self.to_live_actor
            .send(ToLiveActor::HandleConnection { conn })
            .await?;
        Ok(())
    }

    /// Shutdown the sync engine.
    pub async fn shutdown(&self) -> Result<()> {
        self.to_live_actor.send(ToLiveActor::Shutdown).await?;
        self.tasks_fut.clone().await;
        Ok(())
    }
}

pub(crate) fn entry_to_content_status(entry: EntryStatus) -> ContentStatus {
    match entry {
        EntryStatus::Complete => ContentStatus::Complete,
        EntryStatus::Partial => ContentStatus::Incomplete,
        EntryStatus::NotFound => ContentStatus::Missing,
    }
}

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

impl From<live::Event> for LiveEvent {
    fn from(ev: live::Event) -> Self {
        match ev {
            live::Event::ContentReady { hash } => Self::ContentReady { hash },
            live::Event::NeighborUp(peer) => Self::NeighborUp(peer),
            live::Event::NeighborDown(peer) => Self::NeighborDown(peer),
            live::Event::SyncFinished(ev) => Self::SyncFinished(ev),
        }
    }
}

impl LiveEvent {
    fn from_replica_event(ev: iroh_sync::Event, content_status_cb: &ContentStatusCallback) -> Self {
        match ev {
            iroh_sync::Event::Insert { origin, entry, .. } => match origin {
                InsertOrigin::Local => Self::InsertLocal {
                    entry: entry.into(),
                },
                InsertOrigin::Sync { from, .. } => Self::InsertRemote {
                    content_status: content_status_cb(entry.content_hash()),
                    entry: entry.into(),
                    // TODO: unwrap
                    from: PublicKey::from_bytes(&from).unwrap(),
                },
            },
        }
    }
}
