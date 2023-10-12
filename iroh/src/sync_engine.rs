//! Handlers and actors to for live syncing [`iroh_sync`] replicas.
//!
//! [`iroh_sync::Replica`] is also called documents here.

use std::sync::Arc;

use anyhow::Result;
use futures::future::{BoxFuture, FutureExt, Shared};
use iroh_bytes::{
    baomap::{EntryStatus, Store as BaoStore},
    util::runtime::Handle,
};
use iroh_gossip::net::Gossip;
use iroh_net::{MagicEndpoint, PeerAddr};
use iroh_sync::{actor::SyncHandle, store::Store, sync::NamespaceId, ContentStatus};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, error_span, Instrument};

use crate::downloader::Downloader;

mod gossip;
mod live;
pub mod rpc;

use gossip::GossipActor;
use live::{LiveActor, ToLiveActor};

pub use self::live::{KeepCallback, LiveEvent, SyncEvent, LiveStatus, Origin, RemovalToken};
pub use iroh_sync::net::SYNC_ALPN;

/// Capacity of the channel for the [`toLiveActor`] messages.
const ACTOR_CHANNEL_CAP: usize = 64;

/// The SyncEngine contains the [`LiveSync`] handle, and keeps a copy of the store and endpoint.
///
/// The RPC methods dealing with documents and sync operate on the `SyncEngine`, with method
/// implementations in [rpc].
#[derive(Debug, Clone)]
pub struct SyncEngine<S: Store> {
    pub(crate) rt: Handle,
    pub(crate) endpoint: MagicEndpoint,
    pub(crate) sync: SyncHandle,
    live_actor_tx: mpsc::Sender<ToLiveActor>,
    actors_task_fut: Shared<BoxFuture<'static, ()>>,

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
    /// This will spawn a background task for the [`LiveSync`]. When documents are added to the
    /// engine with [`Self::start_sync`], then new entries inserted locally will be sent to peers
    /// through iroh-gossip.
    ///
    /// The engine will also subscribe to replica events to download content for new
    /// entries from peers.
    pub fn spawn<B: BaoStore>(
        rt: Handle,
        endpoint: MagicEndpoint,
        gossip: Gossip,
        replica_store: S,
        bao_store: B,
        downloader: Downloader,
    ) -> Self {
        let (live_actor_tx, live_actor_rx) = mpsc::channel(ACTOR_CHANNEL_CAP);
        let (gossip_actor_tx, gossip_actor_rx) = mpsc::channel(ACTOR_CHANNEL_CAP);
        let me = endpoint.peer_id().fmt_short();

        let content_status_cb = {
            let bao_store = bao_store.clone();
            Arc::new(move |hash| entry_to_content_status(bao_store.contains(&hash)))
        };
        let (sync, sync_events) =
            SyncHandle::spawn(replica_store.clone(), Some(content_status_cb), me.clone());

        let mut actor = LiveActor::new(
            sync.clone(),
            sync_events,
            endpoint.clone(),
            gossip.clone(),
            bao_store,
            downloader.clone(),
            live_actor_rx,
            live_actor_tx.clone(),
            gossip_actor_tx,
        );
        let mut gossip_actor = GossipActor::new(
            gossip_actor_rx,
            sync.clone(),
            gossip,
            downloader,
            live_actor_tx.clone(),
        );
        let actor_task = rt.main().spawn(
            async move {
                if let Err(err) = actor.run().await {
                    error!("sync actor failed: {err:?}");
                }
            }
            .instrument(error_span!("sync", %me)),
        );
        let gossip_recv_task = rt.main().spawn(
            async move {
                if let Err(err) = gossip_actor.run().await {
                    error!("gossip recv actor failed: {err:?}");
                }
            }
            .instrument(error_span!("sync", %me)),
        );
        let actors_task_fut = async move {
            if let Err(err) = actor_task.await {
                error!("Error while joining actor task: {err:?}");
            }
            gossip_recv_task.abort();
            if let Err(err) = gossip_recv_task.await {
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
            live_actor_tx,
            actors_task_fut,
            _store: replica_store,
        }
    }

    /// Start to sync a document.
    ///
    /// If `peers` is non-empty, it will both do an initial set-reconciliation sync with each peer,
    /// and join an iroh-gossip swarm with these peers to receive and broadcast document updates.
    pub async fn start_sync(&self, namespace: NamespaceId, peers: Vec<PeerAddr>) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.live_actor_tx
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
        self.live_actor_tx
            .send(ToLiveActor::JoinPeers { namespace, peers })
            .await?;
        Ok(())
    }

    /// Stop the live sync for a document.
    ///
    /// This will leave the gossip swarm for this document.
    pub async fn leave(&self, namespace: NamespaceId, force_remove: bool) -> Result<()> {
        self.live_actor_tx
            .send(ToLiveActor::Leave {
                namespace,
                force_remove,
            })
            .await?;
        Ok(())
    }

    /// Subscribes `cb` to events on this `namespace`.
    pub async fn subscribe<F>(&self, namespace: NamespaceId, cb: F) -> Result<RemovalToken>
    where
        F: Fn(LiveEvent) -> BoxFuture<'static, KeepCallback> + Send + Sync + 'static,
    {
        let (s, r) = oneshot::channel();
        self.live_actor_tx
            .send(ToLiveActor::Subscribe {
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
        let (s, r) = oneshot::channel();
        self.live_actor_tx
            .send(ToLiveActor::Unsubscribe {
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
        let (s, r) = oneshot::channel();
        self.live_actor_tx
            .send(ToLiveActor::Status { namespace, s })
            .await?;
        let status = r.await?;
        Ok(status)
    }

    /// Handle an incoming iroh-sync connection.
    pub async fn handle_connection(&self, conn: quinn::Connecting) -> anyhow::Result<()> {
        self.live_actor_tx
            .send(ToLiveActor::HandleConnection { conn })
            .await?;
        Ok(())
    }

    /// Shutdown the sync engine.
    pub async fn shutdown(&self) -> Result<()> {
        self.live_actor_tx.send(ToLiveActor::Shutdown).await?;
        self.actors_task_fut.clone().await;
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
