//! Handlers and actors to for live syncing [`iroh_docs`] replicas.
//!
//! [`iroh_docs::Replica`] is also called documents here.

use std::path::PathBuf;
use std::{
    io,
    str::FromStr,
    sync::{Arc, RwLock},
};

use anyhow::{bail, Context, Result};
use futures_lite::{Stream, StreamExt};
use iroh_blobs::downloader::Downloader;
use iroh_blobs::{store::EntryStatus, Hash};
use iroh_docs::{actor::SyncHandle, ContentStatus, ContentStatusCallback, Entry, NamespaceId};
use iroh_docs::{Author, AuthorId};
use iroh_gossip::net::Gossip;
use iroh_net::util::SharedAbortingJoinHandle;
use iroh_net::{key::PublicKey, Endpoint, NodeAddr};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, error_span, Instrument};

mod gossip;
mod live;
pub mod rpc;
mod state;

use gossip::GossipActor;
use live::{LiveActor, ToLiveActor};

pub use self::live::SyncEvent;
pub use self::state::{Origin, SyncReason};

/// Capacity of the channel for the [`ToLiveActor`] messages.
const ACTOR_CHANNEL_CAP: usize = 64;
/// Capacity for the channels for [`Engine::subscribe`].
const SUBSCRIBE_CHANNEL_CAP: usize = 256;

/// The sync engine coordinates actors that manage open documents, set-reconciliation syncs with
/// peers and a gossip swarm for each syncing document.
///
/// The RPC methods dealing with documents and sync operate on the `Engine`, with method
/// implementations in [rpc].
#[derive(derive_more::Debug, Clone)]
pub struct Engine {
    pub(crate) endpoint: Endpoint,
    pub(crate) sync: SyncHandle,
    to_live_actor: mpsc::Sender<ToLiveActor>,
    #[allow(dead_code)]
    actor_handle: SharedAbortingJoinHandle<()>,
    #[debug("ContentStatusCallback")]
    content_status_cb: ContentStatusCallback,
    default_author: Arc<DefaultAuthor>,
}

impl Engine {
    /// Start the sync engine.
    ///
    /// This will spawn two tokio tasks for the live sync coordination and gossip actors, and a
    /// thread for the [`iroh_docs::actor::SyncHandle`].
    pub(crate) async fn spawn<B: iroh_blobs::store::Store>(
        endpoint: Endpoint,
        gossip: Gossip,
        replica_store: iroh_docs::store::Store,
        bao_store: B,
        downloader: Downloader,
        default_author_storage: DefaultAuthorStorage,
    ) -> anyhow::Result<Self> {
        let (live_actor_tx, to_live_actor_recv) = mpsc::channel(ACTOR_CHANNEL_CAP);
        let (to_gossip_actor, to_gossip_actor_recv) = mpsc::channel(ACTOR_CHANNEL_CAP);
        let me = endpoint.node_id().fmt_short();

        let content_status_cb = {
            let bao_store = bao_store.clone();
            Arc::new(move |hash| entry_to_content_status(bao_store.entry_status_sync(&hash)))
        };
        let sync = SyncHandle::spawn(replica_store, Some(content_status_cb.clone()), me.clone());

        let mut actor = LiveActor::new(
            sync.clone(),
            endpoint.clone(),
            gossip.clone(),
            bao_store,
            downloader,
            to_live_actor_recv,
            live_actor_tx.clone(),
            to_gossip_actor,
        );
        let gossip_actor = GossipActor::new(
            to_gossip_actor_recv,
            sync.clone(),
            gossip,
            live_actor_tx.clone(),
        );
        let actor_handle = tokio::task::spawn(
            async move {
                if let Err(err) = actor.run(gossip_actor).await {
                    error!("sync actor failed: {err:?}");
                }
            }
            .instrument(error_span!("sync", %me)),
        );

        let default_author = match DefaultAuthor::load(default_author_storage, &sync).await {
            Ok(author) => author,
            Err(err) => {
                // If loading the default author failed, make sure to shutdown the sync actor before
                // returning.
                sync.shutdown().await?;
                return Err(err);
            }
        };

        Ok(Self {
            endpoint,
            sync,
            to_live_actor: live_actor_tx,
            actor_handle: actor_handle.into(),
            content_status_cb,
            default_author: Arc::new(default_author),
        })
    }

    /// Start to sync a document.
    ///
    /// If `peers` is non-empty, it will both do an initial set-reconciliation sync with each peer,
    /// and join an iroh-gossip swarm with these peers to receive and broadcast document updates.
    async fn start_sync(&self, namespace: NamespaceId, peers: Vec<NodeAddr>) -> Result<()> {
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

    /// Stop the live sync for a document and leave the gossip swarm.
    ///
    /// If `kill_subscribers` is true, all existing event subscribers will be dropped. This means
    /// they will receive `None` and no further events in case of rejoining the document.
    async fn leave(&self, namespace: NamespaceId, kill_subscribers: bool) -> Result<()> {
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
    async fn subscribe(
        &self,
        namespace: NamespaceId,
    ) -> Result<impl Stream<Item = Result<LiveEvent>> + Unpin + 'static> {
        let content_status_cb = self.content_status_cb.clone();

        // Create a future that sends channel senders to the respective actors.
        // We clone `self` so that the future does not capture any lifetimes.
        let this = self.clone();

        // Subscribe to insert events from the replica.
        let a = {
            let (s, r) = flume::bounded(SUBSCRIBE_CHANNEL_CAP);
            this.sync.subscribe(namespace, s).await?;
            r.into_stream()
                .map(move |ev| LiveEvent::from_replica_event(ev, &content_status_cb))
        };

        // Subscribe to events from the [`live::Actor`].
        let b = {
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

        Ok(a.or(b))
    }

    /// Handle an incoming iroh-docs connection.
    pub(super) async fn handle_connection(
        &self,
        conn: iroh_net::endpoint::Connecting,
    ) -> anyhow::Result<()> {
        self.to_live_actor
            .send(ToLiveActor::HandleConnection { conn })
            .await?;
        Ok(())
    }

    pub(crate) async fn start_shutdown(&self) -> Result<()> {
        self.to_live_actor.send(ToLiveActor::Shutdown).await?;
        Ok(())
    }
}

pub(crate) fn entry_to_content_status(entry: io::Result<EntryStatus>) -> ContentStatus {
    match entry {
        Ok(EntryStatus::Complete) => ContentStatus::Complete,
        Ok(EntryStatus::Partial) => ContentStatus::Incomplete,
        Ok(EntryStatus::NotFound) => ContentStatus::Missing,
        Err(cause) => {
            tracing::warn!("Error while checking entry status: {cause:?}");
            ContentStatus::Missing
        }
    }
}

/// Events informing about actions of the live sync progress.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, strum::Display)]
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
    /// All pending content is now ready.
    ///
    /// This event signals that all queued content downloads from the last sync run have either
    /// completed or failed.
    ///
    /// It will only be emitted after a [`Self::SyncFinished`] event, never before.
    ///
    /// Receiving this event does not guarantee that all content in the document is available. If
    /// blobs failed to download, this event will still be emitted after all operations completed.
    PendingContentReady,
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
            live::Event::PendingContentReady => Self::PendingContentReady,
        }
    }
}

impl LiveEvent {
    fn from_replica_event(
        ev: iroh_docs::Event,
        content_status_cb: &ContentStatusCallback,
    ) -> Result<Self> {
        Ok(match ev {
            iroh_docs::Event::LocalInsert { entry, .. } => Self::InsertLocal {
                entry: entry.into(),
            },
            iroh_docs::Event::RemoteInsert { entry, from, .. } => Self::InsertRemote {
                content_status: content_status_cb(entry.content_hash()),
                entry: entry.into(),
                from: PublicKey::from_bytes(&from)?,
            },
        })
    }
}

/// Where to persist the default author.
///
/// If set to `Mem`, a new author will be created in the docs store before spawning the sync
/// engine. Changing the default author will not be persisted.
///
/// If set to `Persistent`, the default author will be loaded from and persisted to the specified
/// path (as base32 encoded string of the author's public key).
#[derive(Debug)]
pub enum DefaultAuthorStorage {
    Mem,
    Persistent(PathBuf),
}

impl DefaultAuthorStorage {
    pub async fn load(&self, docs_store: &SyncHandle) -> anyhow::Result<AuthorId> {
        match self {
            Self::Mem => {
                let author = Author::new(&mut rand::thread_rng());
                let author_id = author.id();
                docs_store.import_author(author).await?;
                Ok(author_id)
            }
            Self::Persistent(ref path) => {
                if path.exists() {
                    let data = tokio::fs::read_to_string(path).await.with_context(|| {
                        format!(
                            "Failed to read the default author file at `{}`",
                            path.to_string_lossy()
                        )
                    })?;
                    let author_id = AuthorId::from_str(&data).with_context(|| {
                        format!(
                            "Failed to parse the default author from `{}`",
                            path.to_string_lossy()
                        )
                    })?;
                    if docs_store.export_author(author_id).await?.is_none() {
                        bail!("The default author is missing from the docs store. To recover, delete the file `{}`. Then iroh will create a new default author.", path.to_string_lossy())
                    }
                    Ok(author_id)
                } else {
                    let author = Author::new(&mut rand::thread_rng());
                    let author_id = author.id();
                    docs_store.import_author(author).await?;
                    self.persist(author_id).await?;
                    Ok(author_id)
                }
            }
        }
    }
    pub async fn persist(&self, author_id: AuthorId) -> anyhow::Result<()> {
        match self {
            Self::Mem => {
                // persistence is not possible for the mem storage so this is a noop.
            }
            Self::Persistent(ref path) => {
                tokio::fs::write(path, author_id.to_string())
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to write the default author to `{}`",
                            path.to_string_lossy()
                        )
                    })?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct DefaultAuthor {
    value: RwLock<AuthorId>,
    storage: DefaultAuthorStorage,
}

impl DefaultAuthor {
    async fn load(storage: DefaultAuthorStorage, docs_store: &SyncHandle) -> Result<Self> {
        let value = storage.load(docs_store).await?;
        Ok(Self {
            value: RwLock::new(value),
            storage,
        })
    }
    fn get(&self) -> AuthorId {
        *self.value.read().unwrap()
    }
    async fn set(&self, author_id: AuthorId, docs_store: &SyncHandle) -> Result<()> {
        if docs_store.export_author(author_id).await?.is_none() {
            bail!("The author does not exist");
        }
        self.storage.persist(author_id).await?;
        *self.value.write().unwrap() = author_id;
        Ok(())
    }
}
