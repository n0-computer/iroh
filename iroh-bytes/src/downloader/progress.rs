use std::{
    collections::HashMap,
    num::NonZeroU64,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::bail;
use futures::FutureExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{
    downloader::state::TransferId,
    get::db::DownloadProgress,
    protocol::RangeSpec,
    store::BaoBlobSize,
    util::progress::{IdGenerator, ProgressSendError, ProgressSender},
    Hash,
};

pub type ProgressSubscriber = flume::Sender<DownloadProgress>;
type ProgressId = u64;

/// Track the progress of transfers.
///
/// This struct allows to create [`ProgressSender`] structs to be passed to
/// [`crate::get::db::get_to_db`]. Each progress sender can be subscribed to by any number of
/// [`ProgressSubscriber`] channel senders, which will receive each progress update (if they have
/// capacity). Additionally, the [`ProgressTracker`] maintains a [`TransferState`] for each
/// transfer, applying each progress update to update this state. When subscribing to an already
/// running transfer, the subscriber will receive a [`DownloadProgress::InitialState`] message
/// containing the state at the time of the subscription, and then receive all further progress
/// events directly.
#[derive(Debug)]
pub struct ProgressTracker {
    transfers: HashMap<TransferId, TrackingProgressSender>,
    id_gen: Arc<AtomicU64>,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            transfers: Default::default(),
            id_gen: Default::default(),
        }
    }

    pub fn create(
        &mut self,
        transfer_id: TransferId,
        root_hash: Hash,
        subscribers: impl IntoIterator<Item = ProgressSubscriber>,
    ) -> TrackingProgressSender {
        let inner = TrackingProgressInner {
            subscribers: RwLock::new(subscribers.into_iter().collect()),
            state: RwLock::new(TransferState::new(root_hash)),
            id_gen: Arc::clone(&self.id_gen),
        };
        let sender = TrackingProgressSender(Arc::new(inner));
        self.transfers.insert(transfer_id, sender.clone());
        sender
    }

    pub async fn subscribe(
        &mut self,
        transfer_id: TransferId,
        sender: ProgressSubscriber,
    ) -> anyhow::Result<()> {
        let Some(tracker) = self.transfers.get_mut(&transfer_id) else {
            bail!("transfer {transfer_id} not found");
        };
        tracker.subscribe(sender).await?;
        Ok(())
    }

    pub fn remove(&mut self, transfer_id: TransferId) {
        self.transfers.remove(&transfer_id);
    }
}

#[derive(Debug, Clone)]
pub struct TrackingProgressSender(Arc<TrackingProgressInner>);

#[derive(Debug)]
struct TrackingProgressInner {
    subscribers: RwLock<Vec<ProgressSubscriber>>,
    state: RwLock<TransferState>,
    id_gen: Arc<AtomicU64>,
}

impl TrackingProgressSender {
    async fn subscribe(&self, sender: ProgressSubscriber) -> anyhow::Result<()> {
        self.0.subscribers.write().push(sender.clone());
        let initial_state = self.0.state.read().clone();
        sender
            .send_async(DownloadProgress::InitialState(initial_state))
            .await?;
        Ok(())
    }

    fn on_progress(&self, progress: DownloadProgress) {
        let mut state = self.0.state.write();
        state.on_progress(progress);
    }
}

impl IdGenerator for TrackingProgressSender {
    fn new_id(&self) -> u64 {
        self.0.id_gen.fetch_add(1, Ordering::SeqCst)
    }
}

impl ProgressSender for TrackingProgressSender {
    type Msg = DownloadProgress;

    type SendFuture<'a> =
        futures::future::BoxFuture<'a, std::result::Result<(), ProgressSendError>>;

    fn send(&self, msg: Self::Msg) -> Self::SendFuture<'_> {
        async move {
            // insert event into state
            self.on_progress(msg.clone());
            // send to subscribers
            let futs = {
                let subscribers = self.0.subscribers.read();
                subscribers
                    .iter()
                    .map(|s| s.clone().into_send_async(msg.clone()))
                    .collect::<Vec<_>>()
            };
            // TODO: handle errors
            let _ = futures::future::join_all(futs).await;
            Ok(())
        }
        .boxed()
    }

    fn try_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        // insert event into state
        self.on_progress(msg.clone());
        let subscribers = self.0.subscribers.read();
        for sender in subscribers.iter() {
            // TODO: remove sender from list on err? but must avoid deadlock
            sender.try_send(msg.clone()).ok();
        }
        Ok(())
    }

    fn blocking_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        // insert event into state
        self.on_progress(msg.clone());
        // we clone the subcribers because the blocking_send could otherwise hold the lock too long
        let subscribers = self.0.subscribers.read().clone();
        for sender in subscribers.iter() {
            // TODO: remove sender from list on error
            sender.send(msg.clone()).ok();
        }
        Ok(())
    }
}

/// Progress state of a transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferState {
    /// The root blob of this transfer (may be a hash seq),
    pub root: BlobState,
    /// Whether we are connected to a node
    pub connected: bool,
    /// Children if the root blob is a hash seq, empty for raw blobs
    pub children: HashMap<NonZeroU64, BlobState>,
    /// Child being transferred at the moment.
    pub current_blob: Option<BlobId>,
    /// Progress ids for individual blobs.
    pub progress_ids: HashMap<ProgressId, BlobId>,
}

impl TransferState {
    /// Create a new, empty transfer state.
    pub fn new(root_hash: Hash) -> Self {
        Self {
            root: BlobState::new(root_hash),
            connected: false,
            children: Default::default(),
            current_blob: None,
            progress_ids: Default::default(),
        }
    }
}

/// State of a single blob in transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobState {
    /// The hash of this blob.
    pub hash: Hash,
    /// The size of this blob. Only known if the blob is partially present locally, or after having
    /// received the size from the remote.
    pub size: Option<BaoBlobSize>,
    /// The current state of the blob transfer.
    pub progress: ProgressState,
    /// Ranges already available locally at the time of starting the transfer.
    pub local_ranges: Option<RangeSpec>,
    /// Number of children (only applies to hashseqs, None for raw blobs).
    pub child_count: Option<u64>,
}

/// Progress state for a single blob
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub enum ProgressState {
    /// Download is pending
    #[default]
    Pending,
    /// Download is in progress
    Progressing(u64),
    /// Download has finished
    Done,
}

impl BlobState {
    /// Create a new [`BlobState`].
    pub fn new(hash: Hash) -> Self {
        Self {
            hash,
            size: None,
            local_ranges: None,
            child_count: None,
            progress: ProgressState::default(),
        }
    }
}

impl TransferState {
    /// Get a blob state by its [`BlobId`] in this transfer.
    pub fn get_blob(&self, blob_id: &BlobId) -> Option<&BlobState> {
        match blob_id {
            BlobId::Root => Some(&self.root),
            BlobId::Child(id) => self.children.get(id),
        }
    }

    /// Get the blob state currently being transferred.
    pub fn get_current(&self) -> Option<&BlobState> {
        self.current_blob.as_ref().and_then(|id| self.get_blob(id))
    }

    fn get_or_insert_blob(&mut self, blob_id: BlobId, hash: Hash) -> &mut BlobState {
        match blob_id {
            BlobId::Root => &mut self.root,
            BlobId::Child(id) => self
                .children
                .entry(id)
                .or_insert_with(|| BlobState::new(hash)),
        }
    }
    fn get_blob_mut(&mut self, blob_id: &BlobId) -> Option<&mut BlobState> {
        match blob_id {
            BlobId::Root => Some(&mut self.root),
            BlobId::Child(id) => self.children.get_mut(&id),
        }
    }

    fn get_by_progress_id(&mut self, progress_id: ProgressId) -> Option<&mut BlobState> {
        let blob_id = *self.progress_ids.get(&progress_id)?;
        self.get_blob_mut(&blob_id)
    }

    /// Update the state with a new [`DownloadProgress`] event for this transfer.
    pub fn on_progress(&mut self, event: DownloadProgress) {
        match event {
            DownloadProgress::FoundLocal {
                child,
                hash,
                size,
                valid_ranges,
            } => {
                let blob = self.get_or_insert_blob(BlobId::from_child_id(child), hash);
                blob.size = Some(size);
                blob.local_ranges = Some(valid_ranges);
            }
            DownloadProgress::Connected => self.connected = true,
            DownloadProgress::Found {
                id: progress_id,
                child,
                hash,
                size,
            } => {
                let blob_id = BlobId::from_child_id(child);
                let blob = self.get_or_insert_blob(blob_id, hash);
                if blob.size.is_none() {
                    blob.size = Some(BaoBlobSize::Verified(size));
                }
                blob.progress = ProgressState::Progressing(0);
                self.progress_ids.insert(progress_id, blob_id);
                self.current_blob = Some(blob_id);
            }
            DownloadProgress::FoundHashSeq { hash, children } => {
                if hash == self.root.hash {
                    self.root.child_count = Some(children);
                } else {
                    // TODO: I think it is an invariant of the protocol that `FoundHashSeq` is only
                    // triggered for the root hash.
                }
            }
            DownloadProgress::Progress { id, offset } => {
                if let Some(blob) = self.get_by_progress_id(id) {
                    blob.progress = ProgressState::Progressing(offset);
                }
            }
            DownloadProgress::Done { id } => {
                if let Some(blob) = self.get_by_progress_id(id) {
                    blob.progress = ProgressState::Done;
                }
            }
            _ => {}
        }
    }
}

/// The id of a blob in a transfer
#[derive(
    Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, std::hash::Hash, Serialize, Deserialize,
)]
pub enum BlobId {
    /// The root blob (child id 0)
    Root,
    /// A child blob (child id > 0)
    Child(NonZeroU64),
}

impl BlobId {
    fn from_child_id(id: u64) -> Self {
        match id {
            0 => BlobId::Root,
            _ => BlobId::Child(NonZeroU64::new(id).expect("just checked")),
        }
    }
}

impl From<BlobId> for u64 {
    fn from(value: BlobId) -> Self {
        match value {
            BlobId::Root => 0,
            BlobId::Child(id) => id.into(),
        }
    }
}
