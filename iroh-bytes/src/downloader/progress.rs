use std::{collections::HashMap, num::NonZeroU64, sync::Arc};

use futures::FutureExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    downloader::state::TransferId,
    get::db::DownloadProgress,
    protocol::RangeSpec,
    store::BaoBlobSize,
    util::progress::{FlumeProgressSender, IdGenerator, ProgressSendError, ProgressSender},
    Hash,
};

pub type ProgressSubscriber = flume::Sender<DownloadProgress>;

type SharedSender = FlumeProgressSender<(TransferId, DownloadProgress)>;
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
    state: HashMap<TransferId, TransferState>,
    broadcaster: ProgressBroadcaster,
    on_progress_rx: flume::Receiver<(TransferId, DownloadProgress)>,
}

impl ProgressTracker {
    pub fn new(cap: usize) -> Self {
        let (broadcaster, on_progress_rx) = ProgressBroadcaster::new(cap);
        Self {
            state: Default::default(),
            broadcaster,
            on_progress_rx,
        }
    }

    /// Poll the progress channel for new events and merge them into the internal progress state.
    ///
    /// This method is cancel safe.
    pub async fn drive_next(&mut self) {
        while let Ok((transfer_id, event)) = self.on_progress_rx.recv_async().await {
            if let Some(transfer) = self.state.get_mut(&transfer_id) {
                transfer.on_progress(event)
            }
        }
    }

    /// Subscribe to a running transfer.
    pub async fn subscribe(&mut self, transfer_id: TransferId, sender: ProgressSubscriber) {
        if let Some(initial_state) = self.state.get(&transfer_id) {
            sender
                .send_async(DownloadProgress::InitialState(initial_state.clone()))
                .await
                .ok();
            self.broadcaster.subscribe(transfer_id, sender.clone());
        } else {
            warn!(
                ?transfer_id,
                "tried to subscribe to progress of unknown transfer"
            )
        }
    }

    /// Start to track a new transfer.
    pub fn insert(&mut self, transfer_id: TransferId, root_hash: Hash) -> BroadcastProgressSender {
        self.state
            .insert(transfer_id, TransferState::new(root_hash));
        self.broadcaster.create(transfer_id)
    }

    /// Start to track a new transfer and provide a list of progress subscribers.
    pub fn insert_with_subscribers(
        &mut self,
        transfer_id: TransferId,
        root_hash: Hash,
        subscribers: impl IntoIterator<Item = ProgressSubscriber>,
    ) -> BroadcastProgressSender {
        let sender = self.insert(transfer_id, root_hash);
        for subscriber in subscribers.into_iter() {
            self.broadcaster.subscribe(transfer_id, subscriber);
        }
        sender
    }

    /// Remove a transfer.
    pub fn remove(&mut self, transfer_id: TransferId) {
        self.state.remove(&transfer_id);
        self.broadcaster.remove(transfer_id);
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
            _ => BlobId::Child(NonZeroU64::new(0).expect("just checked")),
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

#[derive(Debug)]
pub struct ProgressBroadcaster {
    shared: SharedSender,
    transfers: HashMap<TransferId, Arc<BroadcastProgressShared>>,
}

impl ProgressBroadcaster {
    pub fn new(cap: usize) -> (Self, flume::Receiver<(TransferId, DownloadProgress)>) {
        let (on_progress_tx, on_progress_rx) = flume::bounded(cap);
        let shared = FlumeProgressSender::new(on_progress_tx);
        (
            Self {
                shared,
                transfers: Default::default(),
            },
            on_progress_rx,
        )
    }
    pub fn create(&mut self, transfer_id: TransferId) -> BroadcastProgressSender {
        let state = BroadcastProgressShared {
            transfer_id,
            shared: self.shared.clone(),
            subscribers: Default::default(),
        };
        let state = Arc::new(state);
        self.transfers.insert(transfer_id, Arc::clone(&state));
        BroadcastProgressSender(state)
    }

    pub fn subscribe(&mut self, transfer_id: TransferId, sender: ProgressSubscriber) {
        if let Some(state) = self.transfers.get_mut(&transfer_id) {
            state.subscribe(sender);
        }
    }

    pub fn remove(&mut self, transfer_id: TransferId) {
        self.transfers.remove(&transfer_id);
    }
}

#[derive(Debug, Clone)]
pub struct BroadcastProgressSender(Arc<BroadcastProgressShared>);

#[derive(Debug)]
struct BroadcastProgressShared {
    transfer_id: TransferId,
    shared: SharedSender,
    subscribers: RwLock<Vec<ProgressSubscriber>>,
}

impl BroadcastProgressShared {
    pub fn subscribe(&self, sender: ProgressSubscriber) {
        self.subscribers.write().push(sender)
    }
}

impl IdGenerator for BroadcastProgressSender {
    fn new_id(&self) -> u64 {
        self.0.shared.new_id()
    }
}

impl ProgressSender for BroadcastProgressSender {
    type Msg = DownloadProgress;

    type SendFuture<'a> =
        futures::future::BoxFuture<'a, std::result::Result<(), ProgressSendError>>;

    fn send(&self, msg: Self::Msg) -> Self::SendFuture<'_> {
        let inner = self.0.clone();
        async move {
            let send_to_subscribers = {
                let subscribers = inner.subscribers.read();
                let futs = subscribers
                    .iter()
                    .map(|s| s.clone().into_send_async(msg.clone()))
                    .collect::<Vec<_>>();
                drop(subscribers);
                futures::future::join_all(futs)
            };
            let send_to_shared = inner.shared.send((inner.transfer_id, msg.clone()));
            let (_, res) = tokio::join!(send_to_subscribers, send_to_shared);
            res
        }
        .boxed()
    }

    fn try_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        let subscribers = self.0.subscribers.read();
        for sender in subscribers.iter() {
            // TODO: remove sender from list on err? but must avoid deadlock
            sender.try_send(msg.clone()).ok();
        }
        drop(subscribers);
        self.0.shared.try_send((self.0.transfer_id, msg))
    }

    fn blocking_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        let subscribers = self.0.subscribers.read();
        for sender in subscribers.iter() {
            // TODO: remove sender from list on error
            sender.send(msg.clone()).ok();
        }
        self.0.shared.blocking_send((self.0.transfer_id, msg))
    }
}
