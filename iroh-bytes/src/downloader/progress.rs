use std::{
    collections::{hash_map, HashMap},
    convert::identity,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::anyhow;
use parking_lot::Mutex;

use crate::{
    export::ExportProgress,
    get::{db::DownloadProgress, progress::TransferState},
    util::progress::{FlumeProgressSender, IdGenerator, ProgressSendError, ProgressSender},
};

use super::DownloadKind;

/// The channel that can be used to subscribe to progress updates.
pub type ProgressSubscriber = FlumeProgressSender<DownloadProgress>;

/// Track the progress of downloads.
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
    running: HashMap<DownloadKind, Shared>,
    id_gen: Arc<AtomicU64>,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            running: Default::default(),
            id_gen: Default::default(),
        }
    }

    pub fn create(
        &mut self,
        kind: DownloadKind,
        subscribers: impl IntoIterator<Item = ProgressSubscriber>,
    ) -> BroadcastProgressSender {
        let inner = Inner {
            subscribers: subscribers.into_iter().map(Subscriber::new).collect(),
            state: TransferState::new(kind.hash()),
        };
        let shared = Arc::new(Mutex::new(inner));
        self.running.insert(kind, Arc::clone(&shared));
        let id_gen = Arc::clone(&self.id_gen);
        BroadcastProgressSender { shared, id_gen }
    }

    pub async fn subscribe(
        &mut self,
        kind: DownloadKind,
        sender: ProgressSubscriber,
    ) -> anyhow::Result<()> {
        let initial_msg = self
            .running
            .get_mut(&kind)
            .ok_or_else(|| anyhow!("state for download {kind:?} not found"))?
            .lock()
            .subscribe(sender.clone());
        sender.send(initial_msg).await?;
        Ok(())
    }

    pub fn unsubscribe(&mut self, kind: &DownloadKind, sender: &ProgressSubscriber) {
        if let Some(shared) = self.running.get_mut(kind) {
            shared.lock().unsubscribe(sender)
        }
    }

    pub fn remove(&mut self, kind: &DownloadKind) {
        self.running.remove(kind);
    }
}

type Shared = Arc<Mutex<Inner>>;

#[derive(Debug)]
struct Inner {
    subscribers: Vec<Subscriber>,
    state: TransferState,
}

impl Inner {
    fn subscribe(&mut self, sender: ProgressSubscriber) -> DownloadProgress {
        let mut subscriber = Subscriber::new(sender.clone());
        let msg = DownloadProgress::InitialState(self.state.clone());
        let msg = subscriber.map(msg);
        self.subscribers.push(subscriber);
        msg
    }

    fn unsubscribe(&mut self, sender: &ProgressSubscriber) {
        self.subscribers.retain(|s| !s.sender.same_channel(sender));
    }

    fn on_progress(&mut self, progress: DownloadProgress) {
        self.state.on_progress(progress);
    }
}

#[derive(Debug, Clone)]
pub struct BroadcastProgressSender {
    shared: Shared,
    id_gen: Arc<AtomicU64>,
}

impl IdGenerator for BroadcastProgressSender {
    fn new_id(&self) -> u64 {
        self.id_gen.fetch_add(1, Ordering::SeqCst)
    }
}

impl ProgressSender for BroadcastProgressSender {
    type Msg = DownloadProgress;

    async fn send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        // making sure that the lock is not held across an await point.
        let futs = {
            let mut inner = self.shared.lock();
            inner.on_progress(msg.clone());
            let futs = inner
                .subscribers
                .iter_mut()
                .map(|s| {
                    let msg = s.map(msg.clone());
                    let sender = s.sender.clone();
                    async move {
                        match sender.send(msg).await {
                            Ok(()) => None,
                            Err(ProgressSendError::ReceiverDropped) => Some(sender),
                        }
                    }
                })
                .collect::<Vec<_>>();
            drop(inner);
            futs
        };

        let failed_senders = futures::future::join_all(futs).await;
        // remove senders where the receiver is dropped
        if failed_senders.iter().any(|s| s.is_some()) {
            let mut inner = self.shared.lock();
            for sender in failed_senders.into_iter().filter_map(identity) {
                inner.unsubscribe(&sender);
            }
            drop(inner);
        }
        Ok(())
    }

    fn try_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        let mut inner = self.shared.lock();
        inner.on_progress(msg.clone());
        // remove senders where the receiver is dropped
        inner.subscribers.retain_mut(|s| {
            let msg = s.map(msg.clone());
            match s.sender.try_send(msg) {
                Err(ProgressSendError::ReceiverDropped) => false,
                Ok(()) => true,
            }
        });
        Ok(())
    }

    fn blocking_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        let mut inner = self.shared.lock();
        inner.on_progress(msg.clone());
        // remove senders where the receiver is dropped
        inner.subscribers.retain_mut(|s| {
            let msg = s.map(msg.clone());
            match s.sender.blocking_send(msg) {
                Err(ProgressSendError::ReceiverDropped) => false,
                Ok(()) => true,
            }
        });
        Ok(())
    }
}

#[derive(Debug)]
struct Subscriber {
    /// The progress sender as passed in by the user
    sender: FlumeProgressSender<DownloadProgress>,
    /// Map ids from the shared progress events to ids generated by `sender`
    id_map: HashMap<u64, u64>,
}

impl Subscriber {
    fn new(sender: FlumeProgressSender<DownloadProgress>) -> Self {
        Self {
            sender,
            id_map: Default::default(),
        }
    }

    /// Transforms a progress event by replacing all progress ids with progress ids generated by
    /// `self.sender`
    fn map(&mut self, mut p: DownloadProgress) -> DownloadProgress {
        match &mut p {
            DownloadProgress::InitialState(state) => {
                let len = state.progress_id_to_blob.len();
                let old_map =
                    std::mem::replace(&mut state.progress_id_to_blob, HashMap::with_capacity(len));
                for (progress_id, blob_id) in old_map.into_iter() {
                    state
                        .progress_id_to_blob
                        .insert(self.map_id(progress_id), blob_id);
                }
            }
            DownloadProgress::Found { id, .. } => {
                *id = self.map_id(*id);
            }
            DownloadProgress::Progress { id, .. } => {
                *id = self.map_id(*id);
            }
            DownloadProgress::Done { id } => {
                *id = self.map_and_remove_id(*id).unwrap_or_default();
            }
            DownloadProgress::Export(progress) => match progress {
                ExportProgress::Found { id, .. } => {
                    *id = self.map_id(*id);
                }
                ExportProgress::Progress { id, .. } => {
                    *id = self.map_id(*id);
                }
                ExportProgress::Done { id } => {
                    *id = self.map_and_remove_id(*id).unwrap_or_default();
                }
                _ => {}
            },
            _ => {}
        }
        p
    }

    fn map_id(&mut self, id: u64) -> u64 {
        match self.id_map.entry(id) {
            hash_map::Entry::Occupied(entry) => *entry.get(),
            hash_map::Entry::Vacant(entry) => {
                let id = self.sender.new_id();
                entry.insert(id);
                id
            }
        }
    }
    fn map_and_remove_id(&mut self, id: u64) -> Option<u64> {
        self.id_map.remove(&id)
    }
}
