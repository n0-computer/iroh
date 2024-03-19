use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::anyhow;
use parking_lot::RwLock;

use crate::{
    get::{db::DownloadProgress, progress::TransferState},
    util::progress::{IdGenerator, ProgressSendError, ProgressSender},
};

use super::DownloadKind;

/// The channel that can be used to subscribe to progress updates.
pub type ProgressSubscriber = flume::Sender<DownloadProgress>;

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
    transfers: HashMap<DownloadKind, Arc<SharedProgress>>,
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
        kind: DownloadKind,
        subscribers: impl IntoIterator<Item = ProgressSubscriber>,
    ) -> SharedProgressSender {
        let inner = Arc::new(SharedProgress {
            subscribers: RwLock::new(subscribers.into_iter().collect()),
            state: RwLock::new(TransferState::new(kind.hash())),
            id_gen: Arc::clone(&self.id_gen),
        });
        self.transfers.insert(kind, Arc::clone(&inner));
        SharedProgressSender(inner)
    }

    pub async fn subscribe(
        &mut self,
        kind: DownloadKind,
        sender: ProgressSubscriber,
    ) -> anyhow::Result<()> {
        self.transfers
            .get_mut(&kind)
            .ok_or_else(|| anyhow!("state for download {kind:?} not found"))?
            .subscribe(sender)
            .await
    }

    pub fn unsubscribe(&mut self, kind: &DownloadKind, sender: &ProgressSubscriber) {
        if let Some(shared) = self.transfers.get_mut(kind) {
            shared.unsubscribe(sender)
        }
    }

    pub fn remove(&mut self, kind: &DownloadKind) {
        self.transfers.remove(kind);
    }
}

#[derive(Debug)]
struct SharedProgress {
    subscribers: RwLock<Vec<ProgressSubscriber>>,
    state: RwLock<TransferState>,
    id_gen: Arc<AtomicU64>,
}

impl SharedProgress {
    async fn subscribe(&self, sender: ProgressSubscriber) -> anyhow::Result<()> {
        self.subscribers.write().push(sender.clone());
        let initial_state = self.state.read().clone();
        sender
            .send_async(DownloadProgress::InitialState(initial_state))
            .await?;
        Ok(())
    }

    fn unsubscribe(&self, sender: &ProgressSubscriber) {
        self.subscribers.write().retain(|s| !s.same_channel(sender));
    }
}

#[derive(Debug, Clone)]
pub struct SharedProgressSender(Arc<SharedProgress>);

impl SharedProgressSender {
    fn on_progress(&self, progress: DownloadProgress) {
        let mut state = self.0.state.write();
        state.on_progress(progress);
    }
}

impl IdGenerator for SharedProgressSender {
    fn new_id(&self) -> u64 {
        self.0.id_gen.fetch_add(1, Ordering::SeqCst)
    }
}

impl ProgressSender for SharedProgressSender {
    type Msg = DownloadProgress;

    async fn send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
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
