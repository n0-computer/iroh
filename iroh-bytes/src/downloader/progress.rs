use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::anyhow;
use parking_lot::Mutex;

use crate::{
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
#[derive(Debug, Default)]
pub struct ProgressTracker {
    /// Map of shared state for each tracked download.
    running: HashMap<DownloadKind, Shared>,
    /// Shared [`IdGenerator`] for all progress senders created by the tracker.
    id_gen: Arc<AtomicU64>,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a new download with a list of initial subscribers.
    ///
    /// Note that this should only be called for *new* downloads. If a download for the `kind` is
    /// already tracked in this [`ProgressTracker`], calling `track` will replace all existing
    /// state and subscribers (equal to calling [`Self::remove`] first).
    pub fn track(
        &mut self,
        kind: DownloadKind,
        subscribers: impl IntoIterator<Item = ProgressSubscriber>,
    ) -> BroadcastProgressSender {
        let inner = Inner {
            subscribers: subscribers.into_iter().collect(),
            state: TransferState::new(kind.hash()),
        };
        let shared = Arc::new(Mutex::new(inner));
        self.running.insert(kind, Arc::clone(&shared));
        let id_gen = Arc::clone(&self.id_gen);
        BroadcastProgressSender { shared, id_gen }
    }

    /// Subscribe to a tracked download.
    ///
    /// Will return an error if `kind` is not yet tracked.
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

    /// Unsubscribe `sender` from `kind`.
    pub fn unsubscribe(&mut self, kind: &DownloadKind, sender: &ProgressSubscriber) {
        if let Some(shared) = self.running.get_mut(kind) {
            shared.lock().unsubscribe(sender)
        }
    }

    /// Remove all state for a download.
    pub fn remove(&mut self, kind: &DownloadKind) {
        self.running.remove(kind);
    }
}

type Shared = Arc<Mutex<Inner>>;

#[derive(Debug)]
struct Inner {
    subscribers: Vec<ProgressSubscriber>,
    state: TransferState,
}

impl Inner {
    fn subscribe(&mut self, subscriber: ProgressSubscriber) -> DownloadProgress {
        let msg = DownloadProgress::InitialState(self.state.clone());
        self.subscribers.push(subscriber);
        msg
    }

    fn unsubscribe(&mut self, sender: &ProgressSubscriber) {
        self.subscribers.retain(|s| !s.same_channel(sender));
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

    async fn send(&self, msg: Self::Msg) -> Result<(), ProgressSendError> {
        // making sure that the lock is not held across an await point.
        let futs = {
            let mut inner = self.shared.lock();
            inner.on_progress(msg.clone());
            let futs = inner
                .subscribers
                .iter_mut()
                .map(|sender| {
                    let sender = sender.clone();
                    let msg = msg.clone();
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
            for sender in failed_senders.into_iter().flatten() {
                inner.unsubscribe(&sender);
            }
            drop(inner);
        }
        Ok(())
    }

    fn try_send(&self, msg: Self::Msg) -> Result<(), ProgressSendError> {
        let mut inner = self.shared.lock();
        inner.on_progress(msg.clone());
        // remove senders where the receiver is dropped
        inner
            .subscribers
            .retain_mut(|sender| match sender.try_send(msg.clone()) {
                Err(ProgressSendError::ReceiverDropped) => false,
                Ok(()) => true,
            });
        Ok(())
    }

    fn blocking_send(&self, msg: Self::Msg) -> Result<(), ProgressSendError> {
        let mut inner = self.shared.lock();
        inner.on_progress(msg.clone());
        // remove senders where the receiver is dropped
        inner
            .subscribers
            .retain_mut(|sender| match sender.blocking_send(msg.clone()) {
                Err(ProgressSendError::ReceiverDropped) => false,
                Ok(()) => true,
            });
        Ok(())
    }
}
