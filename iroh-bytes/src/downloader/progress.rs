use parking_lot::RwLock;
use std::sync::{atomic::AtomicU64, Arc};

use futures::FutureExt;

use crate::util::progress::{IdGenerator, ProgressSendError, ProgressSender};

/// A progress sender that uses a flume channel.
pub struct MultiProgressSender<T> {
    senders: Arc<RwLock<Vec<flume::Sender<T>>>>,
    id: Arc<AtomicU64>,
}

impl<T> std::fmt::Debug for MultiProgressSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlumeProgressSender")
            .field("id", &self.id)
            .field("senders", &self.senders.read().len())
            .finish()
    }
}

impl<T> Clone for MultiProgressSender<T> {
    fn clone(&self) -> Self {
        Self {
            senders: self.senders.clone(),
            id: self.id.clone(),
        }
    }
}

impl<T> MultiProgressSender<T> {
    /// Create a new MultiProgressSender
    pub fn new() -> Self {
        Self {
            senders: Arc::new(RwLock::new(Default::default())),
            id: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn push(&self, sender: flume::Sender<T>) {
        self.senders.write().push(sender)
    }
}

impl<T> IdGenerator for MultiProgressSender<T> {
    fn new_id(&self) -> u64 {
        self.id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
}

impl<T: Clone + Send + Sync + 'static> ProgressSender for MultiProgressSender<T> {
    type Msg = T;

    type SendFuture<'a> =
        futures::future::BoxFuture<'a, std::result::Result<(), ProgressSendError>>;

    fn send(&self, msg: Self::Msg) -> Self::SendFuture<'_> {
        let senders = self.senders.read();
        let futs = senders
            .iter()
            .map(|s| s.clone().into_send_async(msg.clone()))
            .collect::<Vec<_>>();
        drop(senders);
        futures::future::join_all(futs).map(|_r| Ok(())).boxed()
    }

    fn try_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        let senders = self.senders.read();
        for sender in senders.iter() {
            match sender.try_send(msg.clone()) {
                Ok(_) => {}
                Err(flume::TrySendError::Full(_)) => {}
                Err(flume::TrySendError::Disconnected(_)) => {
                    // TODO: remove sender from list
                }
            }
        }
        Ok(())
    }

    fn blocking_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        let senders = self.senders.read();
        for sender in senders.iter() {
            match sender.send(msg.clone()) {
                Ok(_) => {}
                Err(_) => {
                    // TODO: remove sender from list
                }
            }
        }
        Ok(())
    }
}
