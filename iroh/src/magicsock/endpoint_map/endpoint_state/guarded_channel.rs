use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

/// Creates a new [`mpsc`] channel where the receiver can only close if there are no active senders.
pub(super) fn guarded_channel<T>(cap: usize) -> (GuardedSender<T>, GuardedReceiver<T>) {
    let (tx, rx) = mpsc::channel(cap);
    let tx = Arc::new(Mutex::new(Some(tx)));
    (GuardedSender { tx: tx.clone() }, GuardedReceiver { tx, rx })
}

#[derive(Debug)]
pub(crate) struct GuardedSender<T> {
    tx: Arc<Mutex<Option<mpsc::Sender<T>>>>,
}

impl<T> GuardedSender<T> {
    /// Returns a sender to the channel.
    ///
    /// Returns a new sender if the channel is not closed. It is guaranteed that
    /// [`GuardedReceiver::close_if_idle`] will not return `true` until the sender is dropped.
    /// Returns `None` if the channel has been closed.
    pub(crate) fn get(&self) -> Option<mpsc::Sender<T>> {
        self.tx.lock().expect("poisoned").clone()
    }

    /// Returns `true` if the channel has been closed.
    pub(crate) fn is_closed(&self) -> bool {
        self.tx.lock().expect("poisoned").is_none()
    }
}

#[derive(Debug)]
pub(super) struct GuardedReceiver<T> {
    rx: mpsc::Receiver<T>,
    tx: Arc<Mutex<Option<mpsc::Sender<T>>>>,
}

impl<T> GuardedReceiver<T> {
    /// Receives the next value for this receiver.
    ///
    /// See [`mpsc::Receiver::recv`].
    pub(super) async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await
    }

    /// Returns `true` if the inbox is empty and no senders to the inbox exist.
    pub(super) fn is_idle(&self) -> bool {
        self.rx.is_empty() && self.rx.sender_strong_count() <= 1
    }

    /// Closes the channel if the channel is idle.
    ///
    /// Returns `true` if the channel is idle and has now been closed, and `false` if the channel
    /// is not idle and therefore has not been not closed.
    ///
    /// Uses a lock internally to make sure that there cannot be a race condition between
    /// calling this and a new sender being created.
    pub(super) fn close_if_idle(&mut self) -> bool {
        let mut guard = self.tx.lock().expect("poisoned");
        if self.is_idle() {
            *guard = None;
            self.rx.close();
            true
        } else {
            false
        }
    }
}

impl<T> Drop for GuardedReceiver<T> {
    fn drop(&mut self) {
        let mut guard = self.tx.lock().expect("poisoned");
        *guard = None;
        self.rx.close();
        drop(guard)
    }
}
