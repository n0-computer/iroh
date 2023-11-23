//! Utilities used in [`iroh-net`][`crate`]

use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

use futures::FutureExt;
use tokio::sync::oneshot;

/// A join handle that owns the task it is running, and aborts it when dropped.
#[derive(Debug, derive_more::Deref)]
pub struct AbortingJoinHandle<T>(pub tokio::task::JoinHandle<T>);

impl<T> From<tokio::task::JoinHandle<T>> for AbortingJoinHandle<T> {
    fn from(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(handle)
    }
}

impl<T> Future for AbortingJoinHandle<T> {
    type Output = std::result::Result<T, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

impl<T> Drop for AbortingJoinHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Holds a handle to a task and aborts it on drop.
///
/// See [`tokio::task::AbortHandle`].
#[derive(derive_more::Debug)]
pub struct CancelOnDrop {
    task_name: &'static str,
    #[debug(skip)]
    handle: tokio::task::AbortHandle,
}

impl CancelOnDrop {
    /// Create a [`CancelOnDrop`] with a name and a handle to a task.
    pub fn new(task_name: &'static str, handle: tokio::task::AbortHandle) -> Self {
        CancelOnDrop { task_name, handle }
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.handle.abort();
        tracing::debug!("{} completed", self.task_name);
    }
}

/// Resolves to pending if the inner is `None`.
#[derive(Debug)]
pub struct MaybeFuture<T> {
    /// Future to be polled.
    pub inner: Option<T>,
}

// NOTE: explicit implementation to bypass derive unnecessary bounds
impl<T> Default for MaybeFuture<T> {
    fn default() -> Self {
        MaybeFuture { inner: None }
    }
}

impl<T: Future + Unpin> Future for MaybeFuture<T> {
    type Output = T::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner {
            Some(ref mut t) => Pin::new(t).poll(cx),
            None => Poll::Pending,
        }
    }
}

/// Check if we are running in "derp only" mode, as informed
/// by the compile time env var `DEV_DERP_ONLY`.
///
/// "derp only" mode implies we only use the relay to communicate
/// and do not attempt to do any hole punching.
pub(crate) fn derp_only_mode() -> bool {
    std::option_env!("DEV_DERP_ONLY").is_some()
}

/// A simple notifier.
///
/// The notification is only triggered once. The receiver can be put into an [`std::sync::Arc`] to
/// make it cloneable, and can be received multiple times.
pub fn notifier_channel() -> (NotifySender, NotifyReceiver) {
    let (tx, rx) = oneshot::channel();
    let tx = NotifySender {
        sender: std::sync::Mutex::new(Some(tx)),
        did_sent: AtomicBool::new(false),
    };
    let rx = NotifyReceiver {
        receiver: rx.shared(),
    };
    (tx, rx)
}

/// Sender for [`notifier_channel`].
#[derive(Debug)]
pub struct NotifySender {
    sender: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    did_sent: AtomicBool,
}

impl NotifySender {
    /// Trigger the notification.
    ///
    /// This is a no-op after the first call.
    pub fn trigger(&self) {
        if !self.did_sent.fetch_or(true, Ordering::SeqCst) {
            let _ = self.sender.lock().unwrap().take().unwrap().send(());
        }
    }
}

/// Receiver for [`notifier_channel`].
#[derive(Debug)]
pub struct NotifyReceiver {
    receiver: futures::future::Shared<tokio::sync::oneshot::Receiver<()>>,
}

impl NotifyReceiver {
    /// Wait for the notification to be triggered.
    ///
    /// This will resolve immediately for calls after the notification was triggered, and wait for
    /// the notification if called before.
    pub async fn recv(&self) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        self.receiver.clone().await
    }
}
