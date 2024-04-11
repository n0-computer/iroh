//! Utilities used in [`iroh-net`][`crate`]

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::FutureExt;

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
#[derive(derive_more::Debug, Clone)]
pub struct CancelOnDrop {
    task_name: &'static str,
    #[debug(skip)]
    handle: Arc<tokio::task::AbortHandle>,
}

impl CancelOnDrop {
    /// Create a [`CancelOnDrop`] with a name and a handle to a task.
    pub fn new(task_name: &'static str, handle: tokio::task::AbortHandle) -> Self {
        CancelOnDrop {
            task_name,
            handle: Arc::new(handle),
        }
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.handle.abort();
        tracing::trace!("{} completed (aborted)", self.task_name);
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

/// Check if we are running in "relay only" mode, as informed
/// by the compile time env var `DEV_RELAY_ONLY`.
///
/// "relay only" mode implies we only use the relay to communicate
/// and do not attempt to do any hole punching.
pub(crate) fn relay_only_mode() -> bool {
    std::option_env!("DEV_RELAY_ONLY").is_some()
}
