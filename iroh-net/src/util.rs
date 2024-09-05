//! Utilities used in [`iroh-net`][`crate`]

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_lite::future::Boxed as BoxFuture;
use futures_util::{future::Shared, FutureExt};

pub mod chain;

/// A join handle that owns the task it is running, and aborts it when dropped.
/// It is cloneable and will abort when the last instance is dropped.
#[derive(Debug, Clone)]
pub struct SharedAbortingJoinHandle<T: Clone + Send> {
    fut: Shared<BoxFuture<std::result::Result<T, String>>>,
    abort: Arc<tokio::task::AbortHandle>,
}

impl<T: Clone + Send + 'static> From<tokio::task::JoinHandle<T>> for SharedAbortingJoinHandle<T> {
    fn from(handle: tokio::task::JoinHandle<T>) -> Self {
        let abort = handle.abort_handle();
        let fut: BoxFuture<std::result::Result<T, String>> =
            Box::pin(async move { handle.await.map_err(|e| e.to_string()) });
        Self {
            fut: fut.shared(),
            abort: Arc::new(abort),
        }
    }
}

impl<T: Clone + Send> Future for SharedAbortingJoinHandle<T> {
    type Output = std::result::Result<T, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.fut).poll(cx)
    }
}

impl<T: Clone + Send> Drop for SharedAbortingJoinHandle<T> {
    fn drop(&mut self) {
        if Arc::strong_count(&self.abort) == 1 {
            self.abort.abort();
        }
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
