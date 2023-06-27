use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::FutureExt;

/// A join handle that owns the task it is running, and aborts it when dropped.
#[derive(Debug)]
pub(crate) struct AbortingJoinHandle<T>(tokio::task::JoinHandle<T>);

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

impl<T> std::ops::Deref for AbortingJoinHandle<T> {
    type Target = tokio::task::JoinHandle<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Holds a handle to abort a task.
///
/// The task can be manually aborted, or aborted once self is dropped.
/// See [`tokio::task::AbortHandle`].
pub struct CancelOnDrop {
    task_name: &'static str,
    handle: tokio::task::AbortHandle,
}

impl CancelOnDrop {
    pub fn new(task_name: &'static str, handle: tokio::task::AbortHandle) -> Self {
        CancelOnDrop { task_name, handle }
    }

    pub fn cancel(self) {}
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.handle.abort();
        tracing::debug!("{} completed", self.task_name);
    }
}

impl std::fmt::Debug for CancelOnDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelOnDrop")
            .field("task_name", &self.task_name)
            .finish()
    }
}
