use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_concurrency::future::{future_group, FutureGroup};
use futures_lite::Stream;

#[derive(derive_more::Debug, Eq, PartialEq)]
#[debug("{:?}", _0)]
pub struct TaskKey(future_group::Key);

/// A set of tasks.
///
/// Similar to [`tokio::task::JoinSet`] but can also contain local tasks.
#[derive(Debug, derive_more::Deref)]
pub struct TaskSet<T> {
    tasks: future_group::Keyed<tokio::task::JoinHandle<T>>,
}

impl<T> Default for TaskSet<T> {
    fn default() -> Self {
        Self {
            tasks: FutureGroup::new().keyed(),
        }
    }
}

impl<T: 'static> TaskSet<T> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn spawn_local<F: Future<Output = T> + 'static>(&mut self, future: F) -> TaskKey {
        let handle = tokio::task::spawn_local(future);
        let key = self.tasks.insert(handle);
        TaskKey(key)
    }
}

impl<T: 'static> Stream for TaskSet<T> {
    type Item = (TaskKey, Result<T, tokio::task::JoinError>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some((key, item)) = std::task::ready!(Pin::new(&mut self.tasks).poll_next(cx)) else {
            return Poll::Ready(None);
        };
        Poll::Ready(Some((TaskKey(key), item)))
    }
}

impl<T: Send + 'static> TaskSet<T> {
    pub fn spawn<F: Future<Output = T> + 'static + Send>(
        &mut self,
        future: F,
    ) -> future_group::Key {
        let handle = tokio::task::spawn(future);
        let key = self.tasks.insert(handle);
        key
    }
    pub fn remove(&mut self, key: TaskKey) -> bool {
        self.tasks.remove(key.0)
    }
}
