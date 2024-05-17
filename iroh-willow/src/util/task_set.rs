use std::{
    collections::HashMap,
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
/// Similar to [`tokio::task::JoinSet`] but can also contain local tasks, and each task is
/// identified by a key which is returned upon completion of the task.
#[derive(Debug)]
pub struct TaskMap<K, T> {
    tasks: future_group::Keyed<tokio::task::JoinHandle<T>>,
    keys: HashMap<future_group::Key, K>,
}

impl<K, T> Default for TaskMap<K, T> {
    fn default() -> Self {
        Self {
            tasks: FutureGroup::new().keyed(),
            keys: HashMap::new(),
        }
    }
}

impl<K, T: 'static> TaskMap<K, T> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn spawn_local<F: Future<Output = T> + 'static>(&mut self, key: K, future: F) -> TaskKey {
        let handle = tokio::task::spawn_local(future);
        let k = self.tasks.insert(handle);
        self.keys.insert(k, key);
        TaskKey(k)
    }


    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<(K, Result<T, tokio::task::JoinError>)>> {
        let Some((key, item)) = std::task::ready!(Pin::new(&mut self.tasks).poll_next(cx)) else {
            return Poll::Ready(None);
        };
        let key = self.keys.remove(&key).expect("key to exist");
        Poll::Ready(Some((key, item)))
    }

    pub fn remove(&mut self, task_key: &TaskKey) -> bool {
        self.keys.remove(&task_key.0);
        self.tasks.remove(task_key.0)
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
    pub fn len(&self) -> usize {
        self.tasks.len()
    }
}

impl<K: Unpin, T: 'static> Stream for TaskMap<K, T> {
    type Item = (K, Result<T, tokio::task::JoinError>);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Self::poll_next(self.get_mut(), cx)
    }
}

impl<K, T: Send + 'static> TaskMap<K, T> {
    pub fn spawn<F: Future<Output = T> + 'static + Send>(&mut self, future: F) -> TaskKey {
        let handle = tokio::task::spawn(future);
        let key = self.tasks.insert(handle);
        TaskKey(key)
    }
}
