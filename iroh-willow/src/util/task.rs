//! Utilities for working with tokio tasks.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_concurrency::future::{future_group, FutureGroup};
use futures_lite::Stream;
use tokio::task::JoinError;

#[derive(derive_more::Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[debug("{:?}", _0)]
pub struct TaskKey(future_group::Key);

/// A collection of tasks spawned on a Tokio runtime, associated with hash map keys.
///
/// Similar to [`tokio::task::JoinSet`] but can also contain local tasks, and each task is
/// identified by a key which is returned upon completion of the task.
///
/// Uses [`tokio::task::spawn`] and [`tokio::task::spawn_local`] in combination with [`future_group`] for keeping the join handles around.
//
// TODO: Replace with [`tokio::task::JoinMap`] once it doesn't need tokio unstable anymore.
#[derive(Debug)]
pub struct JoinMap<K, T> {
    tasks: future_group::Keyed<tokio::task::JoinHandle<T>>,
    keys: HashMap<TaskKey, K>,
}

impl<K, T> Default for JoinMap<K, T> {
    fn default() -> Self {
        Self {
            tasks: FutureGroup::new().keyed(),
            keys: HashMap::new(),
        }
    }
}

impl<K, T: 'static> JoinMap<K, T> {
    /// Create a new [`TaskMap`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn a new task on the currently executing [`tokio::task::LocalSet`].
    pub fn spawn_local<F: Future<Output = T> + 'static>(&mut self, key: K, future: F) -> TaskKey {
        let handle = tokio::task::spawn_local(future);
        let k = self.tasks.insert(handle);
        let k = TaskKey(k);
        self.keys.insert(k, key);
        k
    }

    /// Poll for one of the tasks in the map to complete.
    pub fn poll_join_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<(K, Result<T, JoinError>)>> {
        let Some((key, item)) = std::task::ready!(Pin::new(&mut self.tasks).poll_next(cx)) else {
            return Poll::Ready(None);
        };
        let key = self.keys.remove(&TaskKey(key)).expect("key to exist");
        Poll::Ready(Some((key, item)))
    }

    /// Remove a task from the map.
    pub fn remove(&mut self, task_key: &TaskKey) -> bool {
        self.keys.remove(&task_key);
        self.tasks.remove(task_key.0)
    }

    /// Returns `true` if the task map is currently empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Returns the number of tasks currently in the map.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &TaskKey)> {
        self.keys.iter().map(|(a, b)| (b, a))
    }
}

impl<K, T: Send + 'static> JoinMap<K, T> {
    /// Spawn a new, non-local task on the current tokio runtime.
    pub fn spawn<F: Future<Output = T> + 'static + Send>(&mut self, future: F) -> TaskKey {
        let handle = tokio::task::spawn(future);
        let key = self.tasks.insert(handle);
        TaskKey(key)
    }
}

impl<K: Unpin, T: 'static> Stream for JoinMap<K, T> {
    type Item = (K, Result<T, JoinError>);

    /// Poll for one of the tasks to complete.
    ///
    /// See [`Self::poll_join_next`] for details.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Self::poll_join_next(self.get_mut(), cx)
    }
}
