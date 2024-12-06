//! Watchable values.

use std::{
    collections::VecDeque,
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    task::{self, Poll, Waker},
};

use futures_lite::stream::Stream;

#[derive(Debug)]
struct Shared<T> {
    value: RwLock<Option<T>>,
    epoch: AtomicU64,
    watchers: RwLock<VecDeque<Waker>>,
}

impl<T> Default for Shared<T> {
    fn default() -> Self {
        Shared {
            value: Default::default(),
            epoch: INITIAL_EPOCH.into(),
            watchers: Default::default(),
        }
    }
}

impl<T: Clone + Eq> Shared<T> {
    fn get(&self) -> Option<T> {
        self.value.read().unwrap().clone()
    }

    fn once_set(&self) -> impl Future<Output = T> + '_ {
        futures_lite::future::poll_fn(|cx| self.poll_next(cx, 0).map(|(_, t)| t))
    }

    fn poll_next(&self, cx: &mut task::Context<'_>, last_epoch: u64) -> Poll<(u64, T)> {
        let epoch = self.epoch.load(Ordering::SeqCst);
        if last_epoch == epoch {
            self.watchers
                .write()
                .unwrap()
                .push_back(cx.waker().to_owned());
            Poll::Pending
        } else {
            Poll::Ready((epoch, self.get().expect("Never setting back to None")))
        }
    }
}

/// A value, whos changes can be observed.
#[derive(Debug)]
pub struct Watchable<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Default for Watchable<T> {
    fn default() -> Self {
        Self {
            shared: Default::default(),
        }
    }
}

impl<T> Clone for Watchable<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

/// The watcher watching the watchable.
#[derive(Debug, Clone)]
pub struct Watcher<T> {
    shared: Arc<Shared<T>>,
}

const INITIAL_EPOCH: u64 = 1;

impl<T: Clone + Eq> Watchable<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new entity, with the provided initial value.
    pub fn new_with(value: T) -> Self {
        let shared = Shared {
            value: RwLock::new(Some(value)),
            epoch: AtomicU64::new(INITIAL_EPOCH),
            watchers: Default::default(),
        };
        Self {
            shared: Arc::new(shared),
        }
    }

    /// Set the current value.
    ///
    /// If the value changed, returns the old value, otherwise `None`.
    /// Watchers are only notified if the value is changed.
    pub fn set(&self, value: T) -> Option<T> {
        if Some(&value) == self.shared.value.read().unwrap().as_ref() {
            return None;
        }
        let old = std::mem::replace(&mut *self.shared.value.write().unwrap(), Some(value));
        self.shared.epoch.fetch_add(1, Ordering::SeqCst);
        for watcher in self.shared.watchers.write().unwrap().drain(..) {
            watcher.wake();
        }
        old
    }

    /// Creates a watcher that yield new values only.
    pub fn watch(&self) -> Watcher<T> {
        Watcher {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Returns a reference to the currently held value.
    pub fn get(&self) -> Option<T> {
        self.shared.get()
    }

    pub fn once_set(&self) -> impl Future<Output = T> + '_ {
        self.shared.once_set()
    }
}

impl<T: Clone + Eq> Watcher<T> {
    /// Returns a reference to the currently held value.
    pub fn get(&self) -> Option<T> {
        self.shared.get()
    }

    pub fn once_set(&self) -> impl Future<Output = T> + '_ {
        self.shared.once_set()
    }

    pub fn stream_updates_only(self) -> impl Stream<Item = T> {
        let last_epoch = self.shared.epoch.load(Ordering::SeqCst);
        self.stream_from_epoch(last_epoch)
    }

    pub fn stream(self) -> impl Stream<Item = T> {
        let last_epoch = self.shared.epoch.load(Ordering::SeqCst);
        debug_assert!(last_epoch > 0);
        self.stream_from_epoch(last_epoch - 1)
    }

    fn stream_from_epoch(self, mut last_epoch: u64) -> impl Stream<Item = T> {
        futures_lite::stream::poll_fn(move |cx| match self.shared.poll_next(cx, last_epoch) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((epoch, value)) => {
                last_epoch = epoch;
                Poll::Ready(Some(value))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, Instant};

    use futures_lite::StreamExt;
    use rand::{thread_rng, Rng};
    use tokio::task::JoinSet;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn test_watcher() {
        let cancel = CancellationToken::new();
        let watchable = Watchable::new_with(17);

        assert_eq!(watchable.watch().once_set().await, 17);
        assert_eq!(watchable.watch().stream().next().await.unwrap(), 17);

        let start = Instant::now();
        // spawn watchers
        let mut tasks = JoinSet::new();
        for i in 0..3 {
            let mut watch = watchable.watch().stream();
            let cancel = cancel.clone();
            tasks.spawn(async move {
                println!("[{i}] spawn");
                let mut expected_value = 17;
                loop {
                    tokio::select! {
                        biased;
                        value = &mut watch.next() => {
                            let value = value.unwrap();
                            println!("{:?} [{i}] update: {value}", start.elapsed());
                            assert_eq!(value, expected_value);
                            if expected_value == 17 {
                                expected_value = 0;
                            } else {
                                expected_value += 1;
                            }
                        },
                        _ = cancel.cancelled() => {
                            println!("{:?} [{i}] cancel", start.elapsed());
                            assert_eq!(expected_value, 10);
                            break;
                        }
                    }
                }
            });
        }
        for i in 0..3 {
            let mut watch = watchable.watch().stream_updates_only();
            let cancel = cancel.clone();
            tasks.spawn(async move {
                println!("[{i}] spawn");
                let mut expected_value = 0;
                loop {
                    tokio::select! {
                        biased;
                        Some(value) = watch.next() => {
                            println!("{:?} [{i}] stream update: {value}", start.elapsed());
                            assert_eq!(value, expected_value);
                            expected_value += 1;
                        },
                        _ = cancel.cancelled() => {
                            println!("{:?} [{i}] cancel", start.elapsed());
                            assert_eq!(expected_value, 10);
                            break;
                        }
                        else => {
                            panic!("stream died");
                        }
                    }
                }
            });
        }

        // set value
        for next_value in 0..10 {
            let sleep = Duration::from_nanos(thread_rng().gen_range(0..100_000_000));
            println!("{:?} sleep {sleep:?}", start.elapsed());
            tokio::time::sleep(sleep).await;

            let changed = watchable.set(next_value);
            println!("{:?} set {next_value} changed={changed:?}", start.elapsed());
        }

        println!("cancel");
        cancel.cancel();
        while let Some(res) = tasks.join_next().await {
            res.expect("task failed");
        }
    }
}
