//! Watchable values.
//!
//! A [`Watchable`] exists to keep track of a value which may change over time.  It allows
//! observers to be notified of changes to the value.  The aim is to always be aware of the
//! **last** value, not to observe *every* value change.
//!
//! In that way, a [`Watchable`] is like a [`tokio::sync::broadcast::Sender`] (and a
//! [`Watcher`] is like a [`tokio::sync::broadcast::Receiver`]), except that there's no risk
//! of the channel filling up, but instead you might miss items.

#[cfg(not(iroh_loom))]
use std::sync;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Weak},
    task::{self, Poll, Waker},
};

use futures_lite::stream::Stream;
#[cfg(iroh_loom)]
use loom::sync;
use sync::{Mutex, RwLock};

/// A value who's changes over time can be observed.
///
/// Only the most recent value is available to any observer, but but observer is guaranteed
/// to be notified of the most recent value.
#[derive(Debug, Default)]
pub struct Watchable<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for Watchable<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T: Clone + Eq> Watchable<T> {
    /// Creates a [`Watchable`] initialized to given value.
    pub fn new(value: T) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: RwLock::new(State {
                    value,
                    epoch: INITIAL_EPOCH,
                }),
                watchers: Default::default(),
            }),
        }
    }

    /// Sets a new value.
    ///
    /// Returns `Ok(previous_value)` if the value was different from the one set, or
    /// returns the provided value back as `Err(value)` if the value didn't change.
    ///
    /// Watchers are only notified if the value changed.
    pub fn set(&self, value: T) -> Result<T, T> {
        // We don't actually write when the value didn't change, but there's unfortunately
        // no way to upgrade a read guard to a write guard, and locking as read first, then
        // dropping and locking as write introduces a possible race condition.
        let mut state = self.shared.state.write().unwrap();

        // Find out if the value changed
        let changed = state.value != value;

        let ret = if changed {
            let old = std::mem::replace(&mut state.value, value);
            state.epoch += 1;
            Ok(old)
        } else {
            Err(value)
        };
        drop(state); // No need to write anymore

        // Notify watchers
        if changed {
            for watcher in self.shared.watchers.lock().unwrap().drain(..) {
                watcher.wake();
            }
        }
        ret
    }

    /// Creates a [`Watcher`] allowing the value to be observed, but not modified.
    pub fn watch(&self) -> Watcher<T> {
        Watcher {
            epoch: self.shared.state.read().unwrap().epoch,
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// Returns the currently stored value.
    pub fn get(&self) -> T {
        self.shared.get()
    }
}

/// An observer for a value.
///
/// The [`Watcher`] can get the current value, and will be notified when the value changes.
/// Only the most recent value is accessible, and if the thread with the [`Watchable`]
/// changes the value faster than the thread with the [`Watcher`] can keep up with, then
/// it'll miss in-between values.
/// When the thread changing the [`Watchable`] pauses updating, the [`Watcher`] will always
/// end up reporting the most recent state eventually.
#[derive(Debug, Clone)]
pub struct Watcher<T> {
    epoch: u64,
    shared: Weak<Shared<T>>,
}

impl<T: Clone + Eq> Watcher<T> {
    /// Returns the currently held value.
    ///
    /// Returns [`Err(Disconnected)`](Disconnected) if the original
    /// [`Watchable`] was dropped.
    pub fn get(&self) -> Result<T, Disconnected> {
        let shared = self.shared.upgrade().ok_or(Disconnected)?;
        Ok(shared.get())
    }

    /// Returns a future completing with `Ok(value)` once a new value is set, or with
    /// [`Err(Disconnected)`](Disconnected) if the connected [`Watchable`] was dropped.
    pub fn updated(&mut self) -> WatchNextFut<T> {
        WatchNextFut { watcher: self }
    }

    /// Returns a stream which will yield the most recent values as items.
    ///
    /// The first item of the stream is the current value, so that this stream can be easily
    /// used to operate on the most recent value.
    ///
    /// Note however, that only the last item is stored.  If the stream is not polled when an
    /// item is available it can be replaced with another item by the time it is polled.
    ///
    /// This stream ends once the original [`Watchable`] has been dropped.
    pub fn stream(mut self) -> WatcherStream<T> {
        debug_assert!(self.epoch > 0);
        self.epoch -= 1;
        WatcherStream { watcher: self }
    }

    /// Returns a stream which will yield the most recent values as items, starting from
    /// the next unobserved future value.
    ///
    /// This means this stream will only yield values when the watched value changes,
    /// the value stored at the time the stream is created is not yielded.
    ///
    /// Note however, that only the last item is stored.  If the stream is not polled when an
    /// item is available it can be replaced with another item by the time it is polled.
    ///
    /// This stream ends once the original [`Watchable`] has been dropped.
    pub fn stream_updates_only(self) -> WatcherStream<T> {
        WatcherStream { watcher: self }
    }
}

impl<T: Clone + Eq> Watcher<Option<T>> {
    /// Returns a future completing once the value is set to [`Some`] value.
    ///
    /// If the current value is [`Some`] value, this future will resolve immediately.
    ///
    /// This is a utility for the common case of storing an [`Option`] inside a
    /// [`Watchable`].
    pub fn initialized(&mut self) -> WatchInitializedFut<T> {
        self.epoch = PRE_INITIAL_EPOCH;
        WatchInitializedFut { watcher: self }
    }
}

/// Future returning the next item after the current one in a [`Watcher`].
///
/// See [`Watcher::updated`].
#[derive(Debug)]
pub struct WatchNextFut<'a, T> {
    watcher: &'a mut Watcher<T>,
}

impl<T: Clone + Eq> Future for WatchNextFut<'_, T> {
    type Output = Result<T, Disconnected>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let Some(shared) = self.watcher.shared.upgrade() else {
            return Poll::Ready(Err(Disconnected));
        };
        match shared.poll_next(cx, self.watcher.epoch) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((current_epoch, value)) => {
                self.watcher.epoch = current_epoch;
                Poll::Ready(Ok(value))
            }
        }
    }
}

/// Future returning the current or next value that's [`Some`] value.
/// in a [`Watcher`].
///
/// See [`Watcher::initialized`].
#[derive(Debug)]
pub struct WatchInitializedFut<'a, T> {
    watcher: &'a mut Watcher<Option<T>>,
}

impl<T: Clone + Eq> Future for WatchInitializedFut<'_, T> {
    type Output = Result<T, Disconnected>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let Some(shared) = self.watcher.shared.upgrade() else {
            return Poll::Ready(Err(Disconnected));
        };

        let value = loop {
            let (epoch, value) = futures_lite::ready!(shared.poll_next(cx, self.watcher.epoch));
            self.watcher.epoch = epoch;

            if let Some(value) = value {
                break value;
            }
        };

        Poll::Ready(Ok(value))
    }
}

/// A stream for a [`Watcher`]'s next values.
///
/// See [`Watcher::stream`] and [`Watcher::stream_updates_only`].
#[derive(Debug, Clone)]
pub struct WatcherStream<T> {
    watcher: Watcher<T>,
}

impl<T: Clone + Eq> Stream for WatcherStream<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(shared) = self.watcher.shared.upgrade() else {
            return Poll::Ready(None);
        };
        match shared.poll_next(cx, self.watcher.epoch) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((epoch, value)) => {
                self.watcher.epoch = epoch;
                Poll::Ready(Some(value))
            }
        }
    }
}

/// The error for when a [`Watcher`] is disconnected from its underlying
/// [`Watchable`] value, because of that watchable having been dropped.
#[derive(thiserror::Error, Debug)]
#[error("Watch lost connection to underlying Watchable, it was dropped")]
pub struct Disconnected;

// Private:

const INITIAL_EPOCH: u64 = 1;
const PRE_INITIAL_EPOCH: u64 = 0;

/// The shared state for a [`Watchable`].
#[derive(Debug, Default)]
struct Shared<T> {
    /// The value to be watched and its current epoch.
    state: RwLock<State<T>>,
    watchers: Mutex<VecDeque<Waker>>,
}

#[derive(Debug)]
struct State<T> {
    value: T,
    epoch: u64,
}

impl<T: Default> Default for State<T> {
    fn default() -> Self {
        Self {
            value: Default::default(),
            epoch: INITIAL_EPOCH,
        }
    }
}

impl<T: Clone> Shared<T> {
    /// Returns the value, initialized or not.
    fn get(&self) -> T {
        self.state.read().expect("poisoned").value.clone()
    }

    fn poll_next(&self, cx: &mut task::Context<'_>, last_epoch: u64) -> Poll<(u64, T)> {
        {
            let state = self.state.read().unwrap();
            let epoch = state.epoch;

            if last_epoch < epoch {
                // Once initialized, our Option is never set back to None, but nevertheless
                // this code is safer without relying on that invariant.
                return Poll::Ready((epoch, state.value.clone()));
            }
        }

        self.watchers
            .lock()
            .expect("poisoned")
            .push_back(cx.waker().to_owned());

        #[cfg(iroh_loom)]
        loom::thread::yield_now();

        {
            let state = self.state.read().unwrap();
            let epoch = state.epoch;

            if last_epoch < epoch {
                // Once initialized our Option is never set back to None, but nevertheless
                // this code is safer without relying on that invariant.
                return Poll::Ready((epoch, state.value.clone()));
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use futures_lite::StreamExt;
    use rand::{thread_rng, Rng};
    use tokio::task::JoinSet;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[tokio::test]
    async fn test_watcher() {
        let cancel = CancellationToken::new();
        let watchable = Watchable::new(17);

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
                        Some(value) = &mut watch.next() => {
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

    #[test]
    fn test_get() {
        let watchable = Watchable::new(None);
        assert!(watchable.get().is_none());

        watchable.set(Some(1u8)).ok();
        assert_eq!(watchable.get(), Some(1u8));
    }

    #[tokio::test]
    async fn test_initialize() {
        let watchable = Watchable::new(None);

        let mut watcher = watchable.watch();
        let mut initialized = watcher.initialized();

        let poll = futures_lite::future::poll_once(&mut initialized).await;
        assert!(poll.is_none());

        watchable.set(Some(1u8)).ok();

        let poll = futures_lite::future::poll_once(&mut initialized).await;
        assert_eq!(poll.unwrap().unwrap(), 1u8);
    }

    #[tokio::test]
    async fn test_initialize_already_init() {
        let watchable = Watchable::new(Some(1u8));

        let mut watcher = watchable.watch();
        let mut initialized = watcher.initialized();

        let poll = futures_lite::future::poll_once(&mut initialized).await;
        assert_eq!(poll.unwrap().unwrap(), 1u8);
    }

    #[test]
    fn test_initialized_always_resolves() {
        #[cfg(not(iroh_loom))]
        use std::thread;

        #[cfg(iroh_loom)]
        use loom::thread;

        let test_case = || {
            let watchable = Watchable::<Option<u8>>::new(None);

            let mut watch = watchable.watch();
            let thread = thread::spawn(move || futures_lite::future::block_on(watch.initialized()));

            watchable.set(Some(42)).ok();

            thread::yield_now();

            let value: u8 = thread.join().unwrap().unwrap();

            assert_eq!(value, 42);
        };

        #[cfg(iroh_loom)]
        loom::model(test_case);
        #[cfg(not(iroh_loom))]
        test_case();
    }
}
