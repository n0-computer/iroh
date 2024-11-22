//! Watchable values.
//!
//! A [`Watchable`] exists to keep track of a value which may change over time.  It allows
//! observers to be notified of changes to the value.  The aim is to always be aware of the
//! **last** value, not to observe every value there has ever been.

#[cfg(iroh_loom)]
use loom::sync;
#[cfg(not(iroh_loom))]
use std::sync;

use std::collections::VecDeque;
use std::future::{self, Future};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{self, Poll, Waker};
use sync::{Mutex, RwLock};

use futures_lite::stream::Stream;

const INITIAL_EPOCH: u64 = 1;
const PRE_INITIAL_EPOCH: u64 = 0;

type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Watch lost connection to underlying Watchable, it was dropped")]
    WatchableClosed,
}

/// The shared state for a [`Watchable`].
#[derive(Debug)]
struct Shared<T> {
    /// The value to be watched and its current epoch.
    ///
    /// Note that the `Option` is only there to allow initialization.
    /// Once initialized the value can never be cleared again.
    state: RwLock<State<T>>,
    watchers: Mutex<VecDeque<Waker>>,
}

#[derive(Debug)]
struct State<T> {
    value: Option<T>,
    epoch: u64,
}

impl<T> Default for Shared<T> {
    fn default() -> Self {
        Shared {
            state: RwLock::new(State {
                value: None,
                epoch: INITIAL_EPOCH,
            }),
            watchers: Default::default(),
        }
    }
}

impl<T: Clone> Shared<T> {
    /// Returns the value, initialized or not.
    fn get(&self) -> Option<T> {
        self.state.read().expect("poisoned").value.clone()
    }

    /// Returns a future completing once the value is initialized.
    ///
    /// If the value is already initialized the future will complete immediately.
    fn initialized(&self) -> impl Future<Output = T> + '_ {
        future::poll_fn(|cx| self.poll_next(cx, PRE_INITIAL_EPOCH).map(|(_, t)| t))
    }

    fn updated(&self) -> impl Future<Output = T> + '_ {
        let epoch = self.state.read().unwrap().epoch;
        future::poll_fn(move |cx| self.poll_next(cx, epoch).map(|(_, t)| t))
    }

    fn poll_next(&self, cx: &mut task::Context<'_>, last_epoch: u64) -> Poll<(u64, T)> {
        {
            let state = self.state.read().unwrap();
            let epoch = state.epoch;

            if last_epoch < epoch {
                if let Some(value) = state.value.clone() {
                    // Once initialized our Option is never set back to None, but nevertheless
                    // this code is safer without relying on that invariant.
                    return Poll::Ready((epoch, value));
                }
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
                if let Some(value) = state.value.clone() {
                    // Once initialized our Option is never set back to None, but nevertheless
                    // this code is safer without relying on that invariant.
                    return Poll::Ready((epoch, value));
                }
            }
        }

        Poll::Pending
    }
}

/// A value who's changes over time can be observed.
///
/// Only the most recent value is available to any observer, but but observer is guaranteed
/// to be notified of the most recent value.
#[derive(Debug)]
pub(crate) struct Watchable<T> {
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

impl<T: Clone + Eq> Watchable<T> {
    /// Creates an uninitialized observable value.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Creates an initialized observable value.
    pub(crate) fn new_initialized(value: T) -> Self {
        let shared = Shared {
            state: RwLock::new(State {
                value: Some(value),
                epoch: INITIAL_EPOCH,
            }),
            watchers: Default::default(),
        };
        Self {
            shared: Arc::new(shared),
        }
    }

    /// Sets a new value.
    ///
    /// Returns the previous value if it is different from the one set.  If the value was
    /// uninitialized before, or the previous value is the same as the one being set this
    /// returns `None`.
    ///
    /// Watchers are only notified if the value is changed.
    pub(crate) fn set(&self, value: T) -> Option<T> {
        let mut state = self.shared.state.write().unwrap();
        let changed = state.value.as_ref() == Some(&value);
        let old = std::mem::replace(&mut state.value, Some(value));
        state.epoch += 1;
        drop(state);
        if changed {
            for watcher in self.shared.watchers.lock().unwrap().drain(..) {
                watcher.wake();
            }
        }
        old
    }

    /// Creates a watcher allowing the value to be observed.
    pub(crate) fn watch(&self) -> Watcher<T> {
        Watcher {
            epoch: self.shared.state.read().unwrap().epoch,
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// Returns the currently held value.
    pub(crate) fn get(&self) -> Option<T> {
        self.shared.get()
    }

    /// Returns a future completing once the value is initialized.
    pub(crate) fn initialized(&self) -> impl Future<Output = T> + '_ {
        self.shared.initialized()
    }

    /// Returns a future completing once a new value is set.
    pub(crate) fn updated(&self) -> impl Future<Output = T> + '_ {
        self.shared.updated()
    }
}

/// An observer for a value.
///
/// The observer can get the current value, or be notified of the values' latest value.
/// However only the most recent value is accessible, previous values are not available.
#[derive(Debug, Clone)]
pub struct Watcher<T> {
    epoch: u64,
    shared: Weak<Shared<T>>,
}

impl<T: Clone + Eq> Watcher<T> {
    /// Returns the currently held value.
    ///
    /// Returns `None` if the value was not set yet.
    pub fn get(&self) -> Result<Option<T>> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| Error::WatchableClosed)?;
        Ok(shared.get())
    }

    /// Returns a future completing once the value is initialized.
    pub fn initialized(&mut self) -> WatchNextFut<T> {
        self.epoch = PRE_INITIAL_EPOCH;
        WatchNextFut { watcher: self }
    }

    /// Returns a future completing once a new value is set.
    pub(crate) fn updated(&mut self) -> WatchNextFut<T> {
        WatchNextFut { watcher: self }
    }

    /// Returns a stream which will yield an items for the most recent value.
    ///
    /// The first item of the stream is the current value, so that this stream can be easily
    /// used to operate on the most recent value.  If the stream is not yet initialized the
    /// first item of the stream will not be readily available.
    ///
    /// Note however that only the last item is stored.  If the stream is not polled when an
    /// item is available it can be replaced with another item by the time it is polled.
    pub fn stream(mut self) -> WatcherStream<T> {
        debug_assert!(self.epoch > 0);
        self.epoch -= 1;
        WatcherStream { watcher: self }
    }

    /// Returns a stream which will yield an item for changes to the watched value.
    ///
    /// This stream will only yield values when the watched value changes, the value stored
    /// at the time the stream is created is not yielded.
    ///
    /// Note however that only the last item is stored.  If the stream is not polled when an
    /// item is available it can be replaced with another item by the time it is polled.
    pub fn stream_updates_only(self) -> WatcherStream<T> {
        WatcherStream { watcher: self }
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct WatchNextFut<'a, T> {
    watcher: &'a mut Watcher<T>,
}

impl<'a, T: Clone + Eq> Future for WatchNextFut<'a, T> {
    type Output = Result<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let Some(shared) = self.watcher.shared.upgrade() else {
            return Poll::Ready(Err(Error::WatchableClosed));
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

#[derive(Debug, Clone)]
#[repr(transparent)]
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
        let watchable = Watchable::new_initialized(17);

        assert_eq!(watchable.watch().initialized().await.unwrap(), 17);
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

    #[test]
    fn test_get() {
        let watchable = Watchable::new();
        assert!(watchable.get().is_none());

        watchable.set(1u8);
        assert_eq!(watchable.get(), Some(1u8));
    }

    #[tokio::test]
    async fn test_initialize() {
        let watchable = Watchable::new();

        let mut initialized = watchable.initialized();

        let poll = futures_lite::future::poll_once(&mut initialized).await;
        assert!(poll.is_none());

        watchable.set(1u8);

        let poll = futures_lite::future::poll_once(&mut initialized).await;
        assert_eq!(poll, Some(1u8));
    }

    #[tokio::test]
    async fn test_initialize_already_init() {
        let watchable = Watchable::new_initialized(1u8);

        let mut initialized = watchable.initialized();

        let poll = futures_lite::future::poll_once(&mut initialized).await;
        assert_eq!(poll, Some(1u8));
    }

    #[test]
    fn test_initialized_always_resolves() {
        #[cfg(iroh_loom)]
        use loom::thread;
        #[cfg(not(iroh_loom))]
        use std::thread;

        let test_case = || {
            let watchable = Watchable::<u8>::new();

            let mut watch = watchable.watch();
            let thread = thread::spawn(move || futures_lite::future::block_on(watch.initialized()));

            watchable.set(42);

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
