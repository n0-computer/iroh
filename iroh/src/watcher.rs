//! Watchable values.
//!
//! A [`Watchable`] exists to keep track of a value which may change over time.  It allows
//! observers to be notified of changes to the value.  The aim is to always be aware of the
//! **last** value, not to observe *every* value change.
//!
//! In that way, a [`Watchable`] is like a [`tokio::sync::broadcast::Sender`] (and a
//! [`Watcher`] is like a [`tokio::sync::broadcast::Receiver`]), except that there's no risk
//! of the channel filling up, but instead you might miss items.
//!
//! This module is meant to be imported like this (if you use all of these things):
//! ```ignore
//! use iroh::watcher::{self, Watchable, Watcher as _};
//! ```

#[cfg(not(iroh_loom))]
use std::sync;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Weak},
    task::{self, Poll, Waker},
};

#[cfg(iroh_loom)]
use loom::sync;
use snafu::Snafu;
use sync::{Mutex, RwLock};

/// A wrapper around a value that notifies [`Watcher`]s when the value is modified.
///
/// Only the most recent value is available to any observer, but the observer is guaranteed
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
        let mut state = self.shared.state.write().expect("poisoned");

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
            for watcher in self.shared.watchers.lock().expect("poisoned").drain(..) {
                watcher.wake();
            }
        }
        ret
    }

    /// Creates a [`Direct`] [`Watcher`], allowing the value to be observed, but not modified.
    pub fn watch(&self) -> Direct<T> {
        Direct {
            epoch: self.shared.state.read().expect("poisoned").epoch,
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// Returns the currently stored value.
    pub fn get(&self) -> T {
        self.shared.get()
    }
}

/// A handle to a value that's represented by one or more underlying [`Watchable`]s.
///
/// A [`Watcher`] can get the current value, and will be notified when the value changes.
/// Only the most recent value is accessible, and if the threads with the underlying [`Watchable`]s
/// change the value faster than the threads with the [`Watcher`] can keep up with, then
/// it'll miss in-between values.
/// When the thread changing the [`Watchable`] pauses updating, the [`Watcher`] will always
/// end up reporting the most recent state eventually.
///
/// Watchers can be modified via [`Watcher::map`] to observe a value derived from the original
/// value via a function.
///
/// Watchers can be combined via [`Watcher::or`] to allow observing multiple values at once and
/// getting an update in case any of the values updates.
///
/// One of the underlying [`Watchable`]s might already be dropped. In that case,
/// the watcher will be "disconnected" and return [`Err(Disconnected)`](Disconnected)
/// on some function calls or, when turned into a stream, that stream will end.
pub trait Watcher: Clone {
    /// The type of value that can change.
    ///
    /// We require `Clone`, because we need to be able to make
    /// the values have a lifetime that's detached from the original [`Watchable`]'s
    /// lifetime.
    ///
    /// We require `Eq`, to be able to check whether the value actually changed or
    /// not, so we can notify or not notify accordingly.
    type Value: Clone + Eq;

    /// Returns the current state of the underlying value, or errors out with
    /// [`Disconnected`], if one of the underlying [`Watchable`]s has been dropped.
    fn get(&self) -> Result<Self::Value, Disconnected>;

    /// Polls for the next value, or returns [`Disconnected`] if one of the underlying
    /// [`Watchable`]s has been dropped.
    fn poll_updated(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::Value, Disconnected>>;

    /// Returns a future completing with `Ok(value)` once a new value is set, or with
    /// [`Err(Disconnected)`](Disconnected) if the connected [`Watchable`] was dropped.
    ///
    /// # Cancel Safety
    ///
    /// The returned future is cancel-safe.
    fn updated(&mut self) -> NextFut<Self> {
        NextFut { watcher: self }
    }

    /// Returns a future completing once the value is set to [`Some`] value.
    ///
    /// If the current value is [`Some`] value, this future will resolve immediately.
    ///
    /// This is a utility for the common case of storing an [`Option`] inside a
    /// [`Watchable`].
    ///
    /// # Cancel Safety
    ///
    /// The returned future is cancel-safe.
    fn initialized<T>(&mut self) -> InitializedFut<T, Self>
    where
        Self: Watcher<Value = Option<T>>,
    {
        InitializedFut {
            initial: match self.get() {
                Ok(Some(value)) => Some(Ok(value)),
                Ok(None) => None,
                Err(val) => Some(Err(val)),
            },
            watcher: self,
        }
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
    ///
    /// # Cancel Safety
    ///
    /// The returned stream is cancel-safe.
    fn stream(self) -> Stream<Self>
    where
        Self: Unpin,
    {
        Stream {
            initial: self.get().ok(),
            watcher: self,
        }
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
    ///
    /// # Cancel Safety
    ///
    /// The returned stream is cancel-safe.
    fn stream_updates_only(self) -> Stream<Self>
    where
        Self: Unpin,
    {
        Stream {
            initial: None,
            watcher: self,
        }
    }

    /// Maps this watcher with a function that transforms the observed values.
    ///
    /// The returned watcher will only register updates, when the *mapped* value
    /// observably changes. For this, it needs to store a clone of `T` in the watcher.
    fn map<T: Clone + Eq>(
        self,
        map: impl Fn(Self::Value) -> T + 'static,
    ) -> Result<Map<Self, T>, Disconnected> {
        Ok(Map {
            current: (map)(self.get()?),
            map: Arc::new(map),
            watcher: self,
        })
    }

    /// Returns a watcher that updates every time this or the other watcher
    /// updates, and yields both watcher's items together when that happens.
    fn or<W: Watcher>(self, other: W) -> (Self, W) {
        (self, other)
    }
}

/// The immediate, direct observer of a [`Watchable`] value.
///
/// This type is mainly used via the [`Watcher`] interface.
#[derive(Debug, Clone)]
pub struct Direct<T> {
    epoch: u64,
    shared: Weak<Shared<T>>,
}

impl<T: Clone + Eq> Watcher for Direct<T> {
    type Value = T;

    fn get(&self) -> Result<Self::Value, Disconnected> {
        let shared = self.shared.upgrade().ok_or(DisconnectedSnafu.build())?;
        Ok(shared.get())
    }

    fn poll_updated(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::Value, Disconnected>> {
        let Some(shared) = self.shared.upgrade() else {
            return Poll::Ready(Err(DisconnectedSnafu.build()));
        };
        match shared.poll_updated(cx, self.epoch) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((current_epoch, value)) => {
                self.epoch = current_epoch;
                Poll::Ready(Ok(value))
            }
        }
    }
}

impl<S: Watcher, T: Watcher> Watcher for (S, T) {
    type Value = (S::Value, T::Value);

    fn get(&self) -> Result<Self::Value, Disconnected> {
        Ok((self.0.get()?, self.1.get()?))
    }

    fn poll_updated(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::Value, Disconnected>> {
        let poll_0 = self.0.poll_updated(cx)?;
        let poll_1 = self.1.poll_updated(cx)?;
        match (poll_0, poll_1) {
            (Poll::Ready(s), Poll::Ready(t)) => Poll::Ready(Ok((s, t))),
            (Poll::Ready(s), Poll::Pending) => Poll::Ready(self.1.get().map(move |t| (s, t))),
            (Poll::Pending, Poll::Ready(t)) => Poll::Ready(self.0.get().map(move |s| (s, t))),
            (Poll::Pending, Poll::Pending) => Poll::Pending,
        }
    }
}

/// Wraps a [`Watcher`] to allow observing a derived value.
///
/// See [`Watcher::map`].
#[derive(derive_more::Debug, Clone)]
pub struct Map<W: Watcher, T: Clone + Eq> {
    #[debug("Arc<dyn Fn(W::Value) -> T + 'static>")]
    map: Arc<dyn Fn(W::Value) -> T + 'static>,
    watcher: W,
    current: T,
}

impl<W: Watcher, T: Clone + Eq> Watcher for Map<W, T> {
    type Value = T;

    fn get(&self) -> Result<Self::Value, Disconnected> {
        Ok((self.map)(self.watcher.get()?))
    }

    fn poll_updated(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::Value, Disconnected>> {
        loop {
            let value = n0_future::ready!(self.watcher.poll_updated(cx)?);
            let mapped = (self.map)(value);
            if mapped != self.current {
                self.current = mapped.clone();
                return Poll::Ready(Ok(mapped));
            } else {
                self.current = mapped;
            }
        }
    }
}

/// Future returning the next item after the current one in a [`Watcher`].
///
/// See [`Watcher::updated`].
///
/// # Cancel Safety
///
/// This future is cancel-safe.
#[derive(Debug)]
pub struct NextFut<'a, W: Watcher> {
    watcher: &'a mut W,
}

impl<W: Watcher> Future for NextFut<'_, W> {
    type Output = Result<W::Value, Disconnected>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.watcher.poll_updated(cx)
    }
}

/// Future returning the current or next value that's [`Some`] value.
/// in a [`Watcher`].
///
/// See [`Watcher::initialized`].
///
/// # Cancel Safety
///
/// This Future is cancel-safe.
#[derive(Debug)]
pub struct InitializedFut<'a, T, W: Watcher<Value = Option<T>>> {
    initial: Option<Result<T, Disconnected>>,
    watcher: &'a mut W,
}

impl<T: Clone + Eq + Unpin, W: Watcher<Value = Option<T>> + Unpin> Future
    for InitializedFut<'_, T, W>
{
    type Output = Result<T, Disconnected>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        if let Some(value) = self.as_mut().initial.take() {
            return Poll::Ready(value);
        }
        loop {
            if let Some(value) = n0_future::ready!(self.as_mut().watcher.poll_updated(cx)?) {
                return Poll::Ready(Ok(value));
            }
        }
    }
}

/// A stream for a [`Watcher`]'s next values.
///
/// See [`Watcher::stream`] and [`Watcher::stream_updates_only`].
///
/// # Cancel Safety
///
/// This stream is cancel-safe.
#[derive(Debug, Clone)]
pub struct Stream<W: Watcher + Unpin> {
    initial: Option<W::Value>,
    watcher: W,
}

impl<W: Watcher + Unpin> n0_future::stream::Stream for Stream<W>
where
    W::Value: Unpin,
{
    type Item = W::Value;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(value) = self.as_mut().initial.take() {
            return Poll::Ready(Some(value));
        }
        match self.as_mut().watcher.poll_updated(cx) {
            Poll::Ready(Ok(value)) => Poll::Ready(Some(value)),
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The error for when a [`Watcher`] is disconnected from its underlying
/// [`Watchable`] value, because of that watchable having been dropped.
#[derive(Debug, Snafu)]
#[snafu(display("Watch lost connection to underlying Watchable, it was dropped"))]
pub struct Disconnected {
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
}

// Private:

const INITIAL_EPOCH: u64 = 1;

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

    fn poll_updated(&self, cx: &mut task::Context<'_>, last_epoch: u64) -> Poll<(u64, T)> {
        {
            let state = self.state.read().expect("poisoned");
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
            let state = self.state.read().expect("poisoned");
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

    use n0_future::StreamExt;
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

        let poll = n0_future::future::poll_once(&mut initialized).await;
        assert!(poll.is_none());

        watchable.set(Some(1u8)).ok();

        let poll = n0_future::future::poll_once(&mut initialized).await;
        assert_eq!(poll.unwrap().unwrap(), 1u8);
    }

    #[tokio::test]
    async fn test_initialize_already_init() {
        let watchable = Watchable::new(Some(1u8));

        let mut watcher = watchable.watch();
        let mut initialized = watcher.initialized();

        let poll = n0_future::future::poll_once(&mut initialized).await;
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
            let thread = thread::spawn(move || n0_future::future::block_on(watch.initialized()));

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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_update_cancel_safety() {
        let watchable = Watchable::new(0);
        let mut watch = watchable.watch();
        const MAX: usize = 100_000;

        let handle = tokio::spawn(async move {
            let mut last_observed = 0;

            while last_observed != MAX {
                tokio::select! {
                    val = watch.updated() => {
                        let Ok(val) = val else {
                            return;
                        };

                        assert_ne!(val, last_observed, "never observe the same value twice, even with cancellation");
                        last_observed = val;
                    }
                    _ = tokio::time::sleep(Duration::from_micros(thread_rng().gen_range(0..10_000))) => {
                        // We cancel the other future and start over again
                        continue;
                    }
                }
            }
        });

        for i in 1..=MAX {
            watchable.set(i).ok();
            if thread_rng().gen_bool(0.2) {
                tokio::task::yield_now().await;
            }
        }

        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .unwrap()
            .unwrap()
    }
}
