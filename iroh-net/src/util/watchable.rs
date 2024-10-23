//! Watchable values.
//!
//! A [`Watchable`] exists to keep track of a value which may change over time.  It allows
//! observers to be notified of changes to the value.  The aim is to always be aware of the
//! **last** value, not to observe every value there has ever been.

use std::collections::VecDeque;
use std::future::{self, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{self, Poll, Waker};

use futures_lite::stream::Stream;

const INITIAL_EPOCH: u64 = 1;

/// The shared state for a [`Watchable`].
#[derive(Debug)]
struct Shared<T> {
    /// The value to be watched.
    ///
    /// Note that the `Option` is only there to allow initialisation.  Once initialised the
    /// value can never be cleared again.
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

impl<T: Clone> Shared<T> {
    /// Returns the value, initialised or not.
    fn get(&self) -> Option<T> {
        self.value.read().unwrap().clone()
    }

    /// Returns a future completing once the value is initialized.
    ///
    /// If the value is already initialised the future will complete immediately.
    // TODO: maybe writing this as a poll function avoids needing to use Either?
    fn initialized(&self) -> impl Future<Output = T> + '_ {
        let epoch = self.epoch.load(Ordering::Acquire);
        if let Some(ref value) = *self.value.read().expect("poisoned") {
            return Either::Left(future::ready(value.clone()));
        }
        Either::Right(future::poll_fn(move |cx| {
            self.poll_next(cx, epoch).map(|(_, t)| t)
        }))
    }

    fn poll_next(&self, cx: &mut task::Context<'_>, last_epoch: u64) -> Poll<(u64, T)> {
        let epoch = self.epoch.load(Ordering::Acquire);
        // TODO(flub): Pretty sure this can miss a write because the epoch and wakers are
        //    separate:
        //    - thread 1 runs poll_next
        //    - thread 2 runs set
        //    1. thread 1: load epoch
        //    2. thread 2: lock value, replace value, unlock value
        //    3. thread 2: store epoch
        //    4. thread 2: lock wakers, drain wakers, unlock wakers
        //    5. thread 1: lock wakers, install waker, unlock wakers
        //
        //    I believe the epoch and wakers need to be stored in the same RwLock.

        // TODO(flub): This can be written without expect, but the above should probably be
        //    fixed first:

        // if last_epoch < epoch {
        //     if let Some(value) = self.get() {
        //         // Once initialised our Option is never set back to None, but nevertheless
        //         // this code is safer without relying on that invariant.
        //         return Poll::Ready((epoch, value));
        //     }
        // }
        // self.watchers.write().expect("poisoned").push_back(cx.waker().to_owned());
        // Poll::Pending

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
    /// Creates an uninitialised observable value.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Creates an initialised observable value.
    pub(crate) fn new_initialised(value: T) -> Self {
        let shared = Shared {
            value: RwLock::new(Some(value)),
            epoch: AtomicU64::new(INITIAL_EPOCH),
            watchers: Default::default(),
        };
        Self {
            shared: Arc::new(shared),
        }
    }

    /// Sets a new value.
    ///
    /// Returns the previous value if it is different from the one set.  If the value was
    /// uninitialised before, or the previous value is the same as the one being set this
    /// returns `None`.
    ///
    /// Watchers are only notified if the value is changed.
    pub(crate) fn set(&self, value: T) -> Option<T> {
        if Some(&value) == self.shared.value.read().unwrap().as_ref() {
            return None;
        }
        let old = std::mem::replace(&mut *self.shared.value.write().unwrap(), Some(value));
        self.shared.epoch.fetch_add(1, Ordering::AcqRel);
        for watcher in self.shared.watchers.write().unwrap().drain(..) {
            watcher.wake();
        }
        old
    }

    /// Creates a watcher allowing the value to be observed.
    pub(crate) fn watch(&self) -> Watcher<T> {
        Watcher {
            shared: Arc::clone(&self.shared),
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
}

/// An observer for a value.
///
/// The observer can get the current value, or be notified of the values' latest value.
/// However only the most recent value is accessible, previous values are not available.
#[derive(Debug, Clone)]
pub struct Watcher<T> {
    shared: Arc<Shared<T>>,
}

impl<T: Clone + Eq> Watcher<T> {
    /// Returns the currently held value.
    pub fn get(&self) -> Option<T> {
        self.shared.get()
    }

    /// Returns a future completing once the value is initialized.
    pub fn initialized(&self) -> impl Future<Output = T> + '_ {
        self.shared.initialized()
    }

    /// Returns a stream which will yield an items for the most recent value.
    ///
    /// The first item of the stream is the current value, so that this stream can be easily
    /// used to operate on the most recent value.  If the stream is not yet initialised the
    /// first item of the stream will not be readily available.
    ///
    /// Note however that only the last item is stored.  If the stream is not polled when an
    /// item is available it can be replaced with another item by the time it is polled.
    pub fn stream(self) -> impl Stream<Item = T> {
        let epoch = self.shared.epoch.load(Ordering::Acquire);
        debug_assert!(epoch > 0);
        self.stream_from_epoch(epoch - 1)
    }

    /// Returns a stream which will yield an item for changes to the watched value.
    ///
    /// This stream will only yield values when the watched value changes, the value stored
    /// at the time the stream is created is not yielded.
    ///
    /// Note however that only the last item is stored.  If the stream is not polled when an
    /// item is available it can be replaced with another item by the time it is polled.
    pub fn stream_updates_only(self) -> impl Stream<Item = T> {
        let last_epoch = self.shared.epoch.load(Ordering::Acquire);
        self.stream_from_epoch(last_epoch)
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

enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<A, B> Either<A, B> {
    /// Convert `Pin<&mut Either<A, B>>` to `Either<Pin<&mut A>, Pin<&mut B>>`,
    /// pinned projections of the inner variants.
    fn as_pin_mut(self: Pin<&mut Self>) -> Either<Pin<&mut A>, Pin<&mut B>> {
        // SAFETY: `get_unchecked_mut` is fine because we don't move anything.
        // We can use `new_unchecked` because the `inner` parts are guaranteed
        // to be pinned, as they come from `self` which is pinned, and we never
        // offer an unpinned `&mut A` or `&mut B` through `Pin<&mut Self>`. We
        // also don't have an implementation of `Drop`, nor manual `Unpin`.
        unsafe {
            match self.get_unchecked_mut() {
                Self::Left(inner) => Either::Left(Pin::new_unchecked(inner)),
                Self::Right(inner) => Either::Right(Pin::new_unchecked(inner)),
            }
        }
    }
}

impl<A, B> Future for Either<A, B>
where
    A: Future,
    B: Future<Output = A::Output>,
{
    type Output = A::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match self.as_pin_mut() {
            Either::Left(x) => x.poll(cx),
            Either::Right(x) => x.poll(cx),
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
        let watchable = Watchable::new_initialised(17);

        assert_eq!(watchable.watch().initialized().await, 17);
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
        let watchable = Watchable::new_initialised(1u8);

        let mut initialized = watchable.initialized();

        let poll = futures_lite::future::poll_once(&mut initialized).await;
        assert_eq!(poll, Some(1u8));
    }
}
