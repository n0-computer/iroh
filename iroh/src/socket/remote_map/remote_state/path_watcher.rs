//! Path observation for a [`Connection`].
//!
//! [`Connection::paths`] returns a borrowed [`PathList`] with live
//! statistics. [`Connection::path_events`] returns a `'static` stream
//! of [`PathEvent`]s. Subscribing to the event stream before reading
//! the snapshot ensures any change that happens between the read and
//! the next poll is observed by the subscriber.
//!
//! Closed paths are not retained in [`PathList`]; their final
//! statistics arrive inline on [`PathEvent::Closed`].
//!
//! # Internal structure
//!
//! [`PathStateSender`] (owned by the [`RemoteStateActor`]) and
//! [`PathStateReceiver`] (held by the [`Connection`]) share a
//! [`Mutex`]`<`[`State`]`>`, a [`Notify`], and a [`broadcast`] channel.
//! The receiver holds a [`WeakSender`]; when the actor drops the
//! sender, outstanding event streams end.
//!
//! [`Connection`]: crate::endpoint::Connection
//! [`Connection::paths`]: crate::endpoint::Connection::paths
//! [`Connection::path_events`]: crate::endpoint::Connection::path_events
//! [`RemoteStateActor`]: super::RemoteStateActor
//! [`WeakSender`]: broadcast::WeakSender

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use iroh_base::TransportAddr;
use n0_future::{StreamExt, time::Duration};
use noq::WeakPathHandle;
use noq_proto::PathId;
use smallvec::SmallVec;
use tokio::sync::{Notify, broadcast, futures::Notified};
use tokio_stream::{
    Stream,
    wrappers::{BroadcastStream, errors::BroadcastStreamRecvError},
};
use tracing::warn;

use crate::endpoint::PathStats;

/// Per-connection broadcast channel capacity for path events.
const BROADCAST_CAPACITY: usize = 8;

/// Lifecycle notifications for a transmission paths in a connection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum PathEvent {
    /// A new network path was opened.
    Opened {
        /// Path identifier.
        id: PathId,
        /// Remote transport address.
        remote_addr: TransportAddr,
    },
    /// A network path was closed.
    Closed {
        /// Path identifier.
        id: PathId,
        /// Remote transport address.
        remote_addr: TransportAddr,
        /// Path statistics captured at close time.
        last_stats: Box<PathStats>,
    },
    /// This path was selected for transmission of application data.
    Selected {
        /// Path identifier of the newly selected path.
        id: PathId,
        /// Remote transport address of the newly selected path.
        remote_addr: TransportAddr,
    },
    /// Events were dropped before the subscriber received them.
    ///
    /// Yielded when the subscriber does not poll the stream fast
    /// enough to keep up with the writer. The current set of open
    /// paths and the selected path remain accessible via
    /// [`Connection::paths`].
    ///
    /// [`Connection::paths`]: crate::endpoint::Connection::paths
    Lagged {
        /// Number of events dropped since the last delivered event.
        missed: u64,
    },
}

#[derive(Clone, derive_more::Debug)]
#[debug("PathData({}, {})", self.handle.id(), self.remote_addr)]
struct PathData {
    handle: WeakPathHandle,
    remote_addr: TransportAddr,
}

#[derive(Default, Debug, Clone)]
struct State {
    list: SmallVec<[PathData; 4]>,
    selected: Option<PathId>,
    closed: bool,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    notify: Notify,
}

/// The writer-side handle for a connection's path state.
///
/// Owned by the [`RemoteStateActor`]; the only handle that mutates
/// state and emits events. When dropped, every outstanding
/// [`PathEventStream`] ends.
///
/// [`RemoteStateActor`]: super::RemoteStateActor
#[derive(Debug)]
pub(super) struct PathStateSender {
    shared: Arc<Shared>,
    events: broadcast::Sender<PathEvent>,
}

impl PathStateSender {
    /// Creates a sender/receiver pair sharing empty state.
    pub(super) fn new() -> (Self, PathStateReceiver) {
        let (events, _) = broadcast::channel(BROADCAST_CAPACITY);
        let shared = Arc::new(Shared {
            state: Default::default(),
            notify: Notify::new(),
        });
        let receiver = PathStateReceiver {
            shared: shared.clone(),
            events: events.downgrade(),
        };
        let sender = PathStateSender { shared, events };
        (sender, receiver)
    }

    /// Records a newly-opened path and emits [`PathEvent::Opened`].
    pub(super) fn record_opened(&self, handle: WeakPathHandle, remote_addr: TransportAddr) {
        let id = handle.id();
        {
            let mut state = self.shared.state.lock().expect("poisoned");
            let entry = PathData {
                handle,
                remote_addr: remote_addr.clone(),
            };
            match state.list.iter().position(|e| e.handle.id() == id) {
                Some(idx) => state.list[idx] = entry,
                None => state.list.push(entry),
            }
        }
        self.shared.notify.notify_waiters();
        let _ = self.events.send(PathEvent::Opened { id, remote_addr });
    }

    /// Records that a path was abandoned by `noq`.
    pub(super) fn record_abandoned(&self, id: PathId, conn: &noq::Connection) {
        let removed = {
            let mut state = self.shared.state.lock().expect("poisoned");
            if state.selected == Some(id) {
                state.selected = None;
            }
            state
                .list
                .iter()
                .position(|e| e.handle.id() == id)
                .map(|pos| state.list.remove(pos))
        };
        if let Some(data) = removed {
            let stats = conn
                .path_stats(data.handle.id())
                .expect("Holding a WeakPathHandle makes Connection::path_stats infallible");
            self.shared.notify.notify_waiters();
            let _ = self.events.send(PathEvent::Closed {
                id,
                remote_addr: data.remote_addr,
                last_stats: Box::new(stats),
            });
        }
    }

    /// Updates the selected transmission path.
    pub(super) fn record_selected(&self, remote_addr: TransportAddr) {
        let changed = {
            let mut state = self.shared.state.lock().expect("poisoned");
            let selected_path_id = state
                .list
                .iter()
                .find(|p| p.remote_addr == remote_addr)
                .map(|p| p.handle.id());
            if selected_path_id != state.selected {
                state.selected = selected_path_id;
                selected_path_id.map(|path_id| (path_id, remote_addr))
            } else {
                None
            }
        };
        if let Some((id, remote_addr)) = changed {
            let _ = self.events.send(PathEvent::Selected { id, remote_addr });
            self.shared.notify.notify_waiters();
        }
    }

    /// Closes the writer side of the path observation.
    ///
    /// Emits a final [`PathEvent::Closed`] for every remaining open
    /// path with its statistics taken from `closed.path_stats`, marks
    /// the state closed, and drops the sender. No-op if already closed.
    ///
    /// [`WeakPathHandle`]: noq::WeakPathHandle
    pub(super) fn close(self, closed: noq::Closed) {
        let mut state = self.shared.state.lock().expect("poisoned");
        if !state.closed {
            for entry in state.list.iter() {
                if let Some(stats) = closed
                    .path_stats
                    .iter()
                    .find(|(id, _stats)| *id == entry.handle.id())
                    .map(|(_id, stats)| stats)
                {
                    let _ = self.events.send(PathEvent::Closed {
                        id: entry.handle.id(),
                        remote_addr: entry.remote_addr.clone(),
                        last_stats: Box::new(*stats),
                    });
                } else {
                    warn!(
                        "Connection close event is missing path stats for path {}",
                        entry.handle.id()
                    );
                }
            }
            state.closed = true;
            self.shared.notify.notify_waiters();
        }
    }
}

impl Drop for PathStateSender {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().expect("poisoned");
        if !state.closed {
            state.closed = true;
            self.shared.notify.notify_waiters();
        }
    }
}

/// The reader-side handle for a connection's path state.
///
/// Held by a [`Connection`]. Cheap to clone.
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(Clone, Debug)]
pub(crate) struct PathStateReceiver {
    shared: Arc<Shared>,
    events: broadcast::WeakSender<PathEvent>,
}

impl PathStateReceiver {
    /// Returns a snapshot of the currently-open paths, tied to `conn`.
    pub(crate) fn get<'a>(&self, conn: &'a noq::Connection) -> PathList<'a> {
        PathList {
            snapshot: self.shared.state.lock().expect("poisoned").clone(),
            conn,
        }
    }

    /// Returns a stream of [`PathEvent`]s.
    ///
    /// Already closed if the sender has been dropped.
    pub(crate) fn events(&self) -> PathEventStream {
        let receiver = if let Some(sender) = self.events.upgrade() {
            sender.subscribe()
        } else {
            let (_tx, rx) = broadcast::channel(1);
            rx
        };
        PathEventStream {
            inner: BroadcastStream::new(receiver),
        }
    }

    /// Returns a stream of [`PathList`] snapshots tied to `conn`.
    ///
    /// Yields the current snapshot on the first poll, then a fresh
    /// snapshot on every state change. Ends when the state is marked
    /// closed.
    pub(crate) fn updates<'a>(&'a self, conn: &'a noq::Connection) -> PathListStream<'a> {
        PathListStream {
            shared: &self.shared,
            conn,
            notified: Box::pin(self.shared.notify.notified()),
            first_poll: true,
        }
    }
}

/// A borrowed snapshot of a connection's currently-open paths.
///
/// Returned by [`Connection::paths`]. The list is captured at call
/// time and does not reflect later changes. Closed paths are not
/// retained; to track per-path totals over the connection's lifetime,
/// accumulate from [`PathEvent::Closed`].
///
/// [`Connection::paths`]: crate::endpoint::Connection::paths
#[derive(Clone, derive_more::Debug)]
pub struct PathList<'conn> {
    snapshot: State,
    #[debug(skip)]
    conn: &'conn noq::Connection,
}

impl<'conn> PathList<'conn> {
    /// Returns the number of open paths.
    pub fn len(&self) -> usize {
        self.snapshot.list.len()
    }

    /// Returns `true` if no paths are open.
    pub fn is_empty(&self) -> bool {
        self.snapshot.list.is_empty()
    }

    /// Returns an iterator over the open paths.
    pub fn iter(&self) -> PathListIter<'_> {
        PathListIter {
            inner: self.snapshot.list.iter(),
            selected: self.snapshot.selected,
            conn: self.conn,
        }
    }

    /// Returns the path with the given [`PathId`].
    ///
    /// Returns `None` if no open path with that id is present in
    /// this snapshot.
    pub fn get(&self, id: PathId) -> Option<Path<'_>> {
        self.iter().find(|p| p.id() == id)
    }
}

impl<'a> IntoIterator for &'a PathList<'a> {
    type IntoIter = PathListIter<'a>;
    type Item = Path<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over the open paths in a [`PathList`] snapshot.
#[derive(Debug)]
pub struct PathListIter<'a> {
    inner: std::slice::Iter<'a, PathData>,
    selected: Option<PathId>,
    conn: &'a noq::Connection,
}

impl<'a> PathListIter<'a> {
    fn item(&self, data: &'a PathData) -> Path<'a> {
        Path {
            data,
            is_selected: self.selected == Some(data.handle.id()),
            _conn: self.conn,
        }
    }
}

impl<'a> Iterator for PathListIter<'a> {
    type Item = Path<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|d| self.item(d))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a> DoubleEndedIterator for PathListIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|d| self.item(d))
    }
}

impl ExactSizeIterator for PathListIter<'_> {}

/// A single path within a [`PathList`] snapshot.
///
/// Borrows from the enclosing [`PathList`] and from the [`Connection`]
/// that produced it, so a [`Path`] cannot cross a task boundary. If you need
/// to send path data to other tasks, you can clone [`Self::remote_addr`] or
/// [`Self::stats`] into an owned value first.
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(Clone, Debug)]
pub struct Path<'a> {
    data: &'a PathData,
    is_selected: bool,
    /// Unused reference to a `noq::Connection` that makes [`Self::upgraded`] safe.
    _conn: &'a noq::Connection,
}

impl<'conn> Path<'conn> {
    /// Returns a strong [`noq::Path`].
    ///
    /// We know the `upgrade` can never fail because we are holding a `&noq::Connection` on `self`.
    fn upgraded(&self) -> noq::Path {
        self.data
            .handle
            .upgrade()
            .expect("&Connection is held on self so upgrade cannot fail")
    }

    /// Returns the path's [`PathId`].
    pub fn id(&self) -> PathId {
        self.data.handle.id()
    }

    /// Returns the path's remote transport address.
    pub fn remote_addr(&self) -> &TransportAddr {
        &self.data.remote_addr
    }

    /// Returns `true` if this path is currently selected for application data transmission.
    pub fn is_selected(&self) -> bool {
        self.is_selected
    }

    /// Returns `true` if this is a direct IP path.
    pub fn is_ip(&self) -> bool {
        self.data.remote_addr.is_ip()
    }

    /// Returns `true` if this is a relay path.
    pub fn is_relay(&self) -> bool {
        self.data.remote_addr.is_relay()
    }

    /// Returns the path's statistics.
    ///
    /// Returns live statistics from the QUIC state for an open path, or
    /// the final statistics retained by `noq` for a path that closed
    /// after this snapshot was taken.
    pub fn stats(&self) -> PathStats {
        self.upgraded().stats()
    }

    /// Returns the path's round-trip time estimate.
    pub fn rtt(&self) -> Duration {
        self.stats().rtt
    }
}

/// A stream of [`PathList`] snapshots for a connection.
///
/// Returned by [`Connection::path_updates`]. Yields the current
/// snapshot on the first poll and a fresh snapshot whenever the open
/// paths or the selected path change. Ends when the connection closes.
///
/// [`Connection::path_updates`]: crate::endpoint::Connection::path_updates
#[derive(Debug)]
pub struct PathListStream<'conn> {
    shared: &'conn Shared,
    conn: &'conn noq::Connection,
    notified: Pin<Box<Notified<'conn>>>,
    first_poll: bool,
}

impl<'conn> Stream for PathListStream<'conn> {
    type Item = PathList<'conn>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.first_poll {
            this.first_poll = false;
        } else {
            std::task::ready!(this.notified.as_mut().poll(cx));
            this.notified.set(this.shared.notify.notified());
        }
        this.notified.as_mut().enable();
        let snapshot = this.shared.state.lock().expect("poisoned").clone();
        if snapshot.closed {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(PathList {
                snapshot,
                conn: this.conn,
            }))
        }
    }
}

/// A `'static` stream of [`PathEvent`]s.
///
/// Returned by [`Connection::path_events`].
///
/// [`Connection::path_events`]: crate::endpoint::Connection::path_events
#[derive(Debug)]
pub struct PathEventStream {
    inner: BroadcastStream<PathEvent>,
}

impl Stream for PathEventStream {
    type Item = PathEvent;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_next(cx).map(|event| match event? {
            Ok(event) => Some(event),
            Err(BroadcastStreamRecvError::Lagged(missed)) => Some(PathEvent::Lagged { missed }),
        })
    }
}
