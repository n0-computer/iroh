//! Path state observation for connections.
//!
//! This module provides the public API for observing network paths and their statistics
//! on a [`Connection`].
//!
//! The main types are:
//!
//! - [`Paths`]: a borrowed view of current paths, obtained via [`Connection::paths`].
//! - [`PathEntry`]: a single path within a [`Paths`] view, with live stats access.
//! - [`OwnedPathEntry`]: an owned snapshot of a path with captured stats.
//! - [`PathEvent`]: notifications about path lifecycle changes.
//! - [`PathStatsTracker`]: a detachable accumulator that retains stats for abandoned paths.
//!
//! [`Connection`]: crate::endpoint::Connection
//! [`Connection::paths`]: crate::endpoint::Connection::paths

use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use iroh_base::TransportAddr;
use n0_future::{task::AbortOnDropHandle, time::Duration};
use noq::WeakConnectionHandle;
use noq_proto::PathId;
use smallvec::SmallVec;
use tokio::sync::broadcast;
use tracing::trace;

use crate::endpoint::PathStats;

// ═══════════════════════════════════════════════════════════════
// PathMetadata (stored in arc-swap, updated on events only)
// ═══════════════════════════════════════════════════════════════

/// Metadata about all paths for a connection.
///
/// This is the value stored in the [`ArcSwap`] and atomically swapped whenever
/// paths are opened, closed, or the selected path changes.
#[derive(Debug, Clone, Default)]
pub(crate) struct PathMetadata {
    pub(crate) entries: SmallVec<[PathMeta; 4]>,
}

/// Metadata about a single network path.
///
/// This is the internal representation stored in the [`PathMetadata`] snapshot.
/// For live paths, stats are fetched from the noq connection on demand.
/// For closed paths, stats are frozen at abandonment time.
#[derive(Debug, Clone)]
pub(crate) struct PathMeta {
    pub(crate) id: PathId,
    pub(crate) remote_addr: TransportAddr,
    pub(crate) is_closed: bool,
    pub(crate) is_selected: bool,
    /// Stats frozen by the actor at abandonment time. `None` for live paths.
    pub(crate) frozen_stats: Option<PathStats>,
}

// ═══════════════════════════════════════════════════════════════
// PathStore (internal, shared between actor and Connection)
// ═══════════════════════════════════════════════════════════════

/// Internal store for path metadata, shared between the [`RemoteStateActor`] and
/// [`Connection`]s.
///
/// The actor writes via [`PathStore::update`]. Connections read via [`PathStore::load`].
/// Path change events are broadcast to subscribers.
///
/// [`RemoteStateActor`]: super::RemoteStateActor
/// [`Connection`]: crate::endpoint::Connection
#[derive(Debug, Clone)]
pub(crate) struct PathStore {
    metadata: Arc<ArcSwap<PathMetadata>>,
    events_tx: broadcast::Sender<PathEvent>,
}

impl PathStore {
    /// Creates a new, empty path store.
    pub(crate) fn new() -> Self {
        let (events_tx, _) = broadcast::channel(64);
        Self {
            metadata: Arc::new(ArcSwap::new(Arc::new(PathMetadata::default()))),
            events_tx,
        }
    }

    /// Loads the current path metadata.
    ///
    /// This is a lock-free atomic load.
    pub(crate) fn load(&self) -> arc_swap::Guard<Arc<PathMetadata>> {
        self.metadata.load()
    }

    /// Loads the current path metadata as a full [`Arc`].
    pub(crate) fn load_full(&self) -> Arc<PathMetadata> {
        self.metadata.load_full()
    }

    /// Replaces the current path metadata.
    ///
    /// Called by the [`RemoteStateActor`] when paths are opened, closed, or selection changes.
    ///
    /// [`RemoteStateActor`]: super::RemoteStateActor
    pub(crate) fn update(&self, new: PathMetadata) {
        self.metadata.store(Arc::new(new));
    }

    /// Broadcasts a path event to all subscribers.
    pub(crate) fn send_event(&self, event: PathEvent) {
        // Ignore send errors -- nobody listening is fine.
        let _ = self.events_tx.send(event);
    }

    /// Subscribes to path change events.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<PathEvent> {
        self.events_tx.subscribe()
    }

    /// Removes closed paths from metadata if nobody is listening for events.
    pub(crate) fn cleanup_closed(&self) {
        if self.events_tx.receiver_count() == 0 {
            let current = self.metadata.load_full();
            if current.entries.iter().any(|e| e.is_closed) {
                let mut meta = (*current).clone();
                meta.entries.retain(|e| !e.is_closed);
                self.metadata.store(Arc::new(meta));
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Public API: Paths (borrows &Connection)
// ═══════════════════════════════════════════════════════════════

/// Current network paths of a connection.
///
/// Obtained via [`Connection::paths`]. All methods take `&self`.
///
/// This is a lightweight, transient view of the path state. Path metadata (which paths
/// exist, which is selected) is read from an atomically-swapped snapshot. Path statistics
/// (RTT, bytes transferred) are fetched live from the underlying QUIC connection.
///
/// `Paths` borrows the [`Connection`], so it cannot outlive it. For owned path data,
/// use [`Paths::to_owned_list`] or [`PathStatsTracker`].
///
/// # Examples
///
/// ```no_run
/// # use iroh::endpoint::Connection;
/// # fn example(conn: &Connection) {
/// let paths = conn.paths();
/// for path in paths.iter() {
///     println!("{}: rtt={:?} selected={}", path.remote_addr(), path.rtt(), path.is_selected());
/// }
/// # }
/// ```
///
/// [`Connection`]: crate::endpoint::Connection
/// [`Connection::paths`]: crate::endpoint::Connection::paths
pub struct Paths<'a> {
    metadata: arc_swap::Guard<Arc<PathMetadata>>,
    conn: &'a noq::Connection,
    store: &'a PathStore,
}

impl<'a> Paths<'a> {
    /// Creates a new `Paths` view from a path store and connection.
    pub(crate) fn new(store: &'a PathStore, conn: &'a noq::Connection) -> Self {
        Self {
            metadata: store.load(),
            conn,
            store,
        }
    }

    /// Returns an iterator over all current paths.
    ///
    /// The iterator yields [`PathEntry`] values, which provide live access to path
    /// statistics via the connection.
    pub fn iter(&self) -> impl Iterator<Item = PathEntry<'_>> + '_ {
        self.metadata
            .entries
            .iter()
            .map(|meta| PathEntry { meta, conn: self.conn, store: self.store })
    }

    /// Returns the number of paths.
    pub fn len(&self) -> usize {
        self.metadata.entries.len()
    }

    /// Returns `true` if there are no paths.
    pub fn is_empty(&self) -> bool {
        self.metadata.entries.is_empty()
    }

    /// Returns the currently selected path, if any.
    ///
    /// At most one path is selected at a time. The selected path is the primary
    /// transmission path for the connection.
    pub fn selected(&self) -> Option<PathEntry<'_>> {
        self.iter().find(|p| p.is_selected())
    }

    /// Collects all paths into an owned list, capturing stats at this moment.
    ///
    /// This is useful when you need to store path data beyond the lifetime of the
    /// `Paths` borrow.
    pub fn to_owned_list(&self) -> Vec<OwnedPathEntry> {
        self.iter().map(|e| e.to_owned()).collect()
    }
}

impl std::fmt::Debug for Paths<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

// ═══════════════════════════════════════════════════════════════
// PathEntry (borrowed, live stats)
// ═══════════════════════════════════════════════════════════════

/// A single network path in a [`Paths`] view.
///
/// Provides metadata about the path and live access to path statistics.
/// Statistics are fetched from the underlying QUIC connection on demand,
/// so they are always current.
///
/// For closed paths, statistics were frozen at abandonment time and are
/// returned from the snapshot. In either case, [`PathEntry::stats`] always
/// returns a value -- it never returns `Option`.
///
/// If a path is abandoned between the metadata snapshot and a `stats()` call,
/// the entry automatically re-loads fresh metadata from the store to retrieve
/// the frozen stats (one atomic load, only on the race path).
pub struct PathEntry<'a> {
    meta: &'a PathMeta,
    conn: &'a noq::Connection,
    /// Reference to the store for re-loading metadata on stale snapshot.
    store: &'a PathStore,
}

impl<'a> PathEntry<'a> {
    /// Returns the [`PathId`] of this path.
    ///
    /// Path IDs are unique within a connection and are never reused.
    pub fn id(&self) -> PathId {
        self.meta.id
    }

    /// Returns the remote transport address used by this path.
    pub fn remote_addr(&self) -> &TransportAddr {
        &self.meta.remote_addr
    }

    /// Returns `true` if this path is the currently selected transmission path.
    pub fn is_selected(&self) -> bool {
        self.meta.is_selected
    }

    /// Returns `true` if this path has been closed (abandoned).
    ///
    /// A closed path will remain closed forever. If the network path becomes available
    /// again, a new path will be opened with a new [`PathId`].
    pub fn is_closed(&self) -> bool {
        self.meta.is_closed
    }

    /// Returns `true` if this is an IP transport path.
    pub fn is_ip(&self) -> bool {
        self.meta.remote_addr.is_ip()
    }

    /// Returns `true` if this is a relay transport path.
    pub fn is_relay(&self) -> bool {
        self.meta.remote_addr.is_relay()
    }

    /// Returns the current statistics for this path.
    ///
    /// For live paths, stats are fetched from the QUIC connection and are always current.
    /// For closed paths, stats were frozen at the moment the path was abandoned.
    ///
    /// If the metadata snapshot is stale (path was abandoned after this view was created),
    /// the store is re-loaded to retrieve the frozen stats. This costs one additional
    /// atomic load and only happens in a narrow race window.
    pub fn stats(&self) -> PathStats {
        if let Some(frozen) = &self.meta.frozen_stats {
            return frozen.clone();
        }
        if let Some(path) = self.conn.path(self.meta.id) {
            return path.stats();
        }
        // Stale snapshot: path was abandoned after we loaded metadata.
        // Re-load from ArcSwap to get the frozen stats.
        self.reload_frozen_stats()
    }

    /// Returns the current round-trip time estimate for this path.
    ///
    /// For live paths, this fetches RTT directly without constructing the full
    /// [`PathStats`]. For closed paths, returns the frozen RTT.
    pub fn rtt(&self) -> Duration {
        if let Some(frozen) = &self.meta.frozen_stats {
            return frozen.rtt;
        }
        if let Some(rtt) = self.conn.rtt(self.meta.id) {
            return rtt;
        }
        self.reload_frozen_stats().rtt
    }

    /// Re-loads metadata from the [`PathStore`] to retrieve frozen stats for a path
    /// that was abandoned after this view's snapshot was taken.
    #[cold]
    fn reload_frozen_stats(&self) -> PathStats {
        let fresh = self.store.load();
        fresh
            .entries
            .iter()
            .find(|e| e.id == self.meta.id)
            .and_then(|e| e.frozen_stats.clone())
            .unwrap_or_default()
    }

    /// Captures this path entry into an owned value with stats frozen at this moment.
    ///
    /// The returned [`OwnedPathEntry`] is `Clone + Send + Sync + 'static` and can be
    /// stored or sent across tasks.
    pub fn to_owned(&self) -> OwnedPathEntry {
        OwnedPathEntry {
            id: self.meta.id,
            remote_addr: self.meta.remote_addr.clone(),
            is_closed: self.meta.is_closed,
            is_selected: self.meta.is_selected,
            stats: self.stats(),
        }
    }
}

impl std::fmt::Display for PathEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (rtt={:?}{}{})",
            self.meta.remote_addr,
            self.rtt(),
            if self.is_selected() { ", selected" } else { "" },
            if self.is_closed() { ", closed" } else { "" },
        )
    }
}

impl std::fmt::Debug for PathEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathEntry")
            .field("id", &self.meta.id)
            .field("remote_addr", &self.meta.remote_addr)
            .field("is_closed", &self.meta.is_closed)
            .field("is_selected", &self.meta.is_selected)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════
// OwnedPathEntry (captured stats, 'static)
// ═══════════════════════════════════════════════════════════════

/// An owned snapshot of a network path with captured statistics.
///
/// Unlike [`PathEntry`], this type does not borrow the connection and can be stored,
/// cloned, and sent across task boundaries. Stats are frozen at the time the
/// `OwnedPathEntry` was created.
///
/// Created via [`PathEntry::to_owned`] or [`Paths::to_owned_list`].
#[derive(Clone, Debug)]
pub struct OwnedPathEntry {
    id: PathId,
    remote_addr: TransportAddr,
    is_closed: bool,
    is_selected: bool,
    stats: PathStats,
}

impl OwnedPathEntry {
    /// Creates an [`OwnedPathEntry`] from path metadata.
    ///
    /// Uses frozen stats if available, otherwise defaults.
    pub(crate) fn from_meta(meta: &PathMeta) -> Self {
        Self {
            id: meta.id,
            remote_addr: meta.remote_addr.clone(),
            is_closed: meta.is_closed,
            is_selected: meta.is_selected,
            stats: meta.frozen_stats.clone().unwrap_or_default(),
        }
    }

    /// Returns the [`PathId`] of this path.
    pub fn id(&self) -> PathId {
        self.id
    }

    /// Returns the remote transport address used by this path.
    pub fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    /// Returns `true` if this path was the selected transmission path at capture time.
    pub fn is_selected(&self) -> bool {
        self.is_selected
    }

    /// Returns `true` if this path was closed at capture time.
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }

    /// Returns `true` if this is an IP transport path.
    pub fn is_ip(&self) -> bool {
        self.remote_addr.is_ip()
    }

    /// Returns `true` if this is a relay transport path.
    pub fn is_relay(&self) -> bool {
        self.remote_addr.is_relay()
    }

    /// Returns the path statistics captured at creation time.
    pub fn stats(&self) -> &PathStats {
        &self.stats
    }

    /// Returns the round-trip time captured at creation time.
    pub fn rtt(&self) -> Duration {
        self.stats.rtt
    }
}

impl std::fmt::Display for OwnedPathEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (rtt={:?}{}{})",
            self.remote_addr,
            self.stats.rtt,
            if self.is_selected { ", selected" } else { "" },
            if self.is_closed { ", closed" } else { "" },
        )
    }
}

// ═══════════════════════════════════════════════════════════════
// PathEvent
// ═══════════════════════════════════════════════════════════════

/// Notification about a path lifecycle change.
///
/// Path events are broadcast to subscribers when paths are opened, closed, or when
/// the selected path changes. Subscribe via [`Connection::path_events`].
///
/// Events are delivered on a best-effort basis: if a subscriber falls behind, events
/// may be skipped. The current path state can always be obtained via
/// [`Connection::paths`].
///
/// [`Connection::path_events`]: crate::endpoint::Connection::path_events
/// [`Connection::paths`]: crate::endpoint::Connection::paths
#[derive(Clone, Debug, derive_more::Display)]
pub enum PathEvent {
    /// A new path was opened.
    #[display("Opened({id:?}, {remote_addr})")]
    Opened {
        /// The ID of the newly opened path.
        id: PathId,
        /// The remote transport address of the path.
        remote_addr: TransportAddr,
    },
    /// A path was closed (abandoned).
    ///
    /// The path's final statistics are included, captured just before the path was
    /// removed from the QUIC connection.
    #[display("Closed({id:?}, {remote_addr})")]
    Closed {
        /// The ID of the closed path.
        id: PathId,
        /// The remote transport address of the path.
        remote_addr: TransportAddr,
        /// The path's statistics at the moment it was abandoned.
        last_stats: PathStats,
    },
    /// The selected transmission path changed.
    ///
    /// This event is not emitted when the selection is cleared (which only happens
    /// when the connection closes). It is also only emitted for connections that
    /// have the selected path open -- connections without the path will see the
    /// selection change in metadata but will not receive this event.
    #[display("Selected({id:?}, {remote_addr})")]
    Selected {
        /// The ID of the newly selected path.
        id: PathId,
        /// The remote transport address of the newly selected path.
        remote_addr: TransportAddr,
    },
}

// ═══════════════════════════════════════════════════════════════
// PathEventStream
// ═══════════════════════════════════════════════════════════════

/// A stream of [`PathEvent`]s for a connection.
///
/// Created via [`Connection::path_events`]. Dropping the stream unsubscribes.
///
/// If the receiver falls behind, some events may be skipped. The current path state
/// can always be obtained via [`Connection::paths`].
///
/// [`Connection::path_events`]: crate::endpoint::Connection::path_events
/// [`Connection::paths`]: crate::endpoint::Connection::paths
#[derive(Debug)]
pub struct PathEventStream {
    rx: broadcast::Receiver<PathEvent>,
}

impl PathEventStream {
    /// Creates a new event stream from a broadcast receiver.
    pub(crate) fn new(rx: broadcast::Receiver<PathEvent>) -> Self {
        Self { rx }
    }

    /// Receives the next path event.
    ///
    /// Returns `None` when the connection has been closed and no more events will
    /// be produced.
    ///
    /// If events were missed due to the receiver falling behind, the missed events
    /// are silently skipped and the next available event is returned.
    pub async fn recv(&mut self) -> Option<PathEvent> {
        loop {
            match self.rx.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Skipped events -- try again.
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// PathStatsTracker (auto-spawned, abort-on-drop)
// ═══════════════════════════════════════════════════════════════

/// Accumulates path statistics across a connection's lifetime.
///
/// Unlike [`Paths`], a `PathStatsTracker` retains statistics for abandoned paths
/// and can outlive the [`Connection`] that created it.
///
/// The tracker spawns a background task on creation that listens for [`PathEvent`]s
/// and freezes stats when paths close. The task is automatically aborted when the
/// last clone of the tracker is dropped.
///
/// # Limitations
///
/// The tracker only captures paths that exist at creation time or are opened afterwards.
/// If paths were already closed and cleaned up before the tracker was created, they will
/// not appear in [`PathStatsTracker::all_paths`]. Create the tracker early (ideally right
/// after connecting) to ensure complete coverage.
///
/// If the tracker's internal event receiver falls behind (more than 64 events buffered),
/// it recovers by rebuilding from the current metadata snapshot. Paths that were opened
/// and closed during the lag window may be missing if they were also cleaned from the
/// snapshot.
///
/// # Examples
///
/// ```no_run
/// # use iroh::endpoint::Connection;
/// # async fn example(conn: Connection) {
/// let tracker = conn.path_stats_tracker();
///
/// // ... use the connection ...
///
/// // After the connection closes, you can still access all path stats:
/// let all_paths = tracker.all_paths();
/// for path in &all_paths {
///     println!("{}: sent {} bytes", path.remote_addr(), path.stats().udp_tx.bytes);
/// }
/// # }
/// ```
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(Clone, Debug)]
pub struct PathStatsTracker {
    inner: Arc<PathStatsTrackerInner>,
}

#[derive(Debug)]
struct PathStatsTrackerInner {
    /// Accumulated entries (live + abandoned with frozen stats).
    entries: Arc<RwLock<SmallVec<[OwnedPathEntry; 4]>>>,
    /// Abort handle for the background task. Task is aborted on drop.
    _task: AbortOnDropHandle<()>,
}

impl PathStatsTracker {
    /// Creates a new tracker and spawns its background task.
    pub(crate) fn new(store: &PathStore, conn_weak: WeakConnectionHandle) -> Self {
        let entries: Arc<RwLock<SmallVec<[OwnedPathEntry; 4]>>> =
            Arc::new(RwLock::new(SmallVec::new()));

        // Seed with current paths.
        {
            let meta = store.load();
            let mut list = entries.write().expect("panicked");
            if let Some(conn) = conn_weak.upgrade() {
                for m in meta.entries.iter() {
                    let stats = m
                        .frozen_stats
                        .clone()
                        .or_else(|| conn.path(m.id).map(|p| p.stats()))
                        .unwrap_or_default();
                    list.push(OwnedPathEntry {
                        id: m.id,
                        remote_addr: m.remote_addr.clone(),
                        is_closed: m.is_closed,
                        is_selected: m.is_selected,
                        stats,
                    });
                }
            }
        }

        let entries_clone = entries.clone();
        let mut events_rx = store.subscribe();
        let store_clone = store.clone();

        let task = n0_future::task::spawn(async move {
            loop {
                match events_rx.recv().await {
                    Ok(PathEvent::Opened { id, remote_addr }) => {
                        let stats = conn_weak
                            .upgrade()
                            .and_then(|c| c.path(id).map(|p| p.stats()))
                            .unwrap_or_default();
                        entries_clone.write().expect("panicked").push(OwnedPathEntry {
                            id,
                            remote_addr,
                            is_closed: false,
                            is_selected: false,
                            stats,
                        });
                    }
                    Ok(PathEvent::Closed {
                        id, last_stats, ..
                    }) => {
                        let mut entries = entries_clone.write().expect("panicked");
                        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                            entry.is_closed = true;
                            entry.stats = last_stats;
                        }
                    }
                    Ok(PathEvent::Selected { id, .. }) => {
                        let mut entries = entries_clone.write().expect("panicked");
                        for entry in entries.iter_mut() {
                            entry.is_selected = entry.id == id;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        trace!(skipped = n, "PathStatsTracker lagged, rebuilding from snapshot");
                        // Rebuild from current metadata, preserving closed entries
                        // that may have been cleaned from the snapshot.
                        let meta = store_clone.load();
                        let mut entries = entries_clone.write().expect("panicked");
                        for m in meta.entries.iter() {
                            if !entries.iter().any(|e| e.id == m.id) {
                                let stats = m
                                    .frozen_stats
                                    .clone()
                                    .or_else(|| {
                                        conn_weak.upgrade().and_then(|c| {
                                            c.path(m.id).map(|p| p.stats())
                                        })
                                    })
                                    .unwrap_or_default();
                                entries.push(OwnedPathEntry {
                                    id: m.id,
                                    remote_addr: m.remote_addr.clone(),
                                    is_closed: m.is_closed,
                                    is_selected: m.is_selected,
                                    stats,
                                });
                            }
                        }
                        // Update selection state for existing entries.
                        for entry in entries.iter_mut() {
                            if let Some(m) = meta.entries.iter().find(|m| m.id == entry.id) {
                                entry.is_selected = m.is_selected;
                                if m.is_closed && !entry.is_closed {
                                    entry.is_closed = true;
                                    if let Some(frozen) = &m.frozen_stats {
                                        entry.stats = frozen.clone();
                                    }
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        PathStatsTracker {
            inner: Arc::new(PathStatsTrackerInner {
                entries,
                _task: AbortOnDropHandle::new(task),
            }),
        }
    }

    /// Returns all paths (live and abandoned) with their statistics.
    ///
    /// Live path stats reflect the last event update. For the most current stats
    /// on live paths, call [`PathStatsTracker::refresh`] first.
    ///
    /// Abandoned path stats are frozen from when the path was closed.
    pub fn all_paths(&self) -> Vec<OwnedPathEntry> {
        self.inner.entries.read().expect("panicked").to_vec()
    }

    /// Refreshes statistics for all live paths from the underlying QUIC connection.
    ///
    /// This is a no-op for closed paths (their stats are frozen) and if the
    /// connection has been dropped.
    ///
    /// Prefer calling [`Connection::refresh_path_stats`] instead of this method
    /// directly.
    ///
    /// [`Connection::refresh_path_stats`]: crate::endpoint::Connection::refresh_path_stats
    pub(crate) fn refresh_noq(&self, conn: &noq::Connection) {
        let mut entries = self.inner.entries.write().expect("panicked");
        for entry in entries.iter_mut() {
            if !entry.is_closed {
                if let Some(path) = conn.path(entry.id) {
                    entry.stats = path.stats();
                }
            }
        }
    }
}
