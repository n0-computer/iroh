use std::task::Poll;

use iroh_base::TransportAddr;
use n0_future::time::Duration;
use n0_watcher::{Watchable, Watcher};
use quinn::WeakPathHandle;
use quinn_proto::PathId;
use smallvec::SmallVec;

use crate::{endpoint::PathStats, socket::transports};

/// List of [`PathInfo`] for the network paths of a [`Connection`].
///
/// This struct implements [`IntoIterator`].
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PathInfoList(SmallVec<[PathInfo; 4]>);

impl PathInfoList {
    /// Returns an iterator over the path infos.
    pub fn iter(&self) -> impl Iterator<Item = &PathInfo> {
        self.0.iter()
    }

    /// Returns `true` if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of paths.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Iterator returned from [`PathInfoList::into_iter`].
#[derive(Debug)]
pub struct PathInfoListIter(smallvec::IntoIter<[PathInfo; 4]>);

impl IntoIterator for PathInfoList {
    type Item = PathInfo;
    type IntoIter = PathInfoListIter;

    fn into_iter(self) -> Self::IntoIter {
        PathInfoListIter(self.0.into_iter())
    }
}

impl IntoIterator for PathWatcher {
    type Item = PathInfo;
    type IntoIter = PathInfoListIter;

    fn into_iter(mut self) -> Self::IntoIter {
        self.get().into_iter()
    }
}

impl Iterator for PathInfoListIter {
    type Item = PathInfo;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathWatchValue {
    /// The list of network transmission paths.
    paths: SmallVec<[PathInfo; 4]>,
    /// Set to `true` before the `RemoteStateActor` drops the `PathWatchable`.
    ///
    /// Afterwards, no further updates will be received.
    closed: bool,
}

/// Watcher for the open paths and selected transmission path in a connection.
///
/// See [`Connection::paths`] for details.
///
/// [`Connection::paths`]: crate::endpoint::Connection::paths
#[derive(Clone, Debug)]
pub struct PathWatcher {
    paths_watcher: n0_watcher::Direct<PathWatchValue>,
    selected_path_watcher: n0_watcher::Direct<Option<transports::Addr>>,
    current_paths: PathInfoList,
    current_selected_path: Option<transports::Addr>,
}

impl PathWatcher {
    /// Update the selected path from [`Self::selected_path_watcher`].
    ///
    /// This sets [`Self::current_selected_path`] to the current value from
    /// [`Self::selected_path_watcher`], but only if the latter is non-empty.
    ///
    /// It also updates the [`PathInfo::is_selected`] field for all
    /// current paths.
    fn update_selected(&mut self) {
        if let Some(path) = self.selected_path_watcher.peek()
            && Some(path) != self.current_selected_path.as_ref()
        {
            self.current_selected_path = Some(path.clone());
        }

        if let Some(selected_path) = self.current_selected_path.as_ref() {
            for p in self.current_paths.0.iter_mut() {
                p.is_selected = selected_path == p.remote_addr();
            }
        }
    }
}

impl Watcher for PathWatcher {
    type Value = PathInfoList;

    fn update(&mut self) -> bool {
        let mut updated = false;

        if self.paths_watcher.update() {
            updated = true;
            self.current_paths = PathInfoList(self.paths_watcher.peek().paths.clone());
        }

        if self.selected_path_watcher.update() {
            // `Self::current_selected_path` is set in `Self::update_selected` below.
            updated = true;
        }

        if updated {
            self.update_selected();
        }

        updated
    }

    fn peek(&self) -> &Self::Value {
        &self.current_paths
    }

    fn is_connected(&self) -> bool {
        self.paths_watcher.is_connected() && self.selected_path_watcher.is_connected()
    }

    fn poll_updated(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), n0_watcher::Disconnected>> {
        // When the `closed` flag is set on the watched value, we return `Disconnected`
        // to end the watcher update stream. We can't rely on the watchable being dropped,
        // because the watchable is cloned into the `Connection` and thus will stay alive
        // until the last clone of a connection is dropped. However, we want the watcher
        // to end once the connection closes. Therefore we use a manual signal here instead.
        if self.paths_watcher.peek().closed {
            return Poll::Ready(Err(n0_watcher::Disconnected));
        }

        let mut is_ready = false;

        if self.paths_watcher.poll_updated(cx)?.is_ready() {
            self.current_paths = PathInfoList(self.paths_watcher.peek().paths.clone());
            is_ready = true;
        }

        if self.selected_path_watcher.poll_updated(cx)?.is_ready() {
            // `Self::current_selected_path` is set in `Self::update_selected` below.
            is_ready = true;
        }

        if is_ready {
            self.update_selected();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

/// Information about a network transmission path used by a [`Connection`].
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct PathInfo {
    #[debug("{}", path.id())]
    path: WeakPathHandle,
    remote_addr: TransportAddr,
    is_abandoned: bool,
    is_selected: bool,
}

impl PathInfo {
    fn new(conn: &quinn::Connection, id: PathId, remote_addr: TransportAddr) -> Option<Self> {
        let path = conn.path(id)?;
        Some(PathInfo {
            path: path.weak_handle(),
            remote_addr,
            is_abandoned: path.status().is_err(),
            is_selected: false,
        })
    }

    /// Returns the [`PathId`] of this path.
    ///
    /// Path ids are unique-per-connection identifiers for a network transmission path. A path id will never
    /// be reused within a connection.
    pub fn id(&self) -> PathId {
        self.path.id()
    }

    /// The remote transport address used by this network path.
    pub fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    /// Returns `true` if this path is currently the main transmission path for this [`Connection`].
    ///
    /// [`Connection`]: crate::endpoint::Connection
    pub fn is_selected(&self) -> bool {
        self.is_selected
    }

    /// Returns `true` if this path is closed.
    ///
    /// A path is considered closed as soon as the local endpoint has abandoned this path.
    /// A closed path will remain closed forever, so once this returns `true` it will never
    /// return `false` afterwards. If the transmission path becomes available again in the future,
    /// a new path might be opened, but a closed path will never be reopened.
    pub fn is_closed(&self) -> bool {
        self.is_abandoned
    }

    /// Whether this is an IP transport path.
    pub fn is_ip(&self) -> bool {
        self.remote_addr().is_ip()
    }

    /// Whether this is a relay transport path.
    pub fn is_relay(&self) -> bool {
        self.remote_addr().is_relay()
    }

    /// Returns stats for this transmission path.
    ///
    /// Returns `None` if the underlying connection has been dropped.
    pub fn stats(&self) -> Option<PathStats> {
        self.path.upgrade().map(|p| p.stats())
    }

    /// Current best estimate of this paths's latency (round-trip-time).
    ///
    /// Returns `None` if the underlying connection has been dropped.
    pub fn rtt(&self) -> Option<Duration> {
        self.stats().map(|s| s.rtt)
    }
}

/// Watchable for the network paths in a connection.
///
/// This contains a watchable over a [`PathWatchValue`], and a watchable over the selected path for a remote.
///
/// This struct is owned by the [`super::ConnectionState`] and also cloned into the [`Connection`].
/// Most methods are `pub(super)`. The only method that may be called from [`Connection`] is
/// [`Self::watch`].
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(Debug, Clone)]
pub(crate) struct PathWatchable {
    paths: Watchable<PathWatchValue>,
    selected_path: Watchable<Option<transports::Addr>>,
}

impl PathWatchable {
    pub(super) fn new(selected_path: Watchable<Option<transports::Addr>>) -> Self {
        let value = PathWatchValue {
            paths: Default::default(),
            closed: false,
        };
        Self {
            paths: Watchable::new(value),
            selected_path,
        }
    }

    /// Mark the path watchable as closed.
    ///
    /// Once called, watchers will not receive further updates. Must be called once the
    /// [`super::ConnectionState`] that owns this [`PathWatchable`] is dropped.
    ///
    /// We can't rely on dropping the [`Watchable`] to close the watchers, because the
    /// `Watchable` is cloned into the [`crate::endpoint::Connection`], and thus may stay
    /// alive even after we dropped the [`super::ConnectionState`], which is the only place
    /// that can update the [`PathWatchable].
    pub(super) fn close(&self) {
        let mut value = self.paths.get();
        value.closed = true;
        self.paths.set(value).ok();
    }

    /// Inserts a new path.
    pub(super) fn insert(&self, conn: &quinn::Connection, id: PathId, remote_addr: TransportAddr) {
        if let Some(data) = PathInfo::new(conn, id, remote_addr) {
            self.update(move |list| list.push(data));
        }
    }

    /// Marks a path as abandoned.
    ///
    /// If there are no watchers, the path will be removed from the watchable's value.
    /// If there are watchers, the path will not be removed so that the watcher can still access the path's stats.
    pub(super) fn set_abandoned(&self, id: PathId) {
        self.update(|list| {
            if let Some(item) = list.iter_mut().find(|p| p.path.id() == id) {
                item.is_abandoned = true;
            }
        });
    }

    /// Updates the watchable's value through a closure.
    ///
    /// After the update is performed, and if there are currently no watchers, data for abandoned paths
    /// is removed from the path list.
    fn update(&self, f: impl FnOnce(&mut SmallVec<[PathInfo; 4]>)) {
        let mut value = self.paths.get();
        f(&mut value.paths);
        if !self.paths.has_watchers() {
            value.paths.retain(|p| !p.is_abandoned);
            value.paths.shrink_to_fit();
        }
        self.paths.set(value).ok();
    }

    /// Returns a [`PathWatcher`] for this watchable.
    pub(crate) fn watch(&self) -> PathWatcher {
        let paths_watcher = self.paths.watch();
        let selected_path_watcher = self.selected_path.watch();
        let mut watcher = PathWatcher {
            current_paths: PathInfoList(paths_watcher.peek().paths.clone()),
            // Set via `update_selected` below.
            current_selected_path: None,
            paths_watcher,
            selected_path_watcher,
        };
        watcher.update_selected();
        watcher
    }
}
