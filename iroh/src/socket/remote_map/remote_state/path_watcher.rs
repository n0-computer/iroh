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
pub struct PathInfoListIntoIter(smallvec::IntoIter<[PathInfo; 4]>);

impl IntoIterator for PathInfoList {
    type Item = PathInfo;
    type IntoIter = PathInfoListIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        PathInfoListIntoIter(self.0.into_iter())
    }
}

impl IntoIterator for PathWatcher {
    type Item = PathInfo;
    type IntoIter = PathInfoListIntoIter;

    fn into_iter(mut self) -> Self::IntoIter {
        self.get().into_iter()
    }
}

impl Iterator for PathInfoListIntoIter {
    type Item = PathInfo;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathWatchValue {
    paths: SmallVec<[PathInfo; 4]>,
    closed: bool,
}

/// Watcher for the open paths and selected transmission path in a connection.
#[derive(Clone, Debug)]
pub struct PathWatcher {
    paths_watcher: n0_watcher::Direct<PathWatchValue>,
    selected_path_watcher: n0_watcher::Direct<Option<transports::Addr>>,
    current_paths: PathInfoList,
    current_selected_path: Option<transports::Addr>,
}

impl PathWatcher {
    fn update_selected(&mut self) {
        if let Some(path) = self.selected_path_watcher.peek()
            && Some(path) != self.current_selected_path.as_ref()
        {
            self.current_selected_path = Some(path.clone());
        }

        if let Some(selected_path) = self.current_selected_path.as_ref() {
            for p in self.current_paths.0.iter_mut() {
                p.is_selected = selected_path.is_transport_addr(p.remote_addr());
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
        if self.paths_watcher.peek().closed {
            return Poll::Ready(Err(n0_watcher::Disconnected));
        }

        let mut is_ready = false;

        if self.paths_watcher.poll_updated(cx)?.is_ready() {
            self.current_paths = PathInfoList(self.paths_watcher.peek().paths.clone());
            is_ready = true;
        }

        if self.selected_path_watcher.poll_updated(cx)?.is_ready() {
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
    is_closed: bool,
    is_abandoned: bool,
    is_selected: bool,
}

impl PathInfo {
    fn new(conn: &quinn::Connection, id: PathId, remote_addr: TransportAddr) -> Option<Self> {
        let path = conn.path(id)?;
        Some(PathInfo {
            path: path.weak_handle(),
            remote_addr,
            is_closed: path.status().is_err(),
            is_abandoned: false,
            is_selected: false,
        })
    }

    /// Returns the [`PathId`] of this path.
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
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }

    /// Whether this is an IP transport address.
    pub fn is_ip(&self) -> bool {
        self.remote_addr().is_ip()
    }

    /// Whether this is a transport address via a relay server.
    pub fn is_relay(&self) -> bool {
        self.remote_addr().is_relay()
    }

    /// Returns stats for this transmission path.
    ///
    /// Returns `None` if the underlying connection has been dropped.
    pub fn stats(&self) -> Option<PathStats> {
        self.path.upgrade().map(|p| p.stats())
    }

    /// Current best estimate of this paths's latency (round-trip-time)
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
    pub(super) fn disconnect(&self) {
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

    /// Marks a path as closed.
    pub(super) fn set_closed(&self, id: PathId) {
        self.update(|list| {
            if let Some(item) = list.iter_mut().find(|p| p.path.id() == id) {
                item.is_closed = true;
            }
        });
    }

    /// Marks a path as abandoned.
    ///
    /// If there are no watchers, the path will be removed from the watchable's value.
    /// If there are watchers, the path will not be removed so that the watcher can still access the path's stats.
    pub(super) fn set_abandoned(&self, id: PathId) {
        self.update(|list| {
            if let Some(item) = list.iter_mut().find(|p| p.path.id() == id) {
                item.is_closed = true;
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
        let paths = self.paths.watch();
        let mut watcher = PathWatcher {
            current_paths: PathInfoList(paths.peek().paths.clone()),
            paths_watcher: paths,
            selected_path_watcher: self.selected_path.watch(),
            current_selected_path: None,
        };
        watcher.update_selected();
        watcher
    }
}
