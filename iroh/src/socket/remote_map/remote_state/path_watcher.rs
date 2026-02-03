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

type PathDataList = SmallVec<[PathData; 4]>;

/// Watcher for the open paths and selected transmission path in a connection.
#[derive(Clone, Debug)]
pub struct PathWatcher {
    paths: n0_watcher::Direct<PathDataList>,
    selected_path: n0_watcher::Direct<Option<transports::Addr>>,
    current: PathInfoList,
}

impl PathWatcher {
    fn update_current(&mut self) {
        let selected_path = self.selected_path.peek();
        let data = self.paths.peek().clone();
        let current = data
            .into_iter()
            .map(|data| PathInfo::new(data, selected_path.as_ref()))
            .collect();
        self.current = PathInfoList(current)
    }
}

impl Watcher for PathWatcher {
    type Value = PathInfoList;

    fn update(&mut self) -> bool {
        if self.paths.update() || self.selected_path.update() {
            self.update_current();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> &Self::Value {
        &self.current
    }

    fn is_connected(&self) -> bool {
        self.paths.is_connected() && self.selected_path.is_connected()
    }

    fn poll_updated(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), n0_watcher::Disconnected>> {
        let poll_paths = self.paths.poll_updated(cx)?;
        let poll_selected = self.selected_path.poll_updated(cx)?;
        if poll_paths.is_ready() || poll_selected.is_ready() {
            self.update_current();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
struct PathData {
    handle: WeakPathHandle,
    remote_addr: TransportAddr,
    is_closed: bool,
    is_abandoned: bool,
}

impl PathData {
    fn new(conn: &quinn::Connection, id: PathId, remote_addr: TransportAddr) -> Option<Self> {
        let path = conn.path(id)?;
        Some(PathData {
            handle: path.weak_handle(),
            remote_addr,
            is_closed: path.status().is_err(),
            is_abandoned: false,
        })
    }
}

/// Information about a network transmission path used by a [`Connection`].
///
/// [`Connection`]: crate::endpoint::Connection
#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct PathInfo {
    data: PathData,
    is_selected: bool,
}

impl PathInfo {
    fn new(data: PathData, selected_path: Option<&transports::Addr>) -> Self {
        let is_selected = selected_path
            .as_ref()
            .map(|addr| addr.is_transport_addr(&data.remote_addr))
            .unwrap_or(false);
        PathInfo { data, is_selected }
    }

    /// Returns the [`PathId`] of this path.
    pub fn id(&self) -> PathId {
        self.data.handle.id()
    }

    /// The remote transport address used by this network path.
    pub fn remote_addr(&self) -> &TransportAddr {
        &self.data.remote_addr
    }

    /// Returns `true` if this path is currently the main transmission path for this [`Connection`].
    ///
    /// [`Connection`]: crate::endpoint::Connection
    pub fn is_selected(&self) -> bool {
        self.is_selected
    }

    /// Returns `true` if this path is closed.
    pub fn is_closed(&self) -> bool {
        self.data.is_closed
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
        self.data.handle.upgrade().map(|p| p.stats())
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
/// This contains a watchable over a [`PathDataList`], and a watchable over the selected path for a remote.
#[derive(Debug, Clone)]
pub(crate) struct PathWatchable {
    paths: Watchable<PathDataList>,
    selected_path: Watchable<Option<transports::Addr>>,
}

impl PathWatchable {
    pub(super) fn new(selected_path: Watchable<Option<transports::Addr>>) -> Self {
        Self {
            paths: Watchable::new(Default::default()),
            selected_path,
        }
    }

    pub(super) fn insert(&self, conn: &quinn::Connection, id: PathId, remote_addr: TransportAddr) {
        if let Some(data) = PathData::new(conn, id, remote_addr) {
            self.update(move |list| list.push(data));
        }
    }

    pub(super) fn set_closed(&self, id: PathId) {
        self.update(|list| {
            if let Some(item) = list.iter_mut().find(|p| p.handle.id() == id) {
                item.is_closed = true;
            }
        });
    }

    /// Mark a path as abandoned.
    ///
    /// If there are no watchers, the path will be removed from the watchable's value.
    /// If there are watchers, the path will not be removed so that the watcher can still access the path's stats.
    pub(super) fn set_abandoned(&self, id: PathId) {
        self.update(|list| {
            if let Some(item) = list.iter_mut().find(|p| p.handle.id() == id) {
                item.is_closed = true;
                item.is_abandoned = true;
            }
        });
    }

    /// Update the watchable's value through a closure.
    ///
    /// After the update is performed, and if there are currently no watchers, data for abandoned paths
    /// is removed from the path list.
    fn update(&self, f: impl FnOnce(&mut SmallVec<[PathData; 4]>)) {
        let mut value = self.paths.get();
        f(&mut value);
        if !self.paths.has_watchers() {
            value.retain(|p| !p.is_abandoned);
            value.shrink_to_fit();
        }
        self.paths.set(value).ok();
    }

    pub(crate) fn watch(&self) -> PathWatcher {
        let mut watcher = PathWatcher {
            paths: self.paths.watch(),
            selected_path: self.selected_path.watch(),
            current: Default::default(),
        };
        watcher.update_current();
        watcher
    }
}
