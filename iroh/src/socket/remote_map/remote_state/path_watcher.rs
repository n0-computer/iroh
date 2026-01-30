use std::task::Poll;

use iroh_base::TransportAddr;
use n0_future::time::Duration;
use n0_watcher::{Watchable, Watcher};
use quinn::WeakPathHandle;
use quinn_proto::PathId;
use smallvec::SmallVec;

use crate::{endpoint::PathStats, socket::transports};

/// List of [`PathInfo`] for a connection.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PathInfoList(SmallVec<[PathInfo; 4]>);

impl PathInfoList {
    /// TODO
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

#[derive(Debug)]
pub struct PathInfoListIntoIter(smallvec::IntoIter<[PathInfo; 4]>);

impl IntoIterator for PathInfoList {
    type Item = PathInfo;

    type IntoIter = PathInfoListIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        PathInfoListIntoIter(self.0.into_iter())
    }
}

impl Iterator for PathInfoListIntoIter {
    type Item = PathInfo;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[derive(Clone, Debug)]
pub struct PathWatcher {
    paths: n0_watcher::Direct<PathInfoList>,
    selected_path: n0_watcher::Direct<Option<transports::Addr>>,
    current: PathInfoList,
}

impl PathWatcher {
    fn apply_selected_path(&mut self) {
        if let Some(selected_path) = self.selected_path.peek() {
            for path in self.current.0.iter_mut() {
                path.is_selected = selected_path.is_transport_addr(&path.remote_addr);
            }
        }
    }
}

impl Watcher for PathWatcher {
    type Value = PathInfoList;

    fn update(&mut self) -> bool {
        let mut updated = false;
        if self.paths.update() {
            self.current = self.paths.peek().clone();
            updated = true;
        }
        if self.selected_path.update() {
            updated = true;
        }
        if updated {
            self.apply_selected_path();
        }
        updated
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
        if poll_paths.is_ready() {
            self.current = self.paths.peek().clone();
            self.apply_selected_path();
            Poll::Ready(Ok(()))
        } else if poll_selected.is_ready() {
            self.apply_selected_path();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

/// TODO
#[derive(derive_more::Debug, Clone)]
pub struct PathInfo {
    handle: WeakPathHandle,
    remote_addr: TransportAddr,
    is_selected: bool,
    pub(super) is_closed: bool,
    pub(super) is_abandoned: bool,
}

impl PartialEq for PathInfo {
    fn eq(&self, other: &Self) -> bool {
        self.handle.id() == other.handle.id()
            && self.remote_addr == other.remote_addr
            && self.is_selected == other.is_selected
            && self.is_closed == other.is_closed
            && self.is_abandoned == other.is_abandoned
    }
}

impl Eq for PathInfo {}

impl PathInfo {
    pub(crate) fn new(
        conn: &quinn::Connection,
        id: PathId,
        remote_addr: TransportAddr,
        selected_path: Option<&transports::Addr>,
    ) -> Option<Self> {
        let path = conn.path(id)?;
        let is_closed = path.status().is_err();
        let handle = path.weak_handle();
        let is_selected = selected_path
            .as_ref()
            .map(|addr| addr.is_transport_addr(&remote_addr))
            .unwrap_or(false);
        Some(PathInfo {
            handle,
            remote_addr,
            is_selected,
            is_closed,
            is_abandoned: false,
        })
    }
    /// Returns the [`PathId`] of this path.
    pub fn id(&self) -> PathId {
        self.handle.id()
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
    /// Returns empty stats if the connection is dropped.
    pub fn stats(&self) -> PathStats {
        self.handle.upgrade().map(|p| p.stats()).unwrap_or_default()
    }

    /// Current best estimate of this paths's latency (round-trip-time)
    pub fn rtt(&self) -> Duration {
        self.stats().rtt
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PathWatchable {
    paths: Watchable<PathInfoList>,
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
        let Some(info) = PathInfo::new(conn, id, remote_addr, self.selected_path.get().as_ref())
        else {
            return;
        };
        let mut value = self.paths.get();
        value.0.push(info);

        if !self.paths.has_watchers() {
            value.0.retain(|p| !p.is_abandoned);
        }

        self.paths.set(value).ok();
    }

    pub(super) fn update(&self, id: PathId, f: impl Fn(&mut PathInfo) -> bool) {
        let mut value = self.paths.get();
        value
            .0
            .retain_mut(|item| if item.id() == id { f(item) } else { true });

        if !self.paths.has_watchers() {
            value.0.retain(|p| !p.is_abandoned);
        }

        self.paths.set(value).ok();
    }

    pub(crate) fn watch(&self) -> PathWatcher {
        let paths = self.paths.watch();
        let current = paths.peek().clone();
        let mut watcher = PathWatcher {
            paths,
            selected_path: self.selected_path.watch(),
            current,
        };
        watcher.apply_selected_path();
        watcher
    }
}
