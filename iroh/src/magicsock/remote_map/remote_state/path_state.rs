//! The state kept for each network path to a remote endpoint.

use std::collections::{HashMap, VecDeque};

use n0_error::e;
use n0_future::time::Instant;
use rustc_hash::FxHashMap;
use tokio::sync::oneshot;
use tracing::trace;

use super::Source;
use crate::{discovery::DiscoveryError, magicsock::transports};

/// Map of all paths that we are aware of for a remote endpoint.
///
/// Also stores a list of resolve requests which are triggered once at least one path is known,
/// or once this struct is notified of a failed discovery run.
#[derive(Debug, Default)]
pub(super) struct RemotePathState {
    /// All possible paths we are aware of.
    ///
    /// These paths might be entirely impossible to use, since they are added by discovery
    /// mechanisms. The are only potentially usable.
    paths: FxHashMap<transports::Addr, PathState>,
    /// Pending resolve requests from [`Self::resolve_remote`].
    pending_resolve_requests: VecDeque<oneshot::Sender<Result<(), DiscoveryError>>>,
}

impl RemotePathState {
    /// Insert a new address into our list of potential paths.
    ///
    /// This will emit pending resolve requests.
    pub(super) fn insert(&mut self, addr: transports::Addr, source: Source) {
        self.paths
            .entry(addr)
            .or_default()
            .sources
            .insert(source.clone(), Instant::now());
        self.emit_pending_resolve_requests(None);
    }

    /// Inserts multiple addresses into our list of potential paths.
    ///
    /// This will emit pending resolve requests.
    pub(super) fn insert_multiple(
        &mut self,
        addrs: impl Iterator<Item = transports::Addr>,
        source: Source,
    ) {
        let now = Instant::now();
        for addr in addrs {
            self.paths
                .entry(addr)
                .or_default()
                .sources
                .insert(source.clone(), now);
        }
        trace!("added addressing information");
        self.emit_pending_resolve_requests(None);
    }

    /// Triggers `tx` immediately if there are any known paths, or store in the list of pending requests.
    ///
    /// The pending requests will be resolved once a path becomes known, or once discovery
    /// concludes without results, whichever comes first.
    ///
    /// Sends `Ok(())` over `tx` if there are any known paths, and a [`DiscoveryError`] if there are
    /// no known paths by the time a discovery run finished with an error or without results.
    pub(super) fn resolve_remote(&mut self, tx: oneshot::Sender<Result<(), DiscoveryError>>) {
        if !self.paths.is_empty() {
            tx.send(Ok(())).ok();
        } else {
            self.pending_resolve_requests.push_back(tx);
        }
    }

    /// Notifies that a discovery run has finished.
    ///
    /// This will emit pending resolve requests.
    pub(super) fn discovery_finished(&mut self, result: Result<(), DiscoveryError>) {
        self.emit_pending_resolve_requests(result.err());
    }

    /// Returns an iterator over the addresses of all paths.
    pub(super) fn addrs(&self) -> impl Iterator<Item = &transports::Addr> {
        self.paths.keys()
    }

    /// Replies to all pending resolve requests.
    ///
    /// This is a no-op if no requests are queued. Replies `Ok` if we have any known paths,
    /// otherwise with the provided `discovery_error` or with [`DiscoveryError::NoResults`].
    fn emit_pending_resolve_requests(&mut self, discovery_error: Option<DiscoveryError>) {
        if self.pending_resolve_requests.is_empty() {
            return;
        }
        let result = match (self.paths.is_empty(), discovery_error) {
            (false, _) => Ok(()),
            (true, Some(err)) => Err(err),
            (true, None) => Err(e!(DiscoveryError::NoResults)),
        };
        for tx in self.pending_resolve_requests.drain(..) {
            tx.send(result.clone()).ok();
        }
    }
}

/// The state of a single path to the remote endpoint.
///
/// Each path is identified by the destination [`transports::Addr`] and they are stored in
/// the [`RemotePathState`] map at [`RemoteStateActor::paths`].
///
/// [`RemoteStateActor::paths`]: super::RemoteStateActor::paths
#[derive(Debug, Default)]
pub(super) struct PathState {
    /// How we learned about this path, and when.
    ///
    /// We keep track of only the latest [`Instant`] for each [`Source`], keeping the size
    /// of the map of sources down to one entry per type of source.
    pub(super) sources: HashMap<Source, Instant>,
}
