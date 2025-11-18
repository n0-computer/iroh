//! The state kept for each network path to a remote endpoint.

use std::collections::{HashMap, VecDeque};

use n0_error::e;
use n0_future::time::Instant;
use rustc_hash::FxHashMap;
use tokio::sync::oneshot;
use tracing::{debug, trace, warn};

use super::Source;
use crate::{disco::TransactionId, discovery::DiscoveryError, magicsock::transports};

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
    /// Pending requests from [`Self::resolve_remote`].
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

    /// Records a sent disco ping for a path.
    pub(super) fn disco_ping_sent(&mut self, addr: transports::Addr, tx_id: TransactionId) {
        let path = self.paths.entry(addr.clone()).or_default();
        path.ping_sent = Some(tx_id);
    }

    /// Records a received disco pong for a path.
    ///
    /// Returns `true` if we have sent a ping with `tx_id` on the same path.
    pub(super) fn disco_pong_received(
        &mut self,
        src: &transports::Addr,
        tx_id: TransactionId,
    ) -> bool {
        let Some(state) = self.paths.get(src) else {
            warn!(path = ?src, ?self.paths, "ignoring DISCO Pong for unknown path");
            return false;
        };
        if state.ping_sent != Some(tx_id) {
            debug!(path = ?src, ?state.ping_sent, pong_tx = ?tx_id, "ignoring unknown DISCO Pong for path");
            false
        } else {
            true
        }
    }

    /// Notifies that a discovery run has finished.
    ///
    /// This will emit pending resolve requests.
    pub(super) fn discovery_finished(&mut self, error: Option<DiscoveryError>) {
        self.emit_pending_resolve_requests(error);
    }

    /// Returns an iterator over all paths and their state.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&transports::Addr, &PathState)> {
        self.paths.iter()
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
/// the [`RemoteStateActor::paths`] map.
#[derive(Debug, Default)]
pub(super) struct PathState {
    /// How we learned about this path, and when.
    ///
    /// We keep track of only the latest [`Instant`] for each [`Source`], keeping the size
    /// of the map of sources down to one entry per type of source.
    pub(super) sources: HashMap<Source, Instant>,
    /// The last ping sent on this path.
    pub(super) ping_sent: Option<TransactionId>,
}
