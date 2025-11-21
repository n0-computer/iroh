//! The state kept for each network path to a remote endpoint.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};

use n0_error::e;
use n0_future::time::Instant;
use rustc_hash::FxHashMap;
use tokio::sync::oneshot;
use tracing::trace;

use super::Source;
use crate::{discovery::DiscoveryError, magicsock::transports};

/// Number of addresses that are not active that we keep around per endpoint.
pub(super) const MAX_INACTIVE_IP_ADDRESSES: usize = 20;

/// Max duration of how long ago we learned about this source before we are willing
/// to prune it, if the path for this ip address is inactive.
/// TODO(ramfox): fix this comment it's not clear enough
const LAST_SOURCE_PRUNE_DURATION: Duration = Duration::from_secs(120);

/// Duration after sending a ping in which we assume holepunching failed.
const PING_TIMEOUT: Duration = Duration::from_secs(30);

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

    /// Record in the [`PathState`] for the given [`Addr`], that we have
    /// successfully holepunched.
    ///
    /// If this path does exist, no information is added.
    ///
    /// [`Addr`]: transports::Addr
    pub(super) fn holepunched(&mut self, addr: &transports::Addr) {
        if let Some(path) = self.paths.get_mut(addr) {
            path.holepunched = true;
        }
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

    /// Returns whether this stores any addresses.
    pub(super) fn is_empty(&self) -> bool {
        self.paths.is_empty()
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

    /// TODO: fix up docs once review indicates this is actually
    /// the criteria for pruning.
    pub(super) fn prune_ip_paths<'a>(
        &mut self,
        pending: &VecDeque<transports::Addr>,
        selected_path: &Option<transports::Addr>,
        open_paths: impl Iterator<Item = &'a transports::Addr>,
    ) {
        prune_ip_paths(&mut self.paths, pending, selected_path, open_paths);
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
    /// The last ping sent on this path.
    pub(super) ping_sent: Option<Instant>,
    /// Last time we successfully holepunched.
    pub(super) holepunched: bool,
}

impl PathState {
    /// Returns true if a ping was sent in the last [`PING_TIMEOUT`] amount of time.
    fn ping_in_process(&self, now: &Instant) -> bool {
        if let Some(ping_sent) = self.ping_sent {
            if ping_sent + PING_TIMEOUT > *now {
                return true;
            }
        }
        false
    }
}

fn prune_ip_paths<'a>(
    paths: &mut FxHashMap<transports::Addr, PathState>,
    pending: &VecDeque<transports::Addr>,
    selected_path: &Option<transports::Addr>,
    open_paths: impl Iterator<Item = &'a transports::Addr>,
) {
    // if the total number of paths, relay or ip, is less
    // than the max inactive ip addrs we allow, bail early
    if paths.len() < MAX_INACTIVE_IP_ADDRESSES {
        return;
    };

    let ip_paths: HashSet<_> = paths.keys().filter(|p| p.is_ip()).collect();

    let mut protected_paths = HashSet::new();
    for addr in pending {
        protected_paths.insert(addr);
    }
    if let Some(path) = selected_path {
        protected_paths.insert(path);
    }
    for path in open_paths {
        protected_paths.insert(path);
    }

    let inactive_paths: HashSet<_> = ip_paths
        .difference(&protected_paths)
        // cloned here so we can use `paths.retain` later
        .map(|&addr| addr.clone())
        .collect();

    if inactive_paths.len() < MAX_INACTIVE_IP_ADDRESSES {
        return;
    }

    let now = Instant::now();

    paths.retain(|addr, state| {
        if inactive_paths.contains(addr) {
            keep_path(state, &now)
        } else {
            // keep all active paths
            true
        }
    });
}

/// Based on the [`PathState`], returns true if we should keep this path.
///
/// Currently we have four criteria:
/// 1) This path has successfully holepunched, ever
/// 2) We have never attempted to holepunch on this path
/// 3) We are in the process of holepunching
/// 4) The last time we learned about this address was greater than LAST_SOURCE_PRUNE_DURATION
///
/// In other words, paths that have never successfully holepunched, that we learned about
/// over `LAST_SOURCE_PRUNE_DURATION` ago, should not be kept.
fn keep_path(state: &PathState, now: &Instant) -> bool {
    // if we have never successfully holepunched
    state.holepunched
        || state.ping_sent.is_none()
        || state.ping_in_process(now)
        || state
            .sources
            .values()
            // only keep it if this path contains recent sources
            .any(|instant| *instant + LAST_SOURCE_PRUNE_DURATION > *now)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{Ipv4Addr, SocketAddr},
    };

    use n0_error::Result;
    use n0_future::time::{Duration, Instant};
    use rustc_hash::FxHashMap;

    use super::*;
    use crate::magicsock::{remote_map::Private, transports};

    /// Create a test IP address with specific port
    fn test_ip_addr(port: u16) -> transports::Addr {
        transports::Addr::Ip(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        ))
    }

    /// Create a PathState with sources at a specific time offset
    fn test_path_state(time_offset: Duration, sent_ping: Option<Duration>) -> PathState {
        let mut state = PathState::default();
        if let Some(sent_ping_ago) = sent_ping {
            state.ping_sent = Some(Instant::now() - sent_ping_ago);
        }
        state.sources.insert(
            Source::Connection { _0: Private },
            Instant::now() - time_offset,
        );
        state
    }

    #[test]
    fn test_prune_ip_paths_too_few_total_paths() -> Result {
        // create fewer than MAX_INACTIVE_IP_ADDRESSES paths
        let mut paths = FxHashMap::default();
        for i in 0..15 {
            paths.insert(
                test_ip_addr(i),
                test_path_state(Duration::from_secs(0), None),
            );
        }

        let pending = VecDeque::new();
        let selected_path = None;
        let open_paths = Vec::new();

        let initial_len = paths.len();
        // should not prune because we have fewer than MAX_INACTIVE_IP_ADDRESSES paths
        prune_ip_paths(&mut paths, &pending, &selected_path, open_paths.iter());
        assert_eq!(
            paths.len(),
            initial_len,
            "Expected no paths to be pruned when total IP paths < MAX_INACTIVE_IP_ADDRESSES"
        );

        Ok(())
    }

    #[test]
    fn test_prune_ip_paths_too_few_inactive_paths() -> Result {
        // create MAX_INACTIVE_IP_ADDRESSES + 5 paths
        let mut paths = FxHashMap::default();
        for i in 0..25 {
            paths.insert(
                test_ip_addr(i),
                test_path_state(Duration::from_secs(0), None),
            );
        }

        // mark 10 of them as "active" by adding them to open_paths
        let open_paths: Vec<transports::Addr> = (0..10).map(test_ip_addr).collect();

        let pending = VecDeque::new();
        let selected_path = None;

        let initial_len = paths.len();
        // now we have 25 total paths, but only 15 inactive paths (25 - 10 = 15)
        // which is less than MAX_INACTIVE_IP_ADDRESSES (20)
        prune_ip_paths(&mut paths, &pending, &selected_path, open_paths.iter());
        assert_eq!(
            paths.len(),
            initial_len,
            "Expected no paths to be pruned when inactive paths < MAX_INACTIVE_IP_ADDRESSES"
        );

        Ok(())
    }

    #[test]
    fn test_prune_ip_paths_prunes_old_inactive_paths() -> Result {
        // create MAX_INACTIVE_IP_ADDRESSES + 10 paths
        let mut paths = FxHashMap::default();

        // add 20 paths with recent sources (within 2 minutes)
        for i in 0..20 {
            paths.insert(
                test_ip_addr(i),
                test_path_state(
                    Duration::from_secs(60),       // learn about this path 1 min ago
                    Some(Duration::from_secs(60)), // sent ping 1 min ago
                ),
            );
        }

        // add 10 paths with old sources (more than 2 minutes ago)
        for i in 20..30 {
            paths.insert(
                test_ip_addr(i),
                test_path_state(
                    Duration::from_secs(180), // learned about this path 3 mins ago
                    Some(Duration::from_secs(60)),
                ), // sent ping 1 min ago
            );
        }

        let pending = VecDeque::new();
        let selected_path = None;
        let open_paths = Vec::new();

        // we have 30 total paths, all inactive
        // paths with sources older than LAST_SOURCE_PRUNE_DURATION should be pruned
        prune_ip_paths(&mut paths, &pending, &selected_path, open_paths.iter());

        // we should have kept the 20 recent paths
        assert_eq!(
            paths.len(),
            20,
            "Expected to keep 20 paths with recent sources"
        );

        // verify that the kept paths are the ones with recent sources
        for i in 0..20 {
            let addr = test_ip_addr(i);
            assert!(
                paths.contains_key(&addr),
                "Expected to keep path with recent source: {:?}",
                addr
            );
        }

        // verify that the old paths were removed
        for i in 20..30 {
            let addr = test_ip_addr(i);
            assert!(
                !paths.contains_key(&addr),
                "Expected to prune path with old source: {:?}",
                addr
            );
        }

        Ok(())
    }

    #[test]
    fn test_prune_ip_paths_protects_selected_and_open_paths() -> Result {
        // create MAX_INACTIVE_IP_ADDRESSES + 10 paths, all with old sources
        let mut paths = FxHashMap::default();
        for i in 0..30 {
            paths.insert(
                test_ip_addr(i),
                test_path_state(
                    Duration::from_secs(180),      // learned about this path 3 mins ago
                    Some(Duration::from_secs(60)), // sent ping 1 min ago
                ),
            );
        }

        // mark path 3 as holepunched
        paths.get_mut(&test_ip_addr(3)).unwrap().holepunched = true;

        // mark path 4 as having a recent ping (ping in process)
        paths.get_mut(&test_ip_addr(4)).unwrap().ping_sent = Some((
            TransactionId::default(),
            Instant::now() - Duration::from_secs(5),
        ));

        let pending = VecDeque::new();
        // mark one path as selected
        let selected_path = Some(test_ip_addr(0));
        // mark a few paths as open
        let open_paths = [test_ip_addr(1), test_ip_addr(2)];

        prune_ip_paths(&mut paths, &pending, &selected_path, open_paths.iter());

        // protected paths should still be in the result even though they have old sources
        assert!(
            paths.contains_key(&test_ip_addr(0)),
            "Expected to keep selected path even with old source"
        );
        assert!(
            paths.contains_key(&test_ip_addr(1)),
            "Expected to keep open path even with old source"
        );
        assert!(
            paths.contains_key(&test_ip_addr(2)),
            "Expected to keep open path even with old source"
        );
        assert!(
            paths.contains_key(&test_ip_addr(3)),
            "Expected to keep holepunched path even with old source"
        );
        assert!(
            paths.contains_key(&test_ip_addr(4)),
            "Expected to keep path with ping in process even with old source"
        );

        Ok(())
    }
}
