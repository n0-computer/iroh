//! The state kept for each network path to a remote endpoint.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use n0_error::e;
use n0_future::time::Instant;
use rustc_hash::FxHashMap;
use tokio::sync::oneshot;
use tracing::trace;

use super::{Source, TransportAddrInfo, TransportAddrUsage};
use crate::{
    address_lookup::Error as AddressLookupError, metrics::SocketMetrics, socket::transports,
};

/// Maximum number of IP paths we keep around per endpoint.
pub(super) const MAX_IP_PATHS: usize = 30;

/// Maximum number of inactive IP paths we keep around per endpoint.
///
/// These are paths that at one point been opened and are now closed.
pub(super) const MAX_INACTIVE_IP_PATHS: usize = 10;

/// Map of all paths that we are aware of for a remote endpoint.
///
/// Also stores a list of resolve requests which are triggered once at least one path is known,
/// or once this struct is notified of a failed Address Lookup run.
#[derive(Debug)]
pub(super) struct RemotePathState {
    /// All possible paths we are aware of.
    ///
    /// These paths might be entirely impossible to use, since they are added by Address Lookup
    /// mechanisms. The are only potentially usable.
    paths: FxHashMap<transports::Addr, PathState>,
    /// Pending resolve requests from [`Self::resolve_remote`].
    pending_resolve_requests: VecDeque<oneshot::Sender<Result<(), AddressLookupError>>>,
    metrics: Arc<SocketMetrics>,
}

/// Describes the usability of this path, i.e. whether it has ever been opened,
/// when it was closed, or if it has never been usable.
#[derive(Debug, Default)]
pub(super) enum PathStatus {
    /// This path is open and active.
    Open,
    /// This path was once opened, but was abandoned at the given [`Instant`].
    Inactive(Instant),
    /// This path was never usable (we attempted holepunching and it didn't work).
    Unusable,
    /// We have not yet attempted holepunching, or holepunching is currently in
    /// progress, so we do not know the usability of this path.
    #[default]
    Unknown,
}

impl RemotePathState {
    pub(super) fn new(metrics: Arc<SocketMetrics>) -> Self {
        Self {
            paths: Default::default(),
            pending_resolve_requests: Default::default(),
            metrics,
        }
    }

    pub(super) fn to_remote_addrs(&self) -> Vec<TransportAddrInfo> {
        self.paths
            .iter()
            .flat_map(|(addr, state)| {
                let usage = match state.status {
                    PathStatus::Open => TransportAddrUsage::Active,
                    PathStatus::Inactive(_) | PathStatus::Unusable | PathStatus::Unknown => {
                        TransportAddrUsage::Inactive
                    }
                };
                Some(TransportAddrInfo {
                    addr: addr.clone().into(),
                    usage,
                })
            })
            .collect()
    }

    /// Insert a new address of an open path into our list of paths.
    ///
    /// This will emit pending resolve requests and trigger pruning paths.
    pub(super) fn insert_open_path(&mut self, addr: transports::Addr, source: Source) {
        match addr {
            transports::Addr::Ip(_) => self.metrics.transport_ip_paths_added.inc(),
            transports::Addr::Relay(_, _) => self.metrics.transport_relay_paths_added.inc(),
        };
        let state = self.paths.entry(addr).or_default();
        state.status = PathStatus::Open;
        state.sources.insert(source.clone(), Instant::now());
        self.emit_pending_resolve_requests(None);
        self.prune_paths();
    }

    /// Mark a path as abandoned.
    ///
    /// If this path does not exist, it does nothing to the
    /// `RemotePathState`
    pub(super) fn abandoned_path(&mut self, addr: &transports::Addr) {
        if let Some(state) = self.paths.get_mut(addr) {
            if matches!(state.status, PathStatus::Open) {
                match addr {
                    transports::Addr::Ip(_) => self.metrics.transport_ip_paths_removed.inc(),
                    transports::Addr::Relay(_, _) => {
                        self.metrics.transport_relay_paths_removed.inc()
                    }
                };
            }
            match state.status {
                PathStatus::Open | PathStatus::Inactive(_) => {
                    state.status = PathStatus::Inactive(Instant::now());
                }
                PathStatus::Unusable | PathStatus::Unknown => {
                    state.status = PathStatus::Unusable;
                }
            }
        }
    }

    /// Inserts multiple addresses of unknown status into our list of potential paths.
    ///
    /// This will emit pending resolve requests and trigger pruning paths.
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
        self.prune_paths();
    }

    /// Triggers `tx` immediately if there are any known paths, or store in the list of pending requests.
    ///
    /// The pending requests will be resolved once a path becomes known, or once Address Lookup
    /// concludes without results, whichever comes first.
    ///
    /// Sends `Ok(())` over `tx` if there are any known paths, and an [`AddressLookupError`] if there are
    /// no known paths by the time a Address Lookup run finished with an error or without results.
    pub(super) fn resolve_remote(&mut self, tx: oneshot::Sender<Result<(), AddressLookupError>>) {
        if !self.paths.is_empty() {
            tx.send(Ok(())).ok();
        } else {
            self.pending_resolve_requests.push_back(tx);
        }
    }

    /// Notifies that a Address Lookup run has finished.
    ///
    /// This will emit pending resolve requests.
    pub(super) fn address_lookup_finished(&mut self, result: Result<(), AddressLookupError>) {
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
    /// otherwise with the provided `address_lookup_error` or with [`AddressLookupError::NoResults`].
    fn emit_pending_resolve_requests(&mut self, address_lookup_error: Option<AddressLookupError>) {
        if self.pending_resolve_requests.is_empty() {
            return;
        }
        let result = match (self.paths.is_empty(), address_lookup_error) {
            (false, _) => Ok(()),
            (true, Some(err)) => Err(err),
            (true, None) => Err(e!(AddressLookupError::NoResults)),
        };
        for tx in self.pending_resolve_requests.drain(..) {
            tx.send(result.clone()).ok();
        }
    }

    /// Prune paths.
    ///
    /// Should be invoked any time we insert a new path.
    ///
    /// We currently only prune IP paths. For more information on the criteria
    /// for when and which paths we prune, look at the [`prune_ip_paths`] function.
    pub(super) fn prune_paths(&mut self) {
        // right now we only prune IP paths
        prune_ip_paths(&mut self.paths);
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
    /// The usability status of this path.
    pub(super) status: PathStatus,
}

/// Prunes the IP paths in the paths HashMap.
///
/// Only prunes if the number of IP paths is above [`MAX_IP_PATHS`].
///
/// Keeps paths that are open or of unknown status.
///
/// Always prunes paths that have unsuccessfully holepunched.
///
/// Keeps [`MAX_INACTIVE_IP_PATHS`] of the most recently closed paths
/// that are not currently being used but have successfully been
/// holepunched previously.
///
/// This all ensures that:
///
/// - We do not have unbounded growth of paths.
/// - If we have many paths for this remote, we prune the paths that cannot hole punch.
/// - We do not prune holepunched paths that are currently not in use too quickly. For example, if a large number of untested paths are added at once, we will not immediately prune all of the unused, but valid, paths at once.
fn prune_ip_paths(paths: &mut FxHashMap<transports::Addr, PathState>) {
    // if the total number of paths is less than the max, bail early
    if paths.len() < MAX_IP_PATHS {
        return;
    }

    let ip_paths: Vec<_> = paths.iter().filter(|(addr, _)| addr.is_ip()).collect();

    // if the total number of ip paths is less than the max, bail early
    if ip_paths.len() < MAX_IP_PATHS {
        return;
    }

    // paths that were opened at one point but have previously been closed
    let mut inactive = Vec::with_capacity(ip_paths.len());
    // paths where we attempted hole punching but it not successful
    let mut failed = Vec::with_capacity(ip_paths.len());

    for (addr, state) in ip_paths {
        match state.status {
            PathStatus::Inactive(t) => {
                // paths where holepunching succeeded at one point, but the path was closed.
                inactive.push((addr.clone(), t));
            }
            PathStatus::Unusable => {
                // paths where holepunching has been attempted and failed.
                failed.push(addr.clone());
            }
            _ => {
                // ignore paths that are open or the status is unknown
            }
        }
    }

    // All paths are bad, don't prune all of them.
    //
    // This implies that `inactive` is empty.
    if failed.len() == paths.len() {
        // leave the max number of IP paths
        failed.truncate(paths.len().saturating_sub(MAX_IP_PATHS));
    }

    // sort the potentially prunable from most recently closed to least recently closed
    inactive.sort_by(|a, b| b.1.cmp(&a.1));

    // Prune the "oldest" closed paths.
    let old_inactive = inactive.split_off(inactive.len().saturating_sub(MAX_INACTIVE_IP_PATHS));

    // collect all the paths that should be pruned
    let must_prune: HashSet<_> = failed
        .into_iter()
        .chain(old_inactive.into_iter().map(|(addr, _)| addr))
        .collect();

    paths.retain(|addr, _| !must_prune.contains(addr));
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };

    use iroh_base::{RelayUrl, SecretKey};
    use rand::SeedableRng;

    use super::*;

    fn ip_addr(port: u16) -> transports::Addr {
        transports::Addr::Ip(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into())
    }

    fn path_state_inactive(closed: Instant) -> PathState {
        PathState {
            sources: HashMap::new(),
            status: PathStatus::Inactive(closed),
        }
    }

    fn path_state_unusable() -> PathState {
        PathState {
            sources: HashMap::new(),
            status: PathStatus::Unusable,
        }
    }

    #[test]
    fn test_prune_under_max_paths() {
        let mut paths = FxHashMap::default();
        for i in 0..20 {
            paths.insert(ip_addr(i), PathState::default());
        }

        prune_ip_paths(&mut paths);
        assert_eq!(20, paths.len(), "should not prune when under MAX_IP_PATHS");
    }

    #[test]
    fn test_prune_at_max_paths_no_prunable() {
        let mut paths = FxHashMap::default();
        // All paths are active (never abandoned), so none should be pruned
        for i in 0..MAX_IP_PATHS {
            paths.insert(ip_addr(i as u16), PathState::default());
        }

        prune_ip_paths(&mut paths);
        assert_eq!(MAX_IP_PATHS, paths.len(), "should not prune active paths");
    }

    #[test]
    fn test_prune_failed_holepunch() {
        let mut paths = FxHashMap::default();

        // Add 20 active paths
        for i in 0..20 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 15 failed holepunch paths (must_prune)
        for i in 20..35 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        prune_ip_paths(&mut paths);

        // All failed holepunch paths should be pruned
        assert_eq!(20, paths.len());
        for i in 0..20 {
            assert!(paths.contains_key(&ip_addr(i)));
        }
        for i in 20..35 {
            assert!(!paths.contains_key(&ip_addr(i)));
        }
    }

    #[test]
    fn test_prune_keeps_most_recent_inactive() {
        let mut paths = FxHashMap::default();
        let now = Instant::now();

        // Add 15 active paths
        for i in 0..15 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 20 inactive paths with different abandon times
        // Ports 15-34, with port 34 being most recently abandoned
        for i in 0..20 {
            let abandoned_time = now - Duration::from_secs((20 - i) as u64);
            paths.insert(ip_addr(15 + i as u16), path_state_inactive(abandoned_time));
        }

        assert_eq!(35, paths.len());
        prune_ip_paths(&mut paths);

        // Should keep 15 active + 10 most recently abandoned
        assert_eq!(25, paths.len());

        // Active paths should remain
        for i in 0..15 {
            assert!(paths.contains_key(&ip_addr(i)));
        }

        // Most recently abandoned (ports 25-34) should remain
        for i in 25..35 {
            assert!(paths.contains_key(&ip_addr(i)), "port {} should be kept", i);
        }

        // Oldest abandoned (ports 15-24) should be pruned
        for i in 15..25 {
            assert!(
                !paths.contains_key(&ip_addr(i)),
                "port {} should be pruned",
                i
            );
        }
    }

    #[test]
    fn test_prune_mixed_must_and_can_prune() {
        let mut paths = FxHashMap::default();
        let now = Instant::now();

        // Add 15 active paths
        for i in 0..15 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 5 failed holepunch paths
        for i in 15..20 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        // Add 15 usable but abandoned paths
        for i in 0..15 {
            let abandoned_time = now - Duration::from_secs((15 - i) as u64);
            paths.insert(ip_addr(20 + i as u16), path_state_inactive(abandoned_time));
        }

        assert_eq!(35, paths.len());
        prune_ip_paths(&mut paths);

        // Remove all failed paths -> down to 30
        // Keep MAX_INACTIVE_IP_PATHS, eg remove 5 usable but abandoned paths -> down to 20
        assert_eq!(20, paths.len());

        // Active paths should remain
        for i in 0..15 {
            assert!(paths.contains_key(&ip_addr(i)));
        }

        // Failed holepunch should be pruned
        for i in 15..20 {
            assert!(!paths.contains_key(&ip_addr(i)));
        }

        // Most recently abandoned (ports 30-34) should remain
        for i in 30..35 {
            assert!(paths.contains_key(&ip_addr(i)), "port {} should be kept", i);
        }
    }

    #[test]
    fn test_prune_non_ip_paths_not_counted() {
        let mut paths = FxHashMap::default();

        // Add 25 IP paths (under MAX_IP_PATHS)
        for i in 0..25 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let relay_url: RelayUrl = url::Url::parse("https://localhost")
            .expect("should be valid url")
            .into();
        // Add 10 relay addresses
        for _ in 0..10 {
            let id = SecretKey::generate(&mut rng).public();
            let relay_addr = transports::Addr::Relay(relay_url.clone(), id);
            paths.insert(relay_addr, PathState::default());
        }

        assert_eq!(35, paths.len()); // 25 IP + 10 relay
        prune_ip_paths(&mut paths);

        // Should not prune since IP paths < MAX_IP_PATHS
        assert_eq!(35, paths.len());
    }

    #[test]
    fn test_prune_preserves_never_dialed() {
        let mut paths = FxHashMap::default();

        // Add 20 never-dialed paths (PathStatus::Unknown)
        for i in 0..20 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 15 failed paths to trigger pruning
        for i in 20..35 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        prune_ip_paths(&mut paths);

        // Never-dialed paths should be preserved
        for i in 0..20 {
            assert!(paths.contains_key(&ip_addr(i)));
        }
    }

    #[test]
    fn test_prune_all_paths_failed() {
        let mut paths = FxHashMap::default();

        // Add 40 failed holepunch paths (all paths have failed)
        for i in 0..40 {
            paths.insert(ip_addr(i), path_state_unusable());
        }

        assert_eq!(40, paths.len());
        prune_ip_paths(&mut paths);

        // Should keep MAX_IP_PATHS instead of pruning everything
        // This prevents catastrophic loss of all path information
        assert_eq!(
            MAX_IP_PATHS,
            paths.len(),
            "should keep MAX_IP_PATHS when all paths failed"
        );
    }

    #[test]
    fn test_insert_open_path() {
        let mut state = RemotePathState::new(Default::default());
        let addr = ip_addr(1000);
        let source = Source::Udp;

        assert!(state.is_empty());

        state.insert_open_path(addr.clone(), source.clone());

        assert!(!state.is_empty());
        assert!(state.paths.contains_key(&addr));
        let path = &state.paths[&addr];
        assert!(matches!(path.status, PathStatus::Open));
        assert_eq!(path.sources.len(), 1);
        assert!(path.sources.contains_key(&source));
    }

    #[test]
    fn test_abandoned_path() {
        let metrics = Arc::new(SocketMetrics::default());
        let mut state = RemotePathState::new(metrics.clone());

        // Test: Open goes to Inactive
        let addr_open = ip_addr(1000);
        state.insert_open_path(addr_open.clone(), Source::Udp);
        assert!(matches!(state.paths[&addr_open].status, PathStatus::Open));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);

        state.abandoned_path(&addr_open);
        assert!(matches!(
            state.paths[&addr_open].status,
            PathStatus::Inactive(_)
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        // Test: Inactive stays Inactive
        state.abandoned_path(&addr_open);
        assert!(matches!(
            state.paths[&addr_open].status,
            PathStatus::Inactive(_)
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        // Test: Unknown goes to Unusable
        let addr_unknown = ip_addr(2000);
        state.insert_multiple([addr_unknown.clone()].into_iter(), Source::Relay);
        assert!(matches!(
            state.paths[&addr_unknown].status,
            PathStatus::Unknown
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        state.abandoned_path(&addr_unknown);
        assert!(matches!(
            state.paths[&addr_unknown].status,
            PathStatus::Unusable
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        // Test: Unusable stays Unusable
        state.abandoned_path(&addr_unknown);
        assert!(matches!(
            state.paths[&addr_unknown].status,
            PathStatus::Unusable
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 1);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);

        // Test: Unusable can go to open
        state.insert_open_path(addr_unknown.clone(), Source::Udp);
        assert!(matches!(
            state.paths[&addr_unknown].status,
            PathStatus::Open
        ));
        assert_eq!(metrics.transport_ip_paths_added.get(), 2);
        assert_eq!(metrics.transport_ip_paths_removed.get(), 1);
    }
}
