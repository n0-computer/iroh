//! The state kept for each network path to a remote endpoint.

use std::collections::{HashMap, HashSet, VecDeque};

use n0_error::e;
use n0_future::time::Instant;
use rustc_hash::FxHashMap;
use tokio::sync::oneshot;
use tracing::trace;

use super::Source;
use crate::{discovery::DiscoveryError, magicsock::transports};

/// Maximum number of IP paths we keep around per endpoint.
pub(super) const MAX_IP_PATHS: usize = 30;

/// Maximum number of inactive IP paths we keep around per endpoint.
///
/// These are paths that at one point been opened and are now closed.
pub(super) const MAX_INACTIVE_IP_PATHS: usize = 10;

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

    /// Mark a path as abandoned.
    ///
    /// If this path does not exist, it does nothing to the
    /// `RemotePathState`
    pub(super) fn abandoned_path(&mut self, addr: &transports::Addr) {
        if let Some(state) = self.paths.get_mut(addr) {
            state.abandoned = Some(Instant::now());
        }
    }

    /// Mark a path as opened.
    ///
    /// If this path does not exist, it does nothing to the
    /// `RemotePathState`
    pub(super) fn opened_path(&mut self, addr: &transports::Addr) {
        if let Some(state) = self.paths.get_mut(addr) {
            state.usable = true;
            state.abandoned = None;
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
    /// The last time this path was proven usable.
    ///
    /// If this is `false` and closed is `Some`, than we attempted to open this path, but
    /// it did not work.
    ///
    /// If this is `false` and closed is `None`, than we do not know yet if this path is
    /// usable.
    pub(super) usable: bool,
    /// The last time a path with this addr was abandoned.
    ///
    /// If this is `Some` and usable is `None`, than we attempted to use this path and it
    /// did not work.
    pub(super) abandoned: Option<Instant>,
}

/// Prunes the IP paths in the paths HashMap.
///
/// Only prunes if the number of IP paths is above [`MAX_IP_PATHS`].
///
/// Keeps paths that are active or have never been holepunched.
///
/// Always prunes paths that have unsuccessfully holepunched.
///
/// Keeps [`MAX_INACTIVE_PATHS`] of the most recently closed paths
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
    let mut can_prune = Vec::new();
    // paths where we attempted hole punching but it not successful
    let mut must_prune = Vec::new();

    for (addr, state) in ip_paths {
        match state.abandoned {
            // If a path has never been abandoned, it is either
            // open currently or has never been dialed.
            // Keep it.
            None => {}
            Some(abandoned) => {
                if state.usable {
                    // These are paths where hole punching succeeded at one point, but the path was closed.
                    can_prune.push((addr.clone(), abandoned));
                } else {
                    // These are paths where hole punching has been attempted and failed.
                    must_prune.push(addr.clone());
                }
            }
        }
    }

    // sort the potentially prunable from most recently closed to least recently closed
    can_prune.sort_by(|a, b| b.1.cmp(&a.1));

    // Don't prune any potentially usable but inactive paths if we don't need to.
    let prunable_slots = MAX_INACTIVE_IP_PATHS.saturating_sub(must_prune.len());

    // Prune the "oldest" closed paths.
    let prune = can_prune.split_off(can_prune.len().saturating_sub(prunable_slots));

    // collect all the paths that should be pruned
    let must_prune: HashSet<_> = must_prune
        .into_iter()
        .chain(prune.into_iter().map(|(addr, _)| addr))
        .collect();

    paths.retain(|addr, _| !must_prune.contains(addr));
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    use iroh_base::{RelayUrl, SecretKey};
    use rand::SeedableRng;

    use super::*;

    fn ip_addr(port: u16) -> transports::Addr {
        transports::Addr::Ip(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into())
    }

    fn path_state_usable_abandoned(abandoned: Instant) -> PathState {
        PathState {
            sources: HashMap::new(),
            usable: true,
            abandoned: Some(abandoned),
        }
    }

    fn path_state_failed_abandoned(abandoned: Instant) -> PathState {
        PathState {
            sources: HashMap::new(),
            usable: false,
            abandoned: Some(abandoned),
        }
    }

    #[test]
    fn test_prune_under_max_paths() {
        let mut paths = FxHashMap::default();
        for i in 0..20 {
            paths.insert(ip_addr(i), PathState::default());
        }

        prune_ip_paths(&mut paths);
        assert_eq!(paths.len(), 20, "should not prune when under MAX_IP_PATHS");
    }

    #[test]
    fn test_prune_at_max_paths_no_prunable() {
        let mut paths = FxHashMap::default();
        // All paths are active (never abandoned), so none should be pruned
        for i in 0..MAX_IP_PATHS {
            paths.insert(ip_addr(i as u16), PathState::default());
        }

        prune_ip_paths(&mut paths);
        assert_eq!(paths.len(), MAX_IP_PATHS, "should not prune active paths");
    }

    #[test]
    fn test_prune_failed_holepunch() {
        let mut paths = FxHashMap::default();
        let now = Instant::now();

        // Add 20 active paths
        for i in 0..20 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 15 failed holepunch paths (must_prune)
        for i in 20..35 {
            paths.insert(ip_addr(i), path_state_failed_abandoned(now));
        }

        prune_ip_paths(&mut paths);

        // All failed holepunch paths should be pruned
        assert_eq!(paths.len(), 20);
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

        // Add 20 usable but abandoned paths with different abandon times
        // Ports 15-34, with port 34 being most recently abandoned
        for i in 0..20 {
            let abandoned_time = now - Duration::from_secs((20 - i) as u64);
            paths.insert(
                ip_addr(15 + i as u16),
                path_state_usable_abandoned(abandoned_time),
            );
        }

        assert_eq!(paths.len(), 35);
        prune_ip_paths(&mut paths);

        // Should keep 15 active + 10 most recently abandoned
        assert_eq!(paths.len(), 25);

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
            paths.insert(ip_addr(i), path_state_failed_abandoned(now));
        }

        // Add 15 usable but abandoned paths
        for i in 0..15 {
            let abandoned_time = now - Duration::from_secs((15 - i) as u64);
            paths.insert(
                ip_addr(20 + i as u16),
                path_state_usable_abandoned(abandoned_time),
            );
        }

        assert_eq!(paths.len(), 35);
        prune_ip_paths(&mut paths);

        // Total: 15 active + 5 most recent can_prune = 20
        assert_eq!(paths.len(), 20);

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
        let now = Instant::now();

        // Add 25 IP paths (under MAX_IP_PATHS)
        for i in 0..25 {
            paths.insert(ip_addr(i), path_state_failed_abandoned(now));
        }

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let relay_url: RelayUrl = url::Url::parse("https://localhost")
            .expect("should be valid url")
            .into();
        // Add 10 relay addresses
        for _ in 0..10 {
            let id = SecretKey::generate(&mut rng).public();
            let relay_addr = transports::Addr::Relay(relay_url.clone().into(), id);
            paths.insert(relay_addr, PathState::default());
        }

        assert_eq!(paths.len(), 35); // 25 IP + 10 relay
        prune_ip_paths(&mut paths);

        // Should not prune since IP paths < MAX_IP_PATHS
        assert_eq!(paths.len(), 35);
    }

    #[test]
    fn test_prune_preserves_never_dialed() {
        let mut paths = FxHashMap::default();
        let now = Instant::now();

        // Add 20 never-dialed paths (abandoned = None, usable = false)
        for i in 0..20 {
            paths.insert(ip_addr(i), PathState::default());
        }

        // Add 15 failed paths to trigger pruning
        for i in 20..35 {
            paths.insert(ip_addr(i), path_state_failed_abandoned(now));
        }

        prune_ip_paths(&mut paths);

        // Never-dialed paths should be preserved
        for i in 0..20 {
            assert!(paths.contains_key(&ip_addr(i)));
        }
    }
}
