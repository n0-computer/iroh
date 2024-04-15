//! Invariants for the service.

#![cfg(any(test, debug_assertions))]

use super::*;

/// invariants for the service.
impl<G: Getter<Connection = D::Connection>, D: Dialer, S: Store> Service<G, D, S> {
    /// Checks the various invariants the service must maintain
    #[track_caller]
    pub(in crate::downloader) fn check_invariants(&self) {
        self.check_active_request_count();
        self.check_queued_requests_consistency();
        self.check_idle_peer_consistency();
        self.check_concurrency_limits();
        self.check_provider_map_prunning();
    }

    /// Checks concurrency limits are maintained.
    #[track_caller]
    fn check_concurrency_limits(&self) {
        let ConcurrencyLimits {
            max_concurrent_requests,
            max_concurrent_requests_per_node,
            max_open_connections,
            max_concurrent_dials_per_hash,
        } = &self.concurrency_limits;

        // check the total number of active requests to ensure it stays within the limit
        assert!(
            self.in_progress_downloads.len() <= *max_concurrent_requests,
            "max_concurrent_requests exceeded"
        );

        // check that the open and dialing peers don't exceed the connection capacity
        tracing::trace!(
            "limits: conns: {}/{} | reqs: {}/{}",
            self.connections_count(),
            max_open_connections,
            self.in_progress_downloads.len(),
            max_concurrent_requests
        );
        assert!(
            self.connections_count() <= *max_open_connections,
            "max_open_connections exceeded"
        );

        // check the active requests per peer don't exceed the limit
        for (node, info) in self.connected_nodes.iter() {
            assert!(
                info.active_requests() <= *max_concurrent_requests_per_node,
                "max_concurrent_requests_per_node exceeded for {node}"
            )
        }

        // check that we do not dial more nodes than allowed for the next pending hashes
        if let Some(kind) = self.queue.front() {
            let hash = kind.hash();
            let nodes = self.providers.get_candidates(&hash);
            let mut dialing = 0;
            for node in nodes {
                if self.dialer.is_pending(node) {
                    dialing += 1;
                }
            }
            assert!(
                dialing <= *max_concurrent_dials_per_hash,
                "max_concurrent_dials_per_hash exceeded for {hash}"
            )
        }
    }

    /// Checks that the count of active requests per peer is consistent with the active requests,
    /// and that active request are consistent with download futures
    #[track_caller]
    fn check_active_request_count(&self) {
        // check that the count of futures we are polling for downloads is consistent with the
        // number of requests
        assert_eq!(
            self.in_progress_downloads.len(),
            self.active_requests.len(),
            "active_requests and in_progress_downloads are out of sync"
        );
        // check that the count of requests per peer matches the number of requests that have that
        // peer as active
        let mut real_count: HashMap<NodeId, usize> =
            HashMap::with_capacity(self.connected_nodes.len());
        for req_info in self.active_requests.values() {
            // nothing like some classic word count
            *real_count.entry(req_info.node).or_default() += 1;
        }
        for (peer, info) in self.connected_nodes.iter() {
            assert_eq!(
                info.active_requests(),
                real_count.get(peer).copied().unwrap_or_default(),
                "mismatched count of active requests for {peer}"
            )
        }
    }

    /// Checks that the queued requests all appear in the provider map and request map.
    #[track_caller]
    fn check_queued_requests_consistency(&self) {
        // check that all hashes in the queue have candidates
        for entry in self.queue.iter() {
            assert!(
                self.providers
                    .get_candidates(&entry.hash())
                    .next()
                    .is_some(),
                "all queued requests have providers"
            );
            assert!(
                self.requests.get(entry).is_some(),
                "all queued requests have request info"
            );
        }

        // check that all parked hashes should be parked
        for entry in self.queue.iter_parked() {
            assert!(
                matches!(self.next_step(entry), NextStep::Park),
                "next step for parked node ist WaitForNodeRetry"
            );
            assert!(
                self.providers
                    .get_candidates(&entry.hash())
                    .all(|node| matches!(self.node_state(node), NodeState::WaitForRetry)),
                "all parked downloads have only retrying nodes"
            );
        }
    }

    /// Check that peers queued to be disconnected are consistent with peers considered idle.
    #[track_caller]
    fn check_idle_peer_consistency(&self) {
        let idle_peers = self
            .connected_nodes
            .values()
            .filter(|info| info.active_requests() == 0)
            .count();
        assert_eq!(
            self.goodbye_nodes_queue.len(),
            idle_peers,
            "inconsistent count of idle peers"
        );
    }

    /// Check that every hash in the provider map is needed.
    #[track_caller]
    fn check_provider_map_prunning(&self) {
        for hash in self.providers.hash_node.keys() {
            let as_raw = DownloadKind(HashAndFormat::raw(*hash));
            let as_hash_seq = DownloadKind(HashAndFormat::hash_seq(*hash));
            assert!(
                self.queue.contains_hash(*hash)
                    || self.active_requests.contains_key(&as_raw)
                    || self.active_requests.contains_key(&as_hash_seq),
                "all hashes in the provider map are in the queue or active"
            )
        }
    }
}
