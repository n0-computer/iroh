//! Invariants for the service.

#![cfg(any(test, debug_assertions))]

use super::*;

/// invariants for the service.
impl<G: Getter<Connection = D::Connection>, D: Dialer> Service<G, D> {
    /// Checks the various invariants the service must maintain
    #[track_caller]
    pub(in crate::downloader) fn check_invariants(&self) {
        self.check_active_request_count();
        // self.check_scheduled_requests_consistency();
        self.check_idle_peer_consistency();
        self.check_concurrency_limits();
        self.check_provider_map_prunning();
    }

    /// Checks concurrency limits are maintained.
    #[track_caller]
    fn check_concurrency_limits(&self) {
        let ConcurrencyLimits {
            max_concurrent_requests,
            max_concurrent_requests_per_node: max_concurrent_requests_per_peer,
            max_open_connections,
        } = &self.concurrency_limits;

        // check the total number of active requests to ensure it stays within the limit
        assert!(
            self.in_progress_downloads.len() <= *max_concurrent_requests,
            "max_concurrent_requests exceeded"
        );

        // check that the open and dialing peers don't exceed the connection capacity
        assert!(
            self.connections_count() <= *max_open_connections,
            "max_open_connections exceeded"
        );

        // check the active requests per peer don't exceed the limit
        for (peer, info) in self.nodes.iter() {
            assert!(
                info.active_requests() <= *max_concurrent_requests_per_peer,
                "max_concurrent_requests_per_peer exceeded for {peer}"
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
            "current_requests and in_progress_downloads are out of sync"
        );
        // check that the count of requests per peer matches the number of requests that have that
        // peer as active
        let mut real_count: HashMap<NodeId, usize> = HashMap::with_capacity(self.nodes.len());
        for req_info in self.active_requests.values() {
            // nothing like some classic word count
            *real_count.entry(req_info.node).or_default() += 1;
        }
        for (peer, info) in self.nodes.iter() {
            assert_eq!(
                info.active_requests(),
                real_count.get(peer).copied().unwrap_or_default(),
                "mismatched count of active requests for {peer}"
            )
        }
    }

    // /// Checks that the scheduled requests match the queue that handles their delays.
    // #[track_caller]
    // fn check_scheduled_requests_consistency(&self) {
    //     assert_eq!(
    //         self.scheduled_requests.len(),
    //         self.scheduled_request_queue.len(),
    //         "scheduled_request_queue and scheduled_requests are out of sync"
    //     );
    // }

    /// Check that peers queued to be disconnected are consistent with peers considered idle.
    #[track_caller]
    fn check_idle_peer_consistency(&self) {
        let idle_peers = self
            .nodes
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
        // for hash in self.providers.candidates.keys() {
        //     assert!(
        //         self.is_needed(*hash),
        //         "provider map contains {hash:?} which should have been prunned"
        //     );
        // }
    }
}
