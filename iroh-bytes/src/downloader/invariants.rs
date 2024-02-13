//! Invariants for the service.

#![cfg(any(test, debug_assertions))]

use invariants::state::NodeState;

use super::*;

/// invariants for the service.
impl<G: Getter<Connection = D::Connection>, D: Dialer, C: ContentDiscovery> Service<G, D, C> {
    /// Checks the various invariants the service must maintain
    #[track_caller]
    pub(in crate::downloader) fn check_invariants(&self) {
        self.check_active_request_count();
        self.check_concurrency_limits();
        self.check_idle_peer_consistency();
    }

    /// Checks concurrency limits are maintained.
    #[track_caller]
    fn check_concurrency_limits(&self) {
        let ConcurrencyLimits {
            max_concurrent_requests,
            max_concurrent_requests_per_node: max_concurrent_requests_per_peer,
            max_open_connections,
        } = &self.state.limits();

        // check the total number of active requests to ensure it stays within the limit
        assert!(
            self.state.active_transfers().len() <= *max_concurrent_requests,
            "max_concurrent_requests exceeded"
        );

        // check that the open and dialing peers don't exceed the connection capacity
        assert!(
            self.conns.len() <= *max_open_connections,
            "max_open_connections exceeded"
        );

        // check the active requests per peer don't exceed the limit
        for (peer, info) in self.state.nodes().iter() {
            assert!(
                info.active_transfers().len() <= *max_concurrent_requests_per_peer,
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
        // check that the active transfers in state and tasks match up
        assert_eq!(
            self.state.active_transfers().len(),
            self.transfer_controllers.len(),
            "active transfers state incorrect"
        );
        assert_eq!(
            self.state.active_transfers().len(),
            self.transfer_tasks.len(),
            "active transfers tasks incorrect"
        );

        // check that the count of requests per peer matches the number of requests that have that
        // peer as active
        let actual_count = self.transfer_controllers.len();
        assert_eq!(
            actual_count,
            self.state
                .resources()
                .iter()
                .filter(|(_, s)| s.active_transfer().is_some())
                .count(),
            "active transfers by resource incorrect"
        );
        let mut count_by_node = 0;
        for node in self.state.nodes().values() {
            count_by_node += node.active_transfers().len();
        }
        assert_eq!(
            actual_count, count_by_node,
            "active transfers by node incorrect"
        );
    }

    /// Check that peers queued to be disconnected are consistent with peers considered idle.
    #[track_caller]
    fn check_idle_peer_consistency(&self) {
        let mut idle_count = 0;
        for node in self.state.nodes().values() {
            let active = !node.active_transfers().is_empty();
            if active {
                assert!(
                    matches!(
                        node.state(),
                        NodeState::Connected {
                            idle_timer_started: false
                        }
                    ),
                    "active node must be connected"
                );
            } else {
                assert!(
                    matches!(
                        node.state(),
                        NodeState::Connected {
                            idle_timer_started: true
                        } | NodeState::Pending { .. }
                            | NodeState::Disconnected { .. }
                    ),
                    "inactive node must be pending, disconnected, or idle"
                );
            }
            if matches!(
                node.state(),
                NodeState::Connected {
                    idle_timer_started: true
                }
            ) {
                idle_count += 1;
            }
        }
        assert_eq!(
            idle_count,
            self.timers
                .iter()
                .filter(|(_instant, timer)| matches!(timer, Timer::IdleTimeout(_)))
                .count(),
            "inconsistent count of idle peers"
        );
    }
}
