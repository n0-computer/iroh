#![cfg(test)]
// WIP
#![allow(unused)]
use super::*;

impl<G: Getter<Connection = D::Connection>, R: AvailabilityRegistry, D: Dialer> Service<G, R, D> {
    /// Checks the various invariants the service must maintain
    #[track_caller]
    pub(super) fn check_consistency_invariants(&self) {
        self.chech_concurrency_limits();
        self.check_active_request_count();
        self.check_scheduled_requests_consistency();
    }

    /// Checks concurrency limits are maintained.
    #[track_caller]
    fn chech_concurrency_limits(&self) {
        // check the total number of active requests to ensure it stays within the limit
        let active_requests = self.current_requests.len();
        assert!(!self
            .concurrency_limits
            .at_requests_capacity(active_requests));

        // check that the open and dialing peers don't exceed the connection capacity
        assert!(!self.at_connections_capacity());

        // check the active requests per peer don't exceed the limit
        for info in self.peers.values() {
            assert!(!self
                .concurrency_limits
                .peer_at_request_capacity(info.active_requests()))
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
            self.current_requests.len()
        );
        /// check that the count of requests per peer matches the number of requests that have that
        /// peer as active
        let mut real_count: HashMap<PublicKey, usize> = HashMap::with_capacity(self.peers.len());
        for req_info in self.current_requests.values() {
            // nothing like some classic word count
            *real_count.entry(req_info.peer).or_default() += 1;
        }
        for (peer, info) in self.peers.iter() {
            assert_eq!(
                info.active_requests(),
                real_count.get(peer).copied().unwrap_or_default()
            )
        }
    }

    /// Checks that the scheduled requests match the queue that handles their delays.
    #[track_caller]
    fn check_scheduled_requests_consistency(&self) {
        // scheuled requests against scheduled_request_queue
    }
}
