#![cfg(test)]
// WIP
#![allow(unused)]
use super::*;

impl<G: Getter, R: AvailabilityRegistry, D: Dialer> Service<G, R, D> {
    #[track_caller]
    fn check_consistency_invariants(&self) {}

    /// Checks concurrency limits are maintained.
    #[track_caller]
    fn chech_concurrency_limits(&self) {}

    /// Checks that the count of active requests per peer is consistent with the active requests,
    /// and that active request are consistent with download futures
    #[track_caller]
    fn check_active_request_count(&self) {
        // peers against current_requests against in_progress_downloads
    }

    /// Checks that the scheduled requests match the queue that handles their delays.
    #[track_caller]
    fn check_scheduled_requests_consistency(&self) {
        // scheuled requests against scheduled_request_queue
    }
}
