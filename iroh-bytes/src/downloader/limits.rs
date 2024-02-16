use std::num::NonZeroUsize;

/// Concurrency limits for the [`Downloader`].
#[derive(Debug)]
pub struct ConcurrencyLimits {
    /// Maximum number of requests the service performs concurrently.
    pub max_concurrent_requests: usize,
    /// Maximum number of requests performed by a single node concurrently.
    pub max_concurrent_requests_per_node: usize,
    /// Maximum number of open connections the service maintains.
    pub max_open_connections: usize,
}

impl Default for ConcurrencyLimits {
    fn default() -> Self {
        // these numbers should be checked against a running node and might depend on platform
        ConcurrencyLimits {
            max_concurrent_requests: 50,
            max_concurrent_requests_per_node: 4,
            max_open_connections: 25,
        }
    }
}

impl ConcurrencyLimits {
    /// Checks if the maximum number of concurrent requests has been reached.
    pub fn at_requests_capacity(&self, active_requests: usize) -> bool {
        active_requests >= self.max_concurrent_requests
    }

    /// Check how many new rquests can be opened for a node.
    pub fn remaining_request(
        &self,
        active_node_requests: usize,
        active_total_requests: usize,
    ) -> Option<NonZeroUsize> {
        let remaining_at_node = self
            .max_concurrent_requests_per_node
            .saturating_sub(active_node_requests);
        let remaining_at_total = self
            .max_concurrent_requests
            .saturating_sub(active_total_requests);
        NonZeroUsize::new(remaining_at_node.min(remaining_at_total))
    }

    /// Checks if the maximum number of concurrent requests per node has been reached.
    pub fn node_at_request_capacity(&self, active_node_requests: usize) -> bool {
        active_node_requests >= self.max_concurrent_requests_per_node
    }

    /// Checks if the maximum number of connections has been reached.
    pub fn at_connections_capacity(&self, active_connections: usize) -> bool {
        active_connections >= self.max_open_connections
    }

    pub fn remaining_connections(&self, active_connections: usize) -> Option<NonZeroUsize> {
        NonZeroUsize::new(self.max_open_connections.saturating_sub(active_connections))
    }
}
