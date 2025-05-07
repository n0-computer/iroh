//! Metrics support for the server

use iroh_metrics::{Counter, MetricsGroup};

/// Metrics for iroh-dns-server
#[derive(Debug, Default, MetricsGroup)]
#[metrics(name = "dns_server")]
pub struct Metrics {
    /// Number of pkarr relay puts that updated the state
    pub pkarr_publish_update: Counter,
    /// Number of pkarr relay puts that did not update the state
    pub pkarr_publish_noop: Counter,
    /// DNS requests (total)
    pub dns_requests: Counter,
    /// DNS requests via UDP
    pub dns_requests_udp: Counter,
    /// DNS requests via HTTPS (DoH)
    pub dns_requests_https: Counter,
    /// DNS lookup responses with at least one answer
    pub dns_lookup_success: Counter,
    /// DNS lookup responses with no answers
    pub dns_lookup_notfound: Counter,
    /// DNS lookup responses which failed
    pub dns_lookup_error: Counter,
    /// Number of HTTP requests
    pub http_requests: Counter,
    /// Number of HTTP requests with a 2xx status code
    pub http_requests_success: Counter,
    /// Number of HTTP requests with a non-2xx status code
    pub http_requests_error: Counter,
    /// Total duration of all HTTP requests
    pub http_requests_duration_ms: Counter,
    /// Signed packets inserted into the store
    pub store_packets_inserted: Counter,
    /// Signed packets removed from the store
    pub store_packets_removed: Counter,
    /// Number of updates to existing packets
    pub store_packets_updated: Counter,
    /// Number of expired packets
    pub store_packets_expired: Counter,
}
