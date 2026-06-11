//! Metrics exposed by the server.

use iroh_metrics::{Counter, Gauge, MetricsGroup};

/// Counters exposed by iroh-dns-server.
#[derive(Debug, Default, MetricsGroup)]
#[metrics(name = "dns_server")]
#[non_exhaustive]
pub struct Metrics {
    /// Number of pkarr relay puts that updated the stored packet.
    pub pkarr_publish_update: Counter,
    /// Number of pkarr relay puts that did not change the stored packet.
    pub pkarr_publish_noop: Counter,
    /// Total number of DNS requests across all transports.
    pub dns_requests: Counter,
    /// Number of DNS requests received over UDP or TCP.
    pub dns_requests_udp: Counter,
    /// Number of DNS requests received over HTTPS (DoH).
    pub dns_requests_https: Counter,
    /// Number of DNS lookups that returned at least one answer.
    pub dns_lookup_success: Counter,
    /// Number of DNS lookups that returned no answers.
    pub dns_lookup_notfound: Counter,
    /// Number of DNS lookups that failed with an error.
    pub dns_lookup_error: Counter,
    /// Number of HTTP requests served.
    pub http_requests: Counter,
    /// Number of HTTP requests that returned a 2xx status code.
    pub http_requests_success: Counter,
    /// Number of HTTP requests that returned a non-2xx status code.
    pub http_requests_error: Counter,
    /// Cumulative duration of all HTTP requests, in milliseconds.
    pub http_requests_duration_ms: Counter,
    /// Number of signed packets newly inserted into the store.
    pub store_packets_inserted: Counter,
    /// Number of signed packets removed from the store.
    pub store_packets_removed: Counter,
    /// Number of times an existing signed packet was replaced by a newer one.
    pub store_packets_updated: Counter,
    /// Number of signed packets removed by the eviction task.
    pub store_packets_expired: Counter,
    /// Current number of zones in the main cache
    pub cache_zones: Gauge,
    /// Current number of zones in the DHT cache
    pub cache_zones_dht: Gauge,
}
