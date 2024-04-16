//! Metrics support for the server

use iroh_metrics::core::{Core, Counter, Metric};
use struct_iterable::Iterable;

/// Metrics for iroh-dns-server
#[derive(Debug, Clone, Iterable)]
#[allow(missing_docs)]
pub struct Metrics {
    pub pkarr_publish_update: Counter,
    pub pkarr_publish_noop: Counter,
    pub pkarr_publish_error: Counter,
    pub dns_requests: Counter,
    pub dns_requests_udp: Counter,
    pub dns_requests_https: Counter,
    pub dns_lookup_success: Counter,
    pub dns_lookup_notfound: Counter,
    pub dns_lookup_error: Counter,
    pub http_requests: Counter,
    pub http_requests_success: Counter,
    pub http_requests_error: Counter,
    pub http_requests_duration_ms: Counter,
    pub store_packets_inserted: Counter,
    pub store_packets_removed: Counter,
    pub store_packets_updated: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            pkarr_publish_update: Counter::new("Number of pkarr relay puts that updated the state"),
            pkarr_publish_noop: Counter::new(
                "Number of pkarr relay puts that did not update the state",
            ),
            pkarr_publish_error: Counter::new("Number of pkarr relay puts that failed"),
            dns_requests: Counter::new("DNS requests (total)"),
            dns_requests_udp: Counter::new("DNS requests via UDP"),
            dns_requests_https: Counter::new("DNS requests via HTTPS (DoH)"),
            dns_lookup_success: Counter::new("DNS lookup responses with at least one answer"),
            dns_lookup_notfound: Counter::new("DNS lookup responses with no answers"),
            dns_lookup_error: Counter::new("DNS lookup responses which failed"),
            http_requests: Counter::new("Number of HTTP requests"),
            http_requests_success: Counter::new("Number of HTTP requests with a 2xx status code"),
            http_requests_error: Counter::new("Number of HTTP requests with a non-2xx status code"),
            http_requests_duration_ms: Counter::new("Total duration of all HTTP requests"),
            store_packets_inserted: Counter::new("Signed packets inserted into the store"),
            store_packets_removed: Counter::new("Signed packets removed from the store"),
            store_packets_updated: Counter::new("Number of updates to existing packets"),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "dns_server"
    }
}

/// Init the metrics collection core.
pub fn init_metrics() {
    Core::init(|reg, metrics| {
        metrics.insert(Metrics::new(reg));
    });
}
