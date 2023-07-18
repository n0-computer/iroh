use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Enum of metrics for the module
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    pub stun_packets_dropped: Counter,
    pub stun_packets_sent_ipv4: Counter,
    pub stun_packets_sent_ipv6: Counter,
    pub stun_packets_recv_ipv4: Counter,
    pub stun_packets_recv_ipv6: Counter,
    pub reports: Counter,
    pub reports_full: Counter,
    pub reports_error: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            stun_packets_dropped: Counter::new(
                "Incoming STUN packets dropped due to a full receiving queue.",
            ),
            stun_packets_sent_ipv4: Counter::new("Number of IPv4 STUN packets sent"),
            stun_packets_sent_ipv6: Counter::new("Number of IPv6 STUN packets sent"),
            stun_packets_recv_ipv4: Counter::new("Number of IPv4 STUN packets received"),
            stun_packets_recv_ipv6: Counter::new("Number of IPv6 STUN packets received"),
            reports: Counter::new("Number of reports executed by netcheck, including full reports"),
            reports_full: Counter::new("Number of full reports executed by netcheck"),
            reports_error: Counter::new("Number of executed reports resulting in an error"),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "Netcheck"
    }
}
