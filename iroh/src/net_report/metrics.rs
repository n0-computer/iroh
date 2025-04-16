use iroh_metrics::{Counter, MetricsGroup};

/// Enum of metrics for the module
#[derive(Debug, Clone, MetricsGroup)]
#[metrics(name = "net_report")]
#[non_exhaustive]
pub struct Metrics {
    /// Incoming STUN packets dropped due to a full receiving queue.
    pub stun_packets_dropped: Counter,
    /// Number of IPv4 STUN packets sent.
    pub stun_packets_sent_ipv4: Counter,
    /// Number of IPv6 STUN packets sent.
    pub stun_packets_sent_ipv6: Counter,
    /// Number of IPv4 STUN packets received.
    pub stun_packets_recv_ipv4: Counter,
    /// Number of IPv6 STUN packets received.
    pub stun_packets_recv_ipv6: Counter,
    /// Number of reports executed by net_report, including full reports.
    pub reports: Counter,
    /// Number of full reports executed by net_report
    pub reports_full: Counter,
}
