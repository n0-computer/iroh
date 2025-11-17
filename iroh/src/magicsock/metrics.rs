use iroh_metrics::{Counter, MetricsGroup};
use serde::{Deserialize, Serialize};

/// Enum of metrics for the module
// TODO(frando): Add description doc strings for each metric.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize, MetricsGroup)]
#[non_exhaustive]
#[metrics(name = "magicsock", default)]
pub struct Metrics {
    pub update_direct_addrs: Counter,

    // Sends (data or disco)
    pub send_ipv4: Counter,
    pub send_ipv6: Counter,
    pub send_relay: Counter,

    // Data packets (non-disco)
    pub recv_data_relay: Counter,
    pub recv_data_ipv4: Counter,
    pub recv_data_ipv6: Counter,
    /// Number of QUIC datagrams received.
    pub recv_datagrams: Counter,
    /// Number of datagrams received using GRO
    pub recv_gro_datagrams: Counter,

    // Disco packets
    pub send_disco_udp: Counter,
    pub send_disco_relay: Counter,
    pub sent_disco_udp: Counter,
    pub sent_disco_relay: Counter,
    pub sent_disco_ping: Counter,
    pub sent_disco_pong: Counter,
    pub sent_disco_call_me_maybe: Counter,
    pub recv_disco_bad_key: Counter,
    pub recv_disco_bad_parse: Counter,

    pub recv_disco_udp: Counter,
    pub recv_disco_relay: Counter,
    pub recv_disco_ping: Counter,
    pub recv_disco_pong: Counter,
    pub recv_disco_call_me_maybe: Counter,
    pub recv_disco_call_me_maybe_bad_disco: Counter,

    // How many times our relay home endpoint DI has changed from non-zero to a different non-zero.
    pub relay_home_change: Counter,

    /*
     * Connection Metrics
     *
     * These all only count connections that completed the TLS handshake successfully. This means
     * that short lived 0RTT connections are potentially not included in these counts.
     */
    /// Number of connections opened (only handshaked connections are counted).
    pub num_conns_opened: Counter,
    /// Number of connections closed (only handshaked connections are counted).
    pub num_conns_closed: Counter,
    /// Number of connections that had only relay paths over their lifetime.
    pub num_conns_transport_relay_only: Counter,
    /// Number of connections that had only IP paths over their lifetime.
    pub num_conns_transport_ip_only: Counter,
    /// Number of connections that had both IP and relay paths.
    pub num_conns_transport_ip_and_relay: Counter,

    pub actor_tick_main: Counter,
    pub actor_tick_msg: Counter,
    pub actor_tick_re_stun: Counter,
    pub actor_tick_portmap_changed: Counter,
    pub actor_tick_direct_addr_heartbeat: Counter,
    pub actor_link_change: Counter,
    pub actor_tick_other: Counter,
    // /// Histogram of connection latency in milliseconds across all endpoint connections.
    // #[default(Histogram::new(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, f64::INFINITY]))]
    // pub connection_latency_ms: Histogram,
    // /*
    // * Path Congestion Metrics
    // */
    // /// Number of times a path was marked as outdated due to consecutive ping failures.
    // pub path_marked_outdated: Counter,
    // /// Number of ping failures recorded across all paths.
    // pub path_ping_failures: Counter,
    // /// Number of consecutive failure resets (path recovered).
    // pub path_failure_resets: Counter,
    // /// Histogram of packet loss rates (0.0-1.0) observed on UDP paths.
    // #[default(Histogram::new(vec![0.0, 0.01, 0.05, 0.1, 0.2, 0.5, 1.0]))]
    // pub path_packet_loss_rate: Histogram,
    // /// Histogram of RTT variance (in milliseconds) as a congestion indicator.
    // #[default(Histogram::new(vec![0.0, 1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0]))]
    // pub path_rtt_variance_ms: Histogram,
    // /// Histogram of path quality scores (0.0-1.0).
    // #[default(Histogram::new(vec![0.0, 0.3, 0.5, 0.7, 0.85, 0.95, 1.0]))]
    // pub path_quality_score: Histogram,
}
