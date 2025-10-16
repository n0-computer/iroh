use iroh_metrics::{Counter, Histogram, MetricsGroup};
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
    pub send_relay_error: Counter,

    // Data packets (non-disco)
    pub send_data: Counter,
    pub send_data_network_down: Counter,
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
     */
    /// The number of direct connections we have made to peers.
    pub num_direct_conns_added: Counter,
    /// The number of direct connections we have lost to peers.
    pub num_direct_conns_removed: Counter,
    /// The number of connections to peers we have added over relay.
    pub num_relay_conns_added: Counter,
    /// The number of connections to peers we have removed over relay.
    pub num_relay_conns_removed: Counter,

    pub actor_tick_main: Counter,
    pub actor_tick_msg: Counter,
    pub actor_tick_re_stun: Counter,
    pub actor_tick_portmap_changed: Counter,
    pub actor_tick_direct_addr_heartbeat: Counter,
    pub actor_link_change: Counter,
    pub actor_tick_other: Counter,

    /// Number of endpoints we have attempted to contact.
    pub endpoints_contacted: Counter,
    /// Number of endpoints we have managed to contact directly.
    pub endpoints_contacted_directly: Counter,

    /// Number of connections with a successful handshake.
    pub connection_handshake_success: Counter,
    /// Number of connections with a successful handshake that became direct.
    pub connection_became_direct: Counter,

    /*
     * Path Congestion Metrics
     */
    /// Number of times a path was marked as outdated due to consecutive ping failures.
    pub path_marked_outdated: Counter,
    /// Number of ping failures recorded across all paths.
    pub path_ping_failures: Counter,
    /// Number of consecutive failure resets (path recovered).
    pub path_failure_resets: Counter,
    /// Histogram of packet loss rates (0.0-1.0) observed on UDP paths.
    #[default(Histogram::new(vec![0.0, 0.01, 0.05, 0.1, 0.2, 0.5, 1.0]))]
    pub path_packet_loss_rate: Histogram,
    /// Histogram of RTT variance (in milliseconds) as a congestion indicator.
    #[default(Histogram::new(vec![0.0, 1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0]))]
    pub path_rtt_variance_ms: Histogram,
    /// Histogram of path quality scores (0.0-1.0).
    #[default(Histogram::new(vec![0.0, 0.3, 0.5, 0.7, 0.85, 0.95, 1.0]))]
    pub path_quality_score: Histogram,
}
