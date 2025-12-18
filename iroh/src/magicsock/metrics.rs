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

    // How many times our relay home endpoint DI has changed from non-zero to a different non-zero.
    pub relay_home_change: Counter,

    /*
     * Holepunching metrics
     */
    /// The number of NAT traversal attempts initiated.
    pub nat_traversal: Counter,

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

    /// Number of IP transport paths opened.
    pub transport_ip_paths_added: Counter,
    /// Number of IP transport paths closed.
    pub transport_ip_paths_removed: Counter,
    /// Number of relay transport paths opened.
    pub transport_relay_paths_added: Counter,
    /// Number of relay transport paths closed.
    pub transport_relay_paths_removed: Counter,

    pub actor_tick_main: Counter,
    pub actor_tick_msg: Counter,
    pub actor_tick_re_stun: Counter,
    pub actor_tick_portmap_changed: Counter,
    pub actor_tick_direct_addr_heartbeat: Counter,
    pub actor_link_change: Counter,
    pub actor_tick_other: Counter,
}
