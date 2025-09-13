use iroh_metrics::{Counter, MetricsGroup};
use serde::{Deserialize, Serialize};

/// Enum of metrics for the module
// TODO(frando): Add description doc strings for each metric.
#[allow(missing_docs)]
#[derive(Debug, Default, Serialize, Deserialize, MetricsGroup)]
#[non_exhaustive]
#[metrics(name = "magicsock")]
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
    pub recv_data_webrtc: Counter,
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
    pub sent_disco_webrtc_answer: Counter,
    pub sent_disco_webrtc_offer: Counter,
    pub send_disco_webrtc_ice_candidate: Counter,
    pub recv_disco_bad_key: Counter,
    pub recv_disco_bad_parse: Counter,

    pub recv_disco_udp: Counter,
    pub recv_disco_relay: Counter,
    pub recv_disco_ping: Counter,
    pub recv_disco_pong: Counter,
    pub recv_disco_call_me_maybe: Counter,
    pub recv_disco_call_me_maybe_bad_disco: Counter,
    pub recv_disco_webrtc_offer: Counter,
    pub recv_disco_webrtc_answer: Counter,

    // How many times our relay home node DI has changed from non-zero to a different non-zero.
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

    /// Number of nodes we have attempted to contact.
    pub nodes_contacted: Counter,
    /// Number of nodes we have managed to contact directly.
    pub nodes_contacted_directly: Counter,

    /// Number of connections with a successful handshake.
    pub connection_handshake_success: Counter,
    /// Number of connections with a successful handshake that became direct.
    pub connection_became_direct: Counter,
}
