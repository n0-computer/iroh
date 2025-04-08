use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Enum of metrics for the module
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
#[non_exhaustive]
pub struct Metrics {
    pub re_stun_calls: Counter,
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
    pub actor_tick_direct_addr_update_receiver: Counter,
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

impl Default for Metrics {
    fn default() -> Self {
        Self {
            num_relay_conns_added: Counter::new("num_relay_conns added"),
            num_relay_conns_removed: Counter::new("num_relay_conns removed"),

            re_stun_calls: Counter::new("restun_calls"),
            update_direct_addrs: Counter::new("update_endpoints"),

            // Sends (data or disco)
            send_ipv4: Counter::new("send_ipv4"),
            send_ipv6: Counter::new("send_ipv6"),
            send_relay: Counter::new("send_relay"),
            send_relay_error: Counter::new("send_relay_error"),

            // Data packets (non-disco)
            send_data: Counter::new("send_data"),
            send_data_network_down: Counter::new("send_data_network_down"),
            recv_data_relay: Counter::new("recv_data_relay"),
            recv_data_ipv4: Counter::new("recv_data_ipv4"),
            recv_data_ipv6: Counter::new("recv_data_ipv6"),
            recv_datagrams: Counter::new("recv_datagrams"),
            recv_gro_datagrams: Counter::new("recv_gro_packets"),

            // Disco packets
            send_disco_udp: Counter::new("disco_send_udp"),
            send_disco_relay: Counter::new("disco_send_relay"),
            sent_disco_udp: Counter::new("disco_sent_udp"),
            sent_disco_relay: Counter::new("disco_sent_relay"),
            sent_disco_ping: Counter::new("disco_sent_ping"),
            sent_disco_pong: Counter::new("disco_sent_pong"),
            sent_disco_call_me_maybe: Counter::new("disco_sent_callmemaybe"),
            recv_disco_bad_key: Counter::new("disco_recv_bad_key"),
            recv_disco_bad_parse: Counter::new("disco_recv_bad_parse"),

            recv_disco_udp: Counter::new("disco_recv_udp"),
            recv_disco_relay: Counter::new("disco_recv_relay"),
            recv_disco_ping: Counter::new("disco_recv_ping"),
            recv_disco_pong: Counter::new("disco_recv_pong"),
            recv_disco_call_me_maybe: Counter::new("disco_recv_callmemaybe"),
            recv_disco_call_me_maybe_bad_disco: Counter::new("disco_recv_callmemaybe_bad_disco"),

            // How many times our relay home node DI has changed from non-zero to a different non-zero.
            relay_home_change: Counter::new("relay_home_change"),

            num_direct_conns_added: Counter::new(
                "number of direct connections to a peer we have added",
            ),
            num_direct_conns_removed: Counter::new(
                "number of direct connections to a peer we have removed",
            ),

            actor_tick_main: Counter::new("actor_tick_main"),
            actor_tick_msg: Counter::new("actor_tick_msg"),
            actor_tick_re_stun: Counter::new("actor_tick_re_stun"),
            actor_tick_portmap_changed: Counter::new("actor_tick_portmap_changed"),
            actor_tick_direct_addr_heartbeat: Counter::new("actor_tick_direct_addr_heartbeat"),
            actor_tick_direct_addr_update_receiver: Counter::new(
                "actor_tick_direct_addr_update_receiver",
            ),
            actor_link_change: Counter::new("actor_link_change"),
            actor_tick_other: Counter::new("actor_tick_other"),

            nodes_contacted: Counter::new("nodes_contacted"),
            nodes_contacted_directly: Counter::new("nodes_contacted_directly"),

            connection_handshake_success: Counter::new("connection_handshake_success"),
            connection_became_direct: Counter::new("connection_became_direct"),
        }
    }
}

impl Metric for Metrics {
    fn name(&self) -> &'static str {
        "magicsock"
    }
}
