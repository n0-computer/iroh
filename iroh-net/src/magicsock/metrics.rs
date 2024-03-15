use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Enum of metrics for the module
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    pub rebind_calls: Counter,
    pub re_stun_calls: Counter,
    pub update_endpoints: Counter,

    // Sends (data or disco)
    pub send_relay_queued: Counter,
    pub send_relay_error_chan: Counter,
    pub send_relay_error_closed: Counter,
    pub send_relay_error_queue: Counter,
    pub send_ipv4: Counter,
    pub send_ipv4_error: Counter,
    pub send_ipv6: Counter,
    pub send_ipv6_error: Counter,
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

    // Disco packets
    pub send_disco_udp: Counter,
    pub send_disco_relay: Counter,
    pub sent_disco_udp: Counter,
    pub sent_disco_relay: Counter,
    pub sent_disco_ping: Counter,
    pub sent_disco_pong: Counter,
    pub sent_disco_call_me_maybe: Counter,
    pub recv_disco_bad_peer: Counter,
    pub recv_disco_bad_key: Counter,
    pub recv_disco_bad_parse: Counter,

    pub recv_disco_udp: Counter,
    pub recv_disco_relay: Counter,
    pub recv_disco_ping: Counter,
    pub recv_disco_pong: Counter,
    pub recv_disco_call_me_maybe: Counter,
    pub recv_disco_call_me_maybe_bad_node: Counter,
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
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            num_relay_conns_added: Counter::new("num_relay_conns added"),
            num_relay_conns_removed: Counter::new("num_relay_conns removed"),

            rebind_calls: Counter::new("rebind_calls"),
            re_stun_calls: Counter::new("restun_calls"),
            update_endpoints: Counter::new("update_endpoints"),

            // Sends (data or disco)
            send_relay_queued: Counter::new("send_relay_queued"),
            send_relay_error_chan: Counter::new("send_relay_error_chan"),
            send_relay_error_closed: Counter::new("send_relay_error_closed"),
            send_relay_error_queue: Counter::new("send_relay_error_queue"),
            send_ipv4: Counter::new("send_ipv4"),
            send_ipv4_error: Counter::new("send_ipv4_error"),
            send_ipv6: Counter::new("send_ipv6"),
            send_ipv6_error: Counter::new("send_ipv6_error"),
            send_relay: Counter::new("send_relay"),
            send_relay_error: Counter::new("send_relay_error"),

            // Data packets (non-disco)
            send_data: Counter::new("send_data"),
            send_data_network_down: Counter::new("send_data_network_down"),
            recv_data_relay: Counter::new("recv_data_relay"),
            recv_data_ipv4: Counter::new("recv_data_ipv4"),
            recv_data_ipv6: Counter::new("recv_data_ipv6"),
            recv_datagrams: Counter::new("recv_datagrams"),

            // Disco packets
            send_disco_udp: Counter::new("disco_send_udp"),
            send_disco_relay: Counter::new("disco_send_relay"),
            sent_disco_udp: Counter::new("disco_sent_udp"),
            sent_disco_relay: Counter::new("disco_sent_relay"),
            sent_disco_ping: Counter::new("disco_sent_ping"),
            sent_disco_pong: Counter::new("disco_sent_pong"),
            sent_disco_call_me_maybe: Counter::new("disco_sent_callmemaybe"),
            recv_disco_bad_peer: Counter::new("disco_recv_bad_peer"),
            recv_disco_bad_key: Counter::new("disco_recv_bad_key"),
            recv_disco_bad_parse: Counter::new("disco_recv_bad_parse"),

            recv_disco_udp: Counter::new("disco_recv_udp"),
            recv_disco_relay: Counter::new("disco_recv_relay"),
            recv_disco_ping: Counter::new("disco_recv_ping"),
            recv_disco_pong: Counter::new("disco_recv_pong"),
            recv_disco_call_me_maybe: Counter::new("disco_recv_callmemaybe"),
            recv_disco_call_me_maybe_bad_node: Counter::new("disco_recv_callmemaybe_bad_node"),
            recv_disco_call_me_maybe_bad_disco: Counter::new("disco_recv_callmemaybe_bad_disco"),

            // How many times our relay home node DI has changed from non-zero to a different non-zero.
            relay_home_change: Counter::new("relay_home_change"),

            num_direct_conns_added: Counter::new(
                "number of direct connections to a peer we have added",
            ),
            num_direct_conns_removed: Counter::new(
                "number of direct connections to a peer we have removed",
            ),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "magicsock"
    }
}
