use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Metrics tracked for the relay server
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    /*
     * Metrics about packets
     */
    /// Bytes sent from a `FrameType::SendPacket`
    pub bytes_sent: Counter,
    /// Bytes received from a `FrameType::SendPacket`
    pub bytes_recv: Counter,

    /// `FrameType::SendPacket` sent, that are not disco messages
    pub send_packets_sent: Counter,
    /// `FrameType::SendPacket` received, that are not disco messages
    pub send_packets_recv: Counter,
    /// `FrameType::SendPacket` dropped, that are not disco messages
    pub send_packets_dropped: Counter,

    /// `FrameType::SendPacket` sent that are disco messages
    pub disco_packets_sent: Counter,
    /// `FrameType::SendPacket` received that are disco messages
    pub disco_packets_recv: Counter,
    /// `FrameType::SendPacket` dropped that are disco messages
    pub disco_packets_dropped: Counter,

    /// Packets of other `FrameType`s sent
    pub other_packets_sent: Counter,
    /// Packets of other `FrameType`s received
    pub other_packets_recv: Counter,
    /// Packets of other `FrameType`s dropped
    pub other_packets_dropped: Counter,

    /// Number of `FrameType::Ping`s received
    pub got_ping: Counter,
    /// Number of `FrameType::Pong`s sent
    pub sent_pong: Counter,
    /// Number of `FrameType::Unknown` received
    pub unknown_frames: Counter,

    /// Number of frames received from client connection which have been rate-limited.
    pub frames_rx_ratelimited_total: Counter,
    /// Number of client connections which have had any frames rate-limited.
    pub conns_rx_ratelimited_total: Counter,

    /*
     * Metrics about peers
     */
    /// Number of connections we have accepted
    pub accepts: Counter,
    /// Number of connections we have removed because of an error
    pub disconnects: Counter,

    /// Number of unique client keys per day
    pub unique_client_keys: Counter,

    /// Number of accepted websocket connections
    pub websocket_accepts: Counter,
    /// Number of accepted 'iroh derp http' connection upgrades
    pub relay_accepts: Counter,
    // TODO: enable when we can have multiple connections for one node id
    // pub duplicate_client_keys: Counter,
    // pub duplicate_client_conns: Counter,
    // TODO: only important stat that we cannot track right now
    // pub average_queue_duration:
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            /*
             * Metrics about packets
             */
            send_packets_sent: Counter::new("Number of 'send' packets relayed."),
            bytes_sent: Counter::new("Number of bytes sent."),
            send_packets_recv: Counter::new("Number of 'send' packets received."),
            bytes_recv: Counter::new("Number of bytes received."),
            send_packets_dropped: Counter::new("Number of 'send' packets dropped."),
            disco_packets_sent: Counter::new("Number of disco packets sent."),
            disco_packets_recv: Counter::new("Number of disco packets received."),
            disco_packets_dropped: Counter::new("Number of disco packets dropped."),

            other_packets_sent: Counter::new(
                "Number of packets sent that were not disco packets or 'send' packets",
            ),
            other_packets_recv: Counter::new(
                "Number of packets received that were not disco packets or 'send' packets",
            ),
            other_packets_dropped: Counter::new(
                "Number of times a non-disco, non-'send; packet was dropped.",
            ),
            got_ping: Counter::new("Number of times the server has received a Ping from a client."),
            sent_pong: Counter::new("Number of times the server has sent a Pong to a client."),
            unknown_frames: Counter::new("Number of unknown frames sent to this server."),
            frames_rx_ratelimited_total: Counter::new(
                "Number of frames received from client connection which have been rate-limited.",
            ),
            conns_rx_ratelimited_total: Counter::new(
                "Number of client connections which have had any frames rate-limited.",
            ),

            /*
             * Metrics about peers
             */
            accepts: Counter::new("Number of times this server has accepted a connection."),
            disconnects: Counter::new("Number of clients that have then disconnected."),

            unique_client_keys: Counter::new("Number of unique client keys per day."),

            websocket_accepts: Counter::new("Number of accepted websocket connections"),
            relay_accepts: Counter::new("Number of accepted 'iroh derp http' connection upgrades"),
            // TODO: enable when we can have multiple connections for one node id
            // pub duplicate_client_keys: Counter::new("Number of duplicate client keys."),
            // pub duplicate_client_conns: Counter::new("Number of duplicate client connections."),
            // TODO: only important stat that we cannot track right now
            // pub average_queue_duration:
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "relayserver"
    }
}

/// StunMetrics tracked for the relay server
#[derive(Debug, Clone, Iterable)]
pub struct StunMetrics {
    /*
     * Metrics about STUN requests
     */
    /// Number of stun requests made
    pub requests: Counter,
    /// Number of successful requests over ipv4
    pub ipv4_success: Counter,
    /// Number of successful requests over ipv6
    pub ipv6_success: Counter,

    /// Number of bad requests, either non-stun packets or incorrect binding request
    pub bad_requests: Counter,
    /// Number of failures
    pub failures: Counter,
}

impl Default for StunMetrics {
    fn default() -> Self {
        Self {
            /*
             * Metrics about STUN requests
             */
            requests: Counter::new("Number of STUN requests made to the server."),
            ipv4_success: Counter::new("Number of successful ipv4 STUN requests served."),
            ipv6_success: Counter::new("Number of successful ipv6 STUN requests served."),
            bad_requests: Counter::new("Number of bad requests made to the STUN endpoint."),
            failures: Counter::new("Number of STUN requests that end in failure."),
        }
    }
}

impl Metric for StunMetrics {
    fn name() -> &'static str {
        "stun"
    }
}
