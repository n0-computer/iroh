use std::sync::Arc;

use iroh_metrics::{Counter, MetricsGroup, MetricsGroupSet};

/// Metrics tracked for the relay server
#[derive(Debug, Clone, MetricsGroup)]
#[metrics(name = "relayserver")]
pub struct Metrics {
    /*
     * Metrics about packets
     */
    /// Bytes sent from a `FrameType::SendPacket`
    #[metrics(help = "Number of bytes sent.")]
    pub bytes_sent: Counter,
    /// Bytes received from a `FrameType::SendPacket`
    #[metrics(help = "Number of bytes received.")]
    pub bytes_recv: Counter,

    /// `FrameType::SendPacket` sent, that are not disco messages
    #[metrics(help = "Number of 'send' packets relayed.")]
    pub send_packets_sent: Counter,
    /// `FrameType::SendPacket` received, that are not disco messages
    #[metrics(help = "Number of 'send' packets received.")]
    pub send_packets_recv: Counter,
    /// `FrameType::SendPacket` dropped, that are not disco messages
    #[metrics(help = "Number of 'send' packets dropped.")]
    pub send_packets_dropped: Counter,

    /// `FrameType::SendPacket` sent that are disco messages
    #[metrics(help = "Number of disco packets sent.")]
    pub disco_packets_sent: Counter,
    /// `FrameType::SendPacket` received that are disco messages
    #[metrics(help = "Number of disco packets received.")]
    pub disco_packets_recv: Counter,
    /// `FrameType::SendPacket` dropped that are disco messages
    #[metrics(help = "Number of disco packets dropped.")]
    pub disco_packets_dropped: Counter,

    /// Packets of other `FrameType`s sent
    #[metrics(help = "Number of packets sent that were not disco packets or 'send' packets")]
    pub other_packets_sent: Counter,
    /// Packets of other `FrameType`s received
    #[metrics(help = "Number of packets received that were not disco packets or 'send' packets")]
    pub other_packets_recv: Counter,
    /// Packets of other `FrameType`s dropped
    #[metrics(help = "Number of times a non-disco, non-send packet was dropped.")]
    pub other_packets_dropped: Counter,

    /// Number of `FrameType::Ping`s received
    #[metrics(help = "Number of times the server has received a Ping from a client.")]
    pub got_ping: Counter,
    /// Number of `FrameType::Pong`s sent
    #[metrics(help = "Number of times the server has sent a Pong to a client.")]
    pub sent_pong: Counter,
    /// Number of `FrameType::Unknown` received
    #[metrics(help = "Number of unknown frames sent to this server.")]
    pub unknown_frames: Counter,

    /// Number of frames received from client connection which have been rate-limited.
    pub frames_rx_ratelimited_total: Counter,
    /// Number of client connections which have had any frames rate-limited.
    pub conns_rx_ratelimited_total: Counter,

    /*
     * Metrics about peers
     */
    /// Number of times this server has accepted a connection.
    pub accepts: Counter,
    /// Number of connections we have removed because of an error
    #[metrics(help = "Number of clients that have then disconnected.")]
    pub disconnects: Counter,

    /// Number of unique client keys per day
    pub unique_client_keys: Counter,

    /// Number of accepted websocket connections.
    pub websocket_accepts: Counter,
    /// Number of accepted 'iroh derp http' connection upgrades
    pub relay_accepts: Counter,
    // TODO: enable when we can have multiple connections for one node id
    // pub duplicate_client_keys: Counter,
    // pub duplicate_client_conns: Counter,
    // TODO: only important stat that we cannot track right now
    // pub average_queue_duration:
}

/// StunMetrics tracked for the relay server
#[derive(Debug, Clone, MetricsGroup)]
#[metrics(name = "stun")]
pub struct StunMetrics {
    /// Number of STUN requests made to the server.
    pub requests: Counter,
    /// Number of successful ipv4 STUN requests served.
    pub ipv4_success: Counter,
    /// Number of successful ipv6 STUN requests served.
    pub ipv6_success: Counter,
    /// Number of bad requests made to the STUN endpoint.
    pub bad_requests: Counter,
    /// Number of STUN requests that end in failure.
    pub failures: Counter,
}

#[derive(Debug, Default, Clone)]
pub struct RelayMetrics {
    pub stun: Arc<StunMetrics>,
    pub server: Arc<Metrics>,
}

impl MetricsGroupSet for RelayMetrics {
    fn name(&self) -> &'static str {
        "relay"
    }

    fn groups(&self) -> impl Iterator<Item = &dyn MetricsGroup> {
        [
            &*self.stun as &dyn MetricsGroup,
            &*self.server as &dyn MetricsGroup,
        ]
        .into_iter()
    }
}
