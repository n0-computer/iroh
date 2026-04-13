use std::sync::Arc;

use iroh_metrics::{Counter, MetricsGroup, MetricsGroupSet};

/// Metrics tracked for the relay server
#[derive(Debug, Default, MetricsGroup)]
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

    /// `FrameType::SendPacket` sent
    #[metrics(help = "Number of 'send' packets relayed.")]
    pub send_packets_sent: Counter,
    /// `FrameType::SendPacket` received
    #[metrics(help = "Number of 'send' packets received.")]
    pub send_packets_recv: Counter,
    /// `FrameType::SendPacket` dropped
    #[metrics(help = "Number of 'send' packets dropped.")]
    pub send_packets_dropped: Counter,

    /// Packets of other `FrameType`s sent
    #[metrics(help = "Number of packets sent that were not 'send' packets")]
    pub other_packets_sent: Counter,
    /// Packets of other `FrameType`s received
    #[metrics(help = "Number of packets received that were not 'send' packets")]
    pub other_packets_recv: Counter,
    /// Packets of other `FrameType`s dropped
    #[metrics(help = "Number of times, non-send packet was dropped.")]
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

    /// Number of bytes received from client connection which have been rate-limited.
    pub bytes_rx_ratelimited_total: Counter,
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

    /// Number of times a client was moved into the inactive state.
    ///
    /// A client becomes inactive when a new client connects with the same endpoint id. An inactive
    /// client can still send messages, but won't receive anything. If the currently-active client
    /// disconnects, and if there are inactive clients, the most-recent inactive client becomes
    /// active again.
    ///
    /// The number of inactive clients at any time is `clients_inactive_added` - `clients_inactive_removed`.
    pub clients_inactive_added: Counter,

    /// Number of times a client was removed from the inactive state.
    ///
    /// This is increased whenever a client disconnects while being inactive, or if a client is upgraded to be
    /// active again (happens only when the currently-active client for that endpoint id disconnects).
    ///
    /// See [`Self::clients_inactive_added`] for details on when a client becomes inactive.
    pub clients_inactive_removed: Counter,

    // TODO: only important stat that we cannot track right now
    // pub average_queue_duration:
    //
    /// Number of incoming QAD connections.
    ///
    /// After completion, each is counted in either `qad_incoming_error` or `qad_connections`.
    ///
    /// Thus the number of inflight incomings is `qad_incoming` - `qad_incoming_error` - `qad_connections`.
    pub qad_incoming: Counter,

    /// Number of QAD QUIC connections that aborted before completing the handshake.
    pub qad_incoming_error: Counter,

    /// Number of accepted QAD QUIC connections.
    ///
    /// The number of active connections is `qad_connections` - `qad_connections_closed`.
    pub qad_connections: Counter,

    /// Number of QAD QUIC connections that disconnected after being accepted.
    pub qad_connections_closed: Counter,

    /// Number of QAD QUIC connections that disconnected after being accepted, with an error.
    ///
    /// The number is *included* in `qad_connections_closed` (not in addition to).
    pub qad_connections_errored: Counter,

    /// Number of accepted HTTP(S) connections.
    ///
    /// The number of active connections at any time is `http_connections` - `http_connections_closed`
    pub http_connections: Counter,

    /// Number of terminated HTTP(S) connections.
    pub http_connections_closed: Counter,

    /// Number of HTTP(S) connections that terminated with an error.
    ///
    /// The number is *included* in `http_connections_closed` (not in addition to).
    pub http_connections_errored: Counter,
}

/// All metrics tracked in the relay server.
#[derive(Debug, Default, Clone, MetricsGroupSet)]
#[metrics(name = "relay")]
pub struct RelayMetrics {
    /// Metrics tracked for the relay server.
    pub server: Arc<Metrics>,
}
