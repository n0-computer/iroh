use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Metrics tracked for the DERP server
#[allow(missing_docs)]
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

    /// Number of packets we have forwarded out to another packet forwarder
    pub packets_forwarded_out: Counter,
    /// Number of packets we have been asked to forward
    pub packets_forwarded_in: Counter,

    /// Number of `FrameType::Ping`s received
    pub got_ping: Counter,
    /// Number of `FrameType::Pong`s sent
    pub sent_pong: Counter,
    /// Number of `FrameType::Unknown` received
    pub unknown_frames: Counter,

    /*
     * Metrics about peers
     */
    /// Number of packet forwarders added
    pub added_pkt_fwder: Counter,
    /// Number of packet forwarders removed
    pub removed_pkt_fwder: Counter,

    /// Number of connections we have accepted
    pub accepts: Counter,
    /// Number of connections we have removed because of an error
    pub disconnects: Counter,
    // TODO: enable when we can have multiple connections for one peer id
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

            packets_forwarded_out: Counter::new(
                "Number of times the server has sent a forwarded packet",
            ),
            packets_forwarded_in: Counter::new(
                "Number of times the server has received a forwarded packet.",
            ),

            got_ping: Counter::new("Number of times the server has received a Ping from a client."),
            sent_pong: Counter::new("Number of times the server has sent a Pong to a client."),
            unknown_frames: Counter::new("Number of unknown frames sent to this server."),

            /*
             * Metrics about peers
             */
            added_pkt_fwder: Counter::new(
                "Number of times a packeted forwarded was added to this server.",
            ),
            removed_pkt_fwder: Counter::new(
                "Number of times a packet forwarded was removed to this server.",
            ),

            accepts: Counter::new("Number of times this server has accepted a connection."),
            disconnects: Counter::new("Number of clients that have then disconnected."),
            // TODO: enable when we can have multiple connections for one peer id
            // pub duplicate_client_keys: Counter::new("Number of dupliate client keys."),
            // pub duplicate_client_conns: Counter::new("Number of duplicate client connections."),
            // TODO: only important stat that we cannot track right now
            // pub average_queue_duration:
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "derpserver"
    }
}
