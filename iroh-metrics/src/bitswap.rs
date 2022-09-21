use std::fmt;

use prometheus_client::{metrics::counter::Counter, registry::Registry};
use tracing::error;

use crate::{
    core::{HistogramType, MRecorder, MetricType, MetricsRecorder},
    Collector,
};

#[derive(Default, Clone)]
pub(crate) struct Metrics {
    requests_total: Counter,
    canceled_total: Counter,
    sent_block_bytes: Counter,
    received_block_bytes: Counter,
    providers_total: Counter,

    // new metrics
    attempted_dials: Counter,
    known_peers: Counter,
    forgotten_peers: Counter,
    wanted_blocks: Counter,
    want_have_blocks: Counter,
    cancel_blocks: Counter,
    cancel_want_blocks: Counter,
    connected_peers: Counter,
    disconnected_peers: Counter,
    messages_sent: Counter,
    messages_received: Counter,
    events_backpressure_in: Counter,
    events_backpressure_out: Counter,
    poll_action_connected_wants: Counter,
    poll_action_connected: Counter,
    poll_action_not_connected: Counter,
    protocol_unsupported: Counter,
    handler_poll_count: Counter,
    handler_poll_event_count: Counter,
    handler_conn_upgrade_errors: Counter,
    inbound_substreams_created_limit: Counter,
    outbount_substreams_event: Counter,
    outbound_substreams_created_limit: Counter,
    handler_inbound_loop_count: Counter,
    handler_outbound_loop_count: Counter,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store Metrics").finish()
    }
}

impl Metrics {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let sub_registry = registry.sub_registry_with_prefix("bitswap");
        let requests_total = Counter::default();
        sub_registry.register(
            METRICS_CNT_REQUESTS_TOTAL,
            "Total number of requests received by bitswap",
            Box::new(requests_total.clone()),
        );

        let canceled_total = Counter::default();
        sub_registry.register(
            METRICS_CNT_CANCEL_TOTAL,
            "Total number of requests canceled by bitswap",
            Box::new(canceled_total.clone()),
        );

        let sent_block_bytes = Counter::default();
        sub_registry.register(
            METRICS_CNT_BLOCK_BYTES_OUT,
            "Number of bytes streamed",
            Box::new(sent_block_bytes.clone()),
        );

        let received_block_bytes = Counter::default();
        sub_registry.register(
            METRICS_CNT_BLOCK_BYTES_IN,
            "Number of bytes received",
            Box::new(received_block_bytes.clone()),
        );

        let providers_total = Counter::default();
        sub_registry.register(
            METRICS_CNT_PROVIDERS_TOTAL,
            "Number of providers",
            Box::new(providers_total.clone()),
        );

        // new metrics
        let attempted_dials = Counter::default();
        sub_registry.register("attempted_dials", "", Box::new(attempted_dials.clone()));
        let known_peers = Counter::default();
        sub_registry.register("known_peers", "", Box::new(known_peers.clone()));
        let forgotten_peers = Counter::default();
        sub_registry.register("forgotten_peers", "", Box::new(forgotten_peers.clone()));
        let wanted_blocks = Counter::default();
        sub_registry.register("wanted_blocks", "", Box::new(wanted_blocks.clone()));
        let want_have_blocks = Counter::default();
        sub_registry.register("want_have_blocks", "", Box::new(want_have_blocks.clone()));
        let cancel_blocks = Counter::default();
        sub_registry.register("cancel_blocks", "", Box::new(cancel_blocks.clone()));
        let cancel_want_blocks = Counter::default();
        sub_registry.register(
            "cancel_want_blocks",
            "",
            Box::new(cancel_want_blocks.clone()),
        );
        let connected_peers = Counter::default();
        sub_registry.register("connected_peers", "", Box::new(connected_peers.clone()));
        let disconnected_peers = Counter::default();
        sub_registry.register(
            "disconnected_peers",
            "",
            Box::new(disconnected_peers.clone()),
        );
        let messages_sent = Counter::default();
        sub_registry.register("messages_sent", "", Box::new(messages_sent.clone()));
        let messages_received = Counter::default();
        sub_registry.register("messages_received", "", Box::new(messages_received.clone()));
        let events_backpressure_in = Counter::default();
        sub_registry.register(
            "events_backpressure_in",
            "",
            Box::new(events_backpressure_in.clone()),
        );
        let events_backpressure_out = Counter::default();
        sub_registry.register(
            "events_backpressure_out",
            "",
            Box::new(events_backpressure_out.clone()),
        );
        let poll_action_connected_wants = Counter::default();
        sub_registry.register(
            "poll_action_connected_wants",
            "",
            Box::new(poll_action_connected_wants.clone()),
        );
        let poll_action_connected = Counter::default();
        sub_registry.register(
            "poll_action_connected",
            "",
            Box::new(poll_action_connected.clone()),
        );
        let poll_action_not_connected = Counter::default();
        sub_registry.register(
            "poll_action_not_connected",
            "",
            Box::new(poll_action_not_connected.clone()),
        );

        let protocol_unsupported = Counter::default();
        sub_registry.register(
            "protocol_unsupported",
            "",
            Box::new(protocol_unsupported.clone()),
        );

        let handler_poll_count = Counter::default();
        sub_registry.register(
            "handler_poll_count",
            "",
            Box::new(handler_poll_count.clone()),
        );
        let handler_poll_event_count = Counter::default();
        sub_registry.register(
            "handler_poll_event_count",
            "",
            Box::new(handler_poll_event_count.clone()),
        );

        let handler_conn_upgrade_errors = Counter::default();
        sub_registry.register(
            "handler_conn_upgrade_errors",
            "",
            Box::new(handler_conn_upgrade_errors.clone()),
        );

        let inbound_substreams_created_limit = Counter::default();
        sub_registry.register(
            "inbound_substreams_created_limit",
            "",
            Box::new(inbound_substreams_created_limit.clone()),
        );

        let outbount_substreams_event = Counter::default();
        sub_registry.register(
            "outbount_substreams_event",
            "",
            Box::new(outbount_substreams_event.clone()),
        );
        let outbound_substreams_created_limit = Counter::default();
        sub_registry.register(
            "outbound_substreams_created_limit",
            "",
            Box::new(outbound_substreams_created_limit.clone()),
        );
        let handler_inbound_loop_count = Counter::default();
        sub_registry.register(
            "handler_inbound_loop_count",
            "",
            Box::new(handler_inbound_loop_count.clone()),
        );

        let handler_outbound_loop_count = Counter::default();
        sub_registry.register(
            "handler_outbound_loop_count",
            "",
            Box::new(handler_outbound_loop_count.clone()),
        );

        Self {
            requests_total,
            canceled_total,
            sent_block_bytes,
            received_block_bytes,
            providers_total,
            attempted_dials,
            known_peers,
            forgotten_peers,
            wanted_blocks,
            want_have_blocks,
            cancel_blocks,
            cancel_want_blocks,
            connected_peers,
            disconnected_peers,
            messages_sent,
            messages_received,
            events_backpressure_in,
            events_backpressure_out,
            poll_action_connected_wants,
            poll_action_connected,
            poll_action_not_connected,
            protocol_unsupported,
            handler_poll_count,
            handler_poll_event_count,
            handler_conn_upgrade_errors,
            inbound_substreams_created_limit,
            outbount_substreams_event,
            outbound_substreams_created_limit,
            handler_inbound_loop_count,
            handler_outbound_loop_count,
        }
    }
}

impl MetricsRecorder for Metrics {
    fn record<M>(&self, m: M, value: u64)
    where
        M: MetricType + std::fmt::Display,
    {
        if m.name() == BitswapMetrics::Requests.name() {
            self.requests_total.inc_by(value);
        } else if m.name() == BitswapMetrics::Cancels.name() {
            self.canceled_total.inc_by(value);
        } else if m.name() == BitswapMetrics::BlockBytesOut.name() {
            self.sent_block_bytes.inc_by(value);
        } else if m.name() == BitswapMetrics::BlockBytesIn.name() {
            self.received_block_bytes.inc_by(value);
        } else if m.name() == BitswapMetrics::Providers.name() {
            self.providers_total.inc_by(value);
        } else if m.name() == BitswapMetrics::AttemptedDials.name() {
            self.attempted_dials.inc_by(value);
        } else if m.name() == BitswapMetrics::KnownPeers.name() {
            self.known_peers.inc_by(value);
        } else if m.name() == BitswapMetrics::ForgottenPeers.name() {
            self.forgotten_peers.inc_by(value);
        } else if m.name() == BitswapMetrics::WantedBlocks.name() {
            self.wanted_blocks.inc_by(value);
        } else if m.name() == BitswapMetrics::WantHaveBlocks.name() {
            self.want_have_blocks.inc_by(value);
        } else if m.name() == BitswapMetrics::CancelBlocks.name() {
            self.cancel_blocks.inc_by(value);
        } else if m.name() == BitswapMetrics::CancelWantBlocks.name() {
            self.cancel_want_blocks.inc_by(value);
        } else if m.name() == BitswapMetrics::ConnectedPeers.name() {
            self.connected_peers.inc_by(value);
        } else if m.name() == BitswapMetrics::DisconnectedPeers.name() {
            self.disconnected_peers.inc_by(value);
        } else if m.name() == BitswapMetrics::MessagesSent.name() {
            self.messages_sent.inc_by(value);
        } else if m.name() == BitswapMetrics::MessagesReceived.name() {
            self.messages_received.inc_by(value);
        } else if m.name() == BitswapMetrics::EventsBackpressureIn.name() {
            self.events_backpressure_in.inc_by(value);
        } else if m.name() == BitswapMetrics::EventsBackpressureOut.name() {
            self.events_backpressure_out.inc_by(value);
        } else if m.name() == BitswapMetrics::PollActionConnectedWants.name() {
            self.poll_action_connected_wants.inc_by(value);
        } else if m.name() == BitswapMetrics::PollActionConnected.name() {
            self.poll_action_connected.inc_by(value);
        } else if m.name() == BitswapMetrics::PollActionNotConnected.name() {
            self.poll_action_not_connected.inc_by(value);
        } else if m.name() == BitswapMetrics::ProtocolUnsupported.name() {
            self.protocol_unsupported.inc_by(value);
        } else if m.name() == BitswapMetrics::HandlerPollCount.name() {
            self.handler_poll_count.inc_by(value);
        } else if m.name() == BitswapMetrics::HandlerPollEventCount.name() {
            self.handler_poll_event_count.inc_by(value);
        } else if m.name() == BitswapMetrics::HandlerConnUpgradeErrors.name() {
            self.handler_conn_upgrade_errors.inc_by(value);
        } else if m.name() == BitswapMetrics::InboundSubstreamsCreatedLimit.name() {
            self.inbound_substreams_created_limit.inc_by(value);
        } else if m.name() == BitswapMetrics::OutboundSubstreamsEvent.name() {
            self.outbount_substreams_event.inc_by(value);
        } else if m.name() == BitswapMetrics::OutboundSubstreamsCreatedLimit.name() {
            self.outbound_substreams_created_limit.inc_by(value);
        } else if m.name() == BitswapMetrics::HandlerInboundLoopCount.name() {
            self.handler_inbound_loop_count.inc_by(value);
        } else if m.name() == BitswapMetrics::HandlerOutboundLoopCount.name() {
            self.handler_outbound_loop_count.inc_by(value);
        } else {
            error!("record (bitswap): unknown metric {}", m.name());
        }
    }

    fn observe<M>(&self, m: M, _value: f64)
    where
        M: HistogramType + std::fmt::Display,
    {
        error!("observe (bitswap): unknown metric {}", m.name());
    }
}

#[derive(Clone)]
pub enum BitswapMetrics {
    Requests,
    Cancels,
    BlockBytesOut,
    BlockBytesIn,
    Providers,

    AttemptedDials,
    KnownPeers,
    ForgottenPeers,
    WantedBlocks,
    WantHaveBlocks,
    CancelBlocks,
    CancelWantBlocks,
    ConnectedPeers,
    DisconnectedPeers,
    MessagesSent,
    MessagesReceived,
    EventsBackpressureIn,
    EventsBackpressureOut,
    PollActionConnectedWants,
    PollActionConnected,
    PollActionNotConnected,

    ProtocolUnsupported,

    HandlerPollCount,
    HandlerPollEventCount,
    HandlerConnUpgradeErrors,
    InboundSubstreamsCreatedLimit,
    OutboundSubstreamsEvent,
    OutboundSubstreamsCreatedLimit,
    HandlerInboundLoopCount,
    HandlerOutboundLoopCount,
}

impl MetricType for BitswapMetrics {
    fn name(&self) -> &'static str {
        match self {
            BitswapMetrics::Requests => METRICS_CNT_REQUESTS_TOTAL,
            BitswapMetrics::Cancels => METRICS_CNT_CANCEL_TOTAL,
            BitswapMetrics::BlockBytesOut => METRICS_CNT_BLOCK_BYTES_OUT,
            BitswapMetrics::BlockBytesIn => METRICS_CNT_BLOCK_BYTES_IN,
            BitswapMetrics::Providers => METRICS_CNT_PROVIDERS_TOTAL,

            BitswapMetrics::AttemptedDials => METRICS_CNT_ATTEMPTED_DIALS,
            BitswapMetrics::KnownPeers => METRICS_CNT_KNOWN_PEERS,
            BitswapMetrics::ForgottenPeers => METRICS_CNT_FORGOTTEN_PEERS,
            BitswapMetrics::WantedBlocks => METRICS_CNT_WANTED_BLOCKS,
            BitswapMetrics::WantHaveBlocks => METRICS_CNT_WANT_HAVE_BLOCKS,
            BitswapMetrics::CancelBlocks => METRICS_CNT_CANCEL_BLOCKS,
            BitswapMetrics::CancelWantBlocks => METRICS_CNT_CANCEL_WANT_BLOCKS,
            BitswapMetrics::ConnectedPeers => METRICS_CNT_CONNECTED_PEERS,
            BitswapMetrics::DisconnectedPeers => METRICS_CNT_DISCONNECTED_PEERS,
            BitswapMetrics::MessagesSent => METRICS_CNT_MESSAGES_SENT,
            BitswapMetrics::MessagesReceived => METRICS_CNT_MESSAGES_RECEIVED,
            BitswapMetrics::EventsBackpressureIn => METRICS_CNT_EVENTS_BACKPRESSURE_IN,
            BitswapMetrics::EventsBackpressureOut => METRICS_CNT_EVENTS_BACKPRESSURE_OUT,
            BitswapMetrics::PollActionConnectedWants => METRICS_CNT_POLL_ACTION_CONNECTED_WANTS,
            BitswapMetrics::PollActionConnected => METRICS_CNT_POLL_ACTION_CONNECTED,
            BitswapMetrics::PollActionNotConnected => METRICS_CNT_POLL_ACTION_NOT_CONNECTED,

            BitswapMetrics::ProtocolUnsupported => METRICS_CNT_PROTOCOL_UNSUPPORTED,

            BitswapMetrics::HandlerPollCount => "handler_poll_count",
            BitswapMetrics::HandlerPollEventCount => "handler_poll_event_count",
            BitswapMetrics::HandlerConnUpgradeErrors => "handler_conn_upgrade_errors",
            BitswapMetrics::InboundSubstreamsCreatedLimit => "inbound_substreams_created_limit",
            BitswapMetrics::OutboundSubstreamsEvent => "outbound_substreams_event",
            BitswapMetrics::OutboundSubstreamsCreatedLimit => "outbound_substreams_created_limit",
            BitswapMetrics::HandlerInboundLoopCount => "handler_inbound_loop_count",
            BitswapMetrics::HandlerOutboundLoopCount => "handler_outbound_loop_count",
        }
    }
}

impl MRecorder for BitswapMetrics {
    fn record(&self, value: u64) {
        crate::record(Collector::Bitswap, self.clone(), value);
    }
}

impl std::fmt::Display for BitswapMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

pub const METRICS_CNT_REQUESTS_TOTAL: &str = "requests";
pub const METRICS_CNT_CANCEL_TOTAL: &str = "canceled";
pub const METRICS_CNT_BLOCK_BYTES_OUT: &str = "block_bytes_out";
pub const METRICS_CNT_BLOCK_BYTES_IN: &str = "block_bytes_in";
pub const METRICS_CNT_PROVIDERS_TOTAL: &str = "providers";
pub const METRICS_CNT_ATTEMPTED_DIALS: &str = "attempted_dials";
pub const METRICS_CNT_KNOWN_PEERS: &str = "known_peers";
pub const METRICS_CNT_FORGOTTEN_PEERS: &str = "forgotten_peers";
pub const METRICS_CNT_WANTED_BLOCKS: &str = "wanted_blocks";
pub const METRICS_CNT_WANT_HAVE_BLOCKS: &str = "want_have_blocks";
pub const METRICS_CNT_CANCEL_BLOCKS: &str = "cancel_blocks";
pub const METRICS_CNT_CANCEL_WANT_BLOCKS: &str = "cancel_want_blocks";
pub const METRICS_CNT_CONNECTED_PEERS: &str = "connected_peers";
pub const METRICS_CNT_DISCONNECTED_PEERS: &str = "disconnected_peers";
pub const METRICS_CNT_MESSAGES_SENT: &str = "messages_sent";
pub const METRICS_CNT_MESSAGES_RECEIVED: &str = "messages_received";
pub const METRICS_CNT_EVENTS_BACKPRESSURE_IN: &str = "events_backpressure_in";
pub const METRICS_CNT_EVENTS_BACKPRESSURE_OUT: &str = "events_backpressure_out";
pub const METRICS_CNT_POLL_ACTION_CONNECTED_WANTS: &str = "poll_action_connected_wants";
pub const METRICS_CNT_POLL_ACTION_CONNECTED: &str = "poll_action_connected";
pub const METRICS_CNT_POLL_ACTION_NOT_CONNECTED: &str = "poll_action_not_connected";

pub const METRICS_CNT_PROTOCOL_UNSUPPORTED: &str = "protocol_unsupported";
