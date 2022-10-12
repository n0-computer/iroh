use std::fmt;

use prometheus_client::{
    metrics::{counter::Counter, gauge::Gauge},
    registry::Registry,
};
use tracing::error;

use crate::{
    core::{HistogramType, MRecorder, MetricType, MetricsRecorder},
    Collector,
};

make_metrics! {
    Bitswap,
    RequestsTotal: Counter: "Total number of requests received by bitswap",
    CanceledTotal: Counter: "Total number of requests canceled by bitswap",
    SentBlockBytes: Counter: "Number of bytes streamed",
    ReceivedBlockBytes: Counter: "Number of bytes received",
    MessageBytesOut: Counter: "",
    MessageBytesIn: Counter: "",
    BlocksIn: Counter: "",
    BlocksOut: Counter: "",
    ProvidersTotal: Counter: "Number of providers",
    AttemptedDials: Counter: "",
    Dials: Counter: "",
    KnownPeers: Counter: "",
    ForgottenPeers: Counter: "",
    WantedBlocks: Counter: "",
    WantedBlocksReceived: Counter: "",
    WantHaveBlocks: Counter: "",
    CancelBlocks: Counter: "",
    CancelWantBlocks: Counter: "",
    ConnectedPeers: Counter: "",
    DisconnectedPeers: Counter: "",
    MessagesAttempted: Counter: "",
    MessagesSent: Counter: "",
    MessagesReceived: Counter: "",
    EventsBackpressureIn: Counter: "",
    EventsBackpressureOut: Counter: "",
    PollActionConnectedWants: Counter: "",
    PollActionConnected: Counter: "",
    PollActionNotConnected: Counter: "",
    ProtocolUnsupported: Counter: "",
    HandlerPollCount: Counter: "",
    HandlerPollEventCount: Counter: "",
    HandlerConnUpgradeErrors: Counter: "",
    InboundSubstreamsCreatedLimit: Counter: "",
    OutboundSubstreamsEvent: Counter: "",
    OutboundSubstreamsCreatedLimit: Counter: "",
    HandlerInboundLoopCount: Counter: "",
    HandlerOutboundLoopCount: Counter: "",
    SessionsCreated: Counter: "Number of sessions created",
    SessionsDestroyed: Counter: "Number of sessions destroyed",
    ProviderQueryCreated: Counter: "",
    ProviderQuerySuccess: Counter: "",
    ProviderQueryError: Counter: "",
    EngineActiveTasks: Gauge: "",
    EnginePendingTasks: Gauge: ""
}
