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

        Self {
            requests_total,
            canceled_total,
            sent_block_bytes,
            received_block_bytes,
            providers_total,
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
}

impl MetricType for BitswapMetrics {
    fn name(&self) -> &'static str {
        match self {
            BitswapMetrics::Requests => METRICS_CNT_REQUESTS_TOTAL,
            BitswapMetrics::Cancels => METRICS_CNT_CANCEL_TOTAL,
            BitswapMetrics::BlockBytesOut => METRICS_CNT_BLOCK_BYTES_OUT,
            BitswapMetrics::BlockBytesIn => METRICS_CNT_BLOCK_BYTES_IN,
            BitswapMetrics::Providers => METRICS_CNT_PROVIDERS_TOTAL,
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
