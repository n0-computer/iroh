use std::fmt;

use prometheus_client::{
    metrics::{
        counter::Counter,
        gauge::Gauge,
        histogram::{linear_buckets, Histogram},
    },
    registry::Registry,
};
use tracing::error;

use crate::{
    core::{HistogramType, MetricType},
    core::{MObserver, MRecorder, MetricsRecorder},
    Collector,
};

#[derive(Clone)]
pub(crate) struct Metrics {
    requests_total: Counter,
    ttf_block: Gauge,
    tts_block: Gauge,
    tts_file: Gauge,
    bytes_streamed: Counter,
    error_count: Counter,
    fail_count: Counter,
    hist_ttfb: Histogram,
    hist_ttfb_cached: Histogram,
    hist_ttsf: Histogram,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gateway Metrics").finish()
    }
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let sub_registry = registry.sub_registry_with_prefix("gateway");
        let requests_total = Counter::default();
        sub_registry.register(
            METRICS_CNT_REQUESTS_TOTAL,
            "Total number of requests received by the gateway",
            Box::new(requests_total.clone()),
        );

        let ttf_block = Gauge::default();
        sub_registry.register(
            METRICS_TIME_TO_FETCH_FIRST_BLOCK,
            "Time from start of request to fetching the first block",
            Box::new(ttf_block.clone()),
        );

        let tts_block = Gauge::default();
        sub_registry.register(
            METRICS_TIME_TO_SERVE_FIRST_BLOCK,
            "Time from start of request to serving the first block",
            Box::new(tts_block.clone()),
        );

        let tts_file = Gauge::default();
        sub_registry.register(
            METRICS_TIME_TO_SERVE_FULL_FILE,
            "Time from start of request to serving the full file",
            Box::new(tts_file.clone()),
        );

        let bytes_streamed = Counter::default();
        sub_registry.register(
            METRICS_BYTES_STREAMED,
            "Total number of bytes streamed",
            Box::new(bytes_streamed.clone()),
        );

        let error_count = Counter::default();
        sub_registry.register(
            METRICS_ERROR,
            "Number of errors",
            Box::new(error_count.clone()),
        );

        let fail_count = Counter::default();
        sub_registry.register(
            METRICS_FAIL,
            "Number of failed requests",
            Box::new(fail_count.clone()),
        );

        let hist_ttfb = Histogram::new(linear_buckets(0.0, 500.0, 240));
        sub_registry.register(
            METRICS_HIST_TTFB,
            "Histogram of TTFB",
            Box::new(hist_ttfb.clone()),
        );
        let hist_ttfb_cached = Histogram::new(linear_buckets(0.0, 500.0, 240));
        sub_registry.register(
            METRICS_HIST_TTFB_CACHED,
            "Histogram of TTFB from Cache",
            Box::new(hist_ttfb_cached.clone()),
        );

        let hist_ttsf = Histogram::new(linear_buckets(0.0, 500.0, 240));
        sub_registry.register(
            METRICS_HIST_TTSERVE,
            "Histogram of TTSERVE",
            Box::new(hist_ttsf.clone()),
        );

        Self {
            requests_total,
            ttf_block,
            tts_block,
            tts_file,
            bytes_streamed,
            error_count,
            fail_count,
            hist_ttfb,
            hist_ttfb_cached,
            hist_ttsf,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::default();
        Metrics::new(&mut registry)
    }
}

impl MetricsRecorder for Metrics {
    fn record<M>(&self, m: M, value: u64)
    where
        M: MetricType + std::fmt::Display,
    {
        if m.name() == GatewayMetrics::Requests.name() {
            self.requests_total.inc_by(value);
        } else if m.name() == GatewayMetrics::BytesStreamed.name() {
            self.bytes_streamed.inc_by(value);
        } else if m.name() == GatewayMetrics::ErrorCount.name() {
            self.error_count.inc_by(value);
        } else if m.name() == GatewayMetrics::FailCount.name() {
            self.fail_count.inc_by(value);
        } else if m.name() == GatewayMetrics::TimeToFetchFirstBlock.name() {
            self.ttf_block.set(value);
        } else if m.name() == GatewayMetrics::TimeToServeFirstBlock.name() {
            self.tts_block.set(value);
        } else if m.name() == GatewayMetrics::TimeToServeFullFile.name() {
            self.tts_file.set(value);
        } else {
            error!("record (gateway): unknown metric {}", m.name());
        }
    }

    fn observe<M>(&self, m: M, value: f64)
    where
        M: HistogramType + std::fmt::Display,
    {
        if m.name() == GatewayHistograms::TimeToFetchFirstBlock.name() {
            self.hist_ttfb.observe(value);
        } else if m.name() == GatewayHistograms::TimeToFetchFirstBlockCached.name() {
            self.hist_ttfb_cached.observe(value);
        } else if m.name() == GatewayHistograms::TimeToServeFullFile.name() {
            self.hist_ttsf.observe(value);
        } else {
            error!("observe (gateway): unknown metric {}", m.name());
        }
    }
}

#[derive(Clone)]
pub enum GatewayMetrics {
    Requests,
    BytesStreamed,
    ErrorCount,
    FailCount,
    TimeToFetchFirstBlock,
    TimeToServeFirstBlock,
    TimeToServeFullFile,
}

impl MetricType for GatewayMetrics {
    fn name(&self) -> &'static str {
        match self {
            GatewayMetrics::Requests => METRICS_CNT_REQUESTS_TOTAL,
            GatewayMetrics::BytesStreamed => METRICS_BYTES_STREAMED,
            GatewayMetrics::ErrorCount => METRICS_ERROR,
            GatewayMetrics::FailCount => METRICS_FAIL,
            GatewayMetrics::TimeToFetchFirstBlock => METRICS_TIME_TO_FETCH_FIRST_BLOCK,
            GatewayMetrics::TimeToServeFirstBlock => METRICS_TIME_TO_SERVE_FIRST_BLOCK,
            GatewayMetrics::TimeToServeFullFile => METRICS_TIME_TO_SERVE_FULL_FILE,
        }
    }
}

impl MRecorder for GatewayMetrics {
    fn record(&self, value: u64) {
        crate::record(Collector::Gateway, self.clone(), value);
    }
}

impl std::fmt::Display for GatewayMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Clone)]
pub enum GatewayHistograms {
    TimeToFetchFirstBlock,
    TimeToFetchFirstBlockCached,
    TimeToServeFullFile,
}

impl HistogramType for GatewayHistograms {
    fn name(&self) -> &'static str {
        match self {
            GatewayHistograms::TimeToFetchFirstBlock => METRICS_HIST_TTFB,
            GatewayHistograms::TimeToFetchFirstBlockCached => METRICS_HIST_TTFB_CACHED,
            GatewayHistograms::TimeToServeFullFile => METRICS_HIST_TTSERVE,
        }
    }
}

impl MObserver for GatewayHistograms {
    fn observe(&self, value: f64) {
        crate::observe(Collector::Gateway, self.clone(), value);
    }
}

impl std::fmt::Display for GatewayHistograms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

const METRICS_CNT_REQUESTS_TOTAL: &str = "requests_total";
const METRICS_TIME_TO_FETCH_FIRST_BLOCK: &str = "time_to_fetch_first_block";
const METRICS_TIME_TO_SERVE_FIRST_BLOCK: &str = "time_to_serve_first_block";
const METRICS_TIME_TO_SERVE_FULL_FILE: &str = "time_to_serve_full_file";
const METRICS_BYTES_STREAMED: &str = "bytes_streamed";
const METRICS_HIST_TTFB: &str = "hist_time_to_fetch_first_block";
const METRICS_HIST_TTFB_CACHED: &str = "hist_time_to_fetch_first_block_cached";
const METRICS_HIST_TTSERVE: &str = "hist_time_to_serve_full_file";
const METRICS_ERROR: &str = "error_count";
const METRICS_FAIL: &str = "fail_count";
