use std::fmt;

use prometheus_client::{
    metrics::{
        counter::Counter,
        gauge::Gauge,
        histogram::{linear_buckets, Histogram},
    },
    registry::Registry,
};

#[derive(Clone)]
pub struct Metrics {
    pub requests_total: Counter,
    pub ttf_block: Gauge,
    pub tts_block: Gauge,
    pub tts_file: Gauge,
    pub bytes_streamed: Counter,
    pub error_count: Counter,
    pub fail_count: Counter,
    pub hist_ttfb: Histogram,
    pub hist_ttfb_cached: Histogram,
    pub hist_ttsf: Histogram,
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
            Box::new(hist_ttfb.clone()),
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

const METRICS_CNT_REQUESTS_TOTAL: &str = "requests";
const METRICS_TIME_TO_FETCH_FIRST_BLOCK: &str = "time_to_fetch_first_block";
const METRICS_TIME_TO_SERVE_FIRST_BLOCK: &str = "time_to_serve_first_block";
const METRICS_TIME_TO_SERVE_FULL_FILE: &str = "time_to_serve_full_file";
const METRICS_BYTES_STREAMED: &str = "bytes_streamed";
const METRICS_HIST_TTFB: &str = "hist_time_to_fetch_first_block";
const METRICS_HIST_TTFB_CACHED: &str = "hist_time_to_fetch_first_block_cached";
const METRICS_HIST_TTSERVE: &str = "hist_time_to_serve_full_file";
const METRICS_ERROR: &str = "error_count";
const METRICS_FAIL: &str = "fail_count";
