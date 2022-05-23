use std::fmt;

use git_version::git_version;

use opentelemetry::trace::{TraceContextExt, TraceId};
use prometheus_client::{
    metrics::{
        counter::Counter,
        gauge::Gauge,
        histogram::{linear_buckets, Histogram},
    },
    registry::Registry,
};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub fn metrics_config(logger_only: bool) -> iroh_metrics::config::Config {
    // compile time configuration
    let service_name = env!("CARGO_PKG_NAME").to_string();
    let build = git_version!().to_string();
    let version = env!("CARGO_PKG_VERSION").to_string();

    // runtime configuration
    let instance_id = std::env::var("IROH_INSTANCE_ID")
        .unwrap_or_else(|_| names::Generator::default().next().unwrap());
    let service_env = std::env::var("IROH_ENV").unwrap_or_else(|_| "dev".to_string());
    iroh_metrics::config::Config::new(
        service_name,
        instance_id,
        build,
        version,
        service_env,
        logger_only,
    )
}

pub struct Metrics {
    pub requests_total: Counter,
    pub ttf_block: Gauge,
    pub ttf_file: Gauge,
    pub tts_block: Gauge,
    pub tts_file: Gauge,
    pub cache_hit: Counter,
    pub cache_miss: Counter,
    pub bytes_streamed: Counter,
    pub bytes_fetched: Counter,
    pub bytes_per_sec_in: Gauge,
    pub bytes_per_sec_out: Gauge,
    pub error_count: Counter,
    pub fail_count: Counter,
    pub hist_ttfb: Histogram,
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

        let ttf_file = Gauge::default();
        sub_registry.register(
            METRICS_TIME_TO_FETCH_FULL_FILE,
            "Time from start of request to fetching the full file",
            Box::new(ttf_file.clone()),
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

        let cache_hit = Counter::default();
        sub_registry.register(
            METRICS_CACHE_HIT,
            "Number of cache hits",
            Box::new(cache_hit.clone()),
        );

        let cache_miss = Counter::default();
        sub_registry.register(
            METRICS_CACHE_MISS,
            "Number of cache misses",
            Box::new(cache_miss.clone()),
        );

        let bytes_streamed = Counter::default();
        sub_registry.register(
            METRICS_BYTES_STREAMED,
            "Total number of bytes streamed",
            Box::new(bytes_streamed.clone()),
        );

        let bytes_fetched = Counter::default();
        sub_registry.register(
            METRICS_BYTES_FETCHED,
            "Total number of bytes fetched",
            Box::new(bytes_fetched.clone()),
        );

        let bitrate_in = Gauge::default();
        sub_registry.register(
            METRICS_BYTES_PER_SEC_IN,
            "Bitrate of incoming stream",
            Box::new(bitrate_in.clone()),
        );

        let bitrate_out = Gauge::default();
        sub_registry.register(
            METRICS_BYTES_PER_SEC_OUT,
            "Bitrate of outgoing stream",
            Box::new(bitrate_out.clone()),
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

        // let hist_ttfb = Histogram::default();
        let hist_ttfb = Histogram::new(linear_buckets(0.0, 500.0, 240));
        sub_registry.register(
            METRICS_HIST_TTFB,
            "Histogram of TTFB",
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
            ttf_file,
            tts_block,
            tts_file,
            cache_hit,
            cache_miss,
            bytes_streamed,
            bytes_fetched,
            bytes_per_sec_in: bitrate_in,
            bytes_per_sec_out: bitrate_out,
            error_count,
            fail_count,
            hist_ttfb,
            hist_ttsf,
        }
    }
}

pub const METRICS_CNT_REQUESTS_TOTAL: &str = "requests";
pub const METRICS_TIME_TO_FETCH_FIRST_BLOCK: &str = "time_to_fetch_first_block";
pub const METRICS_TIME_TO_FETCH_FULL_FILE: &str = "time_to_fetch_full_file";
pub const METRICS_TIME_TO_SERVE_FIRST_BLOCK: &str = "time_to_serve_first_block";
pub const METRICS_TIME_TO_SERVE_FULL_FILE: &str = "time_to_serve_full_file";
pub const METRICS_CACHE_HIT: &str = "cache_hit";
pub const METRICS_CACHE_MISS: &str = "cache_miss";
pub const METRICS_BYTES_STREAMED: &str = "bytes_streamed";
pub const METRICS_BYTES_FETCHED: &str = "bytes_fetched";
pub const METRICS_BYTES_PER_SEC_IN: &str = "bytes_per_sec_in";
pub const METRICS_BYTES_PER_SEC_OUT: &str = "bytes_per_sec_out";
pub const METRICS_HIST_TTFB: &str = "hist_time_to_fetch_first_block";
pub const METRICS_HIST_TTSERVE: &str = "hist_time_to_serve_full_file";
pub const METRICS_ERROR: &str = "error_count";
pub const METRICS_FAIL: &str = "fail_count";

pub fn get_current_trace_id() -> TraceId {
    tracing::Span::current()
        .context()
        .span()
        .span_context()
        .trace_id()
}
