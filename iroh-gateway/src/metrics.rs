use git_version::git_version;
use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};

use opentelemetry::trace::{TraceContextExt, TraceId};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub fn metrics_config(logger_only: bool) -> iroh_metrics::Config {
    // compile time configuration
    let service_name = env!("CARGO_PKG_NAME").to_string();
    let build = git_version!().to_string();
    let version = env!("CARGO_PKG_VERSION").to_string();

    // runtime configuration
    let instance_id = std::env::var("IROH_INSTANCE_ID")
        .unwrap_or_else(|_| names::Generator::default().next().unwrap());
    let service_env = std::env::var("IROH_ENV").unwrap_or_else(|_| "dev".to_string());
    iroh_metrics::Config::new(
        service_name,
        instance_id,
        build,
        version,
        service_env,
        logger_only,
    )
}

pub const METRICS_CNT_REQUESTS_TOTAL: &str = "gw_requests_total";
pub const METRICS_TIME_TO_FETCH_FIRST_BLOCK: &str = "gw_time_to_fetch_first_block";
pub const METRICS_TIME_TO_FETCH_FULL_FILE: &str = "gw_time_to_fetch_full_file";
pub const METRICS_TIME_TO_SERVE_FIRST_BLOCK: &str = "gw_time_to_serve_first_block";
pub const METRICS_TIME_TO_SERVE_FULL_FILE: &str = "gw_time_to_serve_full_file";
pub const METRICS_CACHE_HIT: &str = "gw_cache_hit";
pub const METRICS_CACHE_MISS: &str = "gw_cache_miss";
pub const METRICS_BYTES_STREAMED: &str = "gw_bytes_streamed";
pub const METRICS_BYTES_FETCHED: &str = "gw_bytes_fetched";
pub const METRICS_BITRATE_IN: &str = "gw_bitrate_in";
pub const METRICS_BITRATE_OUT: &str = "gw_bitrate_out";
pub const METRICS_HIST_TTFB: &str = "gw_hist_time_to_fetch_first_block";
pub const METRICS_HIST_TTSERVE: &str = "gw_hist_time_to_serve_full_file";
pub const METRICS_ERROR: &str = "gw_error_count";
pub const METRICS_FAIL: &str = "gw_fail_count";

pub fn register_counters() {
    describe_counter!(
        METRICS_CNT_REQUESTS_TOTAL,
        Unit::Count,
        "Total number of requests received by the gateway"
    );
    describe_gauge!(
        METRICS_TIME_TO_FETCH_FIRST_BLOCK,
        Unit::Milliseconds,
        "Time from start of request to fetching the first block"
    );
    describe_gauge!(
        METRICS_TIME_TO_FETCH_FULL_FILE,
        Unit::Milliseconds,
        "Time from start of request to fetching the full file"
    );
    describe_gauge!(
        METRICS_TIME_TO_SERVE_FIRST_BLOCK,
        Unit::Milliseconds,
        "Time from start of request to serving the first block"
    );
    describe_gauge!(
        METRICS_TIME_TO_SERVE_FULL_FILE,
        Unit::Milliseconds,
        "Time from start of request to serving the full file"
    );
    describe_counter!(METRICS_CACHE_HIT, Unit::Count, "Number of cache hits");
    describe_counter!(METRICS_CACHE_MISS, Unit::Count, "Number of cache misses");
    describe_counter!(
        METRICS_BYTES_STREAMED,
        Unit::Bytes,
        "Total number of bytes streamed"
    );
    describe_counter!(
        METRICS_BYTES_FETCHED,
        Unit::Bytes,
        "Total number of bytes fetched"
    );
    describe_gauge!(
        METRICS_BITRATE_IN,
        Unit::KilobitsPerSecond,
        "Bitrate of incoming stream"
    );
    describe_gauge!(
        METRICS_BITRATE_OUT,
        Unit::KilobitsPerSecond,
        "Bitrate of outgoing stream"
    );
    describe_counter!(METRICS_ERROR, Unit::Count, "Number of errors");
    describe_counter!(METRICS_FAIL, Unit::Count, "Number of failed requests");
    describe_histogram!(METRICS_HIST_TTFB, Unit::Milliseconds, "Histogram of TTFB");
    describe_histogram!(
        METRICS_HIST_TTSERVE,
        Unit::Milliseconds,
        "Histogram of TTSERVE"
    );
}

pub fn get_current_trace_id() -> TraceId {
    tracing::Span::current()
        .context()
        .span()
        .span_context()
        .trace_id()
}
