use git_version::git_version;
use metrics::{describe_counter, Unit};

use opentelemetry::trace::TraceContextExt;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub fn metrics_config() -> iroh_metrics::Config {
    // compile time configuration
    let service_name = env!("CARGO_PKG_NAME").to_string();
    let build = git_version!().to_string();
    let version = env!("CARGO_PKG_VERSION").to_string();

    // runtime configuration
    let instance_id = std::env::var("IROH_INSTANCE_ID")
        .unwrap_or_else(|_| names::Generator::default().next().unwrap());
    let service_env = std::env::var("IROH_ENV").unwrap_or_else(|_| "dev".to_string());
    iroh_metrics::Config::new(service_name, instance_id, build, version, service_env)
}

pub const METRICS_CNT_REQUESTS_TOTAL: &str = "requests_total";

pub fn register_counters() {
    describe_counter!(
        "requests_total",
        Unit::Count,
        "Total number of requests received by the gateway"
    );
}

pub fn get_current_trace_id() -> String {
    tracing::Span::current()
        .context()
        .span()
        .span_context()
        .trace_id()
        .to_string()
}
