use std::fmt;

use git_version::git_version;

use prometheus_client::{
    metrics::{
        counter::Counter,
        histogram::{linear_buckets, Histogram},
    },
    registry::Registry,
};

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

#[derive(Clone)]
pub struct Metrics {
    pub get_requests_total: Counter,
    pub get_store_hit: Counter,
    pub get_store_miss: Counter,
    pub get_bytes: Counter,
    pub get_request_time: Histogram,
    pub put_requests_total: Counter,
    pub put_bytes: Counter,
    pub put_request_time: Histogram,
    pub get_links_requests_total: Counter,
    pub get_links_hit: Counter,
    pub get_links_miss: Counter,
    pub get_links_request_time: Histogram,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store Metrics").finish()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            get_requests_total: Counter::default(),
            get_store_hit: Counter::default(),
            get_store_miss: Counter::default(),
            get_bytes: Counter::default(),
            get_request_time: Histogram::new(linear_buckets(0.0, 1.0, 1)),
            put_requests_total: Counter::default(),
            put_bytes: Counter::default(),
            put_request_time: Histogram::new(linear_buckets(0.0, 1.0, 1)),
            get_links_requests_total: Counter::default(),
            get_links_hit: Counter::default(),
            get_links_miss: Counter::default(),
            get_links_request_time: Histogram::new(linear_buckets(0.0, 1.0, 1)),
        }
    }
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let sub_registry = registry.sub_registry_with_prefix("store");
        let get_requests_total = Counter::default();
        sub_registry.register(
            METRICS_CNT_GET_REQUESTS_TOTAL,
            "Total number of get requests",
            Box::new(get_requests_total.clone()),
        );
        let get_store_hit = Counter::default();
        sub_registry.register(
            METRICS_CNT_GET_STORE_HIT,
            "Count store hits",
            Box::new(get_store_hit.clone()),
        );
        let get_store_miss = Counter::default();
        sub_registry.register(
            METRICS_CNT_GET_STORE_MISS,
            "Count store miss",
            Box::new(get_store_miss.clone()),
        );
        let get_bytes = Counter::default();
        sub_registry.register(
            METRICS_CNT_GET_BYTES_TOTAL,
            "Bytes served",
            Box::new(get_bytes.clone()),
        );
        let get_request_time = Histogram::new(linear_buckets(0.0, 500.0, 240));
        sub_registry.register(
            METRICS_HIST_GET_REQUEST_TIME,
            "Histogram of get request times",
            Box::new(get_request_time.clone()),
        );

        let put_requests_total = Counter::default();
        sub_registry.register(
            METRICS_CNT_PUT_REQUESTS_TOTAL,
            "Total number of put requests",
            Box::new(put_requests_total.clone()),
        );
        let put_bytes = Counter::default();
        sub_registry.register(
            METRICS_CNT_PUT_BYTES_TOTAL,
            "Bytes ingested",
            Box::new(put_bytes.clone()),
        );
        let put_request_time = Histogram::new(linear_buckets(0.0, 500.0, 240));
        sub_registry.register(
            METRICS_HIST_PUT_REQUEST_TIME,
            "Histogram of put request times",
            Box::new(put_request_time.clone()),
        );

        let get_links_requests_total = Counter::default();
        sub_registry.register(
            METRICS_CNT_GET_LINKS_REQUESTS_TOTAL,
            "Total number of get links requests",
            Box::new(get_links_requests_total.clone()),
        );
        let get_links_hit = Counter::default();
        sub_registry.register(
            METRICS_CNT_GET_LINKS_HIT,
            "Count links hits",
            Box::new(get_links_hit.clone()),
        );
        let get_links_miss = Counter::default();
        sub_registry.register(
            METRICS_CNT_GET_LINKS_MISS,
            "Count links miss",
            Box::new(get_links_miss.clone()),
        );
        let get_links_request_time = Histogram::new(linear_buckets(0.0, 500.0, 240));
        sub_registry.register(
            METRICS_HIST_GET_LINKS_REQUEST_TIME,
            "Histogram of get link request times",
            Box::new(get_links_request_time.clone()),
        );

        Self {
            get_requests_total,
            get_store_hit,
            get_store_miss,
            get_bytes,
            get_request_time,
            put_requests_total,
            put_bytes,
            put_request_time,
            get_links_requests_total,
            get_links_hit,
            get_links_miss,
            get_links_request_time,
        }
    }
}

pub const METRICS_CNT_GET_REQUESTS_TOTAL: &str = "get_requests";
pub const METRICS_CNT_GET_STORE_HIT: &str = "get_hit";
pub const METRICS_CNT_GET_STORE_MISS: &str = "get_miss";
pub const METRICS_CNT_GET_BYTES_TOTAL: &str = "bytes_out";
pub const METRICS_HIST_GET_REQUEST_TIME: &str = "get_request_time";
pub const METRICS_CNT_PUT_REQUESTS_TOTAL: &str = "put_requests";
pub const METRICS_CNT_PUT_BYTES_TOTAL: &str = "bytes_in";
pub const METRICS_HIST_PUT_REQUEST_TIME: &str = "put_request_time";
pub const METRICS_CNT_GET_LINKS_REQUESTS_TOTAL: &str = "get_links_requests";
pub const METRICS_CNT_GET_LINKS_HIT: &str = "get_links_hit";
pub const METRICS_CNT_GET_LINKS_MISS: &str = "get_links_miss";
pub const METRICS_HIST_GET_LINKS_REQUEST_TIME: &str = "get_links_request_time";
