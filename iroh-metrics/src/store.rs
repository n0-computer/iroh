use std::fmt;

use prometheus_client::{
    metrics::{
        counter::Counter,
        histogram::{linear_buckets, Histogram},
    },
    registry::Registry,
};

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

const METRICS_CNT_GET_REQUESTS_TOTAL: &str = "get_requests";
const METRICS_CNT_GET_STORE_HIT: &str = "get_hit";
const METRICS_CNT_GET_STORE_MISS: &str = "get_miss";
const METRICS_CNT_GET_BYTES_TOTAL: &str = "bytes_out";
const METRICS_HIST_GET_REQUEST_TIME: &str = "get_request_time";
const METRICS_CNT_PUT_REQUESTS_TOTAL: &str = "put_requests";
const METRICS_CNT_PUT_BYTES_TOTAL: &str = "bytes_in";
const METRICS_HIST_PUT_REQUEST_TIME: &str = "put_request_time";
const METRICS_CNT_GET_LINKS_REQUESTS_TOTAL: &str = "get_links_requests";
const METRICS_CNT_GET_LINKS_HIT: &str = "get_links_hit";
const METRICS_CNT_GET_LINKS_MISS: &str = "get_links_miss";
const METRICS_HIST_GET_LINKS_REQUEST_TIME: &str = "get_links_request_time";
