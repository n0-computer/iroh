use std::fmt;

use prometheus_client::{
    metrics::{
        counter::Counter,
        histogram::{linear_buckets, Histogram},
    },
    registry::Registry,
};
use tracing::error;

use crate::{
    core::{HistogramType, MObserver, MRecorder, MetricType, MetricsRecorder},
    Collector,
};

#[derive(Clone)]
pub(crate) struct Metrics {
    get_requests_total: Counter,
    get_store_hit: Counter,
    get_store_miss: Counter,
    get_bytes: Counter,
    get_request_time: Histogram,
    put_requests_total: Counter,
    put_bytes: Counter,
    put_request_time: Histogram,
    get_links_requests_total: Counter,
    get_links_hit: Counter,
    get_links_miss: Counter,
    get_links_request_time: Histogram,
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

impl MetricsRecorder for Metrics {
    fn record<M>(&self, m: M, value: u64)
    where
        M: MetricType + std::fmt::Display,
    {
        if m.name() == StoreMetrics::GetRequests.name() {
            self.get_requests_total.inc_by(value);
        } else if m.name() == StoreMetrics::StoreHit.name() {
            self.get_store_hit.inc_by(value);
        } else if m.name() == StoreMetrics::StoreMiss.name() {
            self.get_store_miss.inc_by(value);
        } else if m.name() == StoreMetrics::GetBytes.name() {
            self.get_bytes.inc_by(value);
        } else if m.name() == StoreMetrics::PutRequests.name() {
            self.put_requests_total.inc_by(value);
        } else if m.name() == StoreMetrics::PutBytes.name() {
            self.put_bytes.inc_by(value);
        } else if m.name() == StoreMetrics::GetLinksRequests.name() {
            self.get_links_requests_total.inc_by(value);
        } else if m.name() == StoreMetrics::GetLinksHit.name() {
            self.get_links_hit.inc_by(value);
        } else if m.name() == StoreMetrics::GetLinksHit.name() {
            self.get_links_miss.inc_by(value);
        } else {
            error!("record (store): unknown metric {}", m.name());
        }
    }

    fn observe<M>(&self, m: M, value: f64)
    where
        M: HistogramType + std::fmt::Display,
    {
        if m.name() == StoreHistograms::GetRequests.name() {
            self.get_request_time.observe(value);
        } else if m.name() == StoreHistograms::PutRequests.name() {
            self.put_request_time.observe(value);
        } else if m.name() == StoreHistograms::GetLinksRequests.name() {
            self.get_links_request_time.observe(value);
        } else {
            error!("observe (store): unknown metric {}", m.name());
        }
    }
}

#[derive(Clone)]
pub enum StoreMetrics {
    GetRequests,
    StoreHit,
    StoreMiss,
    GetBytes,
    PutRequests,
    PutBytes,
    GetLinksRequests,
    GetLinksHit,
    GetLinksMiss,
}

impl MetricType for StoreMetrics {
    fn name(&self) -> &'static str {
        match self {
            StoreMetrics::GetRequests => METRICS_CNT_GET_REQUESTS_TOTAL,
            StoreMetrics::StoreHit => METRICS_CNT_GET_STORE_HIT,
            StoreMetrics::StoreMiss => METRICS_CNT_GET_STORE_MISS,
            StoreMetrics::GetBytes => METRICS_CNT_GET_BYTES_TOTAL,
            StoreMetrics::PutRequests => METRICS_CNT_PUT_REQUESTS_TOTAL,
            StoreMetrics::PutBytes => METRICS_CNT_PUT_BYTES_TOTAL,
            StoreMetrics::GetLinksRequests => METRICS_CNT_GET_LINKS_REQUESTS_TOTAL,
            StoreMetrics::GetLinksHit => METRICS_CNT_GET_LINKS_HIT,
            StoreMetrics::GetLinksMiss => METRICS_CNT_GET_LINKS_MISS,
        }
    }
}

impl MRecorder for StoreMetrics {
    fn record(&self, value: u64) {
        crate::record(Collector::Store, self.clone(), value);
    }
}

impl std::fmt::Display for StoreMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Clone)]
pub enum StoreHistograms {
    GetRequests,
    PutRequests,
    GetLinksRequests,
}

impl HistogramType for StoreHistograms {
    fn name(&self) -> &'static str {
        match self {
            StoreHistograms::GetRequests => METRICS_HIST_GET_REQUEST_TIME,
            StoreHistograms::PutRequests => METRICS_HIST_PUT_REQUEST_TIME,
            StoreHistograms::GetLinksRequests => METRICS_HIST_GET_LINKS_REQUEST_TIME,
        }
    }
}

impl MObserver for StoreHistograms {
    fn observe(&self, value: f64) {
        crate::observe(Collector::Store, self.clone(), value);
    }
}

impl std::fmt::Display for StoreHistograms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
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
