use std::fmt;

use prometheus_client::{metrics::counter::Counter, registry::Registry};

#[derive(Default, Clone)]
pub struct Metrics {
    pub requests_total: Counter,
    pub canceled_total: Counter,
    pub sent_block_bytes: Counter,
    pub received_block_bytes: Counter,
    pub providers_total: Counter,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store Metrics").finish()
    }
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
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

pub const METRICS_CNT_REQUESTS_TOTAL: &str = "requests";
pub const METRICS_CNT_CANCEL_TOTAL: &str = "canceled";
pub const METRICS_CNT_BLOCK_BYTES_OUT: &str = "block_bytes_out";
pub const METRICS_CNT_BLOCK_BYTES_IN: &str = "block_bytes_in";
pub const METRICS_CNT_PROVIDERS_TOTAL: &str = "providers";
