//! Metrics for iroh-bytes

use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Enum of metrics for the module
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    pub download_bytes_total: Counter,
    pub download_time_total: Counter,
    pub downloads_success: Counter,
    pub downloads_error: Counter,
    pub downloads_notfound: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            download_bytes_total: Counter::new("Total number of content bytes downloaded"),
            download_time_total: Counter::new("Total time in ms spent downloading content bytes"),
            downloads_success: Counter::new("Total number of successful downloads"),
            downloads_error: Counter::new("Total number of downloads failed with error"),
            downloads_notfound: Counter::new("Total number of downloads failed with not found"),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "iroh-bytes"
    }
}
