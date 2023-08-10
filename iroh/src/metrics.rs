use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Enum of metrics for the module
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    pub requests_total: Counter,
    pub bytes_sent: Counter,
    pub bytes_received: Counter,
    pub download_bytes_total: Counter,
    pub download_time_total: Counter,
    pub downloads_success: Counter,
    pub downloads_error: Counter,
    pub downloads_notfound: Counter,
    pub initial_sync_success: Counter,
    pub initial_sync_failed: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests_total: Counter::new("Total number of requests received"),
            bytes_sent: Counter::new("Number of bytes streamed"),
            bytes_received: Counter::new("Number of bytes received"),
            download_bytes_total: Counter::new("Total number of content bytes downloaded"),
            download_time_total: Counter::new("Total time in ms spent downloading content bytes"),
            downloads_success: Counter::new("Total number of successfull downloads"),
            downloads_error: Counter::new("Total number of downloads failed with error"),
            downloads_notfound: Counter::new("Total number of downloads failed with not found"),
            initial_sync_success: Counter::new("Number of successfull initial syncs "),
            initial_sync_failed: Counter::new("Number of failed initial syncs"),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "Iroh"
    }
}
