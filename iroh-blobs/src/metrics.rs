//! Metrics for iroh-blobs

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

    pub downloader_tick_main: Counter,
    pub downloader_tick_connection_ready: Counter,
    pub downloader_tick_message_received: Counter,
    pub downloader_tick_transfer_completed: Counter,
    pub downloader_tick_transfer_failed: Counter,
    pub downloader_tick_retry_node: Counter,
    pub downloader_tick_goodbye_node: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            download_bytes_total: Counter::new("Total number of content bytes downloaded"),
            download_time_total: Counter::new("Total time in ms spent downloading content bytes"),
            downloads_success: Counter::new("Total number of successful downloads"),
            downloads_error: Counter::new("Total number of downloads failed with error"),
            downloads_notfound: Counter::new("Total number of downloads failed with not found"),

            downloader_tick_main: Counter::new(
                "Number of times the main downloader actor loop ticked",
            ),
            downloader_tick_connection_ready: Counter::new(
                "Number of times the downloader actor ticked for a connection ready",
            ),
            downloader_tick_message_received: Counter::new(
                "Number of times the downloader actor ticked for a message received",
            ),
            downloader_tick_transfer_completed: Counter::new(
                "Number of times the downloader actor ticked for a transfer completed",
            ),
            downloader_tick_transfer_failed: Counter::new(
                "Number of times the downloader actor ticked for a transfer failed",
            ),
            downloader_tick_retry_node: Counter::new(
                "Number of times the downloader actor ticked for a retry node",
            ),
            downloader_tick_goodbye_node: Counter::new(
                "Number of times the downloader actor ticked for a goodbye node",
            ),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "iroh-blobs"
    }
}
