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
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests_total: Counter::new("Total number of requests received"),
            bytes_sent: Counter::new("Number of bytes streamed"),
            bytes_received: Counter::new("Number of bytes received"),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "Iroh"
    }
}
