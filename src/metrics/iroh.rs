use std::fmt;

use prometheus_client::{metrics::counter::Counter, registry::Registry};
use tracing::error;

use crate::{
    metrics::core::Collector,
    metrics::core::{HistogramType, MRecorder, MetricType, MetricsRecorder},
};

make_metrics! {
    Iroh,
    RequestsTotal: Counter: "Total number of requests received",
    BytesSent: Counter: "Number of bytes streamed",
    BytesReceived: Counter: "Number of bytes received"
}
