use iroh_metrics::{Counter, MetricsGroup};
use serde::{Deserialize, Serialize};

/// Enum of metrics for the module
#[derive(Debug, Default, MetricsGroup, Serialize, Deserialize)]
#[metrics(name = "net_report")]
#[non_exhaustive]
pub struct Metrics {
    /// Number of reports executed by net_report, including full reports.
    pub reports: Counter,
    /// Number of full reports executed by net_report
    pub reports_full: Counter,
}
