//! Co-locating all of the iroh metrics structs
use iroh_metrics::core::Metric;
#[cfg(feature = "test-utils")]
pub use iroh_relay::server::Metrics as RelayMetrics;
#[cfg(not(wasm_browser))]
pub use portmapper::Metrics as PortmapMetrics;

pub use crate::{magicsock::Metrics as MagicsockMetrics, net_report::Metrics as NetReportMetrics};

///
#[derive(Default, Debug, Clone)]
pub struct EndpointMetrics {
    ///
    pub magicsock: MagicsockMetrics,
    ///
    pub net_report: NetReportMetrics,
    // TODO(frando): add portmap metrics
    // #[cfg(not(wasm_browser))]
    // portmap: PortmapMetrics
}

impl iroh_metrics::core::MetricSet for EndpointMetrics {
    fn iter<'a>(&'a self) -> impl IntoIterator<Item = &'a dyn Metric> {
        [
            &self.magicsock as &dyn Metric,
            &self.net_report as &dyn Metric,
        ]
    }

    fn name(&self) -> &'static str {
        "endpoint"
    }
}

/// Increments the given counter or gauge by 1.
macro_rules! inc {
    ($msock:expr, $f:ident) => {
        $msock.metrics.magicsock.$f.inc()
    };
}

/// Increments the given counter or gauge by `n`.
macro_rules! inc_by {
    ($msock:ident, $f:ident, $n:expr) => {
        $msock.metrics.magicsock.$f.inc_by($n)
    };
}

pub(crate) use inc;
pub(crate) use inc_by;
