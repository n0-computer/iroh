//! Co-locating all of the iroh metrics structs
use iroh_metrics::core::Metric;
#[cfg(feature = "test-utils")]
pub use iroh_relay::server::Metrics as RelayMetrics;
#[cfg(not(wasm_browser))]
pub use portmapper::Metrics as PortmapMetrics;

pub use crate::{magicsock::Metrics as MagicsockMetrics, net_report::Metrics as NetReportMetrics};

/// Metrics collected by an [`crate::endpoint::Endpoint`].
///
/// The metrics for an endpoint can be accessed via [`crate::endpoint::Endpoint::metrics`].
#[derive(Default, Debug, Clone)]
pub struct EndpointMetrics {
    /// Metrics collected by the endpoint's socket.
    pub magicsock: MagicsockMetrics,
    /// Metrics collected by net reports.
    pub net_report: NetReportMetrics,
    /// Metrics collected by the portmapper service.
    #[cfg(not(wasm_browser))]
    pub portmapper: PortmapMetrics,
}

impl iroh_metrics::core::MetricSet for EndpointMetrics {
    fn iter(&self) -> impl IntoIterator<Item = &dyn Metric> {
        #[cfg(not(wasm_browser))]
        return [
            &self.magicsock as &dyn Metric,
            &self.net_report as &dyn Metric,
            &self.portmapper as &dyn Metric,
        ];
        #[cfg(wasm_browser)]
        return [
            &self.magicsock as &dyn Metric,
            &self.net_report as &dyn Metric,
        ];
    }

    fn name(&self) -> &'static str {
        "endpoint"
    }
}
