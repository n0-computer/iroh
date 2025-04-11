//! Co-locating all of the iroh metrics structs
use std::sync::Arc;

use iroh_metrics::{MetricsGroup, MetricsGroupSet};
#[cfg(feature = "test-utils")]
pub use iroh_relay::server::Metrics as RelayMetrics;
#[cfg(not(wasm_browser))]
pub use portmapper::Metrics as PortmapMetrics;

pub use crate::{magicsock::Metrics as MagicsockMetrics, net_report::Metrics as NetReportMetrics};

/// Metrics collected by an [`crate::endpoint::Endpoint`].
///
/// See [`crate::endpoint::Endpoint::metrics`] for details.
#[derive(Default, Debug, Clone)]
pub struct EndpointMetrics {
    /// Metrics collected by the endpoint's socket.
    pub magicsock: Arc<MagicsockMetrics>,
    /// Metrics collected by net reports.
    pub net_report: Arc<NetReportMetrics>,
    /// Metrics collected by the portmapper service.
    #[cfg(not(wasm_browser))]
    pub portmapper: Arc<PortmapMetrics>,
}

impl MetricsGroupSet for EndpointMetrics {
    fn groups(&self) -> impl Iterator<Item = &dyn MetricsGroup> {
        #[cfg(not(wasm_browser))]
        return [
            &*self.magicsock as &dyn MetricsGroup,
            &*self.net_report as &dyn MetricsGroup,
            &*self.portmapper as &dyn MetricsGroup,
        ]
        .into_iter();
        #[cfg(wasm_browser)]
        return [
            &*self.magicsock as &dyn MetricsGroup,
            &*self.net_report as &dyn MetricsGroup,
        ]
        .into_iter();
    }

    fn name(&self) -> &'static str {
        "endpoint"
    }
}
