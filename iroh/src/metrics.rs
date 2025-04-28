//! Co-locating all of the iroh metrics structs
use std::sync::Arc;

use iroh_metrics::MetricsGroupSet;
#[cfg(feature = "test-utils")]
pub use iroh_relay::server::Metrics as RelayMetrics;
#[cfg(not(wasm_browser))]
pub use portmapper::Metrics as PortmapMetrics;

pub use crate::{magicsock::Metrics as MagicsockMetrics, net_report::Metrics as NetReportMetrics};

/// Metrics collected by an [`crate::endpoint::Endpoint`].
///
/// See [`crate::endpoint::Endpoint::metrics`] for details.
#[derive(Default, Debug, Clone, MetricsGroupSet)]
#[metrics(name = "endpoint")]
#[non_exhaustive]
pub struct EndpointMetrics {
    /// Metrics collected by the endpoint's socket.
    pub magicsock: Arc<MagicsockMetrics>,
    /// Metrics collected by net reports.
    pub net_report: Arc<NetReportMetrics>,
    /// Metrics collected by the portmapper service.
    #[cfg(not(wasm_browser))]
    pub portmapper: Arc<PortmapMetrics>,
}
