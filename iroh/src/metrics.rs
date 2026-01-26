//! Co-locating all of the iroh metrics structs
use std::sync::Arc;

use iroh_metrics::MetricsGroupSet;
#[cfg(feature = "test-utils")]
pub use iroh_relay::server::Metrics as RelayMetrics;
#[cfg(not(wasm_browser))]
pub use portmapper::Metrics as PortmapMetrics;
use serde::{Deserialize, Serialize};

pub use crate::{net_report::Metrics as NetReportMetrics, socket::Metrics as SocketMetrics};

/// Metrics collected by an [`crate::endpoint::Endpoint`].
///
/// See [`crate::endpoint::Endpoint::metrics`] for details.
#[derive(Default, Debug, Clone, Serialize, Deserialize, MetricsGroupSet)]
#[metrics(name = "endpoint")]
#[non_exhaustive]
pub struct EndpointMetrics {
    /// Metrics collected by the endpoint's socket.
    pub socket: Arc<SocketMetrics>,
    /// Metrics collected by net reports.
    pub net_report: Arc<NetReportMetrics>,
    /// Metrics collected by the portmapper service.
    #[cfg(not(wasm_browser))]
    pub portmapper: Arc<PortmapMetrics>,
}

#[cfg(test)]
mod tests {
    use super::EndpointMetrics;
    #[test]
    fn test_serde() {
        let metrics = EndpointMetrics::default();
        metrics.socket.actor_link_change.inc();
        metrics.net_report.reports.inc_by(10);
        let encoded = postcard::to_stdvec(&metrics).unwrap();
        let decoded: EndpointMetrics = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.socket.actor_link_change.get(), 1);
        assert_eq!(decoded.net_report.reports.get(), 10);
    }
}
