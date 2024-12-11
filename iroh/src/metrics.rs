//! Co-locating all of the iroh metrics structs
#[cfg(feature = "test-utils")]
pub use iroh_relay::server::Metrics as RelayMetrics;
pub use net_report::Metrics as NetReportMetrics;
pub use portmapper::Metrics as PortmapMetrics;

pub use crate::magicsock::Metrics as MagicsockMetrics;
