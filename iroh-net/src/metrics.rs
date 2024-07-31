//! Co-locating all of the iroh-net metrics structs
pub use crate::magicsock::Metrics as MagicsockMetrics;
pub use crate::netcheck::Metrics as NetcheckMetrics;
pub use crate::portmapper::Metrics as PortmapMetrics;
#[cfg(feature = "iroh-relay")]
pub use crate::relay::server::Metrics as RelayMetrics;
