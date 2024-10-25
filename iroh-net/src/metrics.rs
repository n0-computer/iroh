//! Co-locating all of the iroh-net metrics structs
pub use portmapper::Metrics as PortmapMetrics;

#[cfg(feature = "iroh-relay")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "iroh-relay")))]
pub use crate::relay::server::Metrics as RelayMetrics;
pub use crate::{magicsock::Metrics as MagicsockMetrics, netcheck::Metrics as NetcheckMetrics};
