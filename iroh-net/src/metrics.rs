//! Co-locating all of the iroh-net metrics structs
#[cfg(feature = "test-utils")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "test-utils")))]
pub use iroh_relay::server::Metrics as RelayMetrics;
pub use portmapper::Metrics as PortmapMetrics;

pub use crate::{magicsock::Metrics as MagicsockMetrics, netcheck::Metrics as NetcheckMetrics};
