//! Metrics collection
//!
//! Enables and manages a global registry of metrics.
//! Divided up into modules, each module has its own metrics.
//! Starting the metrics service will expose the metrics on a OpenMetrics http endpoint.
//!
//! To enable metrics collection, call `init_metrics()` before starting the service.
//!
//! - To record a **gauge** ( or a **counter**), use the [`record`] macro with a value.
//!   Don't use gauges though.
//! - To increment a **counter** by 1, use the [`inc`] macro.
//! - For **histograms** (or **summaries**, but don't use those either) use the [`observe`]
//!   macro with a value.
//!
//! To expose the metrics, start the metrics service with `start_metrics_server()`.
//!
//! # Example:
//! ```
//! use iroh::metrics::init_metrics;
//! use iroh::metrics::iroh::IrohMetrics;
//! use crate::iroh::metrics::core::MRecorder;
//!
//! init_metrics();
//! iroh::record!(IrohMetrics::RequestsTotal, 2);
//! iroh::inc!(IrohMetrics::RequestsTotal);
//! ```
#[cfg(feature = "metrics")]
use self::core::CORE;
#[cfg(feature = "metrics")]
use hyper::Error;
#[cfg(feature = "metrics")]
use std::net::SocketAddr;

mod macros;

/// Expose core types and traits
#[cfg(feature = "metrics")]
pub mod core;
/// Expose iroh metrics
#[cfg(feature = "metrics")]
mod service;

pub mod iroh;
pub mod magicsock;
// Expose the macros in this crate.
#[allow(unused_imports)]
pub(crate) use macros::{inc, make_metric_recorders, observe, record};

/// Enables metrics collection, otherwise all inc!, record! & observe! calls are no-ops
#[cfg(feature = "metrics")]
pub fn init_metrics() {
    CORE.set_enabled(true);
}

/// Start a server to serve the OpenMetrics endpoint.
#[cfg(feature = "metrics")]
pub async fn start_metrics_server(addr: SocketAddr) -> Result<(), Error> {
    self::service::run(addr).await
}
