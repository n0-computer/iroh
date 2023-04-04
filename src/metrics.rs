//! Metrics collection
//!
//! Enables and manages a global registry of metrics.
//! Divided up into modules, each module has its own metrics.
//! Starting the metrics service will expose the metrics on a OpenMetrics http endpoint.
//!
//! To enable metrics collection, call `init_metrics()` before starting the service.
//!
//! To record a metric, use the `record!` macro with the metric and the value to record.
//! To increment a metric by 1, use the `inc!` macro with the metric.
//! To observe a metric, use the `observe!` macro with the metric and the value to observe.
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
use std::net::SocketAddr;

use hyper::Error;

use self::core::CORE;

#[macro_use]
mod macros;

/// Expose core types and traits
pub mod core;
/// Expose iroh metrics
pub mod iroh;
mod service;

/// Enables metrics collection, otherwise all inc!, record! & observe! calls are no-ops
pub fn init_metrics() {
    CORE.set_enabled(true);
}

/// Start a server to serve the OpenMetrics endpoint.
pub async fn start_metrics_server(addr: SocketAddr) -> Result<(), Error> {
    self::service::run(addr).await
}
