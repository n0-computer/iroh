//! Metrics collection
//!
//! Enables and manages a global registry of metrics.
//! Divided up into modules, each module has its own metrics.
//! Starting the metrics service will expose the metrics on a OpenMetrics http endpoint.
//!
//! To enable metrics collection, call `init_metrics()` before starting the service.
//!
//! - To record a **gauge** ( or a **counter**), use the [`crate::core::MRecorder::record`] macro with a value.
//!   Don't use gauges though.
//! - To increment a **counter** by 1, use the [`crate::core::MRecorder::inc`] macro.
//! - For **histograms** (or **summaries**, but don't use those either) use the [`crate::core::MObserver::observe`]
//!   macro with a value.
//!
//! To expose the metrics, start the metrics service with `start_metrics_server()`.
//!
//! # Example:
//! ```rust
//! use iroh_metrics::magicsock;
//! use iroh_metrics::core::{Core, Metric};
//!
//! Core::init(|reg, metrics| {
//!     metrics.insert(magicsock::Metrics::new(reg));
//! });
//!
//! magicsock::Metrics::with_metric(|m| {
//!     m.num_derp_conns_added.inc_by(2);
//!     m.num_derp_conns_added.inc();
//! });
//! ```

#[cfg(feature = "metrics")]
use hyper::Error;
#[cfg(feature = "metrics")]
use std::net::SocketAddr;

/// Start a server to serve the OpenMetrics endpoint.
#[cfg(feature = "metrics")]
pub async fn start_metrics_server(addr: SocketAddr) -> Result<(), Error> {
    crate::service::run(addr).await
}
