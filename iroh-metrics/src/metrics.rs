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
//! ```rust
//! use iroh_metrics::magicsock::{Metrics, MagicsockMetrics};
//! use iroh_metrics::core::{MRecorder, Core, Metric};
//!
//! # tokio_test::block_on(async {
//! Core::init(|reg| {
//!    [(
//!        "Magiscock",
//!        Box::new(Metrics::new(reg)) as Box<dyn Metric>
//!    )].into_iter().collect()
//! });
//!
//! MagicsockMetrics::NumDerpConnsAdded.record(2);
//! MagicsockMetrics::NumDerpConnsAdded.inc();
//! })
//! ```

#[cfg(feature = "metrics")]
use hyper::Error;
#[cfg(feature = "metrics")]
use std::net::SocketAddr;

// Expose the macros in this crate.
#[allow(unused_imports)]
pub use crate::macros::make_metric_recorders;

/// Start a server to serve the OpenMetrics endpoint.
#[cfg(feature = "metrics")]
pub async fn start_metrics_server(addr: SocketAddr) -> Result<(), Error> {
    crate::service::run(addr).await
}
