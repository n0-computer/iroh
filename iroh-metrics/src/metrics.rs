//! Metrics collection
//!
//! Enables and manages a global registry of metrics.
//! Divided up into modules, each module has its own metrics.
//! Starting the metrics service will expose the metrics on a OpenMetrics http endpoint.
//!
//! To enable metrics collection, call `init_metrics()` before starting the service.
//!
//! - To increment a **counter**, use the [`crate::inc`] macro with a value.
//! - To increment a **counter** by 1, use the [`crate::inc_by`] macro.
//!
//! To expose the metrics, start the metrics service with `start_metrics_server()`.
//!
//! # Example:
//! ```rust
//! use iroh_metrics::{magicsock, inc, inc_by};
//! use iroh_metrics::core::{Core, Metric};
//!
//! Core::init(|reg, metrics| {
//!     metrics.insert(magicsock::Metrics::new(reg));
//! });
//!
//! inc_by!(magicsock::Metrics, num_derp_conns_added, 2);
//! inc!(magicsock::Metrics, num_derp_conns_added);
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
