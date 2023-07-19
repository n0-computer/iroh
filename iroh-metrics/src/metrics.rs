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
//! use iroh_metrics::{inc, inc_by};
//! use iroh_metrics::core::{Core, Metric, Counter};
//! use struct_iterable::Iterable;
//!
//! #[derive(Debug, Clone, Iterable)]
//! pub struct Metrics {
//!     pub things_added: Counter,
//! }
//!
//! impl Default for Metrics {
//!     fn default() -> Self {
//!         Self {
//!             things_added: Counter::new("things_added tracks the number of things we have added"),
//!         }
//!     }
//! }
//!
//! impl Metric for Metrics {
//!    fn name() -> &'static str {
//!         "my_metrics"
//!    }
//! }
//!
//! Core::init(|reg, metrics| {
//!     metrics.insert(Metrics::new(reg));
//! });
//!
//! inc_by!(Metrics, things_added, 2);
//! inc!(Metrics, things_added);
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
