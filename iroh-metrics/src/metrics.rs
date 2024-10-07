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

// TODO: move cfg to lib.rs
#[cfg(feature = "metrics")]
use std::net::SocketAddr;

/// Start a server to serve the OpenMetrics endpoint.
#[cfg(feature = "metrics")]
pub async fn start_metrics_server(addr: SocketAddr) -> anyhow::Result<()> {
    crate::service::run(addr).await
}

/// Start a metrics dumper service.
#[cfg(feature = "metrics")]
pub async fn start_metrics_dumper(
    path: std::path::PathBuf,
    interval: std::time::Duration,
) -> anyhow::Result<()> {
    crate::service::dumper(&path, interval).await
}

/// Start a metrics exporter service.
#[cfg(feature = "metrics")]
pub async fn start_metrics_exporter(interval: std::time::Duration) -> anyhow::Result<()> {
    // parse env vars
    let enabled = std::env::var("IROH_TELEMETRY_ENABLED")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);
    if !enabled {
        return Ok(());
    }
    let gateway_endpoint = std::env::var("IROH_TELEMETRY_GATEWAY_ENDPOINT").unwrap();
    let service_name = std::env::var("IROH_TELEMETRY_SERVICE_NAME").unwrap();
    let instance_name = std::env::var("IROH_TELEMETRY_INSTANCE_NAME").unwrap();
    let username = std::env::var("IROH_TELEMETRY_USERNAME").unwrap();
    let password = std::env::var("IROH_TELEMETRY_PASSWORD").unwrap();
    if enabled {
        crate::service::exporter(
            gateway_endpoint,
            service_name,
            instance_name,
            Some(username),
            password,
            interval,
        )
        .await;
    }
    Ok(())
}
