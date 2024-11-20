//! Metrics library for iroh
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod metrics;

/// Expose core types and traits
pub mod core;

/// Expose iroh metrics
#[cfg(feature = "metrics")]
mod service;

use std::collections::HashMap;

/// Reexport to make matching versions easier.
pub use struct_iterable;

/// Increment the given counter by 1.
#[macro_export]
macro_rules! inc {
    ($m:ty, $f:ident) => {
        <$m as $crate::core::Metric>::with_metric(|m| m.$f.inc());
    };
}

/// Increment the given counter `n`.
#[macro_export]
macro_rules! inc_by {
    ($m:ty, $f:ident, $n:expr) => {
        <$m as $crate::core::Metric>::with_metric(|m| m.$f.inc_by($n));
    };
}

/// Set the given counter to `n`.
#[macro_export]
macro_rules! set {
    ($m:ty, $f:ident, $n:expr) => {
        <$m as $crate::core::Metric>::with_metric(|m| m.$f.set($n));
    };
}

/// Parse Prometheus metrics from a string.
pub fn parse_prometheus_metrics(data: &str) -> anyhow::Result<HashMap<String, f64>> {
    let mut metrics = HashMap::new();
    for line in data.lines() {
        if line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let metric = parts[0];
        let value = parts[1].parse::<f64>();
        if value.is_err() {
            continue;
        }
        metrics.insert(metric.to_string(), value.unwrap());
    }
    Ok(metrics)
}

/// Configuration for pushing metrics to a remote endpoint.
#[derive(PartialEq, Eq, Debug, Default, serde::Deserialize, Clone)]
pub struct PushMetricsConfig {
    /// The push interval in seconds.
    pub interval: u64,
    /// The endpoint url for the push metrics collector.
    pub endpoint: String,
    /// The name of the service you're exporting metrics for.
    ///
    /// Generally, `metrics_exporter` is good enough for use
    /// outside of production deployments.
    pub service_name: String,
    /// The name of the instance you're exporting metrics for.
    ///
    /// This should be device-unique. If not, this will sum up
    /// metrics from different devices.
    ///
    /// E.g. `username-laptop`, `username-phone`, etc.
    ///
    /// Another potential scheme with good privacy would be a
    /// keyed blake3 hash of the secret key. (This gives you
    /// an identifier that is as unique as a `NodeID`, but
    /// can't be correlated to `NodeID`s.)
    pub instance_name: String,
    /// The username for basic auth for the push metrics collector.
    pub username: Option<String>,
    /// The password for basic auth for the push metrics collector.
    pub password: String,
}
