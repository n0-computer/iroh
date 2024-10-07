//! Metrics library for iroh
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod metrics;

/// Expose core types and traits
pub mod core;

/// Expose iroh metrics
#[cfg(feature = "metrics")]
mod service;

use core::UsageStatsReport;
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

/// Report usage statistics to the configured endpoint.
#[allow(unused_variables)]
pub async fn report_usage_stats(report: &UsageStatsReport) {
    #[cfg(feature = "metrics")]
    {
        if let Some(core) = core::Core::get() {
            core.usage_reporter()
                .report_usage_stats(report)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to report usage stats: {}", e);
                });
        }
    }
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
    /// Push interval
    pub interval: u64,
    /// Endpoint url
    pub endpoint: String,
    /// Service name
    pub service_name: String,
    /// Instance name
    pub instance_name: String,
    /// Username for basic auth
    pub username: Option<String>,
    /// Password
    pub password: String,
}
