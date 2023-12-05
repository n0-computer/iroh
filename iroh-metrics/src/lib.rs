//! Metrics library for iroh
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod metrics;

/// Expose core types and traits
pub mod core;

/// Expose iroh metrics
#[cfg(feature = "metrics")]
mod service;

use core::UsageStatsReport;
#[cfg(feature = "metrics")]
use std::io;

use anyhow::Error;
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
