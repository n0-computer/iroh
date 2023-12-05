//! Metrics library for iroh
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod metrics;

/// Expose core types and traits
pub mod core;

/// Expose iroh metrics
#[cfg(feature = "metrics")]
mod service;

use core::UsageStatsReport;
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
pub async fn report_usage_stats(report: &UsageStatsReport) -> Result<(), Error> {
    #[cfg(feature = "metrics")]
    {
        let core = core::Core::get()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "metrics disabled"))?;
        core.usage_reporter().report_usage_stats(report).await?;
    }
    Ok(())
}
