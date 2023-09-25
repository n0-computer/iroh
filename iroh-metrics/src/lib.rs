//! Metrics library for iroh
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod metrics;

/// Expose core types and traits
pub mod core;

/// Expose iroh metrics
#[cfg(feature = "metrics")]
mod service;

/// Reexport to make matching versions easier.
pub use struct_iterable;

/// Increment the given counter by 1.
#[macro_export]
macro_rules! inc {
    ($m:ty, $f:ident) => {
        <$m as $crate::core::Metric>::with_metric(|m| m.$f.inc(vec![]));
    };
}

/// Increment the given counter `n`.
#[macro_export]
macro_rules! inc_by {
    ($m:ty, $f:ident, $n:expr) => {
        <$m as $crate::core::Metric>::with_metric(|m| m.$f.inc_by($n, vec![]));
    };
}


/// Increment the given counter by 1 with labels.
#[macro_export]
macro_rules! inc_with_labels {
    ($m:ty, $f:ident, $l:expr) => {
        <$m as $crate::core::Metric>::with_metric(|m| m.$f.inc($l));
    };
}
/// Increment the given counter `n` with labels.
#[macro_export]
macro_rules! inc_by_with_labels {
    ($m:ty, $f:ident, $n:expr, $l:expr) => {
        <$m as $crate::core::Metric>::with_metric(|m| m.$f.inc_by($n, $l));
    };
}

/// TODO
pub fn send_event(event: Event) {
    tracing::error!("send_event(Event): {:?}", event);
   let r = core::CORE.get().unwrap().event_bus().send(event);
   if let Err(e) = r {
       tracing::error!("send_event_err(Event): {:?}", e);
   }
}

/// TODO
#[derive(Debug, Clone)]
pub struct Event {
    /// TODO
    pub event_type: String,
    /// TODO
    pub data: String,
}