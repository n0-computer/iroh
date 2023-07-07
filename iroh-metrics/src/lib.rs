//! Metrics library for iroh
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod metrics;

/// Expose core types and traits
pub mod core;

/// Expose iroh metrics
#[cfg(feature = "metrics")]
mod service;

/// Expose magicsock metrics
pub mod magicsock;
/// Expose netcheck metrics
pub mod netcheck;
/// Expose portmap metrics
pub mod portmap;

/// Reexport to make matching versions easier.
pub use struct_iterable;
