//! Metrics library for iroh
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

/// Expose macros
pub mod macros;
pub mod metrics;

/// Expose core types and traits
#[cfg(feature = "metrics")]
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
