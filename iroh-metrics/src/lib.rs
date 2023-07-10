// #![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod macros;
pub mod metrics;

/// Expose core types and traits
#[cfg(feature = "metrics")]
pub mod core;
/// Expose iroh metrics
#[cfg(feature = "metrics")]
mod service;

pub mod iroh;
pub mod magicsock;
pub mod netcheck;
pub mod portmap;
