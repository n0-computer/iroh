//! Send data over the internet.
//!
//! ## Feature Flags
//!
//! - `metrics`: Enable metrics collection
//! - `fs-store`: Enables the disk based storage backend for `iroh-bytes`.
//!
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

// re-export the iroh crates
#[doc(inline)]
pub use iroh_base as base;
#[doc(inline)]
pub use iroh_bytes as bytes;
#[doc(inline)]
pub use iroh_net as net;
#[doc(inline)]
pub use iroh_sync as sync;

pub mod client;
pub mod node;
pub mod util;

mod rpc_protocol;
mod sync_engine;

/// Expose metrics module
#[cfg(feature = "metrics")]
#[cfg_attr(all(docsrs, feature = "metrics"), doc(cfg(feature = "metrics")))]
pub mod metrics;
