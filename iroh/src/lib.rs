//! Send data over the internet.
//!
//! ## Feature Flags
//!
//! - `metrics`: Enable metrics collection. Enabled by default.
//! - `fs-store`: Enables the disk based storage backend for `iroh-blobs`. Enabled by default.
//!
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

// re-export the iroh crates
#[doc(inline)]
pub use iroh_base as base;
#[doc(inline)]
pub use iroh_blobs as blobs;
#[doc(inline)]
pub use iroh_docs as docs;
#[doc(inline)]
pub use iroh_net as net;

pub mod client;
pub mod node;
pub mod util;

mod rpc_protocol;

/// Expose metrics module
#[cfg(feature = "metrics")]
#[cfg_attr(all(docsrs, feature = "metrics"), doc(cfg(feature = "metrics")))]
pub mod metrics;
