//! Send data over the internet.
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
pub mod dial;
pub mod node;
pub mod sync_engine;
pub mod util;

mod rpc_protocol;

/// Expose metrics module
#[cfg(feature = "metrics")]
pub mod metrics;
