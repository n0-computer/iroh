//! Send data over the internet.
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

// re-export the iroh crates
pub use iroh_base as base;
pub use iroh_bytes as bytes;
pub use iroh_net as net;
pub use iroh_sync as sync;

// reexport types from the iroh_base crate
// iroh_base::hash::* is exported from iroh_bytes as bytes
// iroh_base::rpc::* is exported from mod rpc_protocol
pub use iroh_base::base32;

pub mod client;
pub mod dial;
pub mod node;
pub mod rpc_protocol;
pub mod sync_engine;
pub mod ticket;
pub mod util;

/// Expose metrics module
#[cfg(feature = "metrics")]
pub mod metrics;
