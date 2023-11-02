//! Send data over the internet.
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub use iroh_bytes as bytes;
pub use iroh_net as net;
pub use iroh_sync as sync;

pub mod client;
pub mod collection;
pub mod dial;
pub mod downloader;
pub mod get;
pub mod node;
pub mod rpc_protocol;
pub mod sync_engine;
pub mod ticket;
pub mod util;

/// Expose metrics module
#[cfg(feature = "metrics")]
pub mod metrics;
