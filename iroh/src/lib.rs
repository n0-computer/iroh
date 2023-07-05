//! Send data over the internet.
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub use iroh_bytes as bytes;
pub use iroh_net as net;

pub mod node;
pub mod rpc_protocol;

#[cfg(feature = "cli")]
pub mod commands;
#[cfg(feature = "cli")]
pub mod config;

#[cfg(feature = "metrics")]
pub mod metrics;
