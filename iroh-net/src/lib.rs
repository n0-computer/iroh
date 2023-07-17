//! iroh-net provides connectivity for iroh.
//!
//! This crate is a collection of tools to establish connectivity between peers.  At
//! the high level [`MagicEndpoint`] is used to establish a QUIC connection with
//! authenticated peers, relaying and holepunching support.

#![recursion_limit = "256"]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod defaults;
pub mod hp;
pub mod magic_endpoint;
pub mod metrics;
pub mod net;
pub mod tls;
pub mod util;

pub use magic_endpoint::MagicEndpoint;

#[cfg(test)]
pub(crate) mod test_utils;
