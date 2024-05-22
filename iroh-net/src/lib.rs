//! iroh-net provides connectivity for iroh.
//!
//! This crate is a collection of tools to establish connectivity between peers.  At
//! the high level [`Endpoint`] is used to establish a QUIC connection with
//! authenticated peers, relaying and holepunching support.
//!
//! The "relay-only" feature forces all traffic to send over the relays. We still
//! receive traffic over udp and relay. This feature should only be used for testing.

#![recursion_limit = "256"]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod config;
pub mod conn_manager;
pub mod defaults;
pub mod dialer;
mod disco;
pub mod discovery;
pub mod dns;
pub mod endpoint;
mod magicsock;
pub mod metrics;
pub mod net;
pub mod netcheck;
pub mod ping;
pub mod portmapper;
pub mod relay;
pub mod stun;
pub mod ticket;
pub mod tls;
pub mod util;

pub use endpoint::{AddrInfo, Endpoint, NodeAddr};

pub use iroh_base::key;

pub use iroh_base::key::NodeId;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
