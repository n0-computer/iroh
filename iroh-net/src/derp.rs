//! Package derp implements the Designated Encrypted Relay for Packets (DERP)
//! protocol written by Tailscale.
//
//! DERP routes packets to clients using curve25519 keys as addresses.
//
//! DERP is used by proxy encrypted QUIC packets through the DERP servers when
//! a direct path cannot be found or opened. DERP is a last resort. Both side
//! between very aggressive NATs, firewalls, no IPv6, etc? Well, DERP.
//! Based on tailscale/derp/derp.go

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub(crate) mod client;
pub(crate) mod client_conn;
pub(crate) mod clients;
mod codec;
pub mod http;
mod map;
mod metrics;
pub(crate) mod server;
pub(crate) mod types;

pub use self::client::{Client as DerpClient, ReceivedMessage};
pub use self::codec::MAX_PACKET_SIZE;
pub use self::http::Client as HttpClient;
pub use self::map::{DerpMap, DerpMode, DerpNode};
pub use self::metrics::Metrics;
pub use self::server::{ClientConnHandler, MaybeTlsStream as MaybeTlsStreamServer, Server};
pub use iroh_base::node_addr::DerpUrl;
