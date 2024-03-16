//! Package `relay` implements a revised version of the Designated Encrypted Relay for Packets (DERP)
//! protocol written by Tailscale.
//
//! The relay routes packets to clients using curve25519 keys as addresses.
//
//! The relay is used to proxy encrypted QUIC packets through the relay servers when
//! a direct path cannot be found or opened. The relay is a last resort. If both sides
//! have very aggressive NATs, or firewalls, or no IPv6, we use the relay connection.
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

pub use self::client::{Client as RelayClient, ReceivedMessage};
pub use self::codec::MAX_PACKET_SIZE;
pub use self::http::Client as HttpClient;
pub use self::map::{RelayMap, RelayMode, RelayNode};
pub use self::metrics::Metrics;
pub use self::server::{ClientConnHandler, MaybeTlsStream as MaybeTlsStreamServer, Server};
pub use iroh_base::node_addr::RelayUrl;
