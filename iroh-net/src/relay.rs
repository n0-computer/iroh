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
pub(crate) mod codec;
pub mod http;
mod map;
mod metrics;
#[cfg(feature = "iroh-relay")]
pub mod server;
pub(crate) mod types;

pub use self::client::conn::{Conn as RelayClient, ReceivedMessage};
pub use self::client::{
    Client as HttpClient, ClientBuilder as HttpClientBuilder, ClientReceiver as HttpClientReceiver,
};
pub use self::codec::MAX_PACKET_SIZE;
pub use self::map::{RelayMap, RelayMode, RelayNode};
pub use self::metrics::Metrics;
#[cfg(feature = "iroh-relay")]
pub use self::server::actor::{ClientConnHandler, ServerActorTask};
#[cfg(feature = "iroh-relay")]
pub use self::server::streams::MaybeTlsStream as MaybeTlsStreamServer;
pub use iroh_base::node_addr::RelayUrl;
