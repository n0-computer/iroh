//! Package `relay` implements a revised version of the Designated Encrypted Relay for Packets
//! (DERP) protocol written by Tailscale.
//
//! The relay routes packets to clients using curve25519 keys as addresses.
//
//! The relay is used to proxy encrypted QUIC packets through the relay servers when a direct path
//! cannot be found or opened. The relay is a last resort. If both sides have very aggressive NATs,
//! or firewalls, or no IPv6, we use the relay connection. Based on tailscale/derp/derp.go

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod client;
pub mod defaults;
pub mod http;
pub mod protos;
#[cfg(feature = "server")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "server")))]
pub mod server;

#[cfg(test)]
mod dns;

pub use iroh_base::node_addr::RelayUrl;
pub use protos::relay::MAX_PACKET_SIZE;

pub use self::client::{
    conn::{Conn as RelayConn, ReceivedMessage},
    Client as HttpClient, ClientBuilder as HttpClientBuilder, ClientError as HttpClientError,
    ClientReceiver as HttpClientReceiver,
};
