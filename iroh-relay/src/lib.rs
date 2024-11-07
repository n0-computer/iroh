//! Package `relay` implements a revised version of the Designated Encrypted Relay for Packets
//! (DERP) protocol written by Tailscale.
//
//! The relay routes packets to clients using curve25519 keys as addresses.
//
//! The relay is used to proxy encrypted QUIC packets through the relay servers when a direct path
//! cannot be found or opened. The relay is a last resort. If both sides have very aggressive NATs,
//! or firewalls, or no IPv6, we use the relay connection. Based on tailscale/derp/derp.go

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub(crate) mod client;
mod defaults;
mod dns;
pub mod http;
mod map;
pub mod protos;
#[cfg(feature = "iroh-relay")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "iroh-relay")))]
pub mod server;
mod util;

pub use iroh_base::node_addr::RelayUrl;

/// Environment variable to force the use of staging relays.
#[cfg_attr(iroh_docsrs, doc(cfg(not(test))))]
pub const ENV_FORCE_STAGING_RELAYS: &str = "IROH_FORCE_STAGING_RELAYS";

/// Returns `true` if the use of staging relays is forced.
pub fn force_staging_infra() -> bool {
    matches!(std::env::var(ENV_FORCE_STAGING_RELAYS), Ok(value) if !value.is_empty())
}

pub use self::{
    client::{
        conn::{Conn as RelayConn, ReceivedMessage},
        Client as HttpClient, ClientBuilder as HttpClientBuilder, ClientError as HttpClientError,
        ClientReceiver as HttpClientReceiver,
    },
    map::{RelayMap, RelayMode, RelayNode},
    protos::relay::MAX_PACKET_SIZE,
};
