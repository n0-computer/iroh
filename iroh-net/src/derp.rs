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

use std::fmt;
use std::ops::Deref;
use url::Url;

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
pub use self::server::{
    ClientConnHandler, MaybeTlsStream as MaybeTlsStreamServer, PacketForwarderHandler, Server,
};
pub use self::types::{MeshKey, PacketForwarder};

/// A URL identifying a DERP server.
///
/// This is but a wrapper around [`Url`], with a custom Debug impl.  This makes it much
/// easier to log e.g. an `Option<DerpUrl>` which is extremely common.
#[derive(Clone, derive_more::Display, PartialEq, Eq, Hash)]
pub struct DerpUrl(pub Url);

impl Deref for DerpUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for DerpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
