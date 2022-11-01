mod api;
mod api_ext;
mod config;
mod error;
mod p2p;

#[cfg(feature = "testing")]
pub use crate::api::MockApi;
pub use crate::api::{Api, Iroh, OutType};
pub use crate::api_ext::ApiExt;
pub use crate::error::ApiError;
#[cfg(feature = "testing")]
pub use crate::p2p::MockP2p;
pub use crate::p2p::P2p as P2pApi;
pub use crate::p2p::PeerIdOrAddr;
pub use bytes::Bytes;
pub use cid::Cid;
pub use iroh_resolver::resolver::Path as IpfsPath;
pub use iroh_resolver::unixfs_builder::AddEvent;
pub use iroh_rpc_types::p2p::PeerInfo;
pub use libp2p::gossipsub::MessageId;
pub use libp2p::{Multiaddr, PeerId};
