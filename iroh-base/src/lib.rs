//! Base types and utilities for Iroh
#![cfg_attr(iroh_docsrs, feature(doc_auto_cfg))]

// TODO: remove
#[cfg(feature = "base32")]
pub mod base32;

// TODO: move to own crate
#[cfg(feature = "ticket")]
pub mod ticket;

#[cfg(feature = "hash")]
mod hash;
#[cfg(feature = "key")]
mod key;
#[cfg(feature = "key")]
mod node_addr;
#[cfg(feature = "relay")]
mod relay_map;
#[cfg(feature = "relay")]
mod relay_url;

#[cfg(feature = "hash")]
pub use self::hash::{BlobFormat, Hash, HashAndFormat};
#[cfg(feature = "key")]
pub use self::key::{
    KeyParsingError, NodeId, PublicKey, SecretKey, SharedSecret, Signature, PUBLIC_KEY_LENGTH,
};
#[cfg(feature = "key")]
pub use self::node_addr::NodeAddr;
#[cfg(feature = "relay")]
pub use self::relay_map::{
    RelayMap, RelayNode, RelayQuicConfig, DEFAULT_RELAY_QUIC_PORT, DEFAULT_STUN_PORT,
};
#[cfg(feature = "relay")]
pub use self::relay_url::RelayUrl;
