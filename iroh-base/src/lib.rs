//! Base types and utilities for Iroh
#![cfg_attr(iroh_docsrs, feature(doc_cfg))]

// TODO: remove
#[cfg(feature = "base32")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "base32")))]
pub mod base32;

// TODO: move to own crate
#[cfg(feature = "base32")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "base32")))]
pub mod ticket;

#[cfg(feature = "hash")]
mod hash;
#[cfg(feature = "key")]
mod key;
#[cfg(feature = "key")]
mod node_addr;
#[cfg(feature = "relay")]
mod relay_map;
#[cfg(any(feature = "relay", feature = "key"))]
mod relay_url;

#[cfg(feature = "relay")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "relay")))]
pub use self::relay_map::{
    QuicConfig as RelayQuicConfig, RelayMap, RelayNode, DEFAULT_RELAY_QUIC_PORT, DEFAULT_STUN_PORT,
};
#[cfg(any(feature = "relay", feature = "key"))]
#[cfg_attr(iroh_docsrs, doc(cfg(any(feature = "relay", feature = "key"))))]
pub use self::relay_url::RelayUrl;

#[cfg(feature = "hash")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "hash")))]
pub use self::hash::{BlobFormat, Hash, HashAndFormat};

#[cfg(feature = "key")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "key")))]
pub use self::key::{
    KeyParsingError, NodeId, PublicKey, SecretKey, SharedSecret, Signature, PUBLIC_KEY_LENGTH,
};
#[cfg(feature = "key")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "key")))]
pub use self::node_addr::{AddrInfo, AddrInfoOptions, NodeAddr};
