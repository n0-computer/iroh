//! Base types and utilities for Iroh
#![cfg_attr(iroh_docsrs, feature(doc_auto_cfg))]

// TODO: move to own crate
#[cfg(feature = "ticket")]
pub mod ticket;

#[cfg(feature = "key")]
mod key;
#[cfg(feature = "key")]
mod node_addr;
#[cfg(feature = "relay")]
mod relay_url;

#[cfg(feature = "key")]
pub use self::key::{
    KeyParsingError, NodeId, PublicKey, SecretKey, SharedSecret, Signature, PUBLIC_KEY_LENGTH,
};
#[cfg(feature = "key")]
pub use self::node_addr::NodeAddr;
#[cfg(feature = "relay")]
pub use self::relay_url::RelayUrl;
