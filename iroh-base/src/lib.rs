//! Base types and utilities for Iroh
#![cfg_attr(iroh_docsrs, feature(doc_auto_cfg))]

#[cfg(feature = "base32")]
pub mod base32;
#[cfg(feature = "hash")]
pub mod hash;
#[cfg(feature = "key")]
pub mod key;
#[cfg(feature = "key")]
pub mod node_addr;
#[cfg(feature = "relay")]
pub mod relay_map;
#[cfg(feature = "relay")]
mod relay_url;
#[cfg(feature = "ticket")]
pub mod ticket;
