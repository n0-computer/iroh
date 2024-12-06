//! Base types and utilities for Iroh
#![cfg_attr(iroh_docsrs, feature(doc_cfg))]

#[cfg(feature = "base32")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "base32")))]
pub mod base32;
#[cfg(feature = "hash")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "hash")))]
pub mod hash;
#[cfg(feature = "key")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "key")))]
pub mod key;
#[cfg(feature = "key")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "key")))]
pub mod node_addr;
#[cfg(feature = "relay")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "relay")))]
pub mod relay_map;
#[cfg(any(feature = "relay", feature = "key"))]
mod relay_url;
#[cfg(feature = "base32")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "base32")))]
pub mod ticket;
