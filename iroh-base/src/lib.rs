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
pub mod rpc;
#[cfg(feature = "base32")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "base32")))]
pub mod ticket;
