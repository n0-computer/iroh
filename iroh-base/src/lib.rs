//! Base types and utilities for Iroh
#![cfg_attr(iroh_docsrs, feature(doc_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

// TODO: move to own crate
//#[cfg(feature = "ticket")]
// b mod ticket;

#[cfg(feature = "key")]
mod endpoint_addr;
#[cfg(feature = "key")]
mod key;
#[cfg(feature = "relay")]
mod relay_url;

#[cfg(feature = "key")]
pub use self::endpoint_addr::{AddrType, EndpointAddr};
#[cfg(feature = "key")]
pub use self::key::{EndpointId, KeyParsingError, PublicKey, SecretKey, Signature, SignatureError};
#[cfg(feature = "relay")]
pub use self::relay_url::{RelayUrl, RelayUrlParseError};
