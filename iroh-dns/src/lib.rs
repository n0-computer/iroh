//! DNS-based endpoint discovery for iroh.
//!
//! This crate contains the core types for publishing and resolving iroh endpoint
//! information via DNS, using the [pkarr](https://pkarr.org) signed packet format.
#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

mod attrs;
#[cfg(not(wasm_browser))]
pub mod dns;
pub mod endpoint_info;
pub mod pkarr;

pub use attrs::{EncodingError, IROH_TXT_NAME, ParseError};
