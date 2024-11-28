//! Send data over the internet.
//!
//!
//! ## Reexports
//!
//! The iroh crate re-exports the following crates:
//! - [iroh_base] as [`base`]
//! - [iroh_net] as [`net`]
//! - [iroh_router] as [`router`]
#![cfg_attr(iroh_docsrs, feature(doc_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

// re-export the iroh crates
#[doc(inline)]
pub use iroh_base as base;
#[doc(inline)]
pub use iroh_net as net;
#[doc(inline)]
pub use iroh_router as router;
