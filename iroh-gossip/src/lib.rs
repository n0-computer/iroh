//! Broadcast messages to peers subscribed to a topic
//!
//! The crate is designed to be used from the [iroh] crate, which provides a
//! [high level interface](https://docs.rs/iroh/latest/iroh/client/gossip/index.html),
//! but can also be used standalone.
//!
//! [iroh]: https://docs.rs/iroh
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(iroh_docsrs, feature(doc_cfg))]

pub mod metrics;
#[cfg(feature = "net")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "net")))]
pub mod net;
pub mod proto;
