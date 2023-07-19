//! Broadcast messages to peers subscribed to a topic

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

#[cfg(feature = "net")]
pub mod net;
pub mod proto;
