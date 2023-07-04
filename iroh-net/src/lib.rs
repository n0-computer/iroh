// #![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![recursion_limit = "256"]

#[deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod defaults;
#[allow(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod hp;
#[allow(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod magic_endpoint;
#[allow(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod net;
#[deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod tls;
#[deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod util;

pub use magic_endpoint::MagicEndpoint;
