#![recursion_limit = "256"]

#[deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod defaults;
#[deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod hp;
#[deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod magic_endpoint;
#[deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod net;
#[deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod tls;
#[deny(missing_docs, rustdoc::broken_intra_doc_links)]
pub mod util;

pub use magic_endpoint::MagicEndpoint;

#[cfg(test)]
pub(crate) mod test_utils;
