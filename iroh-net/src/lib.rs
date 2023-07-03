#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![recursion_limit = "256"]

pub mod defaults;
pub mod hp;
pub mod magic_endpoint;
pub mod net;
pub mod tls;
pub mod util;

pub use magic_endpoint::MagicEndpoint;
