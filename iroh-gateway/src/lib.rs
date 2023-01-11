pub mod bad_bits;
pub mod cli;
pub mod client;
pub mod config;
pub mod constants;
pub mod core;
mod cors;
mod error;
pub mod handler_params;
pub mod handlers;
pub mod headers;
mod ipfs_request;
pub mod metrics;
pub mod response;
mod rpc;
pub mod templates;
mod text;

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");
