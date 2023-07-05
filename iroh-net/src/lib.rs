#![recursion_limit = "256"]

pub mod defaults;
pub mod hp;
pub mod magic_endpoint;
pub mod net;
pub mod tls;
pub mod util;

pub use magic_endpoint::MagicEndpoint;

#[cfg(test)]
pub(crate) mod test_utils;
