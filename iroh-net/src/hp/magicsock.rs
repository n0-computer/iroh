//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//! Based on tailscale/wgengine/magicsock

mod conn;
mod derp_actor;
mod endpoint;
mod metrics;
mod rebinding_conn;
mod timer;
mod udp_actor;

pub use self::conn::{Callbacks, Conn, Options};
pub use self::endpoint::EndpointInfo;
pub use self::metrics::Metrics;
pub use self::timer::Timer;

// #[cfg(test)]
// pub(crate) use conn::tests as conn_tests;
