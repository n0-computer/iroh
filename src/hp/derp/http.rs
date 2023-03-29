mod client;
mod server;

pub use client::{Client, ClientBuilder, ClientError};

pub use server::derp_connection_handler;

pub(crate) const HTTP_UPGRADE_PROTOCOL: &str = "iroh derp http";
