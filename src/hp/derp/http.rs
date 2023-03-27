mod client;
mod server;

pub use client::{Client, ClientError};

pub use server::derp_connection_handler;

pub(crate) const HTTP_UPGRADE_PROTOCOL: &str = "iroh derp http";
