//! Allows sending ICMP echo requests to a host in order to determine network latency.
//!
//! Based on https://github.com/tailscale/tailscale/blob/main/net/ping/ping.go.

use std::{net::SocketAddr, time::Duration};

use anyhow::Error;

#[derive(Debug, Clone)]
pub struct Pinger {}

impl Pinger {
    pub fn new() -> Result<Self, Error> {
        todo!()
    }

    pub async fn send(&self, addr: SocketAddr, data: &[u8]) -> Result<Duration, Error> {
        todo!()
    }
}
