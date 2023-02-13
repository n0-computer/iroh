//! Allows sending ICMP echo requests to a host in order to determine network latency.
//!
//! Based on https://github.com/tailscale/tailscale/blob/main/net/ping/ping.go.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Error;

#[derive(Debug, Clone)]
pub struct Pinger(Arc<Inner>);

#[derive(Debug)]
struct Inner {}

impl Pinger {
    pub async fn new() -> Result<Self, Error> {
        Ok(Self(Arc::new(Inner {})))
    }

    pub async fn send(&self, _addr: SocketAddr, _data: &[u8]) -> Result<Duration, Error> {
        anyhow::bail!("icmp is not available yet");
    }
}
