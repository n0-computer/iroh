//! Allows sending ICMP echo requests to a host in order to determine network latency.

use std::{fmt::Debug, net::IpAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};
use tracing::debug;

/// Allows sending ICMP echo requests to a host in order to determine network latency.
/// Will gracefully handle both IPv4 and IPv6.
#[derive(Debug, Clone)]
pub struct Pinger(Arc<Inner>);

impl Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").finish()
    }
}

struct Inner {
    client_v6: Client,
    client_v4: Client,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

impl Pinger {
    /// Create a new [Pinger].
    pub async fn new() -> Result<Self> {
        let client_v4 = Client::new(&Config::builder().kind(ICMP::V4).build())
            .context("failed creating IPv4 pinger")?;
        let client_v6 = Client::new(&Config::builder().kind(ICMP::V6).build())
            .context("failed creating IPv6 pinger")?;

        Ok(Self(Arc::new(Inner {
            client_v4,
            client_v6,
        })))
    }

    /// Send a ping request with asociated data, returning the perceived latency.
    pub async fn send(&self, addr: IpAddr, data: &[u8]) -> Result<Duration> {
        let client = match addr {
            IpAddr::V4(_) => &self.0.client_v4,
            IpAddr::V6(_) => &self.0.client_v6,
        };
        let mut pinger = client.pinger(addr, PingIdentifier(rand::random())).await;
        pinger.timeout(DEFAULT_TIMEOUT);
        match pinger.ping(PingSequence(0), data).await? {
            (IcmpPacket::V4(packet), dur) => {
                debug!(
                    "{} bytes from {}: icmp_seq={} ttl={:?} time={:0.2?}",
                    packet.get_size(),
                    packet.get_source(),
                    packet.get_sequence(),
                    packet.get_ttl(),
                    dur
                );
                Ok(dur)
            }

            (IcmpPacket::V6(packet), dur) => {
                debug!(
                    "{} bytes from {}: icmp_seq={} hlim={} time={:0.2?}",
                    packet.get_size(),
                    packet.get_source(),
                    packet.get_sequence(),
                    packet.get_max_hop_limit(),
                    dur
                );
                Ok(dur)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tracing_subscriber::{prelude::*, EnvFilter};

    #[tokio::test]
    #[ignore] // Doesn't work in CI
    async fn test_ping_google() -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();

        // Public DNS addrs from google based on
        // https://developers.google.com/speed/public-dns/docs/using

        let pinger = Pinger::new().await?;

        // IPv4
        let dur = pinger.send("8.8.8.8".parse()?, &[1u8; 8]).await?;
        assert!(!dur.is_zero());

        // IPv6
        match pinger
            .send("2001:4860:4860:0:0:0:0:8888".parse()?, &[1u8; 8])
            .await
        {
            Ok(dur) => {
                assert!(!dur.is_zero());
            }
            Err(err) => {
                tracing::error!("IPv6 is not available: {:?}", err);
            }
        }

        Ok(())
    }
}
