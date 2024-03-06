//! Allows sending ICMP echo requests to a host in order to determine network latency.

use std::{
    fmt::Debug,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};
use tracing::debug;

/// Whether this error was because we couldn't create a client or a send error.
#[derive(Debug, thiserror::Error)]
pub enum PingError {
    /// Could not create client, probably bind error.
    #[error("Error creating ping client")]
    Client(#[from] anyhow::Error),
    /// Could not send ping.
    #[error("Error sending ping")]
    Ping(#[from] surge_ping::SurgeError),
}

/// Allows sending ICMP echo requests to a host in order to determine network latency.
/// Will gracefully handle both IPv4 and IPv6.
#[derive(Debug, Clone)]
pub struct Pinger(Arc<Inner>);

impl Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").finish()
    }
}

#[derive(Default)]
struct Inner {
    client_v6: Mutex<Option<Client>>,
    client_v4: Mutex<Option<Client>>,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

impl Pinger {
    /// Create a new [Pinger].
    pub fn new() -> Self {
        Self(Arc::new(Default::default()))
    }

    /// Lazily create the ping client.
    ///
    /// We do this because it means we do not bind a socket until we really try to send a
    /// ping.  It makes it more transparent to use the pinger.
    fn get_client(&self, kind: ICMP) -> Result<Client> {
        let client = match kind {
            ICMP::V4 => {
                let mut opt_client = self.0.client_v4.lock().unwrap();
                match *opt_client {
                    Some(ref client) => client.clone(),
                    None => {
                        let cfg = Config::builder().kind(kind).build();
                        let client = Client::new(&cfg).context("failed to create IPv4 pinger")?;
                        *opt_client = Some(client.clone());
                        client
                    }
                }
            }
            ICMP::V6 => {
                let mut opt_client = self.0.client_v6.lock().unwrap();
                match *opt_client {
                    Some(ref client) => client.clone(),
                    None => {
                        let cfg = Config::builder().kind(kind).build();
                        let client = Client::new(&cfg).context("failed to create IPv6 pinger")?;
                        *opt_client = Some(client.clone());
                        client
                    }
                }
            }
        };
        Ok(client)
    }

    /// Send a ping request with associated data, returning the perceived latency.
    pub async fn send(&self, addr: IpAddr, data: &[u8]) -> Result<Duration, PingError> {
        let client = match addr {
            IpAddr::V4(_) => self.get_client(ICMP::V4).map_err(PingError::Client)?,
            IpAddr::V6(_) => self.get_client(ICMP::V6).map_err(PingError::Client)?,
        };
        let ident = PingIdentifier(rand::random());
        debug!(%addr, %ident, "Creating pinger");
        let mut pinger = client.pinger(addr, ident).await;
        pinger.timeout(DEFAULT_TIMEOUT); // todo: timeout too large for netcheck
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

        let pinger = Pinger::new();

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
