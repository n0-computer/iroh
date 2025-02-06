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

use crate::defaults::timeouts::DEFAULT_PINGER_TIMEOUT as DEFAULT_TIMEOUT;

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
#[derive(Debug, Clone, Default)]
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

impl Pinger {
    /// Create a new [Pinger].
    pub fn new() -> Self {
        Default::default()
    }

    /// Lazily create the ping client.
    ///
    /// We do this because it means we do not bind a socket until we really try to send a
    /// ping.  It makes it more transparent to use the pinger.
    fn get_client(&self, kind: ICMP) -> Result<Client> {
        let client = match kind {
            ICMP::V4 => {
                let mut opt_client = self.0.client_v4.lock().expect("poisoned");
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
                let mut opt_client = self.0.client_v6.lock().expect("poisoned");
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
        pinger.timeout(DEFAULT_TIMEOUT); // todo: timeout too large for net_report
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tracing::error;
    use tracing_test::traced_test;

    use super::*;

    // See net_report::reportgen::tests::test_icmp_probe_eu_relay for permissions to ping.
    #[tokio::test]
    #[traced_test]
    async fn test_ping_localhost() {
        let pinger = Pinger::new();

        match pinger.send(Ipv4Addr::LOCALHOST.into(), b"data").await {
            Ok(duration) => {
                assert!(!duration.is_zero());
            }
            Err(PingError::Client(err)) => {
                // We don't have permission, too bad.
                error!("no ping permissions: {err:#}");
            }
            Err(PingError::Ping(err)) => {
                panic!("ping failed: {err:#}");
            }
        }

        match pinger.send(Ipv6Addr::LOCALHOST.into(), b"data").await {
            Ok(duration) => {
                assert!(!duration.is_zero());
            }
            Err(PingError::Client(err)) => {
                // We don't have permission, too bad.
                error!("no ping permissions: {err:#}");
            }
            Err(PingError::Ping(err)) => {
                error!("ping failed, probably no IPv6 stack: {err:#}");
            }
        }
    }
}
