//! A discovery service which publishes node information to a [Pkarr] relay.
//!
//! This service only implements the [`Discovery::publish`] method and does not provide discovery.
//! It encodes the node information into a DNS packet in the format resolvable by the
//! [`super::dns::DnsDiscovery`].
//!
//! [pkarr]: https://pkarr.org

use std::sync::Arc;

use anyhow::Result;
use pkarr::SignedPacket;
use tokio::{
    task::JoinHandle,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};
use url::Url;
use watchable::{Watchable, Watcher};

use crate::{discovery::Discovery, dns::node_info::NodeInfo, key::SecretKey, AddrInfo, NodeId};

/// The pkarr relay run by n0.
pub const N0_DNS_PKARR_RELAY: &str = "https://dns.iroh.link/pkarr";

/// Default TTL for the records in the pkarr signed packet
pub const DEFAULT_PKARR_TTL: u32 = 30;

/// Interval in which we will republish our node info even if unchanged: 5 minutes.
pub const DEFAULT_REPUBLISH_INTERVAL: Duration = Duration::from_secs(60 * 5);

/// Publish node info to a pkarr relay.
#[derive(derive_more::Debug, Clone)]
pub struct PkarrPublisher {
    node_id: NodeId,
    watchable: Watchable<Option<NodeInfo>>,
    join_handle: Arc<JoinHandle<()>>,
}

impl PkarrPublisher {
    /// Create a new config with a secret key and a pkarr relay URL.
    ///
    /// Will use [`DEFAULT_PKARR_TTL`] as the time-to-live value for the published packets.
    /// Will republish info, even if unchanged, every [`DEFAULT_REPUBLISH_INTERVAL`].
    pub fn new(secret_key: SecretKey, pkarr_relay: Url) -> Self {
        Self::with_options(
            secret_key,
            pkarr_relay,
            DEFAULT_PKARR_TTL,
            DEFAULT_REPUBLISH_INTERVAL,
        )
    }

    /// Create a new [`PkarrPublisher`] with a custom time-to-live (ttl) value for the published
    /// [`pkarr::SignedPacket`]s.
    pub fn with_options(
        secret_key: SecretKey,
        pkarr_relay: Url,
        ttl: u32,
        republish_interval: std::time::Duration,
    ) -> Self {
        let node_id = secret_key.public();
        let pkarr_client = PkarrRelayClient::new(pkarr_relay);
        let watchable = Watchable::default();
        let service = PublisherService {
            ttl,
            watcher: watchable.watch(),
            secret_key,
            pkarr_client,
            republish_interval,
        };
        let join_handle = tokio::task::spawn(service.run());
        Self {
            watchable,
            node_id,
            join_handle: Arc::new(join_handle),
        }
    }

    /// Create a config that publishes to the n0 dns server through [`N0_DNS_PKARR_RELAY`].
    pub fn n0_dns(secret_key: SecretKey) -> Self {
        let pkarr_relay: Url = N0_DNS_PKARR_RELAY.parse().expect("url is valid");
        Self::new(secret_key, pkarr_relay)
    }

    /// Publish [`AddrInfo`] about this node to a pkarr relay.
    ///
    /// This is a nonblocking function, the actual update is performed in the background.
    pub fn update_addr_info(&self, info: &AddrInfo) {
        let info = NodeInfo::new(
            self.node_id,
            info.relay_url.clone().map(Into::into),
            Default::default(),
        );
        self.watchable.update(Some(info)).ok();
    }
}

impl Discovery for PkarrPublisher {
    fn publish(&self, info: &AddrInfo) {
        self.update_addr_info(info);
    }
}

impl Drop for PkarrPublisher {
    fn drop(&mut self) {
        // this means we're dropping the last reference
        if let Some(handle) = Arc::get_mut(&mut self.join_handle) {
            handle.abort();
        }
    }
}

/// Publish node info to a pkarr relay.
#[derive(derive_more::Debug, Clone)]
struct PublisherService {
    #[debug("SecretKey")]
    secret_key: SecretKey,
    #[debug("PkarrClient")]
    pkarr_client: PkarrRelayClient,
    watcher: Watcher<Option<NodeInfo>>,
    ttl: u32,
    republish_interval: Duration,
}

impl PublisherService {
    async fn run(self) {
        let mut failed_attemps = 0;
        let republish = tokio::time::sleep(Duration::MAX);
        tokio::pin!(republish);
        loop {
            if let Some(info) = self.watcher.get() {
                if let Err(err) = self.publish_current(info).await {
                    warn!(?err, url = %self.pkarr_client.pkarr_relay , "Failed to publish to pkarr");
                    failed_attemps += 1;
                    // Retry after increasing timeout
                    republish
                        .as_mut()
                        .reset(Instant::now() + Duration::from_secs(failed_attemps));
                } else {
                    failed_attemps = 0;
                    // Republish after fixed interval
                    republish
                        .as_mut()
                        .reset(Instant::now() + self.republish_interval);
                }
            }
            // Wait until either the retry/republish timeout is reached, or the node info changed.
            tokio::select! {
                res = self.watcher.watch_async() => match res {
                    Ok(()) => debug!("Publish node info to pkarr (info changed)"),
                    Err(_disconnected) => break,
                },
                _ = &mut republish => debug!("Publish node info to pkarr (interval elapsed)"),
            }
        }
    }

    async fn publish_current(&self, info: NodeInfo) -> Result<()> {
        info!("Publish node info to pkarr");
        let signed_packet = info.to_pkarr_signed_packet(&self.secret_key, self.ttl)?;
        self.pkarr_client.publish(&signed_packet).await?;
        Ok(())
    }
}

/// A pkarr client to publish [`pkarr::SignedPacket`]s to a pkarr relay.
#[derive(Debug, Clone)]
pub struct PkarrRelayClient {
    inner: pkarr::PkarrClient,
    pkarr_relay: Url,
}

impl PkarrRelayClient {
    /// Create a new client.
    pub fn new(pkarr_relay: Url) -> Self {
        Self {
            inner: pkarr::PkarrClient::builder().build(),
            pkarr_relay,
        }
    }

    /// Publish a [`SignedPacket`]
    pub async fn publish(&self, signed_packet: &SignedPacket) -> anyhow::Result<()> {
        self.inner
            .relay_put(&self.pkarr_relay, signed_packet)
            .await?;
        Ok(())
    }
}
