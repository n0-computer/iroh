//! A discovery service which publishes node information to a [Pkarr] relay.
//!
//! This service only implements the [`Discovery::publish`] method and does not provide discovery.
//! It encodes the node information into a DNS packet in the format resolvable by the
//! [`super::dns::DnsDiscovery`].
//!
//! [pkarr]: https://pkarr.org

use anyhow::Result;
use pkarr::SignedPacket;
use tokio::time::{Duration, Instant};
use tracing::warn;
use url::Url;
use watchable::Watchable;

use crate::{discovery::Discovery, dns::node_info::NodeInfo, key::SecretKey, AddrInfo, NodeId};

/// The n0 testing pkarr relay
pub const N0_DNS_PKARR_RELAY: &str = "https://dns.iroh.link/pkarr";

/// Default TTL for the _iroh_node TXT record in the pkarr signed packet
pub const DEFAULT_PKARR_TTL: u32 = 30;

/// Interval in which we will republish our node info even if unchanged.
pub const DEFAULT_REPUBLISH_INTERVAL: Duration = Duration::from_secs(60 * 5);

/// Publish node info to a pkarr relay.
#[derive(derive_more::Debug, Clone)]
pub struct PkarrPublisher {
    node_id: NodeId,
    watch: Watchable<Option<NodeInfo>>,
}

impl PkarrPublisher {
    /// Create a new config with a secret key and a pkarr relay URL.
    ///
    /// Will use [`DEFAULT_PKARR_TTL`] as the time-to-live value for the published packets.
    /// Will republish info, even if unchanged, every [`DEFAULT_REPUBLISH_INTERVAL`] (5 minutes).
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
        let watch = Watchable::default();
        let service = PublisherService {
            ttl,
            watch: watch.clone(),
            secret_key,
            pkarr_client,
            republish_interval: republish_interval.into(),
        };
        // TODO: Make this task cancelablle and and/or store the task handle.
        tokio::task::spawn(async move {
            if let Err(err) = service.run().await {
                warn!(?err, "PkarrPublisher service failed")
            }
        });
        Self { watch, node_id }
    }

    /// Create a config that publishes to the n0 dns server.
    pub fn n0_dns(secret_key: SecretKey) -> Self {
        let pkarr_relay: Url = N0_DNS_PKARR_RELAY.parse().expect("url is valid");
        Self::new(secret_key, pkarr_relay)
    }

    /// Publish [`AddrInfo`] about this node to a pkarr relay.
    ///
    /// This is a nonblocking function, the actual update is performed in the background.
    pub fn update_addr_info(&self, info: &AddrInfo) {
        let info = NodeInfo::new(self.node_id, info.relay_url.clone().map(Into::into));
        self.watch.update(Some(info)).ok();
    }
}

/// Publish node info to a pkarr relay.
#[derive(derive_more::Debug, Clone)]
struct PublisherService {
    #[debug("SecretKey")]
    secret_key: SecretKey,
    #[debug("PkarrClient")]
    pkarr_client: PkarrRelayClient,
    watch: Watchable<Option<NodeInfo>>,
    ttl: u32,
    republish_interval: Duration,
}

impl PublisherService {
    async fn run(&self) -> Result<()> {
        let watcher = self.watch.watch();
        let republish = tokio::time::sleep(Duration::MAX);
        tokio::pin!(republish);
        loop {
            if watcher.peek().is_some() {
                self.publish_current().await?;
            }
            tokio::select! {
                res = watcher.watch_async() => match res {
                    Ok(()) => {},
                    Err(_disconnected) => break,
                },
                _ = &mut republish => {}
            }
            republish
                .as_mut()
                .reset(Instant::now() + self.republish_interval);
        }
        Ok(())
    }

    async fn publish_current(&self) -> Result<()> {
        if let Some(info) = self.watch.get() {
            let signed_packet = info.to_pkarr_signed_packet(&self.secret_key, self.ttl)?;
            self.pkarr_client.publish(&signed_packet).await?;
        }
        Ok(())
    }
}

impl Discovery for PkarrPublisher {
    fn publish(&self, info: &AddrInfo) {
        self.update_addr_info(info);
    }
}

/// A pkarr client to publish [`pkarr::SignedPacket`]s to a pkarr relay.
#[derive(Debug, Clone)]
pub(crate) struct PkarrRelayClient {
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
