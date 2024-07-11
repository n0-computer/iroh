//! A discovery service which publishes and resolves node information to a [pkarr] relay.
//!
//! [pkarr]: https://pkarr.org

use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use futures_util::stream::BoxStream;
use pkarr::SignedPacket;
use tokio::{
    task::JoinHandle,
    time::{Duration, Instant},
};
use tracing::{debug, error_span, info, warn, Instrument};
use url::Url;
use watchable::{Watchable, Watcher};

use crate::{
    discovery::{Discovery, DiscoveryItem},
    dns::node_info::NodeInfo,
    key::SecretKey,
    AddrInfo, Endpoint, NodeId,
};

/// The pkarr relay run by n0, for production.
pub const N0_DNS_PKARR_RELAY_PROD: &str = "https://dns.iroh.link/pkarr";
/// The pkarr relay run by n0, for testing.
pub const N0_DNS_PKARR_RELAY_STAGING: &str = "https://staging-dns.iroh.link/pkarr";

/// Default TTL for the records in the pkarr signed packet. TTL tells DNS caches
/// how long to store a record. It is ignored by the iroh-dns-server as the home
/// server keeps the records for the domain. When using the pkarr relay no DNS is
/// involved and the setting is ignored.
pub const DEFAULT_PKARR_TTL: u32 = 30;

/// Interval in which we will republish our node info even if unchanged: 5 minutes.
pub const DEFAULT_REPUBLISH_INTERVAL: Duration = Duration::from_secs(60 * 5);

/// Publish node info to a pkarr relay.
///
/// Publishes either the relay url if the relay is enabled or the direct addresses
/// if the relay is disabled.
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
        debug!("creating pkarr publisher that publishes to {pkarr_relay}");
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
        let join_handle = tokio::task::spawn(
            service
                .run()
                .instrument(error_span!("pkarr_publish", me=%node_id.fmt_short())),
        );
        Self {
            watchable,
            node_id,
            join_handle: Arc::new(join_handle),
        }
    }

    /// Create a pkarr publisher which uses the [`N0_DNS_PKARR_RELAY_PROD`] pkarr relay and in testing
    /// uses [`N0_DNS_PKARR_RELAY_STAGING`].
    pub fn n0_dns(secret_key: SecretKey) -> Self {
        #[cfg(not(any(test, feature = "test-utils")))]
        let pkarr_relay = N0_DNS_PKARR_RELAY_PROD;
        #[cfg(any(test, feature = "test-utils"))]
        let pkarr_relay = N0_DNS_PKARR_RELAY_STAGING;

        let pkarr_relay: Url = pkarr_relay.parse().expect("url is valid");
        Self::new(secret_key, pkarr_relay)
    }

    /// Publish [`AddrInfo`] about this node to a pkarr relay.
    ///
    /// This is a nonblocking function, the actual update is performed in the background.
    pub fn update_addr_info(&self, info: &AddrInfo) {
        let (relay_url, direct_addresses) = if let Some(relay_url) = info.relay_url.as_ref() {
            (Some(relay_url.clone().into()), Default::default())
        } else {
            (None, info.direct_addresses.clone())
        };
        let info = NodeInfo::new(self.node_id, relay_url, direct_addresses);
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
        let mut failed_attempts = 0;
        let republish = tokio::time::sleep(Duration::MAX);
        tokio::pin!(republish);
        loop {
            if let Some(info) = self.watcher.get() {
                if let Err(err) = self.publish_current(info).await {
                    warn!(?err, url = %self.pkarr_client.pkarr_relay_url , "Failed to publish to pkarr");
                    failed_attempts += 1;
                    // Retry after increasing timeout
                    republish
                        .as_mut()
                        .reset(Instant::now() + Duration::from_secs(failed_attempts));
                } else {
                    failed_attempts = 0;
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
        info!(
            relay_url = ?info
                .relay_url
                .as_ref()
                .map(|s| s.as_str()),
            "Publish node info to pkarr"
        );
        let signed_packet = info.to_pkarr_signed_packet(&self.secret_key, self.ttl)?;
        self.pkarr_client.publish(&signed_packet).await?;
        Ok(())
    }
}

/// Resolve node info using a pkarr relay.
///
/// Pkarr stores signed DNS records in the mainline dht. These can be queried directly
/// via the pkarr relay HTTP api or alternatively via a dns server that provides the
/// pkarr records using `DnsDiscovery`. The main difference is that `DnsDiscovery` makes
/// use of the system dns resolver and caching which can return stale records, while the
/// `PkarrResolver` always gets recent data.
#[derive(derive_more::Debug, Clone)]
pub struct PkarrResolver {
    pkarr_client: PkarrRelayClient,
}

impl PkarrResolver {
    /// Create a new config with a pkarr relay URL.
    pub fn new(pkarr_relay: Url) -> Self {
        Self {
            pkarr_client: PkarrRelayClient::new(pkarr_relay),
        }
    }

    /// Create a pkarr resolver which uses the [`N0_DNS_PKARR_RELAY_PROD`] pkarr relay and in testing
    /// uses [`N0_DNS_PKARR_RELAY_STAGING`].
    pub fn n0_dns() -> Self {
        #[cfg(not(any(test, feature = "test-utils")))]
        let pkarr_relay = N0_DNS_PKARR_RELAY_PROD;
        #[cfg(any(test, feature = "test-utils"))]
        let pkarr_relay = N0_DNS_PKARR_RELAY_STAGING;

        let pkarr_relay: Url = pkarr_relay.parse().expect("url is valid");
        Self::new(pkarr_relay)
    }
}

impl Discovery for PkarrResolver {
    fn resolve(
        &self,
        _ep: Endpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<'static, Result<DiscoveryItem>>> {
        let pkarr_client = self.pkarr_client.clone();
        let fut = async move {
            let signed_packet = pkarr_client.resolve(node_id).await?;
            let info = NodeInfo::from_pkarr_signed_packet(&signed_packet)?;
            Ok(DiscoveryItem {
                provenance: "pkarr",
                last_updated: None,
                addr_info: info.into(),
            })
        };
        let stream = futures_lite::stream::once_future(fut);
        Some(Box::pin(stream))
    }
}

/// A pkarr client to publish [`pkarr::SignedPacket`]s to a pkarr relay.
#[derive(Debug, Clone)]
pub struct PkarrRelayClient {
    http_client: reqwest::Client,
    pkarr_relay_url: Url,
}

impl PkarrRelayClient {
    /// Create a new client.
    pub fn new(pkarr_relay_url: Url) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            pkarr_relay_url,
        }
    }

    /// Resolve a [`SignedPacket`]
    pub async fn resolve(&self, node_id: NodeId) -> anyhow::Result<SignedPacket> {
        let public_key = pkarr::PublicKey::try_from(node_id.as_bytes())?;
        let mut url = self.pkarr_relay_url.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow!("Failed to resolve: Invalid relay URL"))?
            .push(&public_key.to_z32());

        let response = self.http_client.get(url).send().await?;

        if !response.status().is_success() {
            bail!(format!(
                "Resolve request failed with status {}",
                response.status()
            ))
        }

        let payload = response.bytes().await?;
        Ok(SignedPacket::from_relay_payload(&public_key, &payload)?)
    }

    /// Publish a [`SignedPacket`]
    pub async fn publish(&self, signed_packet: &SignedPacket) -> anyhow::Result<()> {
        let mut url = self.pkarr_relay_url.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow!("Failed to publish: Invalid relay URL"))?
            .push(&signed_packet.public_key().to_z32());

        let response = self
            .http_client
            .put(url)
            .body(signed_packet.to_relay_payload())
            .send()
            .await?;

        if !response.status().is_success() {
            bail!(format!(
                "Publish request failed with status {}",
                response.status()
            ))
        }

        Ok(())
    }
}
