//! Pkarr based node discovery for iroh, supporting both relay servers and the DHT.
//!
//! This module contains pkarr-based node discovery for iroh which can use both pkarr
//! relay servers as well as the Mainline DHT directly.  See the [pkarr module] for an
//! overview of pkarr.
//!
//! [pkarr module]: super
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use iroh_base::{NodeAddr, NodeId, RelayUrl, SecretKey};
use n0_future::{
    boxed::BoxStream,
    stream::StreamExt,
    task::{self, AbortOnDropHandle},
    time::{self, Duration},
    FutureExt,
};
use pkarr::{
    PkarrClient, PkarrClientAsync, PkarrRelayClient, PkarrRelayClientAsync, RelaySettings,
    SignedPacket,
};
use url::Url;

use crate::{
    discovery::{
        pkarr::{DEFAULT_PKARR_TTL, N0_DNS_PKARR_RELAY_PROD},
        Discovery, DiscoveryItem,
    },
    node_info::NodeInfo,
    Endpoint,
};

/// Republish delay for the DHT.
///
/// This is only for when the info does not change.  If the info changes, it will be
/// published immediately.
const REPUBLISH_DELAY: Duration = Duration::from_secs(60 * 60);
/// Initial publish delay.
///
/// This is to avoid spamming the DHT when there are frequent network changes at startup.
const INITIAL_PUBLISH_DELAY: Duration = Duration::from_millis(500);

/// Pkarr Mainline DHT and relay server node discovery.
///
/// It stores node addresses in DNS records, signed by the node's private key, and publishes
/// them to the BitTorrent Mainline DHT.  See the [pkarr module] for more details.
///
/// This implements the [`Discovery`] trait to be used as a node discovery service which can
/// be used as both a publisher and resolver.  Calling [`DhtDiscovery::publish`] will start
/// a background task that periodically publishes the node address.
///
/// [pkarr module]: super
#[derive(Debug, Clone)]
pub struct DhtDiscovery(Arc<Inner>);

impl Default for DhtDiscovery {
    fn default() -> Self {
        Self::builder().build().expect("valid builder")
    }
}

#[derive(derive_more::Debug)]
struct Inner {
    /// Pkarr client for interacting with the DHT.
    pkarr: PkarrClientAsync,
    /// Pkarr client for interacting with a pkarr relay
    #[debug("Option<PkarrRelayClientAsync>")]
    pkarr_relay: Option<PkarrRelayClientAsync>,
    /// The background task that periodically publishes the node address.
    ///
    /// Due to [`AbortOnDropHandle`], this will be aborted when the discovery is dropped.
    task: Mutex<Option<AbortOnDropHandle<()>>>,
    /// Optional keypair for signing the DNS packets.
    ///
    /// If this is None, the node will not publish its address to the DHT.
    secret_key: Option<SecretKey>,
    /// Optional pkarr relay URL to use.
    relay_url: Option<Url>,
    /// Whether to publish to the mainline DHT.
    dht: bool,
    /// Time-to-live value for the DNS packets.
    ttl: u32,
    /// True to include the direct addresses in the DNS packet.
    include_direct_addresses: bool,
    /// Initial delay before the first publish.
    initial_publish_delay: Duration,
    /// Republish delay for the DHT.
    republish_delay: Duration,
}

impl Inner {
    async fn resolve_relay(&self, key: pkarr::PublicKey) -> Option<Result<DiscoveryItem>> {
        tracing::info!("resolving {} from relay {:?}", key.to_z32(), self.relay_url);

        let maybe_packet = self
            .pkarr_relay
            .as_ref()
            .expect("checked")
            .resolve(&key)
            .await;
        match maybe_packet {
            Ok(Some(signed_packet)) => match NodeInfo::from_pkarr_signed_packet(&signed_packet) {
                Ok(node_info) => {
                    let node_addr: NodeAddr = node_info.into();

                    tracing::info!("discovered node info from relay {:?}", node_addr);
                    Some(Ok(DiscoveryItem {
                        node_addr,
                        provenance: "relay",
                        last_updated: None,
                    }))
                }
                Err(_err) => {
                    tracing::debug!("failed to parse signed packet as node info");
                    None
                }
            },
            Ok(None) => {
                tracing::debug!("no signed packet found in relay");
                None
            }
            Err(err) => {
                tracing::debug!("failed to get signed packet from relay: {}", err);
                Some(Err(err.into()))
            }
        }
    }
    async fn resolve_dht(&self, key: pkarr::PublicKey) -> Option<Result<DiscoveryItem>> {
        tracing::info!("resolving {} from DHT", key.to_z32());

        let maybe_packet = self.pkarr.resolve(&key).await;
        match maybe_packet {
            Ok(Some(signed_packet)) => match NodeInfo::from_pkarr_signed_packet(&signed_packet) {
                Ok(node_info) => {
                    let node_addr: NodeAddr = node_info.into();
                    tracing::info!("discovered node info from DHT {:?}", node_addr);
                    Some(Ok(DiscoveryItem {
                        node_addr,
                        provenance: "mainline",
                        last_updated: None,
                    }))
                }
                Err(_err) => {
                    tracing::debug!("failed to parse signed packet as node info");
                    None
                }
            },
            Ok(None) => {
                // nothing to do
                tracing::debug!("no signed packet found in DHT");
                None
            }
            Err(err) => Some(Err(err.into())),
        }
    }
}

/// Builder for [`DhtDiscovery`].
///
/// By default, publishing to the DHT is enabled, and relay publishing is disabled.
#[derive(Debug)]
pub struct Builder {
    client: Option<PkarrClient>,
    secret_key: Option<SecretKey>,
    ttl: Option<u32>,
    pkarr_relay: Option<Url>,
    dht: bool,
    include_direct_addresses: bool,
    initial_publish_delay: Duration,
    republish_delay: Duration,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            client: None,
            secret_key: None,
            ttl: None,
            pkarr_relay: None,
            dht: true,
            include_direct_addresses: false,
            initial_publish_delay: INITIAL_PUBLISH_DELAY,
            republish_delay: REPUBLISH_DELAY,
        }
    }
}

impl Builder {
    /// Explicitly sets the pkarr client to use.
    pub fn client(mut self, client: PkarrClient) -> Self {
        self.client = Some(client);
        self
    }

    /// Sets the secret key to use for signing the DNS packets.
    ///
    /// Without a secret key, the node will not publish its address to the DHT.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Sets the time-to-live value for the DNS packets.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets the pkarr relay URL to use.
    pub fn pkarr_relay(mut self, pkarr_relay: Url) -> Self {
        self.pkarr_relay = Some(pkarr_relay);
        self
    }

    /// Uses the default [number 0] pkarr relay URL.
    ///
    /// [number 0]: https://n0.computer
    pub fn n0_dns_pkarr_relay(mut self) -> Self {
        self.pkarr_relay = Some(N0_DNS_PKARR_RELAY_PROD.parse().expect("valid URL"));
        self
    }

    /// Sets whether to publish to the Mainline DHT.
    pub fn dht(mut self, dht: bool) -> Self {
        self.dht = dht;
        self
    }

    /// Sets whether to include the direct addresses in the DNS packet.
    pub fn include_direct_addresses(mut self, include_direct_addresses: bool) -> Self {
        self.include_direct_addresses = include_direct_addresses;
        self
    }

    /// Sets the initial delay before the first publish.
    pub fn initial_publish_delay(mut self, initial_publish_delay: Duration) -> Self {
        self.initial_publish_delay = initial_publish_delay;
        self
    }

    /// Sets the republish delay for the DHT.
    pub fn republish_delay(mut self, republish_delay: Duration) -> Self {
        self.republish_delay = republish_delay;
        self
    }

    /// Builds the discovery mechanism.
    pub fn build(self) -> Result<DhtDiscovery> {
        let pkarr = match self.client {
            Some(client) => client,
            None => PkarrClient::new(Default::default())?,
        };
        let pkarr = pkarr.as_async();
        let ttl = self.ttl.unwrap_or(DEFAULT_PKARR_TTL);
        let relay_url = self.pkarr_relay;
        let dht = self.dht;
        let include_direct_addresses = self.include_direct_addresses;
        anyhow::ensure!(
            dht || relay_url.is_some(),
            "at least one of DHT or relay must be enabled"
        );

        let pkarr_relay = match relay_url.clone() {
            Some(url) => Some(
                PkarrRelayClient::new(RelaySettings {
                    relays: vec![url.to_string()],
                    ..RelaySettings::default()
                })?
                .as_async(),
            ),
            None => None,
        };

        Ok(DhtDiscovery(Arc::new(Inner {
            pkarr,
            pkarr_relay,
            ttl,
            relay_url,
            dht,
            include_direct_addresses,
            secret_key: self.secret_key,
            initial_publish_delay: self.initial_publish_delay,
            republish_delay: self.republish_delay,
            task: Default::default(),
        })))
    }
}

impl DhtDiscovery {
    /// Creates a new builder for [`DhtDiscovery`].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Periodically publishes the node address to the DHT and/or relay.
    async fn publish_loop(self, keypair: SecretKey, signed_packet: SignedPacket) {
        let this = self;
        let z32 = pkarr::PublicKey::try_from(keypair.public().as_bytes())
            .expect("valid public key")
            .to_z32();
        // initial delay. If the task gets aborted before this delay is over,
        // we have not published anything to the DHT yet.
        time::sleep(this.0.initial_publish_delay).await;
        loop {
            // publish to the DHT if enabled
            let dht_publish = async {
                if this.0.dht {
                    let res = this.0.pkarr.publish(&signed_packet).await;
                    match res {
                        Ok(()) => {
                            tracing::debug!("pkarr publish success. published under {z32}",);
                        }
                        Err(e) => {
                            // we could do a smaller delay here, but in general DHT publish
                            // not working is due to a network issue, and if the network changes
                            // the task will be restarted anyway.
                            //
                            // Being unable to publish to the DHT is something that is expected
                            // to happen from time to time, so this does not warrant a error log.
                            tracing::warn!("pkarr publish error: {}", e);
                        }
                    }
                }
            };
            // publish to the relay if enabled
            let relay_publish = async {
                if let Some(relay) = this.0.pkarr_relay.as_ref() {
                    tracing::info!(
                        "publishing to relay: {:?}",
                        this.0.relay_url.as_ref().map(|r| r.to_string())
                    );
                    match relay.publish(&signed_packet).await {
                        Ok(_) => {
                            tracing::debug!("pkarr publish to relay success");
                        }
                        Err(e) => {
                            tracing::warn!("pkarr publish to relay error: {}", e);
                        }
                    }
                }
            };
            // do both at the same time
            tokio::join!(relay_publish, dht_publish);
            time::sleep(this.0.republish_delay).await;
        }
    }
}

impl Discovery for DhtDiscovery {
    fn publish(&self, url: Option<&RelayUrl>, addrs: &BTreeSet<SocketAddr>) {
        let Some(keypair) = &self.0.secret_key else {
            tracing::debug!("no keypair set, not publishing");
            return;
        };
        tracing::debug!("publishing {:?}, {:?}", url, addrs);
        let info = NodeInfo {
            node_id: keypair.public(),
            relay_url: url.cloned().map(Url::from),
            direct_addresses: if self.0.include_direct_addresses {
                addrs.clone()
            } else {
                Default::default()
            },
        };
        let Ok(signed_packet) = info.to_pkarr_signed_packet(keypair, self.0.ttl) else {
            tracing::warn!("failed to create signed packet");
            return;
        };
        let this = self.clone();
        let curr = task::spawn(this.publish_loop(keypair.clone(), signed_packet));
        let mut task = self.0.task.lock().expect("poisoned");
        *task = Some(AbortOnDropHandle::new(curr));
    }

    fn resolve(
        &self,
        _endpoint: Endpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<anyhow::Result<DiscoveryItem>>> {
        let pkarr_public_key =
            pkarr::PublicKey::try_from(node_id.as_bytes()).expect("valid public key");
        tracing::info!("resolving {} as {}", node_id, pkarr_public_key.to_z32());

        let mut stream = futures_buffered::FuturesUnorderedBounded::new(2);
        if self.0.pkarr_relay.is_some() {
            let key = pkarr_public_key.clone();
            let discovery = self.0.clone();
            stream.push(async move { discovery.resolve_relay(key).await }.boxed());
        }

        if self.0.dht {
            let key = pkarr_public_key.clone();
            let discovery = self.0.clone();
            stream.push(async move { discovery.resolve_dht(key).await }.boxed());
        }

        Some(stream.filter_map(|t| t).boxed())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use iroh_base::RelayUrl;
    use pkarr::mainline::dht::DhtSettings;
    use testresult::TestResult;

    use super::*;

    #[tokio::test]
    #[ignore = "flaky"]
    async fn dht_discovery_smoke() -> TestResult {
        let _logging_guard = iroh_test::logging::setup();
        let ep = crate::Endpoint::builder().bind().await?;
        let secret = ep.secret_key().clone();
        let testnet = pkarr::mainline::dht::Testnet::new(2);
        let settings = pkarr::Settings {
            dht: DhtSettings {
                bootstrap: Some(testnet.bootstrap.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let client = PkarrClient::new(settings)?;
        let discovery = DhtDiscovery::builder()
            .secret_key(secret.clone())
            .initial_publish_delay(Duration::ZERO)
            .client(client)
            .build()?;
        let relay_url: RelayUrl = Url::parse("https://example.com")?.into();

        discovery.publish(Some(&relay_url), &Default::default());

        // publish is fire and forget, so we have no way to wait until it is done.
        tokio::time::timeout(Duration::from_secs(30), async move {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let mut found_relay_urls = BTreeSet::new();
                let items = discovery
                    .resolve(ep.clone(), secret.public())
                    .unwrap()
                    .collect::<Vec<_>>()
                    .await;
                for item in items.into_iter().flatten() {
                    if let Some(url) = item.node_addr.relay_url {
                        found_relay_urls.insert(url);
                    }
                }
                if found_relay_urls.contains(&relay_url) {
                    break;
                }
            }
        })
        .await
        .expect("timeout, relay_url not found on DHT");
        Ok(())
    }
}
