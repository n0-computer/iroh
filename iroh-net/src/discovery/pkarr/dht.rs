//! # Pkarr based node discovery for iroh-net
//!
//! Node discovery is being able to find connecting information about an iroh node based on just its node id.
//!
//! This crate implements a discovery mechanism for iroh-net based on <https://pkarr.org/>.
//!
//! TLDR: Each node publishes its address to the mainline DHT as a DNS packet, signed with its private key.
//! The DNS packet contains the node's direct addresses and optionally a DERP URL.
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    discovery::{
        pkarr::{DEFAULT_PKARR_TTL, N0_DNS_PKARR_RELAY_PROD},
        Discovery, DiscoveryItem,
    },
    dns::node_info::NodeInfo,
    key::SecretKey,
    util::AbortingJoinHandle,
    AddrInfo, Endpoint, NodeId,
};
use futures_lite::StreamExt;
use genawaiter::sync::{Co, Gen};
use pkarr::{
    PkarrClient, PkarrClientAsync, PkarrRelayClient, PkarrRelayClientAsync, PublicKey,
    RelaySettings, SignedPacket,
};
use url::Url;

/// Republish delay for the DHT. This is only for when the info does not change.
/// If the info changes, it will be published immediately.
const REPUBLISH_DELAY: Duration = Duration::from_secs(60 * 60);
/// Initial publish delay. This is to avoid spamming the DHT when there are
/// frequent network changes at startup.
const INITIAL_PUBLISH_DELAY: Duration = Duration::from_millis(500);

/// A discovery mechanism for iroh-net based on <https://pkarr.org/>.
///
/// TLDR: it stores node addresses in DNS records, signed by the node's private key,
/// and publishes them to the bittorrent mainline DHT.
///
/// Calling publish will start a background task that periodically publishes the node address.
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
    /// Due to AbortingJoinHandle, this will be aborted when the discovery is dropped.
    task: Mutex<Option<AbortingJoinHandle<()>>>,
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

/// Builder for PkarrNodeDiscovery.
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
    /// Explicitly set the pkarr client to use.
    pub fn client(mut self, client: PkarrClient) -> Self {
        self.client = Some(client);
        self
    }

    /// Set the secret key to use for signing the DNS packets.
    ///
    /// Without a secret key, the node will not publish its address to the DHT.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Set the time-to-live value for the DNS packets.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the pkarr relay URL to use.
    pub fn pkarr_relay(mut self, pkarr_relay: Url) -> Self {
        self.pkarr_relay = Some(pkarr_relay);
        self
    }

    /// Use the default pkarr relay URL.
    pub fn n0_dns_pkarr_relay(mut self) -> Self {
        self.pkarr_relay = Some(N0_DNS_PKARR_RELAY_PROD.parse().expect("valid URL"));
        self
    }

    /// Set whether to publish to the mainline DHT.
    pub fn dht(mut self, dht: bool) -> Self {
        self.dht = dht;
        self
    }

    /// Set whether to include the direct addresses in the DNS packet.
    pub fn include_direct_addresses(mut self, include_direct_addresses: bool) -> Self {
        self.include_direct_addresses = include_direct_addresses;
        self
    }

    /// Set the initial delay before the first publish.
    pub fn initial_publish_delay(mut self, initial_publish_delay: Duration) -> Self {
        self.initial_publish_delay = initial_publish_delay;
        self
    }

    /// Set the republish delay for the DHT.
    pub fn republish_delay(mut self, republish_delay: Duration) -> Self {
        self.republish_delay = republish_delay;
        self
    }

    /// Build the discovery mechanism.
    pub fn build(self) -> anyhow::Result<DhtDiscovery> {
        let pkarr = self
            .client
            .unwrap_or_else(|| PkarrClient::new(Default::default()).unwrap())
            .as_async();
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
    /// Create a new builder for PkarrNodeDiscovery.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Periodically publish the node address to the DHT and relay.
    async fn publish_loop(self, keypair: SecretKey, signed_packet: SignedPacket) {
        let this = self;
        let z32 = pkarr::PublicKey::try_from(keypair.public().as_bytes())
            .expect("valid public key")
            .to_z32();
        // initial delay. If the task gets aborted before this delay is over,
        // we have not published anything to the DHT yet.
        tokio::time::sleep(this.0.initial_publish_delay).await;
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
                        "publishing to relay: {}",
                        this.0.relay_url.as_ref().unwrap().to_string()
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
            tokio::time::sleep(this.0.republish_delay).await;
        }
    }

    async fn resolve_relay(
        &self,
        pkarr_public_key: PublicKey,
        co: &Co<anyhow::Result<DiscoveryItem>>,
    ) {
        let Some(relay) = &self.0.pkarr_relay else {
            return;
        };
        let url = self.0.relay_url.as_ref().unwrap();
        tracing::info!("resolving {} from relay {}", pkarr_public_key.to_z32(), url);
        let response = relay.resolve(&pkarr_public_key).await;
        match response {
            Ok(Some(signed_packet)) => {
                if let Ok(node_info) = NodeInfo::from_pkarr_signed_packet(&signed_packet) {
                    let addr_info = node_info.into();
                    tracing::info!("discovered node info from relay {:?}", addr_info);
                    co.yield_(Ok(DiscoveryItem {
                        provenance: "relay",
                        last_updated: None,
                        addr_info,
                    }))
                    .await;
                } else {
                    tracing::debug!("failed to parse signed packet as node info");
                }
            }
            Ok(None) => {
                tracing::debug!("no signed packet found in relay");
            }
            Err(e) => {
                tracing::debug!("failed to get signed packet from relay: {}", e);
                co.yield_(Err(e.into())).await;
            }
        }
    }

    /// Resolve a node id from the DHT.
    async fn resolve_dht(
        &self,
        pkarr_public_key: PublicKey,
        co: &Co<anyhow::Result<DiscoveryItem>>,
    ) {
        if !self.0.dht {
            return;
        };
        tracing::info!("resolving {} from DHT", pkarr_public_key.to_z32());
        let response = match self.0.pkarr.resolve(&pkarr_public_key).await {
            Ok(r) => r,
            Err(e) => {
                co.yield_(Err(e.into())).await;
                return;
            }
        };
        let Some(signed_packet) = response else {
            tracing::debug!("no signed packet found in DHT");
            return;
        };
        if let Ok(node_info) = NodeInfo::from_pkarr_signed_packet(&signed_packet) {
            let addr_info = node_info.into();
            tracing::info!("discovered node info from DHT {:?}", addr_info);
            co.yield_(Ok(DiscoveryItem {
                provenance: "mainline",
                last_updated: None,
                addr_info,
            }))
            .await;
        } else {
            tracing::debug!("failed to parse signed packet as node info");
        }
    }

    async fn gen_resolve(self, node_id: NodeId, co: Co<anyhow::Result<DiscoveryItem>>) {
        let pkarr_public_key =
            pkarr::PublicKey::try_from(node_id.as_bytes()).expect("valid public key");
        tokio::join!(
            self.resolve_dht(pkarr_public_key.clone(), &co),
            self.resolve_relay(pkarr_public_key, &co)
        );
    }
}

impl Discovery for DhtDiscovery {
    fn publish(&self, info: &AddrInfo) {
        let Some(keypair) = &self.0.secret_key else {
            tracing::debug!("no keypair set, not publishing");
            return;
        };
        tracing::debug!("publishing {:?}", info);
        let info = NodeInfo {
            node_id: keypair.public(),
            relay_url: info.relay_url.clone().map(Url::from),
            direct_addresses: if self.0.include_direct_addresses {
                info.direct_addresses.clone()
            } else {
                Default::default()
            },
        };
        let Ok(signed_packet) = info.to_pkarr_signed_packet(keypair, self.0.ttl) else {
            tracing::warn!("failed to create signed packet");
            return;
        };
        let this = self.clone();
        let curr = tokio::spawn(this.publish_loop(keypair.clone(), signed_packet));
        let mut task = self.0.task.lock().unwrap();
        *task = Some(curr.into());
    }

    fn resolve(
        &self,
        _endpoint: Endpoint,
        node_id: NodeId,
    ) -> Option<futures_lite::stream::Boxed<anyhow::Result<DiscoveryItem>>> {
        let this = self.clone();
        let pkarr_public_key =
            pkarr::PublicKey::try_from(node_id.as_bytes()).expect("valid public key");
        tracing::info!("resolving {} as {}", node_id, pkarr_public_key.to_z32());
        Some(Gen::new(|co| async move { this.gen_resolve(node_id, co).await }).boxed())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use iroh_base::node_addr::RelayUrl;
    use mainline::dht::DhtSettings;
    use testresult::TestResult;

    #[tokio::test]
    #[ignore = "flaky"]
    async fn dht_discovery_smoke() -> TestResult {
        let _ = tracing_subscriber::fmt::try_init();
        let ep = crate::Endpoint::builder().bind(0).await?;
        let secret = ep.secret_key().clone();
        let testnet = mainline::dht::Testnet::new(2);
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
        discovery.publish(&AddrInfo {
            relay_url: Some(relay_url.clone()),
            direct_addresses: Default::default(),
        });
        // publish is fire and forget, so we have no way to wait until it is done.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let items = discovery
            .resolve(ep, secret.public())
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        let mut found_relay_urls = BTreeSet::new();
        for item in items.into_iter().flatten() {
            if let Some(url) = item.addr_info.relay_url {
                found_relay_urls.insert(url);
            }
        }
        assert!(found_relay_urls.contains(&relay_url));
        Ok(())
    }
}
