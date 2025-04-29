//! A discovery service which publishes and resolves node information using a [pkarr] relay.
//!
//! Public-Key Addressable Resource Records, [pkarr], is a system which allows publishing
//! [DNS Resource Records] owned by a particular [`SecretKey`] under a name derived from its
//! corresponding [`PublicKey`], also known as the [`NodeId`].  Additionally this pkarr
//! Resource Record is signed using the same [`SecretKey`], ensuring authenticity of the
//! record.
//!
//! Pkarr normally stores these records on the [Mainline DHT], but also provides two bridges
//! that do not require clients to directly interact with the DHT:
//!
//! - Resolvers are servers which expose the pkarr Resource Record under a domain name,
//!   e.g. `o3dks..6uyy.dns.iroh.link`.  This allows looking up the pkarr Resource Records
//!   using normal DNS clients.  These resolvers would normally perform lookups on the
//!   Mainline DHT augmented with a local cache to improve performance.
//!
//! - Relays are servers which allow both publishing and looking up of the pkarr Resource
//!   Records using HTTP PUT and GET requests.  They will usually perform the publishing to
//!   the Mainline DHT on behalf on the client as well as cache lookups performed on the DHT
//!   to improve performance.
//!
//! For node discovery in iroh the pkarr Resource Records contain the addressing information,
//! providing nodes which retrieve the pkarr Resource Record with enough detail
//! to contact the iroh node.
//!
//! There are several node discovery services built on top of pkarr, which can be composed
//! to the application's needs:
//!
//! - [`PkarrPublisher`], which publishes to a pkarr relay server using HTTP.
//!
//! - [`PkarrResolver`], which resolves from a pkarr relay server using HTTP.
//!
//! - [`DnsDiscovery`], which resolves from a DNS server.
//!
//! - [`DhtDiscovery`], which resolves and publishes from both pkarr relay servers and well
//!   as the Mainline DHT.
//!
//! [pkarr]: https://pkarr.org
//! [DNS Resource Records]: https://en.wikipedia.org/wiki/Domain_Name_System#Resource_records
//! [Mainline DHT]: https://en.wikipedia.org/wiki/Mainline_DHT
//! [`SecretKey`]: crate::SecretKey
//! [`PublicKey`]: crate::PublicKey
//! [`NodeId`]: crate::NodeId
//! [`DnsDiscovery`]: crate::discovery::dns::DnsDiscovery
//! [`DhtDiscovery`]: dht::DhtDiscovery

use std::sync::Arc;

use anyhow::{anyhow, bail};
use iroh_base::{NodeId, SecretKey};
use iroh_relay::node_info::NodeInfo;
use n0_future::{
    boxed::BoxStream,
    task::{self, AbortOnDropHandle},
    time::{self, Duration, Instant},
};
use pkarr::SignedPacket;
use tracing::{debug, error_span, warn, Instrument};
use url::Url;

use crate::{
    discovery::{Discovery, DiscoveryItem, NodeData},
    endpoint::force_staging_infra,
    watchable::{Disconnected, Watchable, Watcher},
    Endpoint,
};

#[cfg(feature = "discovery-pkarr-dht")]
pub mod dht;

/// The production pkarr relay run by [number 0].
///
/// This server is both a pkarr relay server as well as a DNS resolver, see the [module
/// documentation].  However it does not interact with the Mainline DHT, so is a more
/// central service.  It is a reliable service to use for node discovery.
///
/// [number 0]: https://n0.computer
/// [module documentation]: crate::discovery::pkarr
pub const N0_DNS_PKARR_RELAY_PROD: &str = "https://dns.iroh.link/pkarr";
/// The testing pkarr relay run by [number 0].
///
/// This server operates similarly to [`N0_DNS_PKARR_RELAY_PROD`] but is not as reliable.
/// It is meant for more experimental use and testing purposes.
///
/// [number 0]: https://n0.computer
pub const N0_DNS_PKARR_RELAY_STAGING: &str = "https://staging-dns.iroh.link/pkarr";

/// Default TTL for the records in the pkarr signed packet.
///
/// The Time To Live (TTL) tells DNS caches how long to store a record. It is ignored by the
/// `iroh-dns-server`, e.g. as running on [`N0_DNS_PKARR_RELAY_PROD`], as the home server
/// keeps the records for the domain. When using the pkarr relay no DNS is involved and the
/// setting is ignored.
// TODO(flub): huh?
pub const DEFAULT_PKARR_TTL: u32 = 30;

/// Interval in which to republish the node info even if unchanged: 5 minutes.
pub const DEFAULT_REPUBLISH_INTERVAL: Duration = Duration::from_secs(60 * 5);

/// Publisher of node discovery information to a [pkarr] relay.
///
/// This publisher uses HTTP to publish node discovery information to a pkarr relay
/// server, see the [module docs] for details.
///
/// This implements the [`Discovery`] trait to be used as a node discovery service.  Note
/// that it only publishes node discovery information, for the corresponding resolver use
/// the [`PkarrResolver`] together with [`ConcurrentDiscovery`].
///
/// This publisher will **only** publish the [`RelayUrl`] if it is set, otherwise the *direct addresses* are published instead.
///
/// [pkarr]: https://pkarr.org
/// [module docs]: crate::discovery::pkarr
/// [`RelayUrl`]: crate::RelayUrl
/// [`ConcurrentDiscovery`]: super::ConcurrentDiscovery
#[derive(derive_more::Debug, Clone)]
pub struct PkarrPublisher {
    node_id: NodeId,
    watchable: Watchable<Option<NodeInfo>>,
    _drop_guard: Arc<AbortOnDropHandle<()>>,
}

impl PkarrPublisher {
    /// Creates a new publisher for the [`SecretKey`].
    ///
    /// This publisher will be able to publish [pkarr] records for [`SecretKey`].  It will
    /// use [`DEFAULT_PKARR_TTL`] as the time-to-live value for the published packets.  Will
    /// republish discovery information every [`DEFAULT_REPUBLISH_INTERVAL`], even if the
    /// information is unchanged.
    ///
    /// [pkarr]: https://pkarr.org
    pub fn new(secret_key: SecretKey, pkarr_relay: Url) -> Self {
        Self::with_options(
            secret_key,
            pkarr_relay,
            DEFAULT_PKARR_TTL,
            DEFAULT_REPUBLISH_INTERVAL,
        )
    }

    /// Creates a new [`PkarrPublisher`] with a custom TTL and republish intervals.
    ///
    /// This allows creating the publisher with custom time-to-live values of the
    /// [`pkarr::SignedPacket`]s and well as a custom republish interval.
    pub fn with_options(
        secret_key: SecretKey,
        pkarr_relay: Url,
        ttl: u32,
        republish_interval: Duration,
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
        let join_handle = task::spawn(
            service
                .run()
                .instrument(error_span!("pkarr_publish", me=%node_id.fmt_short())),
        );
        Self {
            watchable,
            node_id,
            _drop_guard: Arc::new(AbortOnDropHandle::new(join_handle)),
        }
    }

    /// Creates a pkarr publisher which uses the [number 0] pkarr relay server.
    ///
    /// This uses the pkarr relay server operated by [number 0], at
    /// [`N0_DNS_PKARR_RELAY_PROD`].
    ///
    /// When running with the environment variable
    /// `IROH_FORCE_STAGING_RELAYS` set to any non empty value [`N0_DNS_PKARR_RELAY_STAGING`]
    /// server is used instead.
    ///
    /// [number 0]: https://n0.computer
    pub fn n0_dns(secret_key: SecretKey) -> Self {
        let pkarr_relay = match force_staging_infra() {
            true => N0_DNS_PKARR_RELAY_STAGING,
            false => N0_DNS_PKARR_RELAY_PROD,
        };

        let pkarr_relay: Url = pkarr_relay.parse().expect("url is valid");
        Self::new(secret_key, pkarr_relay)
    }

    /// Publishes the addressing information about this node to a pkarr relay.
    ///
    /// This is a nonblocking function, the actual update is performed in the background.
    pub fn update_node_data(&self, data: &NodeData) {
        let mut data = data.clone();
        if data.relay_url().is_some() {
            // If relay url is set: only publish relay url, and no direct addrs.
            data.clear_direct_addresses();
        }
        let info = NodeInfo::from_parts(self.node_id, data);
        self.watchable.set(Some(info)).ok();
    }
}

impl Discovery for PkarrPublisher {
    fn publish(&self, data: &NodeData) {
        self.update_node_data(data);
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
    async fn run(mut self) {
        let mut failed_attempts = 0;
        let republish = time::sleep(Duration::MAX);
        tokio::pin!(republish);
        loop {
            let Ok(info) = self.watcher.get() else {
                break; // disconnected
            };
            if let Some(info) = info {
                if let Err(err) = self.publish_current(info).await {
                    failed_attempts += 1;
                    // Retry after increasing timeout
                    let retry_after = Duration::from_secs(failed_attempts);
                    republish.as_mut().reset(Instant::now() + retry_after);
                    warn!(
                        err = %format!("{err:#}"),
                        url = %self.pkarr_client.pkarr_relay_url ,
                        ?retry_after,
                        %failed_attempts,
                        "Failed to publish to pkarr",
                    );
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
                res = self.watcher.updated() => match res {
                    Ok(_) => debug!("Publish node info to pkarr (info changed)"),
                    Err(Disconnected { .. }) => break,
                },
                _ = &mut republish => debug!("Publish node info to pkarr (interval elapsed)"),
            }
        }
    }

    async fn publish_current(&self, info: NodeInfo) -> anyhow::Result<()> {
        debug!(
            data = ?info.data,
            pkarr_relay = %self.pkarr_client.pkarr_relay_url,
            "Publish node info to pkarr"
        );
        let signed_packet = info.to_pkarr_signed_packet(&self.secret_key, self.ttl)?;
        self.pkarr_client.publish(&signed_packet).await?;
        Ok(())
    }
}

/// Resolver of node discovery information from a [pkarr] relay.
///
/// The resolver uses HTTP to query node discovery information from a pkarr relay server,
/// see the [module docs] for details.
///
/// This implements the [`Discovery`] trait to be used as a node discovery service.  Note
/// that it only resolves node discovery information, for the corresponding publisher use
/// the [`PkarrPublisher`] together with [`ConcurrentDiscovery`].
///
/// [pkarr]: https://pkarr.org
/// [module docs]: crate::discovery::pkarr
/// [`ConcurrentDiscovery`]: super::ConcurrentDiscovery
#[derive(derive_more::Debug, Clone)]
pub struct PkarrResolver {
    pkarr_client: PkarrRelayClient,
}

impl PkarrResolver {
    /// Creates a new publisher using the pkarr relay server at the URL.
    pub fn new(pkarr_relay: Url) -> Self {
        Self {
            pkarr_client: PkarrRelayClient::new(pkarr_relay),
        }
    }

    /// Creates a pkarr resolver which uses the [number 0] pkarr relay server.
    ///
    /// This uses the pkarr relay server operated by [number 0] at
    /// [`N0_DNS_PKARR_RELAY_PROD`].
    ///
    /// When running with the environment variable `IROH_FORCE_STAGING_RELAYS`
    /// set to any non empty value [`N0_DNS_PKARR_RELAY_STAGING`]
    /// server is used instead.
    ///
    /// [number 0]: https://n0.computer
    pub fn n0_dns() -> Self {
        let pkarr_relay = match force_staging_infra() {
            true => N0_DNS_PKARR_RELAY_STAGING,
            false => N0_DNS_PKARR_RELAY_PROD,
        };

        let pkarr_relay: Url = pkarr_relay.parse().expect("url is valid");
        Self::new(pkarr_relay)
    }
}

impl Discovery for PkarrResolver {
    fn resolve(
        &self,
        _ep: Endpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<anyhow::Result<DiscoveryItem>>> {
        let pkarr_client = self.pkarr_client.clone();
        let fut = async move {
            let signed_packet = pkarr_client.resolve(node_id).await?;
            let info = NodeInfo::from_pkarr_signed_packet(&signed_packet)?;
            let item = DiscoveryItem::new(info, "pkarr", None);
            Ok(item)
        };
        let stream = n0_future::stream::once_future(fut);
        Some(Box::pin(stream))
    }
}

/// A [pkarr] client to publish [`pkarr::SignedPacket`]s to a pkarr relay.
///
/// [pkarr]: https://pkarr.org
#[derive(Debug, Clone)]
pub struct PkarrRelayClient {
    http_client: reqwest::Client,
    pkarr_relay_url: Url,
}

impl PkarrRelayClient {
    /// Creates a new client.
    pub fn new(pkarr_relay_url: Url) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            pkarr_relay_url,
        }
    }

    /// Resolves a [`SignedPacket`] for the given [`NodeId`].
    pub async fn resolve(&self, node_id: NodeId) -> anyhow::Result<SignedPacket> {
        // We map the error to string, as in browsers the error is !Send
        let public_key = pkarr::PublicKey::try_from(node_id.as_bytes())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
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
        // We map the error to string, as in browsers the error is !Send
        SignedPacket::from_relay_payload(&public_key, &payload)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    /// Publishes a [`SignedPacket`].
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
