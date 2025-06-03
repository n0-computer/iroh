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

use iroh_base::{NodeId, RelayUrl, SecretKey};
use iroh_relay::node_info::NodeInfo;
use n0_future::{
    boxed::BoxStream,
    task::{self, AbortOnDropHandle},
    time::{self, Duration, Instant},
};
use pkarr::{
    errors::{PublicKeyError, SignedPacketVerifyError},
    SignedPacket,
};
use snafu::{ResultExt, Snafu};
use tracing::{debug, error_span, warn, Instrument};
use url::Url;

use super::{DiscoveryContext, DiscoveryError, IntoDiscovery, IntoDiscoveryError};
#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
use crate::{
    discovery::{Discovery, DiscoveryItem, NodeData, ParsePacketSnafu, SignedPacketSnafu},
    endpoint::force_staging_infra,
    watcher::{self, Disconnected, Watchable, Watcher as _},
};

#[cfg(feature = "discovery-pkarr-dht")]
pub mod dht;

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PkarrError {
    #[snafu(display("Invalid public key"))]
    PublicKey { source: PublicKeyError },
    #[snafu(display("Packet failed to verify"))]
    Verify { source: SignedPacketVerifyError },
    #[snafu(display("Invalid relay URL"))]
    InvalidRelayUrl { url: RelayUrl },
    #[snafu(display("Error sending http request"))]
    HttpSend { source: reqwest::Error },
    #[snafu(display("Error resolving http request"))]
    HttpRequest { status: reqwest::StatusCode },
    #[snafu(display("Http payload error"))]
    HttpPayload { source: reqwest::Error },
}

impl From<PkarrError> for DiscoveryError {
    fn from(err: PkarrError) -> Self {
        DiscoveryError::from_err("pkarr", err)
    }
}

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

/// Builder for [`PkarrPublisher`].
///
/// See [`PkarrPublisher::builder`].
#[derive(Debug)]
pub struct PkarrPublisherBuilder {
    pkarr_relay: Url,
    ttl: u32,
    republish_interval: Duration,
    #[cfg(not(wasm_browser))]
    dns_resolver: Option<DnsResolver>,
}

impl PkarrPublisherBuilder {
    /// See [`PkarrPublisher::builder`].
    fn new(pkarr_relay: Url) -> Self {
        Self {
            pkarr_relay,
            ttl: DEFAULT_PKARR_TTL,
            republish_interval: DEFAULT_REPUBLISH_INTERVAL,
            #[cfg(not(wasm_browser))]
            dns_resolver: None,
        }
    }

    /// See [`PkarrPublisher::n0_dns`].
    fn n0_dns() -> Self {
        let pkarr_relay = match force_staging_infra() {
            true => N0_DNS_PKARR_RELAY_STAGING,
            false => N0_DNS_PKARR_RELAY_PROD,
        };

        let pkarr_relay: Url = pkarr_relay.parse().expect("url is valid");
        Self::new(pkarr_relay)
    }

    /// Sets the TTL (time-to-live) for published packets.
    ///
    /// Default is [`DEFAULT_PKARR_TTL`].
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets the interval after which packets are republished even if our node info did not change.
    ///
    /// Default is [`DEFAULT_REPUBLISH_INTERVAL`].
    pub fn republish_interval(mut self, republish_interval: Duration) -> Self {
        self.republish_interval = republish_interval;
        self
    }

    /// Sets the DNS resolver to use for resolving the pkarr relay URL.
    #[cfg(not(wasm_browser))]
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Builds the [`PkarrPublisher`] with the passed secret key for signing packets.
    ///
    /// This publisher will be able to publish [pkarr] records for [`SecretKey`].
    pub fn build(self, secret_key: SecretKey) -> PkarrPublisher {
        PkarrPublisher::new(
            secret_key,
            self.pkarr_relay,
            self.ttl,
            self.republish_interval,
            #[cfg(not(wasm_browser))]
            self.dns_resolver,
        )
    }
}

impl IntoDiscovery for PkarrPublisherBuilder {
    fn into_discovery(
        mut self,
        context: &DiscoveryContext,
    ) -> Result<impl Discovery, IntoDiscoveryError> {
        #[cfg(not(wasm_browser))]
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(context.dns_resolver().clone());
        }

        Ok(self.build(context.secret_key().clone()))
    }
}

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
    /// Returns a [`PkarrPublisherBuilder`] that publishes node info to a [pkarr] relay at `pkarr_relay`.
    ///
    /// If no further options are set, the pkarr publisher  will use [`DEFAULT_PKARR_TTL`] as the
    /// time-to-live value for the published packets, and it will republish discovery information
    /// every [`DEFAULT_REPUBLISH_INTERVAL`], even if the information is unchanged.
    ///
    /// [`PkarrPublisherBuilder`] implements [`IntoDiscovery`], so it can be passed to [`add_discovery`].
    /// It will then use the endpoint's secret key to sign published packets.
    ///
    /// [`add_discovery`]:  crate::endpoint::Builder::add_discovery
    /// [pkarr]: https://pkarr.org
    pub fn builder(pkarr_relay: Url) -> PkarrPublisherBuilder {
        PkarrPublisherBuilder::new(pkarr_relay)
    }

    /// Creates a new [`PkarrPublisher`] with a custom TTL and republish intervals.
    ///
    /// This allows creating the publisher with custom time-to-live values of the
    /// [`pkarr::SignedPacket`]s and well as a custom republish interval.
    fn new(
        secret_key: SecretKey,
        pkarr_relay: Url,
        ttl: u32,
        republish_interval: Duration,
        #[cfg(not(wasm_browser))] dns_resolver: Option<DnsResolver>,
    ) -> Self {
        debug!("creating pkarr publisher that publishes to {pkarr_relay}");
        let node_id = secret_key.public();

        #[cfg(wasm_browser)]
        let pkarr_client = PkarrRelayClient::new(pkarr_relay);

        #[cfg(not(wasm_browser))]
        let pkarr_client = if let Some(dns_resolver) = dns_resolver {
            PkarrRelayClient::with_dns_resolver(pkarr_relay, dns_resolver)
        } else {
            PkarrRelayClient::new(pkarr_relay)
        };

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
    pub fn n0_dns() -> PkarrPublisherBuilder {
        PkarrPublisherBuilder::n0_dns()
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
    watcher: watcher::Direct<Option<NodeInfo>>,
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

    async fn publish_current(&self, info: NodeInfo) -> Result<(), DiscoveryError> {
        debug!(
            data = ?info.data,
            pkarr_relay = %self.pkarr_client.pkarr_relay_url,
            "Publish node info to pkarr"
        );
        let signed_packet = info
            .to_pkarr_signed_packet(&self.secret_key, self.ttl)
            .context(SignedPacketSnafu)?;
        self.pkarr_client.publish(&signed_packet).await?;
        Ok(())
    }
}

/// Builder for [`PkarrResolver`].
///
/// See [`PkarrResolver::builder`].
#[derive(Debug)]
pub struct PkarrResolverBuilder {
    pkarr_relay: Url,
    #[cfg(not(wasm_browser))]
    dns_resolver: Option<DnsResolver>,
}

impl PkarrResolverBuilder {
    /// Sets the DNS resolver to use for resolving the pkarr relay URL.
    #[cfg(not(wasm_browser))]
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Creates a [`PkarrResolver`] from this builder.
    pub fn build(self) -> PkarrResolver {
        #[cfg(wasm_browser)]
        let pkarr_client = PkarrRelayClient::new(self.pkarr_relay);

        #[cfg(not(wasm_browser))]
        let pkarr_client = if let Some(dns_resolver) = self.dns_resolver {
            PkarrRelayClient::with_dns_resolver(self.pkarr_relay, dns_resolver)
        } else {
            PkarrRelayClient::new(self.pkarr_relay)
        };

        PkarrResolver { pkarr_client }
    }
}

impl IntoDiscovery for PkarrResolverBuilder {
    fn into_discovery(
        mut self,
        context: &DiscoveryContext,
    ) -> Result<impl Discovery, IntoDiscoveryError> {
        #[cfg(not(wasm_browser))]
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(context.dns_resolver().clone());
        }

        Ok(self.build())
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
    /// Creates a new resolver builder using the pkarr relay server at the URL.
    ///
    /// The builder implements [`IntoDiscovery`].
    pub fn builder(pkarr_relay: Url) -> PkarrResolverBuilder {
        PkarrResolverBuilder {
            pkarr_relay,
            #[cfg(not(wasm_browser))]
            dns_resolver: None,
        }
    }

    /// Creates a pkarr resolver builder which uses the [number 0] pkarr relay server.
    ///
    /// This uses the pkarr relay server operated by [number 0] at
    /// [`N0_DNS_PKARR_RELAY_PROD`].
    ///
    /// When running with the environment variable `IROH_FORCE_STAGING_RELAYS`
    /// set to any non empty value [`N0_DNS_PKARR_RELAY_STAGING`]
    /// server is used instead.
    ///
    /// [number 0]: https://n0.computer
    pub fn n0_dns() -> PkarrResolverBuilder {
        let pkarr_relay = match force_staging_infra() {
            true => N0_DNS_PKARR_RELAY_STAGING,
            false => N0_DNS_PKARR_RELAY_PROD,
        };

        let pkarr_relay: Url = pkarr_relay.parse().expect("url is valid");
        Self::builder(pkarr_relay)
    }
}

impl Discovery for PkarrResolver {
    fn resolve(&self, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        let pkarr_client = self.pkarr_client.clone();
        let fut = async move {
            let signed_packet = pkarr_client.resolve(node_id).await?;
            let info =
                NodeInfo::from_pkarr_signed_packet(&signed_packet).context(ParsePacketSnafu)?;
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

    /// Creates a new client while passing a DNS resolver to use.
    #[cfg(not(wasm_browser))]
    pub fn with_dns_resolver(pkarr_relay_url: Url, dns_resolver: crate::dns::DnsResolver) -> Self {
        let http_client = reqwest::Client::builder()
            .dns_resolver(Arc::new(dns_resolver))
            .build()
            .expect("failed to create request client");
        Self {
            http_client,
            pkarr_relay_url,
        }
    }

    /// Resolves a [`SignedPacket`] for the given [`NodeId`].
    pub async fn resolve(&self, node_id: NodeId) -> Result<SignedPacket, DiscoveryError> {
        // We map the error to string, as in browsers the error is !Send
        let public_key = pkarr::PublicKey::try_from(node_id.as_bytes()).context(PublicKeySnafu)?;

        let mut url = self.pkarr_relay_url.clone();
        url.path_segments_mut()
            .map_err(|_| {
                InvalidRelayUrlSnafu {
                    url: self.pkarr_relay_url.clone(),
                }
                .build()
            })?
            .push(&public_key.to_z32());

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .context(HttpSendSnafu)?;

        if !response.status().is_success() {
            return Err(HttpRequestSnafu {
                status: response.status(),
            }
            .build()
            .into());
        }

        let payload = response.bytes().await.context(HttpPayloadSnafu)?;
        // We map the error to string, as in browsers the error is !Send
        let packet =
            SignedPacket::from_relay_payload(&public_key, &payload).context(VerifySnafu)?;
        Ok(packet)
    }

    /// Publishes a [`SignedPacket`].
    pub async fn publish(&self, signed_packet: &SignedPacket) -> Result<(), DiscoveryError> {
        let mut url = self.pkarr_relay_url.clone();
        url.path_segments_mut()
            .map_err(|_| {
                InvalidRelayUrlSnafu {
                    url: self.pkarr_relay_url.clone(),
                }
                .build()
            })?
            .push(&signed_packet.public_key().to_z32());

        let response = self
            .http_client
            .put(url)
            .body(signed_packet.to_relay_payload())
            .send()
            .await
            .context(HttpSendSnafu)?;

        if !response.status().is_success() {
            return Err(HttpRequestSnafu {
                status: response.status(),
            }
            .build()
            .into());
        }

        Ok(())
    }
}
