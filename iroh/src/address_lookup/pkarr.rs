//! An address lookup service which publishes and resolves endpoint information using a [pkarr] relay.
//!
//! Public-Key Addressable Resource Records, [pkarr], is a system which allows publishing
//! [DNS Resource Records] owned by a particular [`SecretKey`] under a name derived from its
//! corresponding [`PublicKey`], also known as the [`EndpointId`].  Additionally this pkarr
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
//! For address lookup in iroh the pkarr Resource Records contain the addressing information,
//! providing endpoints which retrieve the pkarr Resource Record with enough detail
//! to contact the iroh endpoint.
//!
//! There are several Address Lookup's built on top of pkarr, which can be composed
//! to the application's needs:
//!
//! - [`PkarrPublisher`], which publishes to a pkarr relay server using HTTP.
//!
//! - [`PkarrResolver`], which resolves from a pkarr relay server using HTTP.
//!
//! - [`address_lookup::DnsAddressLookup`], which resolves from a DNS server.
//!
//! - [`address_lookup::DhtAddressLookup`], which resolves and publishes from both pkarr relay servers and well
//!   as the Mainline DHT.
//!
//! [pkarr]: https://pkarr.org
//! [DNS Resource Records]: https://en.wikipedia.org/wiki/Domain_Name_System#Resource_records
//! [Mainline DHT]: https://en.wikipedia.org/wiki/Mainline_DHT
//! [`SecretKey`]: crate::SecretKey
//! [`PublicKey`]: crate::PublicKey
//! [`EndpointId`]: crate::EndpointId
//! [`address_lookup::DnsAddressLookup`]: crate::address_lookup::DnsAddressLookup
//! [`address_lookup::DhtAddressLookup`]: crate::address_lookup::DhtAddressLookup

use std::sync::Arc;

use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_relay::endpoint_info::{EncodingError, EndpointInfo};
use n0_error::{e, stack_error};
use n0_future::{
    boxed::BoxStream,
    task::{self, AbortOnDropHandle},
    time::{self, Duration, Instant},
};
use n0_watcher::{Disconnected, Watchable, Watcher as _};
use pkarr::{
    SignedPacket,
    errors::{PublicKeyError, SignedPacketVerifyError},
};
use tracing::{Instrument, debug, error_span, warn};
use url::Url;

#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
use crate::{
    Endpoint,
    address_lookup::{
        AddressLookup, EndpointData, Error as AddressLookupError, IntoAddressLookup,
        IntoAddressLookupError, Item as AddressLookupItem,
    },
    endpoint::force_staging_infra,
    util::reqwest_client_builder,
};

#[cfg(feature = "address-lookup-pkarr-dht")]
pub mod dht;

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum PkarrError {
    #[error("Invalid public key")]
    PublicKey {
        #[error(std_err)]
        source: PublicKeyError,
    },
    #[error("Packet failed to verify")]
    Verify {
        #[error(std_err)]
        source: SignedPacketVerifyError,
    },
    #[error("Invalid relay URL")]
    InvalidRelayUrl { url: RelayUrl },
    #[error("Error sending http request")]
    HttpSend {
        #[error(std_err)]
        source: reqwest::Error,
    },
    #[error("Error resolving http request")]
    HttpRequest { status: reqwest::StatusCode },
    #[error("Http payload error")]
    HttpPayload {
        #[error(std_err)]
        source: reqwest::Error,
    },
    #[error("EncodingError")]
    Encoding { source: EncodingError },
}

impl From<PkarrError> for AddressLookupError {
    fn from(err: PkarrError) -> Self {
        AddressLookupError::from_err_any("pkarr", err)
    }
}

/// The production pkarr relay run by [number 0].
///
/// This server is both a pkarr relay server as well as a DNS resolver, see the [module
/// documentation].  However it does not interact with the Mainline DHT, so is a more
/// central service.  It is a reliable service to use for address lookup.
///
/// [number 0]: https://n0.computer
/// [module documentation]: crate::address_lookup::pkarr
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

/// Interval in which to republish the endpoint info even if unchanged: 5 minutes.
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

    /// Sets the interval after which packets are republished even if our endpoint info did not change.
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

impl IntoAddressLookup for PkarrPublisherBuilder {
    fn into_address_lookup(
        mut self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, IntoAddressLookupError> {
        #[cfg(not(wasm_browser))]
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(endpoint.dns_resolver().clone());
        }

        Ok(self.build(endpoint.secret_key().clone()))
    }
}

/// Publisher of address lookup information to a [pkarr] relay.
///
/// This publisher uses HTTP to publish address lookup information to a pkarr relay
/// server, see the [module docs] for details.
///
/// This implements the [`AddressLookup`] trait to be used as an address lookup service.  Note
/// that it only publishes address lookup information, for the corresponding resolver use
/// the [`PkarrResolver`] together with [`ConcurrentAddressLookup`].
///
/// This publisher will **only** publish the [`RelayUrl`] if it is set, otherwise the *direct addresses* are published instead.
///
/// [pkarr]: https://pkarr.org
/// [module docs]: crate::address_lookup::pkarr
/// [`RelayUrl`]: crate::RelayUrl
/// [`ConcurrentAddressLookup`]: super::ConcurrentAddressLookup
#[derive(derive_more::Debug, Clone)]
pub struct PkarrPublisher {
    endpoint_id: EndpointId,
    watchable: Watchable<Option<EndpointInfo>>,
    _drop_guard: Arc<AbortOnDropHandle<()>>,
}

impl PkarrPublisher {
    /// Returns a [`PkarrPublisherBuilder`] that publishes endpoint info to a [pkarr] relay at `pkarr_relay`.
    ///
    /// If no further options are set, the pkarr publisher  will use [`DEFAULT_PKARR_TTL`] as the
    /// time-to-live value for the published packets, and it will republish Address Lookup information
    /// every [`DEFAULT_REPUBLISH_INTERVAL`], even if the information is unchanged.
    ///
    /// [`PkarrPublisherBuilder`] implements [`IntoAddressLookup`], so it can be passed to [`address_lookup`].
    /// It will then use the endpoint's secret key to sign published packets.
    ///
    /// [`address_lookup`]:  crate::endpoint::Builder::address_lookup
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
        let endpoint_id = secret_key.public();

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
                .instrument(error_span!("pkarr_publish", me=%endpoint_id.fmt_short())),
        );
        Self {
            watchable,
            endpoint_id,
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

    /// Publishes the addressing information about this endpoint to a pkarr relay.
    ///
    /// This is a nonblocking function, the actual update is performed in the background.
    pub fn update_endpoint_data(&self, data: &EndpointData) {
        let mut data = data.clone();
        if data.relay_urls().next().is_some() {
            // If relay url is set: only publish relay url, and no  addrs.
            data.clear_ip_addrs();
        }
        let info = EndpointInfo::from_parts(self.endpoint_id, data);
        self.watchable.set(Some(info)).ok();
    }
}

impl AddressLookup for PkarrPublisher {
    fn publish(&self, data: &EndpointData) {
        self.update_endpoint_data(data);
    }
}

/// Publish endpoint info to a pkarr relay.
#[derive(derive_more::Debug, Clone)]
struct PublisherService {
    #[debug("SecretKey")]
    secret_key: SecretKey,
    #[debug("PkarrClient")]
    pkarr_client: PkarrRelayClient,
    watcher: n0_watcher::Direct<Option<EndpointInfo>>,
    ttl: u32,
    republish_interval: Duration,
}

impl PublisherService {
    async fn run(mut self) {
        let mut failed_attempts = 0;
        let republish = time::sleep(Duration::MAX);
        tokio::pin!(republish);
        loop {
            if !self.watcher.is_connected() {
                break;
            }
            if let Some(info) = self.watcher.get() {
                match self.publish_current(info).await {
                    Err(err) => {
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
                    }
                    _ => {
                        failed_attempts = 0;
                        // Republish after fixed interval
                        republish
                            .as_mut()
                            .reset(Instant::now() + self.republish_interval);
                    }
                }
            }
            // Wait until either the retry/republish timeout is reached, or the endpoint info changed.
            tokio::select! {
                res = self.watcher.updated() => match res {
                    Ok(_) => debug!("Publish endpoint info to pkarr (info changed)"),
                    Err(Disconnected { .. }) => break,
                },
                _ = &mut republish => debug!("Publish endpoint info to pkarr (interval elapsed)"),
            }
        }
    }

    async fn publish_current(&self, info: EndpointInfo) -> Result<(), PkarrError> {
        debug!(
            data = ?info.data,
            pkarr_relay = %self.pkarr_client.pkarr_relay_url,
            "Publish endpoint info to pkarr"
        );
        let signed_packet = info
            .to_pkarr_signed_packet(&self.secret_key, self.ttl)
            .map_err(|err| e!(PkarrError::Encoding, err))?;
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

impl IntoAddressLookup for PkarrResolverBuilder {
    fn into_address_lookup(
        mut self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, IntoAddressLookupError> {
        #[cfg(not(wasm_browser))]
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(endpoint.dns_resolver().clone());
        }

        Ok(self.build())
    }
}

/// Resolver of address lookup information from a [pkarr] relay.
///
/// The resolver uses HTTP to query address lookup information from a pkarr relay server,
/// see the [module docs] for details.
///
/// This implements the [`AddressLookup`] trait to be used as an address lookup service.  Note
/// that it only resolves address lookup information, for the corresponding publisher use
/// the [`PkarrPublisher`] together with [`ConcurrentAddressLookup`].
///
/// [pkarr]: https://pkarr.org
/// [module docs]: crate::address_lookup::pkarr
/// [`ConcurrentAddressLookup`]: super::ConcurrentAddressLookup
#[derive(derive_more::Debug, Clone)]
pub struct PkarrResolver {
    pkarr_client: PkarrRelayClient,
}

impl PkarrResolver {
    /// Creates a new resolver builder using the pkarr relay server at the URL.
    ///
    /// The builder implements [`IntoAddressLookup`].
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

impl AddressLookup for PkarrResolver {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        let pkarr_client = self.pkarr_client.clone();
        let fut = async move {
            let signed_packet = pkarr_client.resolve(endpoint_id).await?;
            let info = EndpointInfo::from_pkarr_signed_packet(&signed_packet)
                .map_err(|err| AddressLookupError::from_err_any("pkarr", err))?;
            let item = AddressLookupItem::new(info, "pkarr", None);
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
            http_client: reqwest_client_builder()
                .build()
                .expect("failed to create reqwest client"),
            pkarr_relay_url,
        }
    }

    /// Creates a new client while passing a DNS resolver to use.
    #[cfg(not(wasm_browser))]
    pub fn with_dns_resolver(pkarr_relay_url: Url, dns_resolver: crate::dns::DnsResolver) -> Self {
        let http_client = reqwest_client_builder()
            .dns_resolver(Arc::new(dns_resolver))
            .build()
            .expect("failed to create request client");
        Self {
            http_client,
            pkarr_relay_url,
        }
    }

    /// Resolves a [`SignedPacket`] for the given [`EndpointId`].
    pub async fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<SignedPacket, AddressLookupError> {
        // We map the error to string, as in browsers the error is !Send
        let public_key = pkarr::PublicKey::try_from(endpoint_id.as_bytes())
            .map_err(|err| e!(PkarrError::PublicKey, err))?;

        let mut url = self.pkarr_relay_url.clone();
        url.path_segments_mut()
            .map_err(|_| {
                e!(PkarrError::InvalidRelayUrl {
                    url: self.pkarr_relay_url.clone().into()
                })
            })?
            .push(&public_key.to_z32());

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|err| e!(PkarrError::HttpSend, err))?;

        if !response.status().is_success() {
            return Err(e!(PkarrError::HttpRequest {
                status: response.status()
            })
            .into());
        }

        let payload = response
            .bytes()
            .await
            .map_err(|source| e!(PkarrError::HttpPayload { source }))?;
        // We map the error to string, as in browsers the error is !Send
        let packet = SignedPacket::from_relay_payload(&public_key, &payload)
            .map_err(|err| e!(PkarrError::Verify, err))?;
        Ok(packet)
    }

    /// Publishes a [`SignedPacket`].
    pub async fn publish(&self, signed_packet: &SignedPacket) -> Result<(), PkarrError> {
        let mut url = self.pkarr_relay_url.clone();
        url.path_segments_mut()
            .map_err(|_| {
                e!(PkarrError::InvalidRelayUrl {
                    url: self.pkarr_relay_url.clone().into()
                })
            })?
            .push(&signed_packet.public_key().to_z32());

        let response = self
            .http_client
            .put(url)
            .body(signed_packet.to_relay_payload())
            .send()
            .await
            .map_err(|source| e!(PkarrError::HttpSend { source }))?;

        if !response.status().is_success() {
            return Err(e!(PkarrError::HttpRequest {
                status: response.status()
            }));
        }

        Ok(())
    }
}
