//! Lookup the address of an Endpoint ID.
//!
//! To connect to an iroh endpoint a [`EndpointAddr`] is needed, which may contain a
//! [`RelayUrl`] or one or more *direct addresses* in addition to the [`EndpointId`].
//!
//! Since there is a conversion from [`EndpointId`] to [`EndpointAddr`], you can also use
//! connect directly with a [`EndpointId`].
//!
//! For this to work however, the endpoint has to get the addressing  information by
//! other means.
//!
//! [`AddressLookup`] is an automated system for an [`Endpoint`] to retrieve this addressing
//! information.  Each iroh endpoint will automatically publish their own addressing
//! information.  Usually this means publishing which [`RelayUrl`] to use for their
//! [`EndpointId`], but they could also publish their direct addresses.
//!
//! The [`AddressLookup`] trait is used to define an address lookup system.  This allows multiple
//! implementations to co-exist because there are many possible ways to implement this.
//! Each [`Endpoint`] can use the address lookup mechanisms most suitable to the application.
//! The [`Builder::address_lookup`] method is used to add an address lookup mechanism to an
//! [`Endpoint`].
//!
//! Each address lookup service receives the full set of transport addresses when publishing,
//! but may only publish a subset of them based on its own constraints.
//!
//! To control which addresses are published to a particular service, you can supply an
//! [`AddrFilter`] on its builder (e.g. [`PkarrPublisherBuilder::addr_filter`]).  The filter
//! receives the full set of addresses and returns an ordered [`Vec`], allowing you to both
//! remove addresses you don't want published and prioritize the ones you do. Each service
//! may apply additional filtering on top based on its own constraints, but will not publish
//! addresses outside of what the filter returns.  See each service's documentation for details.
//!
//! Some generally useful Address Lookup implementations are provided:
//!
//! - [`MemoryLookup`] which allows application to add and remove out-of-band addressing
//!   information.
//!
//! - The [`address_lookup::DnsAddressLookup`] which performs lookups via the standard DNS systems.  To publish
//!   to this DNS server a [`PkarrPublisher`] is needed.  [Number 0] runs a public instance
//!   of a [`PkarrPublisher`] with attached DNS server which is globally available and a
//!   reliable default choice.
//!
//! - The [`PkarrResolver`] which can perform lookups from designated [pkarr relay servers]
//!   using HTTP.
//!
//! - [`address_lookup::MdnsAddressLookup`]: mdns::MdnsAddressLookup which uses the crate `swarm-discovery`, an
//!   opinionated mDNS implementation, to discover endpoints on the local network.
//!
//! - The [`address_lookup::DhtAddressLookup`] also uses the [`pkarr`] system but can also publish and lookup
//!   records to/from the Mainline DHT. It requires enabling the `address-lookup-pkarr-dht` feature.
//!
//! To use multiple Address Lookup'ssimultaneously you can call [`Builder::address_lookup`].
//! This will use [`ConcurrentAddressLookup`] under the hood, which performs lookups to all
//! Address Lookupsystems at the same time.
//!
//! [`Builder::address_lookup`] takes any type that implements [`AddressLookupBuilder`]. You can
//! implement that trait on a builder struct if your Address Lookup needs information
//! from the endpoint it is mounted on. After endpoint construction, your Address Lookup
//! is built by calling [`AddressLookupBuilder::into_address_lookup`], passing the finished [`Endpoint`] to your
//! builder.
//!
//! If your Address Lookupdoes not need any information from its endpoint, you can
//! pass the Address Lookupservice directly to [`Builder::address_lookup`]: All types that
//! implement [`AddressLookup`] also have a blanket implementation of [`AddressLookupBuilder`].
//!
//! # Examples
//!
//! A very common setup is to enable DNS Address Lookup, which needs to be done in two parts as a
//! [`PkarrPublisher`] and [`address_lookup::DnsAddressLookup`]:
//!
//! ```no_run
//! # #[cfg(with_crypto_provider)]
//! # {
//! use iroh::{
//!     Endpoint, SecretKey,
//!     address_lookup::{self, AddrFilter, PkarrPublisher},
//!     endpoint::{RelayMode, presets},
//! };
//!
//! # async fn wrapper() -> n0_error::Result<()> {
//! let ep = Endpoint::builder(presets::Minimal)
//!     .addr_filter(AddrFilter::relay_only())
//!     .address_lookup(PkarrPublisher::n0_dns())
//!     .address_lookup(address_lookup::DnsAddressLookup::n0_dns())
//!     .bind()
//!     .await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! To also enable [`address_lookup::MdnsAddressLookup`] it can be added as another service.
//!
//! ```no_run
//! #[cfg(feature = "address-lookup-mdns")]
//! # {
//! # use iroh::{
//! #    address_lookup::{self, AddrFilter, PkarrPublisher},
//! #    endpoint::{presets, RelayMode},
//! #    Endpoint, SecretKey,
//! # };
//! #
//! # async fn wrapper() -> n0_error::Result<()> {
//! let ep = Endpoint::builder(presets::Minimal)
//!     .relay_mode(RelayMode::Default)
//!     .addr_filter(AddrFilter::relay_only())
//!     .address_lookup(PkarrPublisher::n0_dns())
//!     .address_lookup(address_lookup::DnsAddressLookup::n0_dns())
//!     .address_lookup(address_lookup::MdnsAddressLookup::builder())
//!     .bind()
//!     .await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! [`EndpointAddr`]: iroh_base::EndpointAddr
//! [`RelayUrl`]: crate::RelayUrl
//! [`Builder::address_lookup`]: crate::endpoint::Builder::address_lookup
//! [`address_lookup::DnsAddressLookup`]: crate::address_lookup::DnsAddressLookup
//! [Number 0]: https://n0.computer
//! [`PkarrResolver`]: pkarr::PkarrResolver
//! [`PkarrPublisher`]: pkarr::PkarrPublisher
//! [`PkarrPublisherBuilder::addr_filter`]: pkarr::PkarrPublisherBuilder::addr_filter
//! [`address_lookup::DhtAddressLookup`]: crate::address_lookup::DhtAddressLookup
//! [pkarr relay servers]: https://pkarr.org/#servers
//! [`address_lookup::MdnsAddressLookup`]: crate::address_lookup::MdnsAddressLookup
//! [`MemoryLookup`]: memory::MemoryLookup

use std::{
    borrow::{Borrow, Cow},
    sync::{Arc, RwLock},
};

use iroh_base::{EndpointAddr, EndpointId};
pub use iroh_relay::endpoint_info::AddrFilter;
use n0_error::{AnyError, e, stack_error};
use n0_future::boxed::BoxStream;

pub use crate::endpoint_info::{EndpointData, EndpointInfo, ParseError, UserData};
use crate::{Endpoint, endpoint::EndpointError};

#[cfg(not(wasm_browser))]
pub mod dns;
#[cfg(feature = "address-lookup-mdns")]
pub mod mdns;
pub mod memory;
pub mod pkarr;

#[cfg(not(wasm_browser))]
pub use dns::*;
#[cfg(feature = "address-lookup-mdns")]
pub use mdns::*;
pub use memory::*;
#[cfg(feature = "address-lookup-pkarr-dht")]
pub use pkarr::dht::*;
pub use pkarr::*;

/// Trait for structs that can be converted into [`AddressLookup`]s.
///
/// This trait is implemented on builders for Address Lookup's. Any type that implements this
/// trait can be added as a Address Lookup in [`Builder::address_lookup`].
///
/// Any type that implements [`AddressLookup`] also implements [`AddressLookupBuilder`].
///
/// Iroh uses this trait to allow configuring the set of address lookup services on
/// the endpoint builder, while also providing them access to information about the
/// endpoint to [`AddressLookupBuilder::into_address_lookup`].
///
/// [`Builder::address_lookup`]: crate::endpoint::Builder::address_lookup
pub trait AddressLookupBuilder: Send + Sync + std::fmt::Debug + 'static {
    /// Turns this builder into a ready-to-use [`AddressLookup`].
    ///
    /// If an error is returned, building the endpoint will fail with this error.
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError>;
}

/// An [`AddressLookup`] wrapper that filters addresses before publishing.
#[derive(Debug, Clone)]
pub struct FilteredAddressLookup<T> {
    inner: T,
    filter: AddrFilter,
}

impl<T> FilteredAddressLookup<T> {
    /// Wraps an address lookup with an address filter.
    ///
    /// The filter allows to specify which addresses the address
    /// lookup service will publish.
    pub fn new(inner: T, filter: AddrFilter) -> Self {
        Self { inner, filter }
    }

    /// Removes the filter wrapper and returns the inner address lookup.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> AsRef<T> for FilteredAddressLookup<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: AddressLookup> AddressLookup for FilteredAddressLookup<T> {
    fn publish(&self, data: &EndpointData) {
        let data = data.apply_filter(&self.filter);
        self.inner.publish(data.borrow());
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        self.inner.resolve(endpoint_id)
    }
}

/// Blanket no-op impl of `AddressLookupBuilder` for `T: AddressLookup`.
impl<T: AddressLookup> AddressLookupBuilder for T {
    fn into_address_lookup(
        self,
        _endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        Ok(self)
    }
}

/// Non-public dyn-compatible version of [`AddressLookupBuilder`], used in [`crate::endpoint::Builder`].
pub(crate) trait DynAddressLookupBuilder: Send + Sync + std::fmt::Debug + 'static {
    /// See [`AddressLookupBuilder::into_address_lookup`]
    fn into_address_lookup(
        self: Box<Self>,
        endpoint: &Endpoint,
    ) -> Result<Box<dyn AddressLookup>, AddressLookupBuilderError>;
}

impl<T: AddressLookupBuilder> DynAddressLookupBuilder for T {
    fn into_address_lookup(
        self: Box<Self>,
        endpoint: &Endpoint,
    ) -> Result<Box<dyn AddressLookup>, AddressLookupBuilderError> {
        let addr_lookup: Box<dyn AddressLookup> =
            Box::new(AddressLookupBuilder::into_address_lookup(*self, endpoint)?);
        Ok(addr_lookup)
    }
}

/// [`AddressLookupBuilder`] errors
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub enum AddressLookupBuilderError {
    #[error("Service '{provenance}' error")]
    User {
        provenance: &'static str,
        source: AnyError,
    },
    #[error(transparent)]
    EndpointClosed { source: EndpointError },
}

impl AddressLookupBuilderError {
    /// Creates a new user error from an arbitrary error type.
    pub fn from_err<T: std::error::Error + Send + Sync + 'static>(
        provenance: &'static str,
        source: T,
    ) -> Self {
        e!(AddressLookupBuilderError::User {
            provenance,
            source: AnyError::from_std(source)
        })
    }

    /// Creates a new user error from an arbitrary boxed error type.
    pub fn from_err_box(
        provenance: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        e!(AddressLookupBuilderError::User {
            provenance,
            source: AnyError::from_std_box(source)
        })
    }
}

/// [`AddressLookup`] errors
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
#[derive(Clone)]
pub enum Error {
    #[error("No address lookup configured")]
    NoServiceConfigured,
    #[error("Address lookup produced no results")]
    NoResults,
    #[error("Service '{provenance}' error")]
    User {
        provenance: &'static str,
        source: Arc<AnyError>,
    },
}

impl Error {
    /// Creates a new user error from an arbitrary error type.
    #[track_caller]
    pub fn from_err<T: std::error::Error + Send + Sync + 'static>(
        provenance: &'static str,
        source: T,
    ) -> Self {
        Self::from_err_any(provenance, AnyError::from_std(source))
    }

    /// Creates a new user error from an arbitrary boxed error type.
    #[track_caller]
    pub fn from_err_box(
        provenance: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Self::from_err_any(provenance, AnyError::from_std_box(source))
    }

    /// Creates a new user error from an arbitrary error type that can be converted into [`AnyError`].
    #[track_caller]
    pub fn from_err_any(provenance: &'static str, source: impl Into<AnyError>) -> Self {
        e!(Error::User {
            provenance,
            source: Arc::new(source.into())
        })
    }
}

/// AddressLookup system for [`super::Endpoint`].
///
/// This trait defines publishing and resolving addressing information for a [`EndpointId`].
/// This enables connecting to other endpoints with only knowing the [`EndpointId`], by using this
/// [`AddressLookup`] system to look up the actual addressing information.  It is common for
/// implementations to require each endpoint to publish their own information before it can be
/// looked up by other endpoints.
///
/// The published addressing information can include both a [`RelayUrl`] and/or direct
/// addresses. See [`EndpointData`] for details.
///
/// To allow for Address Lookup, the [`super::Endpoint`] will call `publish` whenever
/// Address Lookup information changes. If an Address Lookup mechanism requires a periodic
/// refresh, it should start its own task.
///
/// [`RelayUrl`]: crate::RelayUrl
pub trait AddressLookup: std::fmt::Debug + Send + Sync + 'static {
    /// Publishes the given [`EndpointData`] to the Address Lookup mechanism.
    ///
    /// This is fire and forget, since the [`Endpoint`] can not wait for successful
    /// publishing. If publishing is async, the implementation should start it's own task.
    ///
    /// This will be called from a tokio task, so it is safe to spawn new tasks.
    /// These tasks will be run on the runtime of the [`super::Endpoint`].
    fn publish(&self, _data: &EndpointData) {}

    /// Resolves the [`Item`] for the given [`EndpointId`].
    ///
    /// Once the returned [`BoxStream`] is dropped, the service should stop any pending
    /// work.
    fn resolve(&self, _endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        None
    }
}

impl<T: AddressLookup> AddressLookup for Arc<T> {
    fn publish(&self, data: &EndpointData) {
        self.as_ref().publish(data);
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        self.as_ref().resolve(endpoint_id)
    }
}

/// Address lookup results from [`AddressLookup`]s.
///
/// This is the item in the streams returned from [`AddressLookup::resolve`].
/// It contains the [`EndpointData`] about the resolved endpoint addresses,
/// and some additional metadata about the address lookup system.
///
/// This struct derefs to [`EndpointData`], so you can access the methods from [`EndpointData`]
/// directly from [`Item`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Item {
    /// The endpoint info for the endpoint, as discovered by the the Address Lookup.
    endpoint_info: EndpointInfo,
    /// A static string to identify the Address Lookup source.
    ///
    /// Should be uniform per Address Lookup.
    provenance: &'static str,
    /// Optional timestamp when this endpoint address info was last updated.
    ///
    /// Must be microseconds since the unix epoch.
    // TODO(ramfox): this is currently unused. As we develop more `AddressLookup`s, we may discover that we do not need this. It is only truly relevant when comparing `relay_urls`, since we can attempt to dial any number of socket addresses, but expect each endpoint to have one "home relay" that we will attempt to contact them on. This means we would need some way to determine which relay url to choose between, if more than one relay url is reported.
    last_updated: Option<u64>,
}

impl Item {
    /// Creates a new [`Item`] from a [`EndpointInfo`].
    pub fn new(
        endpoint_info: EndpointInfo,
        provenance: &'static str,
        last_updated: Option<u64>,
    ) -> Self {
        Self {
            endpoint_info,
            provenance,
            last_updated,
        }
    }

    /// Returns the endpoint id of the discovered endpoint.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_info.endpoint_id
    }

    /// Returns the [`EndpointInfo`] for the discovered endpoint.
    pub fn endpoint_info(&self) -> &EndpointInfo {
        &self.endpoint_info
    }

    /// Returns the provenance of this Address Lookup item.
    ///
    /// The provenance is a static string which identifies the Address Lookup service that produced
    /// this item.
    pub fn provenance(&self) -> &'static str {
        self.provenance
    }

    /// Returns the optional timestamp when this endpoint info was last updated.
    ///
    /// The value is microseconds since the unix epoch.
    pub fn last_updated(&self) -> Option<u64> {
        self.last_updated
    }

    /// Converts into a [`EndpointAddr`] by cloning the needed fields.
    pub fn to_endpoint_addr(&self) -> EndpointAddr {
        self.endpoint_info.to_endpoint_addr()
    }

    /// Converts into a [`EndpointAddr`] without cloning.
    pub fn into_endpoint_addr(self) -> EndpointAddr {
        self.endpoint_info.into_endpoint_addr()
    }

    /// Returns any user-defined data.
    pub fn user_data(&self) -> Option<UserData> {
        self.endpoint_info().data.user_data().cloned()
    }
}

impl std::ops::Deref for Item {
    type Target = EndpointData;
    fn deref(&self) -> &Self::Target {
        &self.endpoint_info.data
    }
}

impl From<Item> for EndpointInfo {
    fn from(item: Item) -> Self {
        item.endpoint_info
    }
}

/// An Address Lookup service that combines multiple Address Lookup sources.
///
/// The Address Lookup will resolve concurrently.
#[derive(Debug, Default, Clone)]
pub struct ConcurrentAddressLookup {
    services: Arc<RwLock<Vec<Box<dyn AddressLookup>>>>,
    /// The data last published, used to publish when adding a new service.
    last_data: Arc<RwLock<Option<EndpointData>>>,
    /// Optional filter applied to all data before publishing to any service.
    addr_filter: Arc<RwLock<Option<AddrFilter>>>,
}

impl ConcurrentAddressLookup {
    /// Creates an empty [`ConcurrentAddressLookup`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates a new [`ConcurrentAddressLookup`].
    pub fn from_services(services: Vec<Box<dyn AddressLookup>>) -> Self {
        Self {
            services: Arc::new(RwLock::new(services)),
            last_data: Default::default(),
            addr_filter: Default::default(),
        }
    }

    /// Sets the address filter applied before publishing to any service.
    ///
    /// When set, all address data is filtered once before being distributed
    /// to the individual address lookup services. This ensures consistent
    /// filtering regardless of how many services are configured.
    pub fn set_addr_filter(&self, filter: AddrFilter) {
        *self.addr_filter.write().expect("poisoned") = Some(filter);
    }

    /// Adds an [`AddressLookup`] service.
    ///
    /// If there is historical Address Lookup data, it will be published immediately on this service.
    pub fn add(&self, service: impl AddressLookup + 'static) {
        self.add_boxed(Box::new(service))
    }

    /// Adds an already `Box`ed [`AddressLookup`] service.
    ///
    /// If there is historical Address Lookup data, it will be published immediately on this service.
    pub fn add_boxed(&self, service: Box<dyn AddressLookup>) {
        {
            let data = self.last_data.read().expect("poisoned");
            if let Some(data) = &*data {
                service.publish(data)
            }
        }
        self.services.write().expect("poisoned").push(service);
    }

    /// Are there any services configured?
    pub fn is_empty(&self) -> bool {
        self.services.read().expect("poisoned").is_empty()
    }

    /// Returns the number of services configured.
    pub fn len(&self) -> usize {
        self.services.read().expect("poisoned").len()
    }

    /// Removes all configured services.
    pub fn clear(&self) {
        let mut services = self.services.write().expect("poisoned");
        services.clear();
    }
}

impl<T> From<T> for ConcurrentAddressLookup
where
    T: IntoIterator<Item = Box<dyn AddressLookup>>,
{
    fn from(iter: T) -> Self {
        let services = iter.into_iter().collect::<Vec<_>>();
        Self {
            services: Arc::new(RwLock::new(services)),
            last_data: Default::default(),
            addr_filter: Default::default(),
        }
    }
}

impl AddressLookup for ConcurrentAddressLookup {
    fn publish(&self, data: &EndpointData) {
        let data = match &*self.addr_filter.read().expect("poisoned") {
            Some(filter) => data.apply_filter(filter),
            None => Cow::Borrowed(data),
        };
        let services = self.services.read().expect("poisoned");
        for service in &*services {
            service.publish(&data);
        }

        self.last_data
            .write()
            .expect("poisoned")
            .replace(data.into_owned());
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let services = self.services.read().expect("poisoned");
        let streams = services
            .iter()
            .filter_map(|service| service.resolve(endpoint_id));

        let streams = n0_future::MergeBounded::from_iter(streams);
        Some(Box::pin(streams))
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime},
    };

    use iroh_base::{EndpointAddr, SecretKey, TransportAddr};
    use n0_error::{AnyError, Result, StackResultExt};
    use n0_future::{StreamExt, time};
    use n0_tracing_test::traced_test;
    use rand::{CryptoRng, Rng, SeedableRng};
    use tokio_util::task::AbortOnDropHandle;

    use super::*;
    use crate::{
        Endpoint,
        endpoint::{ConnectOptions, IdleTimeout, QuicTransportConfig, presets},
    };

    type InfoStore = HashMap<EndpointId, (EndpointData, u64)>;

    #[derive(Debug, Clone, Default)]
    struct TestAddressLookupShared {
        endpoints: Arc<Mutex<InfoStore>>,
    }

    impl TestAddressLookupShared {
        pub fn create_address_lookup(&self, endpoint_id: EndpointId) -> TestAddressLookup {
            TestAddressLookup {
                endpoint_id,
                shared: self.clone(),
                publish: true,
                resolve_wrong: false,
                delay: Duration::from_millis(200),
            }
        }

        pub fn create_lying_address_lookup(&self, endpoint_id: EndpointId) -> TestAddressLookup {
            TestAddressLookup {
                endpoint_id,
                shared: self.clone(),
                publish: false,
                resolve_wrong: true,
                delay: Duration::from_millis(100),
            }
        }
    }

    #[derive(Debug)]
    struct TestAddressLookup {
        endpoint_id: EndpointId,
        shared: TestAddressLookupShared,
        publish: bool,
        resolve_wrong: bool,
        delay: Duration,
    }

    impl AddressLookup for TestAddressLookup {
        fn publish(&self, data: &EndpointData) {
            if !self.publish {
                return;
            }
            let now = system_time_now();
            self.shared
                .endpoints
                .lock()
                .unwrap()
                .insert(self.endpoint_id, (data.clone(), now));
        }

        fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
            let addr_info = if self.resolve_wrong {
                let ts = system_time_now() - 100_000;
                let port: u16 = rand::rng().random_range(10_000..20_000);
                // "240.0.0.0/4" is reserved and unreachable
                let addr: SocketAddr = format!("240.0.0.1:{port}").parse().unwrap();
                let data = EndpointData::from_iter([TransportAddr::Ip(addr)]);
                Some((data, ts))
            } else {
                self.shared
                    .endpoints
                    .lock()
                    .unwrap()
                    .get(&endpoint_id)
                    .cloned()
            };
            let stream = match addr_info {
                Some((data, ts)) => {
                    let item = Item::new(
                        EndpointInfo::from_parts(endpoint_id, data),
                        "test-addr-lookup",
                        Some(ts),
                    );
                    let delay = self.delay;
                    let fut = async move {
                        time::sleep(delay).await;
                        tracing::debug!("resolve: {} = {item:?}", endpoint_id.fmt_short());
                        Ok(item)
                    };
                    n0_future::stream::once_future(fut).boxed()
                }
                None => n0_future::stream::empty().boxed(),
            };
            Some(stream)
        }
    }

    #[derive(Debug, Clone)]
    struct EmptyAddressLookup;

    impl AddressLookup for EmptyAddressLookup {
        fn publish(&self, _data: &EndpointData) {}

        fn resolve(&self, _endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
            Some(n0_future::stream::empty().boxed())
        }
    }

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    /// This is a smoke test for our Address Lookupmechanism.
    #[tokio::test]
    #[traced_test]
    async fn address_lookup_simple_shared() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let eir_shared = TestAddressLookupShared::default();
        let (ep1, _guard1) =
            new_endpoint(&mut rng, |ep| eir_shared.create_address_lookup(ep.id())).await;

        let (ep2, _guard2) =
            new_endpoint(&mut rng, |ep| eir_shared.create_address_lookup(ep.id())).await;
        let ep1_addr = EndpointAddr::new(ep1.id());
        let _conn = ep2.connect(ep1_addr, TEST_ALPN).await?;
        Ok(())
    }

    /// This is a smoke test to ensure a Address Lookup can be
    /// `Arc`-d, and Address Lookup will still work
    #[tokio::test]
    #[traced_test]
    async fn address_lookup_simple_shared_with_arc() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let address_lookup_shared = TestAddressLookupShared::default();
        let (ep1, _guard1) = new_endpoint(&mut rng, |ep| {
            Arc::new(address_lookup_shared.create_address_lookup(ep.id()))
        })
        .await;

        let (ep2, _guard2) = new_endpoint(&mut rng, |ep| {
            Arc::new(address_lookup_shared.create_address_lookup(ep.id()))
        })
        .await;
        let ep1_addr = EndpointAddr::new(ep1.id());
        let _conn = ep2.connect(ep1_addr, TEST_ALPN).await?;
        Ok(())
    }

    /// This test adds an empty Address Lookupwhich provides no addresses.
    #[tokio::test]
    #[traced_test]
    async fn address_lookup_combined_with_empty_and_right() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let address_lookup_shared = TestAddressLookupShared::default();
        let (ep1, _guard1) = new_endpoint(&mut rng, |ep| {
            address_lookup_shared.create_address_lookup(ep.id())
        })
        .await;
        let (ep2, _guard2) = new_endpoint_add(&mut rng, |ep| {
            let addr_lookup1 = EmptyAddressLookup;
            let addr_lookup2 = address_lookup_shared.create_address_lookup(ep.id());
            ep.address_lookup()
                .expect("endpoint is still open")
                .add(addr_lookup1);
            ep.address_lookup()
                .expect("endpoint is still open")
                .add(addr_lookup2);
        })
        .await;

        let ep1_addr = EndpointAddr::new(ep1.id());

        assert_eq!(
            ep2.address_lookup().expect("endpoint is still open").len(),
            2
        );
        let _conn = ep2
            .connect(ep1_addr, TEST_ALPN)
            .await
            .context("connecting")?;
        Ok(())
    }

    /// This test adds a "lying" address_lookup service which provides a wrong address.
    /// This is to make sure that as long as one of the services returns a working address, we
    /// will connect successfully.
    #[tokio::test]
    #[traced_test]
    async fn address_lookup_combined_with_empty_and_wrong() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let address_lookup_shared = TestAddressLookupShared::default();
        let (ep1, _guard1) = new_endpoint(&mut rng, |ep| {
            address_lookup_shared.create_address_lookup(ep.id())
        })
        .await;

        let (ep2, _guard2) = new_endpoint(&mut rng, |ep| {
            let address_lookup1 = EmptyAddressLookup;
            let address_lookup2 = address_lookup_shared.create_lying_address_lookup(ep.id());
            let address_lookup3 = address_lookup_shared.create_address_lookup(ep.id());
            let address_lookup = ConcurrentAddressLookup::empty();
            address_lookup.add(address_lookup1);
            address_lookup.add(address_lookup2);
            address_lookup.add(address_lookup3);
            address_lookup
        })
        .await;

        let _conn = ep2.connect(ep1.id(), TEST_ALPN).await?;
        Ok(())
    }

    /// This test only has the "lying" address lookup system. It is here to make sure that this actually fails.
    #[tokio::test]
    #[traced_test]
    async fn address_lookup_combined_wrong_only() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let address_lookup_shared = TestAddressLookupShared::default();
        let (ep1, _guard1) = new_endpoint(&mut rng, |ep| {
            address_lookup_shared.create_address_lookup(ep.id())
        })
        .await;

        let (ep2, _guard2) = new_endpoint(&mut rng, |ep| {
            let address_lookup1 = address_lookup_shared.create_lying_address_lookup(ep.id());
            ConcurrentAddressLookup::from_services(vec![Box::new(address_lookup1)])
        })
        .await;

        // 10x faster test via a 3s idle timeout instead of the 30s default
        let cfg = QuicTransportConfig::builder()
            .keep_alive_interval(Duration::from_secs(1))
            .max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(3)).unwrap()))
            .build();
        let opts = ConnectOptions::new().with_transport_config(cfg);

        let res = ep2
            .connect_with_opts(ep1.id(), TEST_ALPN, opts)
            .await? // -> Connecting works
            .await; // -> Connection is expected to fail
        assert!(res.is_err());
        Ok(())
    }

    /// This test first adds a wrong address manually (e.g. from an outdated&endpoint_id ticket).
    /// Connect should still succeed because the address lookup service service will be invoked (after a delay).
    #[tokio::test]
    #[traced_test]
    async fn address_lookup_with_wrong_existing_addr() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let address_lookup_shared = TestAddressLookupShared::default();
        let (ep1, _guard1) = new_endpoint(&mut rng, |ep| {
            address_lookup_shared.create_address_lookup(ep.id())
        })
        .await;
        let (ep2, _guard2) = new_endpoint(&mut rng, |ep| {
            address_lookup_shared.create_address_lookup(ep.id())
        })
        .await;

        let ep1_wrong_addr = EndpointAddr::from_parts(
            ep1.id(),
            [TransportAddr::Ip("240.0.0.1:1000".parse().unwrap())],
        );
        let _conn = ep2.connect(ep1_wrong_addr, TEST_ALPN).await?;
        Ok(())
    }

    #[test]
    fn concurrent_address_lookup_addr_filter() {
        use iroh_base::RelayUrl;

        // Create a service that records what it receives.
        #[derive(Debug, Clone, Default)]
        struct RecordingLookup {
            published: Arc<Mutex<Vec<EndpointData>>>,
        }
        impl AddressLookup for RecordingLookup {
            fn publish(&self, data: &EndpointData) {
                self.published.lock().unwrap().push(data.clone());
            }
            fn resolve(&self, _endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
                None
            }
        }

        let recorder = RecordingLookup::default();
        let lookup = ConcurrentAddressLookup::empty();
        lookup.set_addr_filter(AddrFilter::relay_only());
        lookup.add(recorder.clone());

        let relay_url: RelayUrl = "https://relay.example.com".parse().unwrap();
        let ip_addr: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let data = EndpointData::from_iter([
            TransportAddr::Relay(relay_url.clone()),
            TransportAddr::Ip(ip_addr),
        ]);
        lookup.publish(&data);

        let published = recorder.published.lock().unwrap();
        assert_eq!(published.len(), 1);
        let addrs: Vec<_> = published[0].addrs().cloned().collect();
        assert_eq!(addrs, vec![TransportAddr::Relay(relay_url)]);
        assert!(
            !addrs.contains(&TransportAddr::Ip(ip_addr)),
            "IP address should have been filtered out"
        );
    }

    async fn new_endpoint<R: CryptoRng, D: AddressLookup + 'static, F: FnOnce(&Endpoint) -> D>(
        rng: &mut R,
        create_address_lookup: F,
    ) -> (Endpoint, AbortOnDropHandle<Result<()>>) {
        new_endpoint_add(rng, |ep| {
            let address_lookup = create_address_lookup(ep);
            ep.address_lookup()
                .expect("endpoint is still open")
                .add(address_lookup);
        })
        .await
    }

    async fn new_endpoint_add<R: CryptoRng, F: FnOnce(&Endpoint)>(
        rng: &mut R,
        add_address_lookup: F,
    ) -> (Endpoint, AbortOnDropHandle<Result<()>>) {
        let secret = SecretKey::generate(rng);

        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        add_address_lookup(&ep);

        let handle = tokio::spawn({
            let ep = ep.clone();
            async move {
                // Keep connections alive until the task is dropped.
                let mut connections = Vec::new();
                // we skip accept() errors, they can be caused by retransmits
                while let Some(accepting) = ep.accept().await.and_then(|inc| inc.accept().ok()) {
                    // Just accept incoming connections, but don't do anything with them.
                    let conn = accepting.await.context("accepting")?;
                    connections.push(conn);
                }

                Ok::<_, AnyError>(())
            }
        });

        (ep, AbortOnDropHandle::new(handle))
    }

    fn system_time_now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time drift")
            .as_micros() as u64
    }
}

/// This module contains end-to-end tests for DNS address lookup service.
///
/// The tests run a minimal test DNS server to resolve against, and a minimal pkarr relay to
/// publish to. The DNS and pkarr servers share their state.
#[cfg(test)]
mod test_dns_pkarr {
    use iroh_base::{EndpointAddr, SecretKey, TransportAddr};
    use iroh_relay::{
        endpoint_info::UserData,
        tls::{CaRootsConfig, default_provider},
    };
    use n0_error::{Result, StackResultExt};
    use n0_future::time::Duration;
    use n0_tracing_test::traced_test;
    use rand::SeedableRng;

    use crate::{
        address_lookup::{EndpointData, PkarrPublisher},
        dns::DnsResolver,
        endpoint_info::EndpointInfo,
        test_utils::{DnsPkarrServer, dns_server::run_dns_server, pkarr_dns_state::State},
    };

    const PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

    #[tokio::test]
    #[traced_test]
    async fn dns_resolve() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let origin = "testdns.example".to_string();
        let state = State::new(origin.clone());
        let (nameserver, _dns_drop_guard) = run_dns_server(state.clone())
            .await
            .context("Running DNS server")?;

        let secret_key = SecretKey::generate(&mut rng);
        let endpoint_info = EndpointInfo::new(secret_key.public())
            .with_relay_url("https://relay.example".parse().unwrap());
        let signed_packet = endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?;
        state
            .upsert(signed_packet)
            .context("update and insert signed packet")?;

        let resolver = DnsResolver::with_nameserver(nameserver);
        let resolved = resolver
            .lookup_endpoint_by_id(&endpoint_info.endpoint_id, &origin)
            .await?;

        assert_eq!(resolved, endpoint_info);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn pkarr_publish_dns_resolve() -> Result<()> {
        let origin = "testdns.example".to_string();
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let dns_pkarr_server = DnsPkarrServer::run_with_origin(origin.clone())
            .await
            .context("DnsPkarrServer")?;

        let secret_key = SecretKey::generate(&mut rng);
        let endpoint_id = secret_key.public();

        let relay_url = Some(TransportAddr::Relay(
            "https://relay.example".parse().unwrap(),
        ));

        let tls_config = CaRootsConfig::insecure_skip_verify()
            .client_config(default_provider())
            .expect("infallible");
        let resolver = DnsResolver::with_nameserver(dns_pkarr_server.nameserver);
        let publisher = PkarrPublisher::builder(dns_pkarr_server.pkarr_url.clone())
            .build(secret_key, tls_config);
        let user_data: UserData = "foobar".parse().unwrap();
        let data = EndpointData::from_iter(relay_url.clone()).with_user_data(user_data.clone());
        // does not block, update happens in background task
        publisher.update_endpoint_data(&data);
        // wait until our shared state received the update from pkarr publishing
        dns_pkarr_server
            .on_endpoint(&endpoint_id, PUBLISH_TIMEOUT)
            .await
            .context("wait for on endpoint update")?;
        let resolved = resolver
            .lookup_endpoint_by_id(&endpoint_id, &origin)
            .await?;
        println!("resolved {resolved:?}");

        let expected_addr = EndpointAddr::from_parts(endpoint_id, relay_url);

        assert_eq!(resolved.to_endpoint_addr(), expected_addr);
        assert_eq!(resolved.user_data(), Some(&user_data));
        Ok(())
    }

    #[cfg(with_crypto_provider)]
    const TEST_ALPN: &[u8] = b"TEST";

    #[cfg(with_crypto_provider)]
    #[tokio::test]
    #[traced_test]
    async fn pkarr_publish_dns_address_lookup() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let dns_pkarr_server = DnsPkarrServer::run().await.context("DnsPkarrServer run")?;
        let (relay_map, _relay_url, _relay_guard) = crate::test_utils::run_relay_server().await?;

        let (ep1, _guard1) =
            ep_with_address_lookup(&mut rng, &relay_map, &dns_pkarr_server).await?;
        let (ep2, _guard2) =
            ep_with_address_lookup(&mut rng, &relay_map, &dns_pkarr_server).await?;

        // wait until our shared state received the update from pkarr publishing
        dns_pkarr_server
            .on_endpoint(&ep1.id(), PUBLISH_TIMEOUT)
            .await
            .context("wait for on endpoint update")?;

        // we connect only by endpoint id!
        let _conn = ep2.connect(ep1.id(), TEST_ALPN).await?;
        Ok(())
    }

    #[cfg(with_crypto_provider)]
    async fn ep_with_address_lookup<R: rand::CryptoRng + ?Sized>(
        rng: &mut R,
        relay_map: &iroh_relay::RelayMap,
        dns_pkarr_server: &DnsPkarrServer,
    ) -> Result<(
        crate::Endpoint,
        n0_future::task::AbortOnDropHandle<Result<()>>,
    )> {
        use n0_future::task::AbortOnDropHandle;

        use crate::{Endpoint, RelayMode, endpoint::presets};

        let secret_key = SecretKey::generate(rng);
        let ep = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .ca_roots_config(CaRootsConfig::insecure_skip_verify())
            .secret_key(secret_key.clone())
            .alpns(vec![TEST_ALPN.to_vec()])
            .preset(dns_pkarr_server.preset())
            .bind()
            .await?;

        let handle = tokio::spawn({
            let ep = ep.clone();
            async move {
                // we skip accept() errors, they can be caused by retransmits

                use n0_error::AnyError;
                while let Some(accepting) = ep.accept().await.and_then(|inc| inc.accept().ok()) {
                    let _conn = accepting.await.context("accepting")?;
                    // Just accept incoming connections, but don't do anything with them.
                }

                Ok::<_, AnyError>(())
            }
        });

        Ok((ep, AbortOnDropHandle::new(handle)))
    }
}
