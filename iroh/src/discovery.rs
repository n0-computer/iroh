//! Endpoint address discovery.
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
//! Endpoint discovery is an automated system for an [`Endpoint`] to retrieve this addressing
//! information.  Each iroh endpoint will automatically publish their own addressing
//! information.  Usually this means publishing which [`RelayUrl`] to use for their
//! [`EndpointId`], but they could also publish their direct addresses.
//!
//! The [`Discovery`] trait is used to define endpoint discovery.  This allows multiple
//! implementations to co-exist because there are many possible ways to implement this.
//! Each [`Endpoint`] can use the discovery mechanisms most suitable to the application.
//! The [`Builder::discovery`] method is used to add a discovery mechanism to an
//! [`Endpoint`].
//!
//! Some generally useful discovery implementations are provided:
//!
//! - [`StaticProvider`] which allows application to add and remove out-of-band addressing
//!   information.
//!
//! - The [`DnsDiscovery`] which performs lookups via the standard DNS systems.  To publish
//!   to this DNS server a [`PkarrPublisher`] is needed.  [Number 0] runs a public instance
//!   of a [`PkarrPublisher`] with attached DNS server which is globally available and a
//!   reliable default choice.
//!
//! - The [`PkarrResolver`] which can perform lookups from designated [pkarr relay servers]
//!   using HTTP.
//!
//! - [`MdnsDiscovery`]: mdns::MdnsDiscovery which uses the crate `swarm-discovery`, an
//!   opinionated mDNS implementation, to discover endpoints on the local network.
//!
//! - The [`DhtDiscovery`] also uses the [`pkarr`] system but can also publish and lookup
//!   records to/from the Mainline DHT.
//!
//! To use multiple discovery systems simultaneously you can call [`Builder::discovery`].
//! This will use [`ConcurrentDiscovery`] under the hood, which performs lookups to all
//! discovery systems at the same time.
//!
//! [`Builder::discovery`] takes any type that implements [`IntoDiscovery`]. You can
//! implement that trait on a builder struct if your discovery service needs information
//! from the endpoint it is mounted on. After endpoint construction, your discovery service
//! is built by calling [`IntoDiscovery::into_discovery`], passing the finished [`Endpoint`] to your
//! builder.
//!
//! If your discovery service does not need any information from its endpoint, you can
//! pass the discovery service directly to [`Builder::discovery`]: All types that
//! implement [`Discovery`] also have a blanket implementation of [`IntoDiscovery`].
//!
//! # Examples
//!
//! A very common setup is to enable DNS discovery, which needs to be done in two parts as a
//! [`PkarrPublisher`] and [`DnsDiscovery`]:
//!
//! ```no_run
//! use iroh::{
//!     Endpoint, SecretKey,
//!     discovery::{dns::DnsDiscovery, pkarr::PkarrPublisher},
//!     endpoint::RelayMode,
//! };
//!
//! # async fn wrapper() -> n0_error::Result<()> {
//! let ep = Endpoint::empty_builder(RelayMode::Default)
//!     .discovery(PkarrPublisher::n0_dns())
//!     .discovery(DnsDiscovery::n0_dns())
//!     .bind()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! To also enable [`MdnsDiscovery`] it can be added as another service.
//!
//! ```no_run
//! #[cfg(feature = "discovery-local-network")]
//! # {
//! # use iroh::{
//! #    discovery::{dns::DnsDiscovery, pkarr::PkarrPublisher, mdns::MdnsDiscovery},
//! #    endpoint::RelayMode,
//! #    Endpoint, SecretKey,
//! # };
//! #
//! # async fn wrapper() -> n0_error::Result<()> {
//! let ep = Endpoint::empty_builder(RelayMode::Default)
//!     .discovery(PkarrPublisher::n0_dns())
//!     .discovery(DnsDiscovery::n0_dns())
//!     .discovery(MdnsDiscovery::builder())
//!     .bind()
//!     .await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! [`EndpointAddr`]: iroh_base::EndpointAddr
//! [`RelayUrl`]: crate::RelayUrl
//! [`Builder::discovery`]: crate::endpoint::Builder::discovery
//! [`DnsDiscovery`]: dns::DnsDiscovery
//! [Number 0]: https://n0.computer
//! [`PkarrResolver`]: pkarr::PkarrResolver
//! [`PkarrPublisher`]: pkarr::PkarrPublisher
//! [`DhtDiscovery`]: pkarr::dht::DhtDiscovery
//! [pkarr relay servers]: https://pkarr.org/#servers
//! [`MdnsDiscovery`]: mdns::MdnsDiscovery
//! [`StaticProvider`]: static_provider::StaticProvider

use std::sync::{Arc, RwLock};

use iroh_base::{EndpointAddr, EndpointId};
use n0_error::{AnyError, Err, Error, add_meta, e};
use n0_future::{
    boxed::BoxStream,
    stream::StreamExt,
    task::{self, AbortOnDropHandle},
    time::{self, Duration},
};
use tokio::sync::oneshot;
use tracing::{Instrument, debug, error_span, warn};

use crate::Endpoint;
pub use crate::endpoint_info::{EndpointData, EndpointInfo, ParseError, UserData};

#[cfg(not(wasm_browser))]
pub mod dns;

#[cfg(feature = "discovery-local-network")]
pub mod mdns;
pub mod pkarr;
pub mod static_provider;

/// Trait for structs that can be converted into [`Discovery`].
///
/// This trait is implemented on builders for discovery services. Any type that implements this
/// trait can be added as a discovery service in [`Builder::discovery`].
///
/// Any type that implements [`Discovery`] also implements [`IntoDiscovery`].
///
/// Iroh uses this trait to allow configuring the set of discovery services on the endpoint
/// builder, while providing the discovery services access to information about the endpoint
/// to [`IntoDiscovery::into_discovery`].
///
/// [`Builder::discovery`]: crate::endpoint::Builder::discovery
pub trait IntoDiscovery: Send + Sync + std::fmt::Debug + 'static {
    /// Turns this discovery builder into a ready-to-use discovery service.
    ///
    /// If an error is returned, building the endpoint will fail with this error.
    fn into_discovery(self, endpoint: &Endpoint) -> Result<impl Discovery, IntoDiscoveryError>;
}

/// Blanket no-op impl of `IntoDiscovery` for `T: Discovery`.
impl<T: Discovery> IntoDiscovery for T {
    fn into_discovery(self, _endpoint: &Endpoint) -> Result<impl Discovery, IntoDiscoveryError> {
        Ok(self)
    }
}

/// Non-public dyn-compatible version of [`IntoDiscovery`], used in [`crate::endpoint::Builder`].
pub(crate) trait DynIntoDiscovery: Send + Sync + std::fmt::Debug + 'static {
    /// See [`IntoDiscovery::into_discovery`]
    fn into_discovery(
        self: Box<Self>,
        endpoint: &Endpoint,
    ) -> Result<Box<dyn Discovery>, IntoDiscoveryError>;
}

impl<T: IntoDiscovery> DynIntoDiscovery for T {
    fn into_discovery(
        self: Box<Self>,
        endpoint: &Endpoint,
    ) -> Result<Box<dyn Discovery>, IntoDiscoveryError> {
        let disco: Box<dyn Discovery> = Box::new(IntoDiscovery::into_discovery(*self, endpoint)?);
        Ok(disco)
    }
}

/// IntoDiscovery errors
#[allow(missing_docs)]
#[add_meta]
#[derive(Error)]
#[non_exhaustive]
pub enum IntoDiscoveryError {
    #[display("Service '{provenance}' error")]
    User {
        provenance: &'static str,
        source: AnyError,
    },
}

impl IntoDiscoveryError {
    /// Creates a new user error from an arbitrary error type.
    pub fn from_err<T: std::error::Error + Send + Sync + 'static>(
        provenance: &'static str,
        source: T,
    ) -> Self {
        e!(IntoDiscoveryError::User {
            provenance,
            source: AnyError::from_std(source)
        })
    }

    /// Creates a new user error from an arbitrary boxed error type.
    pub fn from_err_box(
        provenance: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        e!(IntoDiscoveryError::User {
            provenance,
            source: AnyError::from_std_box(source)
        })
    }
}

/// Discovery errors
#[allow(missing_docs)]
#[add_meta]
#[derive(Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    #[display("No discovery service configured")]
    NoServiceConfigured,
    #[display("Discovery produced no results for {}", endpoint_id.fmt_short())]
    NoResults { endpoint_id: EndpointId },
    #[display("Service '{provenance}' error")]
    User {
        provenance: &'static str,
        source: AnyError,
    },
}

impl DiscoveryError {
    /// Creates a new user error from an arbitrary error type.
    pub fn from_err<T: std::error::Error + Send + Sync + 'static>(
        provenance: &'static str,
        source: T,
    ) -> Self {
        e!(DiscoveryError::User {
            provenance,
            source: AnyError::from_std(source)
        })
    }

    /// Creates a new user error from an arbitrary boxed error type.
    pub fn from_err_box(
        provenance: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        e!(DiscoveryError::User {
            provenance,
            source: AnyError::from_std_box(source)
        })
    }
}

/// Endpoint discovery for [`super::Endpoint`].
///
/// This trait defines publishing and resolving addressing information for a [`EndpointId`].
/// This enables connecting to other endpoints with only knowing the [`EndpointId`], by using this
/// [`Discovery`] system to look up the actual addressing information.  It is common for
/// implementations to require each endpoint to publish their own information before it can be
/// looked up by other endpoints.
///
/// The published addressing information can include both a [`RelayUrl`] and/or direct
/// addresses. See [`EndpointData`] for details.
///
/// To allow for discovery, the [`super::Endpoint`] will call `publish` whenever
/// discovery information changes. If a discovery mechanism requires a periodic
/// refresh, it should start its own task.
///
/// [`RelayUrl`]: crate::RelayUrl
pub trait Discovery: std::fmt::Debug + Send + Sync + 'static {
    /// Publishes the given [`EndpointData`] to the discovery mechanism.
    ///
    /// This is fire and forget, since the [`Endpoint`] can not wait for successful
    /// publishing. If publishing is async, the implementation should start it's own task.
    ///
    /// This will be called from a tokio task, so it is safe to spawn new tasks.
    /// These tasks will be run on the runtime of the [`super::Endpoint`].
    fn publish(&self, _data: &EndpointData) {}

    /// Resolves the [`DiscoveryItem`] for the given [`EndpointId`].
    ///
    /// Once the returned [`BoxStream`] is dropped, the service should stop any pending
    /// work.
    fn resolve(
        &self,
        _endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        None
    }
}

impl<T: Discovery> Discovery for Arc<T> {
    fn publish(&self, data: &EndpointData) {
        self.as_ref().publish(data);
    }

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        self.as_ref().resolve(endpoint_id)
    }
}

/// Endpoint discovery results from [`Discovery`] services.
///
/// This is the item in the streams returned from [`Discovery::resolve`].
/// It contains the [`EndpointData`] about the discovered endpoint,
/// and some additional metadata about the discovery.
///
/// This struct derefs to [`EndpointData`], so you can access the methods from [`EndpointData`]
/// directly from [`DiscoveryItem`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DiscoveryItem {
    /// The endpoint info for the endpoint, as discovered by the the discovery service.
    endpoint_info: EndpointInfo,
    /// A static string to identify the discovery source.
    ///
    /// Should be uniform per discovery service.
    provenance: &'static str,
    /// Optional timestamp when this endpoint address info was last updated.
    ///
    /// Must be microseconds since the unix epoch.
    // TODO(ramfox): this is currently unused. As we develop more `DiscoveryService`s, we may discover that we do not need this. It is only truly relevant when comparing `relay_urls`, since we can attempt to dial any number of socket addresses, but expect each endpoint to have one "home relay" that we will attempt to contact them on. This means we would need some way to determine which relay url to choose between, if more than one relay url is reported.
    last_updated: Option<u64>,
}

impl DiscoveryItem {
    /// Creates a new [`DiscoveryItem`] from a [`EndpointInfo`].
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

    /// Returns the provenance of this discovery item.
    ///
    /// The provenance is a static string which identifies the discovery service that produced
    /// this discovery item.
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

impl std::ops::Deref for DiscoveryItem {
    type Target = EndpointData;
    fn deref(&self) -> &Self::Target {
        &self.endpoint_info.data
    }
}

impl From<DiscoveryItem> for EndpointInfo {
    fn from(item: DiscoveryItem) -> Self {
        item.endpoint_info
    }
}

/// A discovery service that combines multiple discovery sources.
///
/// The discovery services will resolve concurrently.
#[derive(Debug, Default, Clone)]
pub struct ConcurrentDiscovery {
    services: Arc<RwLock<Vec<Box<dyn Discovery>>>>,
    /// The data last published, used to publish when adding a new service.
    last_data: Arc<RwLock<Option<EndpointData>>>,
}

impl ConcurrentDiscovery {
    /// Creates an empty [`ConcurrentDiscovery`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates a new [`ConcurrentDiscovery`].
    pub fn from_services(services: Vec<Box<dyn Discovery>>) -> Self {
        Self {
            services: Arc::new(RwLock::new(services)),
            last_data: Default::default(),
        }
    }

    /// Adds a [`Discovery`] service.
    ///
    /// If there is historical discovery data, it will be published immediately on this service.
    pub fn add(&self, service: impl Discovery + 'static) {
        self.add_boxed(Box::new(service))
    }

    /// Adds an already `Box`ed [`Discovery`] service.
    ///
    /// If there is historical discovery data, it will be published immediately on this service.
    pub fn add_boxed(&self, service: Box<dyn Discovery>) {
        {
            let data = self.last_data.read().expect("poisoned");
            if let Some(data) = &*data {
                service.publish(data)
            }
        }
        self.services.write().expect("poisoned").push(service);
    }

    /// Is there any services configured?
    pub fn is_empty(&self) -> bool {
        self.services.read().expect("poisoned").is_empty()
    }

    /// Returns the number of services configured.
    pub fn len(&self) -> usize {
        self.services.read().expect("poisoned").len()
    }
}

impl<T> From<T> for ConcurrentDiscovery
where
    T: IntoIterator<Item = Box<dyn Discovery>>,
{
    fn from(iter: T) -> Self {
        let services = iter.into_iter().collect::<Vec<_>>();
        Self {
            services: Arc::new(RwLock::new(services)),
            last_data: Default::default(),
        }
    }
}

impl Discovery for ConcurrentDiscovery {
    fn publish(&self, data: &EndpointData) {
        let services = self.services.read().expect("poisoned");
        for service in &*services {
            service.publish(data);
        }

        self.last_data
            .write()
            .expect("poisoned")
            .replace(data.clone());
    }

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        let services = self.services.read().expect("poisoned");
        let streams = services
            .iter()
            .filter_map(|service| service.resolve(endpoint_id));

        let streams = n0_future::MergeBounded::from_iter(streams);
        Some(Box::pin(streams))
    }
}

/// Maximum duration since the last control or data message received from an endpoint to make us
/// start a discovery task.
const MAX_AGE: Duration = Duration::from_secs(10);

/// A wrapper around a tokio task which runs an endpoint discovery.
pub(super) struct DiscoveryTask {
    on_first_rx: oneshot::Receiver<Result<(), DiscoveryError>>,
    _task: AbortOnDropHandle<()>,
}

impl DiscoveryTask {
    /// Starts a discovery task.
    pub(super) fn start(ep: Endpoint, endpoint_id: EndpointId) -> Result<Self, DiscoveryError> {
        n0_error::ensure!(
            !ep.discovery().is_empty(),
            e!(DiscoveryError::NoServiceConfigured)
        );
        let (on_first_tx, on_first_rx) = oneshot::channel();
        let me = ep.id();
        let task = task::spawn(
            async move { Self::run(ep, endpoint_id, on_first_tx).await }.instrument(
                error_span!("discovery", me = %me.fmt_short(), endpoint = %endpoint_id.fmt_short()),
            ),
        );
        Ok(Self {
            _task: AbortOnDropHandle::new(task),
            on_first_rx,
        })
    }

    /// Starts a discovery task after a delay and only if no path to the endpoint was recently active.
    ///
    /// This returns `None` if we received data or control messages from the remote endpoint
    /// recently enough. If not it returns a [`DiscoveryTask`].
    ///
    /// If `delay` is set, the [`DiscoveryTask`] will first wait for `delay` and then check again
    /// if we recently received messages from remote endpoint. If true, the task will abort.
    /// Otherwise, or if no `delay` is set, the discovery will be started.
    pub(super) fn maybe_start_after_delay(
        ep: &Endpoint,
        endpoint_id: EndpointId,
        delay: Option<Duration>,
    ) -> Result<Option<Self>, DiscoveryError> {
        // If discovery is not needed, don't even spawn a task.
        if !ep.needs_discovery(endpoint_id, MAX_AGE) {
            return Ok(None);
        }
        n0_error::ensure!(
            !ep.discovery().is_empty(),
            e!(DiscoveryError::NoServiceConfigured)
        );
        let (on_first_tx, on_first_rx) = oneshot::channel();
        let ep = ep.clone();
        let me = ep.id();
        let task = task::spawn(
            async move {
                // If delay is set, wait and recheck if discovery is needed. If not, early-exit.
                if let Some(delay) = delay {
                    time::sleep(delay).await;
                    if !ep.needs_discovery(endpoint_id, MAX_AGE) {
                        debug!("no discovery needed, abort");
                        on_first_tx.send(Ok(())).ok();
                        return;
                    }
                }
                Self::run(ep, endpoint_id, on_first_tx).await
            }
            .instrument(
                error_span!("discovery", me = %me.fmt_short(), endpoint = %endpoint_id.fmt_short()),
            ),
        );
        Ok(Some(Self {
            _task: AbortOnDropHandle::new(task),
            on_first_rx,
        }))
    }

    /// Waits until the discovery task produced at least one result.
    pub(super) async fn first_arrived(&mut self) -> Result<(), DiscoveryError> {
        let fut = &mut self.on_first_rx;
        fut.await.expect("sender dropped")?;
        Ok(())
    }

    fn create_stream(
        ep: &Endpoint,
        endpoint_id: EndpointId,
    ) -> Result<BoxStream<Result<DiscoveryItem, DiscoveryError>>, DiscoveryError> {
        n0_error::ensure!(
            !ep.discovery().is_empty(),
            e!(DiscoveryError::NoServiceConfigured)
        );
        let stream = ep
            .discovery()
            .resolve(endpoint_id)
            .ok_or_else(|| e!(DiscoveryError::NoResults { endpoint_id }))?;
        Ok(stream)
    }

    async fn run(
        ep: Endpoint,
        endpoint_id: EndpointId,
        on_first_tx: oneshot::Sender<Result<(), DiscoveryError>>,
    ) {
        let mut stream = match Self::create_stream(&ep, endpoint_id) {
            Ok(stream) => stream,
            Err(err) => {
                on_first_tx.send(Err(err)).ok();
                return;
            }
        };
        let mut on_first_tx = Some(on_first_tx);
        debug!("starting");
        loop {
            match stream.next().await {
                Some(Ok(r)) => {
                    let provenance = r.provenance;
                    let endpoint_addr = r.to_endpoint_addr();
                    if endpoint_addr.is_empty() {
                        debug!(%provenance, "empty address found");
                        continue;
                    }
                    debug!(%provenance, addr = ?endpoint_addr, "new address found");
                    let source = crate::magicsock::Source::Discovery {
                        name: provenance.to_string(),
                    };
                    ep.add_endpoint_addr(endpoint_addr, source).ok();

                    if let Some(tx) = on_first_tx.take() {
                        tx.send(Ok(())).ok();
                    }
                }
                Some(Err(err)) => {
                    warn!(?err, "discovery service produced error");
                    break;
                }
                None => break,
            }
        }
        if let Some(tx) = on_first_tx.take() {
            tx.send(Err!(DiscoveryError::NoResults { endpoint_id }))
                .ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap},
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::SystemTime,
    };

    use iroh_base::{EndpointAddr, SecretKey};
    use n0_error::{AnyError as Error, Result, StdResultExt};
    use quinn::{IdleTimeout, TransportConfig};
    use rand::{CryptoRng, Rng, SeedableRng};
    use tokio_util::task::AbortOnDropHandle;
    use tracing_test::traced_test;

    use super::*;
    use crate::{Endpoint, RelayMode, endpoint::ConnectOptions};

    type InfoStore = HashMap<EndpointId, (EndpointData, u64)>;

    #[derive(Debug, Clone, Default)]
    struct TestDiscoveryShared {
        endpoints: Arc<Mutex<InfoStore>>,
    }

    impl TestDiscoveryShared {
        pub fn create_discovery(&self, endpoint_id: EndpointId) -> TestDiscovery {
            TestDiscovery {
                endpoint_id,
                shared: self.clone(),
                publish: true,
                resolve_wrong: false,
                delay: Duration::from_millis(200),
            }
        }

        pub fn create_lying_discovery(&self, endpoint_id: EndpointId) -> TestDiscovery {
            TestDiscovery {
                endpoint_id,
                shared: self.clone(),
                publish: false,
                resolve_wrong: true,
                delay: Duration::from_millis(100),
            }
        }
    }

    #[derive(Debug)]
    struct TestDiscovery {
        endpoint_id: EndpointId,
        shared: TestDiscoveryShared,
        publish: bool,
        resolve_wrong: bool,
        delay: Duration,
    }

    impl Discovery for TestDiscovery {
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

        fn resolve(
            &self,
            endpoint_id: EndpointId,
        ) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
            let addr_info = if self.resolve_wrong {
                let ts = system_time_now() - 100_000;
                let port: u16 = rand::rng().random_range(10_000..20_000);
                // "240.0.0.0/4" is reserved and unreachable
                let addr: SocketAddr = format!("240.0.0.1:{port}").parse().unwrap();
                let data = EndpointData::new(None, BTreeSet::from([addr]));
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
                    let item = DiscoveryItem::new(
                        EndpointInfo::from_parts(endpoint_id, data),
                        "test-disco",
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
    struct EmptyDiscovery;

    impl Discovery for EmptyDiscovery {
        fn publish(&self, _data: &EndpointData) {}

        fn resolve(
            &self,
            _endpoint_id: EndpointId,
        ) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
            Some(n0_future::stream::empty().boxed())
        }
    }

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    /// This is a smoke test for our discovery mechanism.
    #[tokio::test]
    #[traced_test]
    async fn endpoint_discovery_simple_shared() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let disco_shared = TestDiscoveryShared::default();
        let (ep1, _guard1) =
            new_endpoint(&mut rng, |ep| disco_shared.create_discovery(ep.id())).await;

        let (ep2, _guard2) =
            new_endpoint(&mut rng, |ep| disco_shared.create_discovery(ep.id())).await;
        let ep1_addr = EndpointAddr::new(ep1.id());
        let _conn = ep2.connect(ep1_addr, TEST_ALPN).await?;
        Ok(())
    }

    /// This is a smoke test to ensure a discovery service can be
    /// `Arc`-d, and discovery will still work
    #[tokio::test]
    #[traced_test]
    async fn endpoint_discovery_simple_shared_with_arc() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let disco_shared = TestDiscoveryShared::default();
        let (ep1, _guard1) = new_endpoint(&mut rng, |ep| {
            Arc::new(disco_shared.create_discovery(ep.id()))
        })
        .await;

        let (ep2, _guard2) = new_endpoint(&mut rng, |ep| {
            Arc::new(disco_shared.create_discovery(ep.id()))
        })
        .await;
        let ep1_addr = EndpointAddr::new(ep1.id());
        let _conn = ep2.connect(ep1_addr, TEST_ALPN).await?;
        Ok(())
    }

    /// This test adds an empty discovery which provides no addresses.
    #[tokio::test]
    #[traced_test]
    async fn endpoint_discovery_combined_with_empty_and_right() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let disco_shared = TestDiscoveryShared::default();
        let (ep1, _guard1) =
            new_endpoint(&mut rng, |ep| disco_shared.create_discovery(ep.id())).await;
        let (ep2, _guard2) = new_endpoint_add(&mut rng, |ep| {
            let disco1 = EmptyDiscovery;
            let disco2 = disco_shared.create_discovery(ep.id());
            ep.discovery().add(disco1);
            ep.discovery().add(disco2);
        })
        .await;

        let ep1_addr = EndpointAddr::new(ep1.id());

        assert_eq!(ep2.discovery().len(), 2);
        let _conn = ep2
            .connect(ep1_addr, TEST_ALPN)
            .await
            .std_context("connecting")?;
        Ok(())
    }

    /// This test adds a "lying" discovery which provides a wrong address.
    /// This is to make sure that as long as one of the discoveries returns a working address, we
    /// will connect successfully.
    #[tokio::test]
    #[traced_test]
    async fn endpoint_discovery_combined_with_empty_and_wrong() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let disco_shared = TestDiscoveryShared::default();
        let (ep1, _guard1) =
            new_endpoint(&mut rng, |ep| disco_shared.create_discovery(ep.id())).await;

        let (ep2, _guard2) = new_endpoint(&mut rng, |ep| {
            let disco1 = EmptyDiscovery;
            let disco2 = disco_shared.create_lying_discovery(ep.id());
            let disco3 = disco_shared.create_discovery(ep.id());
            let disco = ConcurrentDiscovery::empty();
            disco.add(disco1);
            disco.add(disco2);
            disco.add(disco3);
            disco
        })
        .await;

        let _conn = ep2.connect(ep1.id(), TEST_ALPN).await?;
        Ok(())
    }

    /// This test only has the "lying" discovery. It is here to make sure that this actually fails.
    #[tokio::test]
    #[traced_test]
    async fn endpoint_discovery_combined_wrong_only() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let disco_shared = TestDiscoveryShared::default();
        let (ep1, _guard1) =
            new_endpoint(&mut rng, |ep| disco_shared.create_discovery(ep.id())).await;

        let (ep2, _guard2) = new_endpoint(&mut rng, |ep| {
            let disco1 = disco_shared.create_lying_discovery(ep.id());
            ConcurrentDiscovery::from_services(vec![Box::new(disco1)])
        })
        .await;

        // 10x faster test via a 3s idle timeout instead of the 30s default
        let mut config = TransportConfig::default();
        config.keep_alive_interval(Some(Duration::from_secs(1)));
        config.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(3)).unwrap()));
        let opts = ConnectOptions::new().with_transport_config(Arc::new(config));

        let res = ep2
            .connect_with_opts(ep1.id(), TEST_ALPN, opts)
            .await? // -> Connecting works
            .await; // -> Connection is expected to fail
        assert!(res.is_err());
        Ok(())
    }

    /// This test first adds a wrong address manually (e.g. from an outdated&endpoint_id ticket).
    /// Connect should still succeed because the discovery service will be invoked (after a delay).
    #[tokio::test]
    #[traced_test]
    async fn endpoint_discovery_with_wrong_existing_addr() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let disco_shared = TestDiscoveryShared::default();
        let (ep1, _guard1) =
            new_endpoint(&mut rng, |ep| disco_shared.create_discovery(ep.id())).await;
        let (ep2, _guard2) =
            new_endpoint(&mut rng, |ep| disco_shared.create_discovery(ep.id())).await;

        let ep1_wrong_addr = EndpointAddr {
            endpoint_id: ep1.id(),
            relay_url: None,
            direct_addresses: BTreeSet::from(["240.0.0.1:1000".parse().unwrap()]),
        };
        let _conn = ep2.connect(ep1_wrong_addr, TEST_ALPN).await?;
        Ok(())
    }

    async fn new_endpoint<R: CryptoRng, D: Discovery + 'static, F: FnOnce(&Endpoint) -> D>(
        rng: &mut R,
        create_disco: F,
    ) -> (Endpoint, AbortOnDropHandle<Result<()>>) {
        new_endpoint_add(rng, |ep| {
            let disco = create_disco(ep);
            ep.discovery().add(disco);
        })
        .await
    }

    async fn new_endpoint_add<R: CryptoRng, F: FnOnce(&Endpoint)>(
        rng: &mut R,
        add_disco: F,
    ) -> (Endpoint, AbortOnDropHandle<Result<()>>) {
        let secret = SecretKey::generate(rng);

        let ep = Endpoint::empty_builder(RelayMode::Disabled)
            .secret_key(secret)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        add_disco(&ep);

        let handle = tokio::spawn({
            let ep = ep.clone();
            async move {
                // Keep connections alive until the task is dropped.
                let mut connections = Vec::new();
                // we skip accept() errors, they can be caused by retransmits
                while let Some(connecting) = ep.accept().await.and_then(|inc| inc.accept().ok()) {
                    // Just accept incoming connections, but don't do anything with them.
                    let conn = connecting.await.std_context("connecting")?;
                    connections.push(conn);
                }

                Ok::<_, Error>(())
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

/// This module contains end-to-end tests for DNS endpoint discovery.
///
/// The tests run a minimal test DNS server to resolve against, and a minimal pkarr relay to
/// publish to. The DNS and pkarr servers share their state.
#[cfg(test)]
mod test_dns_pkarr {
    use iroh_base::{EndpointAddr, SecretKey};
    use iroh_relay::{RelayMap, endpoint_info::UserData};
    use n0_error::{AnyError as Error, Result, StdResultExt};
    use n0_future::time::Duration;
    use rand::{CryptoRng, SeedableRng};
    use tokio_util::task::AbortOnDropHandle;
    use tracing_test::traced_test;

    use crate::{
        Endpoint, RelayMode,
        discovery::{EndpointData, pkarr::PkarrPublisher},
        dns::DnsResolver,
        endpoint_info::EndpointInfo,
        test_utils::{
            DnsPkarrServer, dns_server::run_dns_server, pkarr_dns_state::State, run_relay_server,
        },
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
            .std_context("Running DNS server")?;

        let secret_key = SecretKey::generate(&mut rng);
        let endpoint_info = EndpointInfo::new(secret_key.public())
            .with_relay_url(Some("https://relay.example".parse().unwrap()));
        let signed_packet = endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?;
        state
            .upsert(signed_packet)
            .std_context("update and insert signed packet")?;

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
            .std_context("DnsPkarrServer")?;

        let secret_key = SecretKey::generate(&mut rng);
        let endpoint_id = secret_key.public();

        let relay_url = Some("https://relay.example".parse().unwrap());

        let resolver = DnsResolver::with_nameserver(dns_pkarr_server.nameserver);
        let publisher =
            PkarrPublisher::builder(dns_pkarr_server.pkarr_url.clone()).build(secret_key);
        let user_data: UserData = "foobar".parse().unwrap();
        let data = EndpointData::new(relay_url.clone(), Default::default())
            .with_user_data(Some(user_data.clone()));
        // does not block, update happens in background task
        publisher.update_endpoint_data(&data);
        // wait until our shared state received the update from pkarr publishing
        dns_pkarr_server
            .on_endpoint(&endpoint_id, PUBLISH_TIMEOUT)
            .await
            .std_context("wait for on endpoint update")?;
        let resolved = resolver
            .lookup_endpoint_by_id(&endpoint_id, &origin)
            .await?;
        println!("resolved {resolved:?}");

        let expected_addr = EndpointAddr {
            endpoint_id,
            relay_url,
            direct_addresses: Default::default(),
        };

        assert_eq!(resolved.to_endpoint_addr(), expected_addr);
        assert_eq!(resolved.user_data(), Some(&user_data));
        Ok(())
    }

    const TEST_ALPN: &[u8] = b"TEST";

    #[tokio::test]
    #[traced_test]
    async fn pkarr_publish_dns_discover() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let dns_pkarr_server = DnsPkarrServer::run()
            .await
            .std_context("DnsPkarrServer run")?;
        let (relay_map, _relay_url, _relay_guard) = run_relay_server().await?;

        let (ep1, _guard1) = ep_with_discovery(&mut rng, &relay_map, &dns_pkarr_server).await?;
        let (ep2, _guard2) = ep_with_discovery(&mut rng, &relay_map, &dns_pkarr_server).await?;

        // wait until our shared state received the update from pkarr publishing
        dns_pkarr_server
            .on_endpoint(&ep1.id(), PUBLISH_TIMEOUT)
            .await
            .std_context("wait for on endpoint update")?;

        // we connect only by endpoint id!
        let _conn = ep2.connect(ep1.id(), TEST_ALPN).await?;
        Ok(())
    }

    async fn ep_with_discovery<R: CryptoRng + ?Sized>(
        rng: &mut R,
        relay_map: &RelayMap,
        dns_pkarr_server: &DnsPkarrServer,
    ) -> Result<(Endpoint, AbortOnDropHandle<Result<()>>)> {
        let secret_key = SecretKey::generate(rng);
        let ep = Endpoint::empty_builder(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .secret_key(secret_key.clone())
            .alpns(vec![TEST_ALPN.to_vec()])
            .dns_resolver(dns_pkarr_server.dns_resolver())
            .discovery(dns_pkarr_server.discovery(secret_key))
            .bind()
            .await?;

        let handle = tokio::spawn({
            let ep = ep.clone();
            async move {
                // we skip accept() errors, they can be caused by retransmits
                while let Some(connecting) = ep.accept().await.and_then(|inc| inc.accept().ok()) {
                    let _conn = connecting.await.std_context("connecting")?;
                    // Just accept incoming connections, but don't do anything with them.
                }

                Ok::<_, Error>(())
            }
        });

        Ok((ep, AbortOnDropHandle::new(handle)))
    }
}
