//! Node address discovery.
//!
//! To connect to an iroh node a [`NodeAddr`] is needed, which may contain a
//! [`RelayUrl`] or one or more *direct addresses* in addition to the [`NodeId`].
//!
//! Since there is a conversion from [`NodeId`] to [`NodeAddr`], you can also use
//! connect directly with a [`NodeId`].
//!
//! For this to work however, the endpoint has to get the addressing  information by
//! other means.
//!
//! Node discovery is an automated system for an [`Endpoint`] to retrieve this addressing
//! information.  Each iroh node will automatically publish their own addressing
//! information.  Usually this means publishing which [`RelayUrl`] to use for their
//! [`NodeId`], but they could also publish their direct addresses.
//!
//! The [`Discovery`] trait is used to define node discovery.  This allows multiple
//! implementations to co-exist because there are many possible ways to implement this.
//! Each [`Endpoint`] can use the discovery mechanisms most suitable to the application.
//! The [`Builder::add_discovery`] method is used to add a discovery mechanism to an
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
//!   opinionated mDNS implementation, to discover nodes on the local network.
//!
//! - The [`DhtDiscovery`] also uses the [`pkarr`] system but can also publish and lookup
//!   records to/from the Mainline DHT.
//!
//! To use multiple discovery systems simultaneously you can call [`Builder::add_discovery`].
//! This will use [`ConcurrentDiscovery`] under the hood, which performs lookups to all
//! discovery systems at the same time.
//!
//! [`Builder::add_discovery`] takes any type that implements [`IntoDiscovery`]. You can
//! implement that trait on a builder struct if your discovery service needs information
//! from the endpoint it is mounted on. During endpoint construction, your discovery service
//! is built by calling [`IntoDiscovery::into_discovery`], passing a [`DiscoveryContext`] to your
//! builder. The [`DiscoveryContext`] gives access to the endpoint's secret key and DNS resolver.
//!
//! If your discovery service does not need any information from its endpoint, you can
//! pass the discovery service directly to [`Builder::add_discovery`]: All types that
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
//! };
//!
//! # async fn wrapper() -> n0_snafu::Result<()> {
//! let ep = Endpoint::builder()
//!     .add_discovery(PkarrPublisher::n0_dns())
//!     .add_discovery(DnsDiscovery::n0_dns())
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
//! #    Endpoint, SecretKey,
//! # };
//! #
//! # async fn wrapper() -> n0_snafu::Result<()> {
//! let ep = Endpoint::builder()
//!     .add_discovery(PkarrPublisher::n0_dns())
//!     .add_discovery(DnsDiscovery::n0_dns())
//!     .add_discovery(MdnsDiscovery::builder())
//!     .bind()
//!     .await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! [`NodeAddr`]: iroh_base::NodeAddr
//! [`RelayUrl`]: crate::RelayUrl
//! [`Builder::add_discovery`]: crate::endpoint::Builder::add_discovery
//! [`DnsDiscovery`]: dns::DnsDiscovery
//! [Number 0]: https://n0.computer
//! [`PkarrResolver`]: pkarr::PkarrResolver
//! [`PkarrPublisher`]: pkarr::PkarrPublisher
//! [`DhtDiscovery`]: pkarr::dht::DhtDiscovery
//! [pkarr relay servers]: https://pkarr.org/#servers
//! [`MdnsDiscovery`]: mdns::MdnsDiscovery
//! [`StaticProvider`]: static_provider::StaticProvider

use std::sync::{Arc, RwLock};

use iroh_base::{NodeAddr, NodeId};
use n0_future::{
    boxed::BoxStream,
    stream::StreamExt,
    task::{self, AbortOnDropHandle},
    time::{self, Duration},
};
use nested_enum_utils::common_fields;
use snafu::{IntoError, Snafu, ensure};
use tokio::sync::oneshot;
use tracing::{Instrument, debug, error_span, warn};

#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
pub use crate::node_info::{NodeData, NodeInfo, ParseError, UserData};
use crate::{Endpoint, SecretKey};

#[cfg(not(wasm_browser))]
pub mod dns;

#[cfg(feature = "discovery-local-network")]
pub mod mdns;
pub mod pkarr;
pub mod static_provider;

/// Trait for structs that can be converted into [`Discovery`].
///
/// This trait is implemented on builders for discovery services. Any type that implements this
/// trait can be added as a discovery service in [`Builder::add_discovery`].
///
/// Any type that implements [`Discovery`] also implements [`IntoDiscovery`].
///
/// Iroh uses this trait to allow configuring the set of discovery services on the endpoint
/// builder, while providing the discovery services access to information about the endpoint
/// creation via the [`DiscoveryContext`] parameter to [`IntoDiscovery::into_discovery`].
///
/// [`Builder::add_discovery`]: crate::endpoint::Builder::add_discovery
pub trait IntoDiscovery: Send + Sync + std::fmt::Debug + 'static {
    /// Turns this discovery builder into a ready-to-use discovery service.
    ///
    /// The [`DiscoveryContext`] contains information about the [`Endpoint`] onto which this
    /// discovery service is being added. It can be used by discovery services that need
    /// a DNS resolver, or the endpoint's secret key to sign messages.
    ///
    /// If an error is returned, building the endpoint will fail with this error.
    fn into_discovery(
        self,
        context: &DiscoveryContext,
    ) -> Result<impl Discovery, IntoDiscoveryError>;
}

/// Blanket no-op impl of `IntoDiscovery` for `T: Discovery`.
impl<T: Discovery> IntoDiscovery for T {
    fn into_discovery(
        self,
        _context: &DiscoveryContext,
    ) -> Result<impl Discovery, IntoDiscoveryError> {
        Ok(self)
    }
}

/// Non-public dyn-compatible version of [`IntoDiscovery`], used in [`crate::endpoint::Builder`].
pub(crate) trait DynIntoDiscovery: Send + Sync + std::fmt::Debug + 'static {
    /// See [`IntoDiscovery::into_discovery`]
    fn into_discovery(
        self: Box<Self>,
        context: &DiscoveryContext,
    ) -> Result<Box<dyn Discovery>, IntoDiscoveryError>;
}

impl<T: IntoDiscovery> DynIntoDiscovery for T {
    fn into_discovery(
        self: Box<Self>,
        context: &DiscoveryContext,
    ) -> Result<Box<dyn Discovery>, IntoDiscoveryError> {
        let disco: Box<dyn Discovery> = Box::new(IntoDiscovery::into_discovery(*self, context)?);
        Ok(disco)
    }
}

/// Context about the [`Endpoint`] for discovery services.
#[derive(Debug)]
pub struct DiscoveryContext<'a> {
    #[cfg(not(wasm_browser))]
    pub(crate) dns_resolver: &'a DnsResolver,
    pub(crate) secret_key: &'a SecretKey,
}

impl DiscoveryContext<'_> {
    /// Returns the [`NodeId`] of the endpoint.
    pub fn node_id(&self) -> NodeId {
        self.secret_key.public()
    }

    /// Returns the [`SecretKey`] of the endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        self.secret_key
    }

    /// Returns the [`DnsResolver`] used by the endpoint.
    #[cfg(not(wasm_browser))]
    pub fn dns_resolver(&self) -> &DnsResolver {
        self.dns_resolver
    }
}

/// IntoDiscovery errors
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(module)]
pub enum IntoDiscoveryError {
    #[snafu(display("Service '{provenance}' error"))]
    User {
        provenance: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl IntoDiscoveryError {
    /// Creates a new user error from an arbitrary error type.
    pub fn from_err<T: std::error::Error + Send + Sync + 'static>(
        provenance: &'static str,
        source: T,
    ) -> Self {
        into_discovery_error::UserSnafu { provenance }.into_error(Box::new(source))
    }

    /// Creates a new user error from an arbitrary boxed error type.
    pub fn from_err_box(
        provenance: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        into_discovery_error::UserSnafu { provenance }.into_error(source)
    }
}

/// Discovery errors
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DiscoveryError {
    #[snafu(display("No discovery service configured"))]
    NoServiceConfigured {},
    #[snafu(display("Discovery produced no results for {}", node_id.fmt_short()))]
    NoResults { node_id: NodeId },
    #[snafu(display("Service '{provenance}' error"))]
    User {
        provenance: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl DiscoveryError {
    /// Creates a new user error from an arbitrary error type.
    pub fn from_err<T: std::error::Error + Send + Sync + 'static>(
        provenance: &'static str,
        source: T,
    ) -> Self {
        UserSnafu { provenance }.into_error(Box::new(source))
    }

    /// Creates a new user error from an arbitrary boxed error type.
    pub fn from_err_box(
        provenance: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        UserSnafu { provenance }.into_error(source)
    }
}

/// Node discovery for [`super::Endpoint`].
///
/// This trait defines publishing and resolving addressing information for a [`NodeId`].
/// This enables connecting to other nodes with only knowing the [`NodeId`], by using this
/// [`Discovery`] system to look up the actual addressing information.  It is common for
/// implementations to require each node to publish their own information before it can be
/// looked up by other nodes.
///
/// The published addressing information can include both a [`RelayUrl`] and/or direct
/// addresses. See [`NodeData`] for details.
///
/// To allow for discovery, the [`super::Endpoint`] will call `publish` whenever
/// discovery information changes. If a discovery mechanism requires a periodic
/// refresh, it should start its own task.
///
/// [`RelayUrl`]: crate::RelayUrl
pub trait Discovery: std::fmt::Debug + Send + Sync + 'static {
    /// Publishes the given [`NodeData`] to the discovery mechanism.
    ///
    /// This is fire and forget, since the [`Endpoint`] can not wait for successful
    /// publishing. If publishing is async, the implementation should start it's own task.
    ///
    /// This will be called from a tokio task, so it is safe to spawn new tasks.
    /// These tasks will be run on the runtime of the [`super::Endpoint`].
    fn publish(&self, _data: &NodeData) {}

    /// Resolves the [`DiscoveryItem`] for the given [`NodeId`].
    ///
    /// Once the returned [`BoxStream`] is dropped, the service should stop any pending
    /// work.
    fn resolve(
        &self,
        _node_id: NodeId,
    ) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        None
    }
}

impl<T: Discovery> Discovery for Arc<T> {
    fn publish(&self, data: &NodeData) {
        self.as_ref().publish(data);
    }

    fn resolve(&self, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        self.as_ref().resolve(node_id)
    }
}

/// Node discovery results from [`Discovery`] services.
///
/// This is the item in the streams returned from [`Discovery::resolve`].
/// It contains the [`NodeData`] about the discovered node,
/// and some additional metadata about the discovery.
///
/// This struct derefs to [`NodeData`], so you can access the methods from [`NodeData`]
/// directly from [`DiscoveryItem`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DiscoveryItem {
    /// The node info for the node, as discovered by the the discovery service.
    node_info: NodeInfo,
    /// A static string to identify the discovery source.
    ///
    /// Should be uniform per discovery service.
    provenance: &'static str,
    /// Optional timestamp when this node address info was last updated.
    ///
    /// Must be microseconds since the unix epoch.
    // TODO(ramfox): this is currently unused. As we develop more `DiscoveryService`s, we may discover that we do not need this. It is only truly relevant when comparing `relay_urls`, since we can attempt to dial any number of socket addresses, but expect each node to have one "home relay" that we will attempt to contact them on. This means we would need some way to determine which relay url to choose between, if more than one relay url is reported.
    last_updated: Option<u64>,
}

impl DiscoveryItem {
    /// Creates a new [`DiscoveryItem`] from a [`NodeInfo`].
    pub fn new(node_info: NodeInfo, provenance: &'static str, last_updated: Option<u64>) -> Self {
        Self {
            node_info,
            provenance,
            last_updated,
        }
    }

    /// Returns the node id of the discovered node.
    pub fn node_id(&self) -> NodeId {
        self.node_info.node_id
    }

    /// Returns the [`NodeInfo`] for the discovered node.
    pub fn node_info(&self) -> &NodeInfo {
        &self.node_info
    }

    /// Returns the provenance of this discovery item.
    ///
    /// The provenance is a static string which identifies the discovery service that produced
    /// this discovery item.
    pub fn provenance(&self) -> &'static str {
        self.provenance
    }

    /// Returns the optional timestamp when this node info was last updated.
    ///
    /// The value is microseconds since the unix epoch.
    pub fn last_updated(&self) -> Option<u64> {
        self.last_updated
    }

    /// Converts into a [`NodeAddr`] by cloning the needed fields.
    pub fn to_node_addr(&self) -> NodeAddr {
        self.node_info.to_node_addr()
    }

    /// Converts into a [`NodeAddr`] without cloning.
    pub fn into_node_addr(self) -> NodeAddr {
        self.node_info.into_node_addr()
    }

    /// Returns any user-defined data.
    pub fn user_data(&self) -> Option<UserData> {
        self.node_info().data.user_data().cloned()
    }
}

impl std::ops::Deref for DiscoveryItem {
    type Target = NodeData;
    fn deref(&self) -> &Self::Target {
        &self.node_info.data
    }
}

impl From<DiscoveryItem> for NodeInfo {
    fn from(item: DiscoveryItem) -> Self {
        item.node_info
    }
}

/// A discovery service that combines multiple discovery sources.
///
/// The discovery services will resolve concurrently.
#[derive(Debug, Default, Clone)]
pub struct ConcurrentDiscovery {
    services: Arc<RwLock<Vec<Box<dyn Discovery>>>>,
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
        }
    }

    /// Adds a [`Discovery`] service.
    pub fn add(&self, service: impl Discovery + 'static) {
        self.services
            .write()
            .expect("poisoned")
            .push(Box::new(service));
    }

    /// Is there any services configured?
    pub fn is_empty(&self) -> bool {
        self.services.read().expect("poisoned").is_empty()
    }

    /// How many services are configured
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
        }
    }
}

impl Discovery for ConcurrentDiscovery {
    fn publish(&self, data: &NodeData) {
        let services = self.services.read().expect("poisoned");
        for service in &*services {
            service.publish(data);
        }
    }

    fn resolve(&self, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        let services = self.services.read().expect("poisoned");
        let streams = services
            .iter()
            .filter_map(|service| service.resolve(node_id));

        let streams = n0_future::MergeBounded::from_iter(streams);
        Some(Box::pin(streams))
    }
}

/// Maximum duration since the last control or data message received from an endpoint to make us
/// start a discovery task.
const MAX_AGE: Duration = Duration::from_secs(10);

/// A wrapper around a tokio task which runs a node discovery.
pub(super) struct DiscoveryTask {
    on_first_rx: oneshot::Receiver<Result<(), DiscoveryError>>,
    _task: AbortOnDropHandle<()>,
}

impl DiscoveryTask {
    /// Starts a discovery task.
    pub(super) fn start(ep: Endpoint, node_id: NodeId) -> Result<Self, DiscoveryError> {
        ensure!(!ep.discovery().is_empty(), NoServiceConfiguredSnafu);
        let (on_first_tx, on_first_rx) = oneshot::channel();
        let me = ep.node_id();
        let task = task::spawn(
            async move { Self::run(ep, node_id, on_first_tx).await }.instrument(
                error_span!("discovery", me = %me.fmt_short(), node = %node_id.fmt_short()),
            ),
        );
        Ok(Self {
            _task: AbortOnDropHandle::new(task),
            on_first_rx,
        })
    }

    /// Starts a discovery task after a delay and only if no path to the node was recently active.
    ///
    /// This returns `None` if we received data or control messages from the remote endpoint
    /// recently enough. If not it returns a [`DiscoveryTask`].
    ///
    /// If `delay` is set, the [`DiscoveryTask`] will first wait for `delay` and then check again
    /// if we recently received messages from remote endpoint. If true, the task will abort.
    /// Otherwise, or if no `delay` is set, the discovery will be started.
    pub(super) fn start_after_delay(
        ep: &Endpoint,
        node_id: NodeId,
        delay: Duration,
    ) -> Result<Option<Self>, DiscoveryError> {
        // If discovery is not needed, don't even spawn a task.
        ensure!(!ep.discovery().is_empty(), NoServiceConfiguredSnafu);
        let (on_first_tx, on_first_rx) = oneshot::channel();
        let ep = ep.clone();
        let me = ep.node_id();
        let task = task::spawn(
            async move {
                time::sleep(delay).await;
                Self::run(ep, node_id, on_first_tx).await
            }
            .instrument(
                error_span!("discovery", me = %me.fmt_short(), node = %node_id.fmt_short()),
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
        node_id: NodeId,
    ) -> Result<BoxStream<Result<DiscoveryItem, DiscoveryError>>, DiscoveryError> {
        ensure!(!ep.discovery().is_empty(), NoServiceConfiguredSnafu);
        let stream = ep
            .discovery()
            .resolve(node_id)
            .ok_or(NoResultsSnafu { node_id }.build())?;
        Ok(stream)
    }

    async fn run(
        ep: Endpoint,
        node_id: NodeId,
        on_first_tx: oneshot::Sender<Result<(), DiscoveryError>>,
    ) {
        let mut stream = match Self::create_stream(&ep, node_id) {
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
                    let node_addr = r.to_node_addr();
                    if node_addr.is_empty() {
                        debug!(%provenance, "empty address found");
                        continue;
                    }
                    debug!(%provenance, addr = ?node_addr, "new address found");
                    ep.add_node_addr_with_source(node_addr, provenance)
                        .await
                        .ok();
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
            tx.send(Err(NoResultsSnafu { node_id }.build())).ok();
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

    use iroh_base::{NodeAddr, SecretKey};
    use n0_snafu::{Error, Result, ResultExt};
    use n0_watcher::Watcher as _;
    use quinn::{IdleTimeout, TransportConfig};
    use rand::{Rng, SeedableRng};
    use tokio_util::task::AbortOnDropHandle;
    use tracing_test::traced_test;

    use super::*;
    use crate::{Endpoint, RelayMode, endpoint::ConnectOptions};

    type InfoStore = HashMap<NodeId, (NodeData, u64)>;

    #[derive(Debug, Clone, Default)]
    struct TestDiscoveryShared {
        nodes: Arc<Mutex<InfoStore>>,
    }

    impl TestDiscoveryShared {
        pub fn create_discovery(&self, node_id: NodeId) -> TestDiscovery {
            TestDiscovery {
                node_id,
                shared: self.clone(),
                publish: true,
                resolve_wrong: false,
                delay: Duration::from_millis(200),
            }
        }

        pub fn create_lying_discovery(&self, node_id: NodeId) -> TestDiscovery {
            TestDiscovery {
                node_id,
                shared: self.clone(),
                publish: false,
                resolve_wrong: true,
                delay: Duration::from_millis(100),
            }
        }
    }

    #[derive(Debug)]
    struct TestDiscovery {
        node_id: NodeId,
        shared: TestDiscoveryShared,
        publish: bool,
        resolve_wrong: bool,
        delay: Duration,
    }

    impl Discovery for TestDiscovery {
        fn publish(&self, data: &NodeData) {
            if !self.publish {
                return;
            }
            let now = system_time_now();
            self.shared
                .nodes
                .lock()
                .unwrap()
                .insert(self.node_id, (data.clone(), now));
        }

        fn resolve(
            &self,
            node_id: NodeId,
        ) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
            let addr_info = if self.resolve_wrong {
                let ts = system_time_now() - 100_000;
                let port: u16 = rand::rng().random_range(10_000..20_000);
                // "240.0.0.0/4" is reserved and unreachable
                let addr: SocketAddr = format!("240.0.0.1:{port}").parse().unwrap();
                let data = NodeData::new(None, BTreeSet::from([addr]));
                Some((data, ts))
            } else {
                self.shared.nodes.lock().unwrap().get(&node_id).cloned()
            };
            let stream = match addr_info {
                Some((data, ts)) => {
                    let item = DiscoveryItem::new(
                        NodeInfo::from_parts(node_id, data),
                        "test-disco",
                        Some(ts),
                    );
                    let delay = self.delay;
                    let fut = async move {
                        time::sleep(delay).await;
                        tracing::debug!("resolve: {} = {item:?}", node_id.fmt_short());
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
        fn publish(&self, _data: &NodeData) {}

        fn resolve(
            &self,
            _node_id: NodeId,
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
        let (ep1, _guard1) = {
            let secret = SecretKey::generate(&mut rng);
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let (ep2, _guard2) = {
            let secret = SecretKey::generate(&mut rng);
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let ep1_addr = NodeAddr::new(ep1.node_id());
        // wait for our address to be updated and thus published at least once
        ep1.watch_node_addr().initialized().await;
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
        let (ep1, _guard1) = {
            let secret = SecretKey::generate(&mut rng);
            let disco = disco_shared.create_discovery(secret.public());
            let disco = Arc::new(disco);
            new_endpoint(secret, disco).await
        };
        let (ep2, _guard2) = {
            let secret = SecretKey::generate(&mut rng);
            let disco = disco_shared.create_discovery(secret.public());
            let disco = Arc::new(disco);
            new_endpoint(secret, disco).await
        };
        let ep1_addr = NodeAddr::new(ep1.node_id());
        // wait for our address to be updated and thus published at least once
        ep1.watch_node_addr().initialized().await;
        let _conn = ep2.connect(ep1_addr, TEST_ALPN).await?;
        Ok(())
    }

    /// This test adds an empty discovery which provides no addresses.
    #[tokio::test]
    #[traced_test]
    async fn endpoint_discovery_combined_with_empty() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let disco_shared = TestDiscoveryShared::default();
        let (ep1, _guard1) = {
            let secret = SecretKey::generate(&mut rng);
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let (ep2, _guard2) = {
            let secret = SecretKey::generate(&mut rng);
            let disco1 = EmptyDiscovery;
            let disco2 = disco_shared.create_discovery(secret.public());
            let disco = ConcurrentDiscovery::empty();
            disco.add(disco1);
            disco.add(disco2);
            new_endpoint(secret, disco).await
        };
        let ep1_addr = NodeAddr::new(ep1.node_id());
        // wait for out address to be updated and thus published at least once
        ep1.watch_node_addr().initialized().await;
        let _conn = ep2
            .connect(ep1_addr, TEST_ALPN)
            .await
            .context("connecting")?;
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
        let (ep1, _guard1) = {
            let secret = SecretKey::generate(&mut rng);
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let (ep2, _guard2) = {
            let secret = SecretKey::generate(&mut rng);
            let disco1 = EmptyDiscovery;
            let disco2 = disco_shared.create_lying_discovery(secret.public());
            let disco3 = disco_shared.create_discovery(secret.public());
            let disco = ConcurrentDiscovery::empty();
            disco.add(disco1);
            disco.add(disco2);
            disco.add(disco3);
            new_endpoint(secret, disco).await
        };
        // wait for out address to be updated and thus published at least once
        ep1.watch_node_addr().initialized().await;
        let _conn = ep2.connect(ep1.node_id(), TEST_ALPN).await?;
        Ok(())
    }

    /// This test only has the "lying" discovery. It is here to make sure that this actually fails.
    #[tokio::test]
    #[traced_test]
    async fn endpoint_discovery_combined_wrong_only() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let disco_shared = TestDiscoveryShared::default();
        let (ep1, _guard1) = {
            let secret = SecretKey::generate(&mut rng);
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let (ep2, _guard2) = {
            let secret = SecretKey::generate(&mut rng);
            let disco1 = disco_shared.create_lying_discovery(secret.public());
            let disco = ConcurrentDiscovery::from_services(vec![Box::new(disco1)]);
            new_endpoint(secret, disco).await
        };
        // wait for out address to be updated and thus published at least once
        ep1.watch_node_addr().initialized().await;

        // 10x faster test via a 3s idle timeout instead of the 30s default
        let mut config = TransportConfig::default();
        config.keep_alive_interval(Some(Duration::from_secs(1)));
        config.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(3)).unwrap()));
        let opts = ConnectOptions::new().with_transport_config(Arc::new(config));

        let res = ep2
            .connect_with_opts(ep1.node_id(), TEST_ALPN, opts)
            .await? // -> Connecting works
            .await; // -> Connection is expected to fail
        assert!(res.is_err());
        Ok(())
    }

    /// This test first adds a wrong address manually (e.g. from an outdated&node_id ticket).
    /// Connect should still succeed because the discovery service will be invoked (after a delay).
    #[tokio::test]
    #[traced_test]
    async fn endpoint_discovery_with_wrong_existing_addr() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let disco_shared = TestDiscoveryShared::default();
        let (ep1, _guard1) = {
            let secret = SecretKey::generate(&mut rng);
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let (ep2, _guard2) = {
            let secret = SecretKey::generate(&mut rng);
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        // wait for out address to be updated and thus published at least once
        ep1.watch_node_addr().initialized().await;
        let ep1_wrong_addr = NodeAddr {
            node_id: ep1.node_id(),
            relay_url: None,
            direct_addresses: BTreeSet::from(["240.0.0.1:1000".parse().unwrap()]),
        };
        let _conn = ep2.connect(ep1_wrong_addr, TEST_ALPN).await?;
        Ok(())
    }

    async fn new_endpoint(
        secret: SecretKey,
        disco: impl IntoDiscovery + 'static,
    ) -> (Endpoint, AbortOnDropHandle<Result<()>>) {
        let ep = Endpoint::builder()
            .secret_key(secret)
            .add_discovery(disco)
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();

        let handle = tokio::spawn({
            let ep = ep.clone();
            async move {
                // Keep connections alive until the task is dropped.
                let mut connections = Vec::new();
                // we skip accept() errors, they can be caused by retransmits
                while let Some(connecting) = ep.accept().await.and_then(|inc| inc.accept().ok()) {
                    // Just accept incoming connections, but don't do anything with them.
                    let conn = connecting.await.context("connecting")?;
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

/// This module contains end-to-end tests for DNS node discovery.
///
/// The tests run a minimal test DNS server to resolve against, and a minimal pkarr relay to
/// publish to. The DNS and pkarr servers share their state.
#[cfg(test)]
mod test_dns_pkarr {
    use iroh_base::{NodeAddr, SecretKey};
    use iroh_relay::{RelayMap, node_info::UserData};
    use n0_future::time::Duration;
    use n0_snafu::{Error, Result, ResultExt};
    use rand::{CryptoRng, SeedableRng};
    use tokio_util::task::AbortOnDropHandle;
    use tracing_test::traced_test;

    use crate::{
        Endpoint, RelayMode,
        discovery::{NodeData, pkarr::PkarrPublisher},
        dns::DnsResolver,
        node_info::NodeInfo,
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
            .context("Running DNS server")?;

        let secret_key = SecretKey::generate(&mut rng);
        let node_info = NodeInfo::new(secret_key.public())
            .with_relay_url(Some("https://relay.example".parse().unwrap()));
        let signed_packet = node_info.to_pkarr_signed_packet(&secret_key, 30)?;
        state
            .upsert(signed_packet)
            .context("update and insert signed packet")?;

        let resolver = DnsResolver::with_nameserver(nameserver);
        let resolved = resolver
            .lookup_node_by_id(&node_info.node_id, &origin)
            .await?;

        assert_eq!(resolved, node_info);

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
        let node_id = secret_key.public();

        let relay_url = Some("https://relay.example".parse().unwrap());

        let resolver = DnsResolver::with_nameserver(dns_pkarr_server.nameserver);
        let publisher =
            PkarrPublisher::builder(dns_pkarr_server.pkarr_url.clone()).build(secret_key);
        let user_data: UserData = "foobar".parse().unwrap();
        let data = NodeData::new(relay_url.clone(), Default::default())
            .with_user_data(Some(user_data.clone()));
        // does not block, update happens in background task
        publisher.update_node_data(&data);
        // wait until our shared state received the update from pkarr publishing
        dns_pkarr_server
            .on_node(&node_id, PUBLISH_TIMEOUT)
            .await
            .context("wait for on node update")?;
        let resolved = resolver.lookup_node_by_id(&node_id, &origin).await?;
        println!("resolved {resolved:?}");

        let expected_addr = NodeAddr {
            node_id,
            relay_url,
            direct_addresses: Default::default(),
        };

        assert_eq!(resolved.to_node_addr(), expected_addr);
        assert_eq!(resolved.user_data(), Some(&user_data));
        Ok(())
    }

    const TEST_ALPN: &[u8] = b"TEST";

    #[tokio::test]
    #[traced_test]
    async fn pkarr_publish_dns_discover() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let dns_pkarr_server = DnsPkarrServer::run().await.context("DnsPkarrServer run")?;
        let (relay_map, _relay_url, _relay_guard) = run_relay_server().await?;

        let (ep1, _guard1) = ep_with_discovery(&mut rng, &relay_map, &dns_pkarr_server).await?;
        let (ep2, _guard2) = ep_with_discovery(&mut rng, &relay_map, &dns_pkarr_server).await?;

        // wait until our shared state received the update from pkarr publishing
        dns_pkarr_server
            .on_node(&ep1.node_id(), PUBLISH_TIMEOUT)
            .await
            .context("wait for on node update")?;

        // we connect only by node id!
        let _conn = ep2.connect(ep1.node_id(), TEST_ALPN).await?;
        Ok(())
    }

    async fn ep_with_discovery<R: CryptoRng + ?Sized>(
        rng: &mut R,
        relay_map: &RelayMap,
        dns_pkarr_server: &DnsPkarrServer,
    ) -> Result<(Endpoint, AbortOnDropHandle<Result<()>>)> {
        let secret_key = SecretKey::generate(rng);
        let ep = Endpoint::builder()
            .relay_mode(RelayMode::Custom(relay_map.clone()))
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
                    let _conn = connecting.await.context("connecting")?;
                    // Just accept incoming connections, but don't do anything with them.
                }

                Ok::<_, Error>(())
            }
        });

        Ok((ep, AbortOnDropHandle::new(handle)))
    }
}
