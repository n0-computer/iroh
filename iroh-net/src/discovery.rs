//! Trait and utils for the node discovery mechanism.

use std::time::Duration;

use anyhow::{anyhow, ensure, Result};
use futures::{stream::BoxStream, StreamExt};
use iroh_base::node_addr::NodeAddr;
use tokio::{sync::oneshot, task::JoinHandle};
use tracing::{debug, error_span, warn, Instrument};

use crate::{AddrInfo, MagicEndpoint, NodeId};

pub mod dns;
pub mod pkarr_publish;

/// Node discovery for [`super::MagicEndpoint`].
///
/// The purpose of this trait is to hook up a node discovery mechanism that
/// allows finding information such as the relay URL and direct addresses
/// of a node given its [`NodeId`].
///
/// To allow for discovery, the [`super::MagicEndpoint`] will call `publish` whenever
/// discovery information changes. If a discovery mechanism requires a periodic
/// refresh, it should start its own task.
pub trait Discovery: std::fmt::Debug + Send + Sync {
    /// Publish the given [`AddrInfo`] to the discovery mechanisms.
    ///
    /// This is fire and forget, since the magicsock can not wait for successful
    /// publishing. If publishing is async, the implementation should start it's
    /// own task.
    ///
    /// This will be called from a tokio task, so it is safe to spawn new tasks.
    /// These tasks will be run on the runtime of the [`super::MagicEndpoint`].
    fn publish(&self, _info: &AddrInfo) {}

    /// Resolve the [`AddrInfo`] for the given [`NodeId`].
    ///
    /// Once the returned [`BoxStream`] is dropped, the service should stop any pending
    /// work.
    fn resolve(
        &self,
        _endpoint: MagicEndpoint,
        _node_id: NodeId,
    ) -> Option<BoxStream<'_, Result<DiscoveryItem>>> {
        None
    }
}

/// The results returned from [`Discovery::resolve`].
#[derive(Debug, Clone)]
pub struct DiscoveryItem {
    /// A static string to identify the discovery source.
    ///
    /// Should be uniform per discovery service.
    pub provenance: &'static str,
    /// Optional timestamp when this node address info was last updated.
    ///
    /// Must be microseconds since the unix epoch.
    pub last_updated: Option<u64>,
    /// The adress info for the node being resolved.
    pub addr_info: AddrInfo,
}

/// A discovery service that combines multiple discovery sources.
///
/// The discovery services will resolve concurrently.
#[derive(Debug, Default)]
pub struct ConcurrentDiscovery {
    services: Vec<Box<dyn Discovery>>,
}

impl ConcurrentDiscovery {
    /// Create a empty [`ConcurrentDiscovery`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create a new [`ConcurrentDiscovery`].
    pub fn new(services: Vec<Box<dyn Discovery>>) -> Self {
        Self { services }
    }

    /// Add a [`Discovery`] service.
    pub fn add(&mut self, service: impl Discovery + 'static) {
        self.services.push(Box::new(service));
    }
}

impl<T> From<T> for ConcurrentDiscovery
where
    T: IntoIterator<Item = Box<dyn Discovery>>,
{
    fn from(iter: T) -> Self {
        let services = iter.into_iter().collect::<Vec<_>>();
        Self { services }
    }
}

impl Discovery for ConcurrentDiscovery {
    fn publish(&self, info: &AddrInfo) {
        for service in &self.services {
            service.publish(info);
        }
    }

    fn resolve(
        &self,
        endpoint: MagicEndpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<'_, Result<DiscoveryItem>>> {
        let streams = self
            .services
            .iter()
            .filter_map(|service| service.resolve(endpoint.clone(), node_id));
        let streams = futures::stream::select_all(streams);
        Some(Box::pin(streams))
    }
}

/// Maximum duration since the last control or data message received from an endpoint to make us
/// start a discovery task.
const MAX_AGE: Duration = Duration::from_secs(10);

/// A wrapper around a tokio task which runs a node discovery.
pub(super) struct DiscoveryTask {
    on_first_rx: oneshot::Receiver<Result<()>>,
    task: JoinHandle<()>,
}

impl DiscoveryTask {
    /// Start a discovery task.
    pub fn start(ep: MagicEndpoint, node_id: NodeId) -> Result<Self> {
        ensure!(ep.discovery().is_some(), "No discovery services configured");
        let (on_first_tx, on_first_rx) = oneshot::channel();
        let me = ep.node_id();
        let task = tokio::task::spawn(
            async move { Self::run(ep, node_id, on_first_tx).await }.instrument(
                error_span!("discovery", me = %me.fmt_short(), node = %node_id.fmt_short()),
            ),
        );
        Ok(Self { task, on_first_rx })
    }

    /// Start a discovery task after a delay and only if no path to the node was recently active.
    ///
    /// This returns `None` if we received data or control messages from the remote endpoint
    /// recently enough. If not it returns a [`DiscoveryTask`].
    ///
    /// If `delay` is set, the [`DiscoveryTask`] will first wait for `delay` and then check again
    /// if we recently received messages from remote endpoint. If true, the task will abort.
    /// Otherwise, or if no `delay` is set, the discovery will be started.
    pub fn maybe_start_after_delay(
        ep: &MagicEndpoint,
        node_id: NodeId,
        delay: Option<Duration>,
    ) -> Result<Option<Self>> {
        // If discovery is not needed, don't even spawn a task.
        if !Self::needs_discovery(ep, node_id) {
            return Ok(None);
        }
        ensure!(ep.discovery().is_some(), "No discovery services configured");
        let (on_first_tx, on_first_rx) = oneshot::channel();
        let ep = ep.clone();
        let me = ep.node_id();
        let task = tokio::task::spawn(
            async move {
                // If delay is set, wait and recheck if discovery is needed. If not, early-exit.
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                    if !Self::needs_discovery(&ep, node_id) {
                        debug!("no discovery needed, abort");
                        on_first_tx.send(Ok(())).ok();
                        return;
                    }
                }
                Self::run(ep, node_id, on_first_tx).await
            }
            .instrument(
                error_span!("discovery", me = %me.fmt_short(), node = %node_id.fmt_short()),
            ),
        );
        Ok(Some(Self { task, on_first_rx }))
    }

    /// Wait until the discovery task produced at least one result.
    pub async fn first_arrived(&mut self) -> Result<()> {
        let fut = &mut self.on_first_rx;
        fut.await??;
        Ok(())
    }

    /// Cancel the discovery task.
    pub fn cancel(&self) {
        self.task.abort();
    }

    fn create_stream(
        ep: &MagicEndpoint,
        node_id: NodeId,
    ) -> Result<BoxStream<'_, Result<DiscoveryItem>>> {
        let discovery = ep
            .discovery()
            .ok_or_else(|| anyhow!("No discovery service configured"))?;
        let stream = discovery
            .resolve(ep.clone(), node_id)
            .ok_or_else(|| anyhow!("No discovery service can resolve node {node_id}",))?;
        Ok(stream)
    }

    fn needs_discovery(ep: &MagicEndpoint, node_id: NodeId) -> bool {
        match ep.connection_info(node_id) {
            // No connection info means no path to node -> start discovery.
            None => true,
            Some(info) => match info.last_received() {
                // No path to node -> start discovery.
                None => true,
                // If we haven't received for MAX_AGE, start discovery.
                Some(elapsed) => elapsed > MAX_AGE,
            },
        }
    }

    async fn run(ep: MagicEndpoint, node_id: NodeId, on_first_tx: oneshot::Sender<Result<()>>) {
        let mut stream = match Self::create_stream(&ep, node_id) {
            Ok(stream) => stream,
            Err(err) => {
                on_first_tx.send(Err(err)).ok();
                return;
            }
        };
        let mut on_first_tx = Some(on_first_tx);
        debug!("discovery: start");
        loop {
            let next = tokio::select! {
                _ = ep.cancelled() => break,
                next = stream.next() => next
            };
            match next {
                Some(Ok(r)) => {
                    debug!(provenance = %r.provenance, addr = ?r.addr_info, "discovery: new address found");
                    let addr = NodeAddr {
                        info: r.addr_info,
                        node_id,
                    };
                    ep.add_node_addr(addr).ok();
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
            let err = anyhow!("Discovery produced no results for {}", node_id.fmt_short());
            tx.send(Err(err)).ok();
        }
    }
}

impl Drop for DiscoveryTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap},
        net::SocketAddr,
        sync::Arc,
        time::{Duration, SystemTime},
    };

    use futures::{stream, StreamExt};
    use parking_lot::Mutex;
    use rand::Rng;

    use crate::{key::SecretKey, relay::RelayMode, NodeAddr};

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct TestDiscoveryShared {
        nodes: Arc<Mutex<HashMap<NodeId, (AddrInfo, u64)>>>,
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
        fn publish(&self, info: &AddrInfo) {
            if !self.publish {
                return;
            }
            let now = system_time_now();
            self.shared
                .nodes
                .lock()
                .insert(self.node_id, (info.clone(), now));
        }

        fn resolve(
            &self,
            endpoint: MagicEndpoint,
            node_id: NodeId,
        ) -> Option<BoxStream<'_, Result<DiscoveryItem>>> {
            let addr_info = match self.resolve_wrong {
                false => self.shared.nodes.lock().get(&node_id).cloned(),
                true => {
                    let ts = system_time_now() - 100_000;
                    let port: u16 = rand::thread_rng().gen_range(10_000..20_000);
                    // "240.0.0.0/4" is reserved and unreachable
                    let addr: SocketAddr = format!("240.0.0.1:{port}").parse().unwrap();
                    let addr_info = AddrInfo {
                        relay_url: None,
                        direct_addresses: BTreeSet::from([addr]),
                    };
                    Some((addr_info, ts))
                }
            };
            let stream = match addr_info {
                Some((addr_info, ts)) => {
                    let item = DiscoveryItem {
                        provenance: "test-disco",
                        last_updated: Some(ts),
                        addr_info,
                    };
                    let delay = self.delay;
                    let fut = async move {
                        tokio::time::sleep(delay).await;
                        tracing::debug!(
                            "resolve on {}: {} = {item:?}",
                            endpoint.node_id().fmt_short(),
                            node_id.fmt_short()
                        );
                        Ok(item)
                    };
                    stream::once(fut).boxed()
                }
                None => stream::empty().boxed(),
            };
            Some(stream)
        }
    }

    #[derive(Debug)]
    struct EmptyDiscovery;
    impl Discovery for EmptyDiscovery {
        fn publish(&self, _info: &AddrInfo) {}

        fn resolve(
            &self,
            _endpoint: MagicEndpoint,
            _node_id: NodeId,
        ) -> Option<BoxStream<'_, Result<DiscoveryItem>>> {
            Some(stream::empty().boxed())
        }
    }

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    /// This is a smoke test for our discovery mechanism.
    #[tokio::test]
    async fn magic_endpoint_discovery_simple_shared() -> anyhow::Result<()> {
        let _guard = iroh_test::logging::setup();
        let disco_shared = TestDiscoveryShared::default();
        let ep1 = {
            let secret = SecretKey::generate();
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let ep2 = {
            let secret = SecretKey::generate();
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let ep1_addr = NodeAddr::new(ep1.node_id());
        // wait for out address to be updated and thus published at least once
        ep1.my_addr().await?;
        let _conn = ep2.connect(ep1_addr, TEST_ALPN).await?;
        Ok(())
    }

    /// This test adds an empty discovery which provides no addresses.
    #[tokio::test]
    async fn magic_endpoint_discovery_combined_with_empty() -> anyhow::Result<()> {
        let _guard = iroh_test::logging::setup();
        let disco_shared = TestDiscoveryShared::default();
        let ep1 = {
            let secret = SecretKey::generate();
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let ep2 = {
            let secret = SecretKey::generate();
            let disco1 = EmptyDiscovery;
            let disco2 = disco_shared.create_discovery(secret.public());
            let mut disco = ConcurrentDiscovery::empty();
            disco.add(disco1);
            disco.add(disco2);
            new_endpoint(secret, disco).await
        };
        let ep1_addr = NodeAddr::new(ep1.node_id());
        // wait for out address to be updated and thus published at least once
        ep1.my_addr().await?;
        let _conn = ep2.connect(ep1_addr, TEST_ALPN).await?;
        Ok(())
    }

    /// This test adds a "lying" discovery which provides a wrong address.
    /// This is to make sure that as long as one of the discoveries returns a working address, we
    /// will connect successfully.
    #[tokio::test]
    async fn magic_endpoint_discovery_combined_with_empty_and_wrong() -> anyhow::Result<()> {
        let _guard = iroh_test::logging::setup();
        let disco_shared = TestDiscoveryShared::default();
        let ep1 = {
            let secret = SecretKey::generate();
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let ep2 = {
            let secret = SecretKey::generate();
            let disco1 = EmptyDiscovery;
            let disco2 = disco_shared.create_lying_discovery(secret.public());
            let disco3 = disco_shared.create_discovery(secret.public());
            let mut disco = ConcurrentDiscovery::empty();
            disco.add(disco1);
            disco.add(disco2);
            disco.add(disco3);
            new_endpoint(secret, disco).await
        };
        let ep1_addr = NodeAddr::new(ep1.node_id());
        // wait for out address to be updated and thus published at least once
        ep1.my_addr().await?;
        let _conn = ep2.connect(ep1_addr, TEST_ALPN).await?;
        Ok(())
    }

    /// This test only has the "lying" discovery. It is here to make sure that this actually fails.
    #[tokio::test]
    async fn magic_endpoint_discovery_combined_wrong_only() -> anyhow::Result<()> {
        let _guard = iroh_test::logging::setup();
        let disco_shared = TestDiscoveryShared::default();
        let ep1 = {
            let secret = SecretKey::generate();
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let ep2 = {
            let secret = SecretKey::generate();
            let disco1 = disco_shared.create_lying_discovery(secret.public());
            let disco = ConcurrentDiscovery::new(vec![Box::new(disco1)]);
            new_endpoint(secret, disco).await
        };
        let ep1_addr = NodeAddr::new(ep1.node_id());
        // wait for out address to be updated and thus published at least once
        ep1.my_addr().await?;
        let res = ep2.connect(ep1_addr, TEST_ALPN).await;
        assert!(res.is_err());
        Ok(())
    }

    /// This test first adds a wrong address manually (e.g. from an outdated&node_id ticket).
    /// Connect should still succeed because the discovery service will be invoked (after a delay).
    #[tokio::test]
    async fn magic_endpoint_discovery_with_wrong_existing_addr() -> anyhow::Result<()> {
        let _guard = iroh_test::logging::setup();
        let disco_shared = TestDiscoveryShared::default();
        let ep1 = {
            let secret = SecretKey::generate();
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        let ep2 = {
            let secret = SecretKey::generate();
            let disco = disco_shared.create_discovery(secret.public());
            new_endpoint(secret, disco).await
        };
        // wait for out address to be updated and thus published at least once
        ep1.my_addr().await?;
        let ep1_wrong_addr = NodeAddr {
            node_id: ep1.node_id(),
            info: AddrInfo {
                relay_url: None,
                direct_addresses: BTreeSet::from(["240.0.0.1:1000".parse().unwrap()]),
            },
        };
        let _conn = ep2.connect(ep1_wrong_addr, TEST_ALPN).await?;
        Ok(())
    }

    async fn new_endpoint(secret: SecretKey, disco: impl Discovery + 'static) -> MagicEndpoint {
        MagicEndpoint::builder()
            .secret_key(secret)
            .discovery(Box::new(disco))
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind(0)
            .await
            .unwrap()
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
/// publish to. The relay and DNS servers share their state.
#[cfg(test)]
mod test_dns_pkarr {
    use std::future::Future;
    use std::net::SocketAddr;

    use anyhow::Result;
    use hickory_resolver::{config::NameServerConfig, AsyncResolver, TokioAsyncResolver};
    use iroh_base::key::SecretKey;
    use pkarr::SignedPacket;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;
    use url::Url;

    use crate::{
        discovery::pkarr_publish,
        dns::node_info::{lookup_by_id, parse_hickory_node_info_name, NodeInfo},
        relay::{RelayMap, RelayMode},
        test_utils::{
            dns_server::{run_dns_server, Resolver},
            run_relay_server,
        },
        AddrInfo, MagicEndpoint, NodeAddr,
    };

    use self::{pkarr_relay::run_pkarr_relay, state::State};

    use super::{dns::DnsDiscovery, ConcurrentDiscovery};

    #[tokio::test]
    async fn dns_resolve() -> Result<()> {
        let _logging_guard = iroh_test::logging::setup();
        let cancel = CancellationToken::new();
        let origin = "testdns.example".to_string();
        let state = State::new(origin.clone());
        let (nameserver, dns_task) = run_dns_server(state.clone(), cancel.clone()).await?;

        let node_secret = SecretKey::generate();
        let (node_info, signed_packet) = generate_node_info(&node_secret);
        state.upsert(signed_packet)?;

        let resolver = dns_resolver(nameserver)?;
        let resolved = lookup_by_id(&resolver, &node_info.node_id, &origin).await?;

        assert_eq!(resolved, node_info.into());

        cancel.cancel();
        dns_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn pkarr_publish_dns_resolve() -> Result<()> {
        let _logging_guard = iroh_test::logging::setup();

        let cancel = CancellationToken::new();
        let origin = "testdns.example".to_string();
        let (nameserver, pkarr_url, _state, task) =
            spawn_dns_and_pkarr(origin.clone(), cancel.clone()).await?;

        let secret_key = SecretKey::generate();
        let node_id = secret_key.public();
        let publisher = pkarr_publish::Publisher::new(secret_key, pkarr_url);

        let addr_info = AddrInfo {
            relay_url: Some("https://relay.example".parse().unwrap()),
            ..Default::default()
        };
        publisher.publish_addr_info(&addr_info).await?;

        let resolver = dns_resolver(nameserver)?;
        let resolved = lookup_by_id(&resolver, &node_id, &origin).await?;

        let expected = NodeAddr {
            info: addr_info,
            node_id,
        };

        assert_eq!(resolved, expected);

        cancel.cancel();
        task.await??;
        Ok(())
    }

    const TEST_ALPN: &[u8] = b"TEST";

    #[tokio::test]
    async fn pkarr_publish_dns_discover() -> Result<()> {
        let _logging_guard = iroh_test::logging::setup();

        let cancel = CancellationToken::new();
        let origin = "testdns.example".to_string();
        let (nameserver, pkarr_url, state, task) =
            spawn_dns_and_pkarr(origin.clone(), cancel.clone()).await?;

        let (relay_map, _relay_url, _relay_guard) = run_relay_server().await.unwrap();
        let ep1 = ep_with_discovery(relay_map.clone(), nameserver, &origin, &pkarr_url).await?;
        let ep2 = ep_with_discovery(relay_map, nameserver, &origin, &pkarr_url).await?;

        // wait until our shared state received the update from pkarr publishing
        state.on_update().await;

        // we connect only by node id!
        let ep2_node_id = ep2.node_id();
        let res = ep1.connect(ep2_node_id.into(), TEST_ALPN).await;
        assert!(res.is_ok(), "connection established");
        cancel.cancel();
        task.await??;
        Ok(())
    }

    async fn ep_with_discovery(
        relay_map: RelayMap,
        nameserver: SocketAddr,
        node_origin: &str,
        pkarr_relay: &Url,
    ) -> Result<MagicEndpoint> {
        let secret_key = SecretKey::generate();
        let resolver = dns_resolver(nameserver)?;
        let discovery = ConcurrentDiscovery::new(vec![
            Box::new(DnsDiscovery::new(node_origin.to_string())),
            Box::new(pkarr_publish::Publisher::new(
                secret_key.clone(),
                pkarr_relay.clone(),
            )),
        ]);
        let ep = MagicEndpoint::builder()
            .relay_mode(RelayMode::Custom(relay_map))
            .secret_key(secret_key)
            .dns_resolver(resolver)
            .alpns(vec![TEST_ALPN.to_vec()])
            .discovery(Box::new(discovery))
            .bind(0)
            .await?;
        Ok(ep)
    }

    fn dns_resolver(nameserver: SocketAddr) -> Result<TokioAsyncResolver> {
        let mut config = hickory_resolver::config::ResolverConfig::new();
        let nameserver_config =
            NameServerConfig::new(nameserver, hickory_resolver::config::Protocol::Udp);
        config.add_name_server(nameserver_config);
        let resolver = AsyncResolver::tokio(config, Default::default());
        Ok(resolver)
    }

    fn generate_node_info(secret: &SecretKey) -> (NodeInfo, SignedPacket) {
        let node_id = secret.public();
        let relay_url: Url = "https://relay.example".parse().expect("valid url");
        let node_info = NodeInfo {
            node_id,
            relay_url: Some(relay_url.clone()),
        };
        let signed_packet = node_info
            .to_pkarr_signed_packet(secret, 30)
            .expect("valid packet");
        (node_info, signed_packet)
    }

    async fn spawn_dns_and_pkarr(
        origin: String,
        cancel: CancellationToken,
    ) -> Result<(SocketAddr, Url, State, JoinHandle<Result<()>>)> {
        let state = State::new(origin);
        let (nameserver, dns_task) = run_dns_server(state.clone(), cancel.clone()).await?;
        let (pkarr_url, pkarr_task) = run_pkarr_relay(state.clone(), cancel.clone()).await?;
        let join_handle = tokio::task::spawn(async move {
            dns_task.await??;
            pkarr_task.await??;
            Ok(())
        });
        Ok((nameserver, pkarr_url, state, join_handle))
    }

    mod state {
        use crate::NodeId;
        use parking_lot::{Mutex, MutexGuard};
        use pkarr::SignedPacket;
        use std::{
            collections::{hash_map, HashMap},
            ops::Deref,
            sync::Arc,
        };

        #[derive(Debug, Clone)]
        pub struct State {
            packets: Arc<Mutex<HashMap<NodeId, SignedPacket>>>,
            pub origin: String,
            notify: Arc<tokio::sync::Notify>,
        }

        impl State {
            pub fn new(origin: String) -> Self {
                Self {
                    packets: Default::default(),
                    origin,
                    notify: Arc::new(tokio::sync::Notify::new()),
                }
            }

            pub fn on_update(&self) -> tokio::sync::futures::Notified<'_> {
                self.notify.notified()
            }

            pub fn upsert(&self, signed_packet: SignedPacket) -> anyhow::Result<bool> {
                let node_id = NodeId::from_bytes(&signed_packet.public_key().to_bytes())?;
                let mut map = self.packets.lock();
                let updated = match map.entry(node_id) {
                    hash_map::Entry::Vacant(e) => {
                        e.insert(signed_packet);
                        true
                    }
                    hash_map::Entry::Occupied(mut e) => {
                        if signed_packet.more_recent_than(e.get()) {
                            e.insert(signed_packet);
                            true
                        } else {
                            false
                        }
                    }
                };
                if updated {
                    self.notify.notify_waiters();
                }
                Ok(updated)
            }
            pub fn get(&self, node_id: &NodeId) -> Option<impl Deref<Target = SignedPacket> + '_> {
                println!("GET {node_id}");
                let map = self.packets.lock();
                if map.contains_key(node_id) {
                    let guard = MutexGuard::map(map, |state| state.get_mut(node_id).unwrap());
                    Some(guard)
                } else {
                    None
                }
            }
        }
    }

    impl Resolver for State {
        fn resolve(
            &self,
            query: &hickory_proto::op::Message,
            reply: &mut hickory_proto::op::Message,
        ) -> impl Future<Output = Result<()>> + Send {
            const TTL: u32 = 30;
            let this = self.clone();
            async move {
                for query in query.queries() {
                    let Some(node_id) = parse_hickory_node_info_name(query.name()) else {
                        continue;
                    };
                    let packet = this.get(&node_id);
                    let Some(packet) = packet.as_ref() else {
                        continue;
                    };
                    let node_info = NodeInfo::from_pkarr_signed_packet(packet)?;
                    let record = node_info.to_hickory_record(&this.origin, TTL)?;
                    reply.add_answer(record);
                }
                Ok(())
            }
        }
    }

    mod pkarr_relay {
        use std::net::{Ipv4Addr, SocketAddr};

        use anyhow::Result;
        use axum::{
            extract::{Path, State},
            response::IntoResponse,
            routing::put,
            Router,
        };
        use bytes::Bytes;
        use tokio::task::JoinHandle;
        use tokio_util::sync::CancellationToken;
        use tracing::warn;
        use url::Url;

        use super::State as AppState;

        pub async fn run_pkarr_relay(
            state: AppState,
            cancel: CancellationToken,
        ) -> Result<(Url, JoinHandle<Result<()>>)> {
            let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let app = Router::new()
                .route("/pkarr/:key", put(pkarr_put))
                .with_state(state);
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            let bound_addr = listener.local_addr()?;
            let url: Url = format!("http://{bound_addr}/pkarr")
                .parse()
                .expect("valid url");
            let join_handle = tokio::task::spawn(async move {
                let serve = axum::serve(listener, app);
                let serve = serve.with_graceful_shutdown(cancel.cancelled_owned());
                serve.await?;
                Ok(())
            });
            Ok((url, join_handle))
        }

        async fn pkarr_put(
            State(state): State<AppState>,
            Path(key): Path<String>,
            body: Bytes,
        ) -> Result<impl IntoResponse, AppError> {
            let key = pkarr::PublicKey::try_from(key.as_str())?;
            let signed_packet = pkarr::SignedPacket::from_relay_response(key, body)?;
            let _updated = state.upsert(signed_packet)?;
            Ok(http::StatusCode::NO_CONTENT)
        }

        #[derive(Debug)]
        struct AppError(anyhow::Error);
        impl<T: Into<anyhow::Error>> From<T> for AppError {
            fn from(value: T) -> Self {
                Self(value.into())
            }
        }
        impl IntoResponse for AppError {
            fn into_response(self) -> axum::response::Response {
                warn!(err = ?self, "request failed");
                (http::StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
            }
        }
    }
}
