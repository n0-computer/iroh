//! Trait and utils for the node discovery mechanism.

use anyhow::Result;
use futures::stream::BoxStream;

use crate::{AddrInfo, MagicEndpoint, NodeId};

/// Node discovery for [`super::MagicEndpoint`].
///
/// The purpose of this trait is to hoop up a node discovery mechanism that
/// allows finding information such as the derp url and current addresses
/// of a node given the id.
///
/// To allow for discovery, the [`super::MagicEndpoint`] will call `publish` whenever
/// discovery information changes. If a discovery mechanism requires a periodic
/// refresh, it should start it's own task.
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
    ) -> Option<BoxStream<'static, Result<DiscoveryItem>>> {
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
#[derive(Debug, Default)]
pub struct CombinedDiscovery {
    services: Vec<Box<dyn Discovery>>,
}

impl CombinedDiscovery {
    /// Create a new [`CombinedDiscovery`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a [`Discovery`] service.
    pub fn add(&mut self, service: impl Discovery + 'static) {
        self.services.push(Box::new(service));
    }
}

impl<T> From<T> for CombinedDiscovery
where
    T: IntoIterator<Item = Box<dyn Discovery>>,
{
    fn from(iter: T) -> Self {
        let services = iter.into_iter().collect::<Vec<_>>();
        Self { services }
    }
}

impl Discovery for CombinedDiscovery {
    fn publish(&self, info: &AddrInfo) {
        for service in &self.services {
            service.publish(info);
        }
    }

    fn resolve(
        &self,
        endpoint: MagicEndpoint,
        node_id: NodeId,
    ) -> Option<BoxStream<'static, Result<DiscoveryItem>>> {
        let streams = self
            .services
            .iter()
            .filter_map(|service| service.resolve(endpoint.clone(), node_id));
        let streams = futures::stream::select_all(streams);
        Some(Box::pin(streams))
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

    use crate::{derp::DerpMode, key::SecretKey, NodeAddr};

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
        ) -> Option<BoxStream<'static, Result<DiscoveryItem>>> {
            let addr_info = match self.resolve_wrong {
                false => self.shared.nodes.lock().get(&node_id).cloned(),
                true => {
                    let ts = system_time_now() - 100_000;
                    let port: u16 = rand::random();
                    // "240.0.0.0/4" is reserved and unreachable
                    let addr: SocketAddr = format!("240.0.0.1:{port}").parse().unwrap();
                    let addr_info = AddrInfo {
                        derp_url: None,
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
        ) -> Option<BoxStream<'static, Result<DiscoveryItem>>> {
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
            let mut disco = CombinedDiscovery::new();
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
            let mut disco = CombinedDiscovery::new();
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
            let mut disco = CombinedDiscovery::new();
            disco.add(disco1);
            new_endpoint(secret, disco).await
        };
        let ep1_addr = NodeAddr::new(ep1.node_id());
        // wait for out address to be updated and thus published at least once
        ep1.my_addr().await?;
        let res = ep2.connect(ep1_addr, TEST_ALPN).await;
        assert!(matches!(res, Err(_)));
        Ok(())
    }

    async fn new_endpoint(secret: SecretKey, disco: impl Discovery + 'static) -> MagicEndpoint {
        MagicEndpoint::builder()
            .secret_key(secret)
            .discovery(Box::new(disco))
            .derp_mode(DerpMode::Disabled)
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
