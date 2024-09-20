//! A discovery service that uses an mdns-like service to discover local nodes.
//!
//! This allows you to use an mdns-like swarm discovery service to find address information about nodes that are on your local network, no relay or outside internet needed.
//! See the [`swarm-discovery`](https://crates.io/crates/swarm-discovery) crate for more details.

use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use derive_more::FromStr;
use futures_lite::stream::Boxed as BoxStream;
use futures_util::FutureExt;
use tracing::{debug, error, info_span, trace, warn, Instrument};
use watchable::Watchable;

use async_trait::async_trait;
use iroh_base::key::PublicKey;
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    discovery::{Discovery, DiscoveryItem},
    AddrInfo, Endpoint, NodeId,
};

/// The n0 local swarm node discovery name
const N0_LOCAL_SWARM: &str = "iroh.local.swarm";

/// Provenance string
const PROVENANCE: &str = "local";

/// How long we will wait before we stop sending discovery items
const DISCOVERY_DURATION: Duration = Duration::from_secs(10);

/// Discovery using `swarm-discovery`, a variation on mdns
#[derive(Debug)]
pub struct LocalSwarmDiscovery {
    #[allow(dead_code)]
    handle: AbortOnDropHandle<()>,
    sender: mpsc::Sender<Message>,
    addrs: Watchable<Option<AddrInfo>>,
}

#[derive(Debug)]
enum Message {
    Discovery(String, Peer),
    SendAddrs(NodeId, mpsc::Sender<Result<DiscoveryItem>>),
    Timeout(NodeId, usize),
    Subscribe(mpsc::Sender<(NodeId, DiscoveryItem)>),
}

impl LocalSwarmDiscovery {
    /// Create a new [`LocalSwarmDiscovery`] Service.
    ///
    /// This starts a [`Discoverer`] that broadcasts your addresses and receives addresses from other nodes in your local network.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    pub fn new(node_id: NodeId) -> Result<Self> {
        debug!("Creating new LocalSwarmDiscovery service");
        let (send, mut recv) = mpsc::channel(64);
        let task_sender = send.clone();
        let rt = tokio::runtime::Handle::current();
        let discovery = LocalSwarmDiscovery::spawn_discoverer(
            node_id,
            task_sender.clone(),
            BTreeSet::new(),
            &rt,
        )?;

        let addrs: Watchable<Option<AddrInfo>> = Watchable::new(None);
        let addrs_change = addrs.watch();
        let discovery_fut = async move {
            let mut node_addrs: HashMap<PublicKey, Peer> = HashMap::default();
            let mut subscribers: Vec<mpsc::Sender<(NodeId, DiscoveryItem)>> = vec![];
            let mut last_id = 0;
            let mut senders: HashMap<
                PublicKey,
                HashMap<usize, mpsc::Sender<Result<DiscoveryItem>>>,
            > = HashMap::default();
            let mut timeouts = JoinSet::new();
            loop {
                trace!(?node_addrs, "LocalSwarmDiscovery Service loop tick");
                let msg = tokio::select! {
                    msg = recv.recv() => {
                        msg
                    }
                    Ok(Some(addrs))= addrs_change.next_value_async() => {
                        tracing::info!(?addrs, "LocalSwarmDiscovery address changed");
                        discovery.remove_all();
                        let addrs =
                            LocalSwarmDiscovery::socketaddrs_to_addrs(addrs.direct_addresses);
                        for addr in addrs {
                            discovery.add(addr.0, addr.1)
                        }
                        continue;
                    }
                };
                let msg = match msg {
                    None => {
                        error!("LocalSwarmDiscovery channel closed");
                        error!("closing LocalSwarmDiscovery");
                        timeouts.abort_all();
                        return;
                    }
                    Some(msg) => msg,
                };
                match msg {
                    Message::Discovery(discovered_node_id, peer_info) => {
                        trace!(
                            ?discovered_node_id,
                            ?peer_info,
                            "LocalSwarmDiscovery Message::Discovery"
                        );
                        let discovered_node_id = match PublicKey::from_str(&discovered_node_id) {
                            Ok(node_id) => node_id,
                            Err(e) => {
                                warn!(
                                    discovered_node_id,
                                    "couldn't parse node_id from mdns discovery service: {e:?}"
                                );
                                continue;
                            }
                        };

                        if discovered_node_id == node_id {
                            continue;
                        }

                        if peer_info.is_expiry() {
                            trace!(
                                ?discovered_node_id,
                                "removing node from LocalSwarmDiscovery address book"
                            );
                            node_addrs.remove(&discovered_node_id);
                            continue;
                        }

                        let entry = node_addrs.entry(discovered_node_id);
                        if let std::collections::hash_map::Entry::Occupied(ref entry) = entry {
                            if entry.get() == &peer_info {
                                // this is a republish we already know about
                                continue;
                            }
                        }

                        debug!(
                            ?discovered_node_id,
                            ?peer_info,
                            "adding node to LocalSwarmDiscovery address book"
                        );

                        let item: DiscoveryItem = (&peer_info).into();
                        if let Some(senders) = senders.get(&discovered_node_id) {
                            trace!(?item, senders = senders.len(), "sending DiscoveryItem");
                            for sender in senders.values() {
                                sender.send(Ok(item.clone())).await.ok();
                            }
                        }
                        entry.or_insert(peer_info);

                        // update and clean up subscribers
                        let mut clean_up = vec![];
                        for (i, subscriber) in subscribers.iter().enumerate() {
                            // assume subscriber was dropped
                            if (subscriber.send((discovered_node_id, item.clone())).await).is_err()
                            {
                                clean_up.push(i);
                            }
                        }
                        for i in clean_up {
                            subscribers.swap_remove(i);
                        }
                    }
                    Message::SendAddrs(node_id, sender) => {
                        let id = last_id + 1;
                        last_id = id;
                        trace!(?node_id, "LocalSwarmDiscovery Message::SendAddrs");
                        if let Some(peer_info) = node_addrs.get(&node_id) {
                            let item: DiscoveryItem = peer_info.into();
                            debug!(?item, "sending DiscoveryItem");
                            sender.send(Ok(item)).await.ok();
                        }
                        if let Some(senders_for_node_id) = senders.get_mut(&node_id) {
                            senders_for_node_id.insert(id, sender);
                        } else {
                            let mut senders_for_node_id = HashMap::new();
                            senders_for_node_id.insert(id, sender);
                            senders.insert(node_id, senders_for_node_id);
                        }
                        let timeout_sender = task_sender.clone();
                        timeouts.spawn(async move {
                            tokio::time::sleep(DISCOVERY_DURATION).await;
                            trace!(?node_id, "discovery timeout");
                            timeout_sender
                                .send(Message::Timeout(node_id, id))
                                .await
                                .ok();
                        });
                    }
                    Message::Timeout(node_id, id) => {
                        trace!(?node_id, "LocalSwarmDiscovery Message::Timeout");
                        if let Some(senders_for_node_id) = senders.get_mut(&node_id) {
                            senders_for_node_id.remove(&id);
                            if senders_for_node_id.is_empty() {
                                senders.remove(&node_id);
                            }
                        }
                    }
                    Message::Subscribe(subscriber) => {
                        trace!("LocalSwarmDiscovery Message::Subscribe");
                        subscribers.push(subscriber);
                    }
                }
            }
        };
        let handle = tokio::spawn(discovery_fut.instrument(info_span!("swarm-discovery.actor")));
        Ok(Self {
            handle: AbortOnDropHandle::new(handle),
            sender: send,
            addrs,
        })
    }

    fn spawn_discoverer(
        node_id: PublicKey,
        sender: mpsc::Sender<Message>,
        socketaddrs: BTreeSet<SocketAddr>,
        rt: &tokio::runtime::Handle,
    ) -> Result<DropGuard> {
        let spawn_rt = rt.clone();
        let callback = move |node_id: &str, peer: &Peer| {
            trace!(
                node_id,
                ?peer,
                "Received peer information from LocalSwarmDiscovery"
            );

            let sender = sender.clone();
            let node_id = node_id.to_string();
            let peer = peer.clone();
            spawn_rt.spawn(async move {
                sender.send(Message::Discovery(node_id, peer)).await.ok();
            });
        };
        let addrs = LocalSwarmDiscovery::socketaddrs_to_addrs(socketaddrs);
        let mut discoverer =
            Discoverer::new_interactive(N0_LOCAL_SWARM.to_string(), node_id.to_string())
                .with_callback(callback)
                .with_ip_class(IpClass::Auto);
        for addr in addrs {
            discoverer = discoverer.with_addrs(addr.0, addr.1);
        }
        discoverer.spawn(rt)
    }

    fn socketaddrs_to_addrs(socketaddrs: BTreeSet<SocketAddr>) -> HashMap<u16, Vec<IpAddr>> {
        let mut addrs: HashMap<u16, Vec<IpAddr>> = HashMap::default();
        for socketaddr in socketaddrs {
            addrs
                .entry(socketaddr.port())
                .and_modify(|a| a.push(socketaddr.ip()))
                .or_insert(vec![socketaddr.ip()]);
        }
        addrs
    }
}

impl From<&Peer> for DiscoveryItem {
    fn from(peer_info: &Peer) -> Self {
        let direct_addresses: BTreeSet<SocketAddr> = peer_info
            .addrs()
            .iter()
            .map(|(ip, port)| SocketAddr::new(*ip, *port))
            .collect();
        DiscoveryItem {
            provenance: PROVENANCE,
            last_updated: None,
            addr_info: AddrInfo {
                relay_url: None,
                direct_addresses,
            },
        }
    }
}

#[async_trait]
impl Discovery for LocalSwarmDiscovery {
    fn resolve(&self, _ep: Endpoint, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem>>> {
        let (send, recv) = mpsc::channel(20);
        let discovery_sender = self.sender.clone();
        let stream = async move {
            discovery_sender
                .send(Message::SendAddrs(node_id, send))
                .await
                .ok();
            tokio_stream::wrappers::ReceiverStream::new(recv)
        };
        Some(Box::pin(stream.flatten_stream()))
    }

    fn publish(&self, info: &AddrInfo) {
        tracing::info!("PUBLISHING aka replacing `addrs`");
        self.addrs.replace(Some(info.clone()));
    }

    async fn subscribe(&self) -> Option<BoxStream<(NodeId, DiscoveryItem)>> {
        let (sender, recv) = mpsc::channel(20);
        self.sender.send(Message::Subscribe(sender)).await.ok();
        let stream = tokio_stream::wrappers::ReceiverStream::new(recv);

        Some(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {

    /// This module's name signals nextest to run test in a single thread (no other concurrent
    /// tests)
    mod run_in_isolation {
        use super::super::*;
        use futures_lite::StreamExt;
        use testresult::TestResult;

        #[tokio::test]
        async fn local_swarm_discovery_smoke() -> TestResult {
            // need to ensure that these tests run one after the other, otherwise
            // they interfere with each other
            test_local_swarm_discovery().await?;
            test_subscribe().await
        }

        async fn test_local_swarm_discovery() -> TestResult {
            let _guard = iroh_test::logging::setup();
            let (_, discovery_a) = make_discoverer()?;
            let (node_id_b, discovery_b) = make_discoverer()?;

            // make addr info for discoverer b
            let addr_info = AddrInfo {
                relay_url: None,
                direct_addresses: BTreeSet::from(["0.0.0.0:11111".parse()?]),
            };

            // pass in endpoint, this is never used
            let ep = crate::endpoint::Builder::default().bind().await?;
            // resolve twice to ensure we can create separate streams for the same node_id
            let mut s1 = discovery_a.resolve(ep.clone(), node_id_b).unwrap();
            let mut s2 = discovery_a.resolve(ep, node_id_b).unwrap();

            tracing::debug!("Subscribe to node a's discovery events");
            let mut events = discovery_a.subscribe().await.unwrap();

            tracing::debug!(?node_id_b, "Discovering node id b");
            // publish discovery_b's address
            discovery_b.publish(&addr_info);
            let s1_res = tokio::time::timeout(Duration::from_secs(5), s1.next())
                .await?
                .unwrap()?;
            let s2_res = tokio::time::timeout(Duration::from_secs(5), s2.next())
                .await?
                .unwrap()?;
            assert_eq!(s1_res.addr_info, addr_info);
            assert_eq!(s2_res.addr_info, addr_info);

            if let Some((id, item)) = events.next().await {
                assert_eq!(node_id_b, id);
                assert_eq!(addr_info, item.addr_info);
            }

            Ok(())
        }

        async fn test_subscribe() -> TestResult {
            // number of nodes
            let num_nodes = 5;
            let mut node_ids = BTreeSet::new();
            let mut discoverers = vec![];
            let (_, discovery) = make_discoverer()?;
            let addr_info = AddrInfo {
                relay_url: None,
                direct_addresses: BTreeSet::from(["0.0.0.0:11111".parse()?]),
            };

            for _ in 0..num_nodes {
                let (node_id, discovery) = make_discoverer()?;
                node_ids.insert(node_id);
                discovery.publish(&addr_info);
                discoverers.push(discovery);
            }

            let mut events = discovery.subscribe().await.unwrap();

            let test = async move {
                let mut got_ids = BTreeSet::new();
                while got_ids.len() != num_nodes {
                    if let Some((id, _)) = events.next().await {
                        if node_ids.contains(&id) {
                            got_ids.insert(id);
                        }
                    } else {
                        anyhow::bail!(
                            "no more events, only got {} ids, expected {num_nodes}\n",
                            got_ids.len()
                        );
                    }
                }
                assert_eq!(got_ids, node_ids);
                anyhow::Ok(())
            };
            tokio::time::timeout(Duration::from_secs(5), test).await??;
            Ok(())
        }

        fn make_discoverer() -> Result<(PublicKey, LocalSwarmDiscovery)> {
            let node_id = crate::key::SecretKey::generate().public();
            Ok((node_id, LocalSwarmDiscovery::new(node_id)?))
        }
    }
}
