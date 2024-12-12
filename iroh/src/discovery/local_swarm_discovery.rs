//! A discovery service that uses an mdns-like service to discover local nodes.
//!
//! This allows you to use an mdns-like swarm discovery service to find address information about nodes that are on your local network, no relay or outside internet needed.
//! See the [`swarm-discovery`](https://crates.io/crates/swarm-discovery) crate for more details.
//!
//! When [`LocalSwarmDiscovery`] is enabled, it's possible to get a list of the locally discovered nodes by filtering a list of `RemoteInfo`s.
//!
//! ```
//! use std::time::Duration;
//!
//! use iroh::endpoint::{Endpoint, Source};
//!
//! #[tokio::main]
//! async fn main() {
//!     let recent = Duration::from_secs(600); // 10 minutes in seconds
//!
//!     let endpoint = Endpoint::builder().bind().await.unwrap();
//!     let remotes = endpoint.remote_info_iter();
//!     let locally_discovered: Vec<_> = remotes
//!         .filter(|remote| {
//!             remote.sources().iter().any(|(source, duration)| {
//!                 if let Source::Discovery { name } = source {
//!                     name == iroh::discovery::local_swarm_discovery::NAME && *duration <= recent
//!                 } else {
//!                     false
//!                 }
//!             })
//!         })
//!         .collect();
//!     println!("locally discovered nodes: {locally_discovered:?}");
//! }
//! ```
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use derive_more::FromStr;
use futures_lite::stream::Boxed as BoxStream;
use futures_util::FutureExt;
use iroh_base::{key::PublicKey, node_addr::NodeAddr};
use iroh_relay::RelayUrl;
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::{
    sync::mpsc::{
        error::TrySendError,
        {self},
    },
    task::JoinSet,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, error, info_span, trace, warn, Instrument};

use crate::{
    discovery::{Discovery, DiscoveryItem},
    watchable::Watchable,
    Endpoint, NodeId,
};

/// The n0 local swarm node discovery name
const N0_LOCAL_SWARM: &str = "iroh.local.swarm";

/// Name of this discovery service.
///
/// Used as the `provenance` field in [`DiscoveryItem`]s.
///
/// Used in the [`crate::endpoint::Source::Discovery`] enum variant as the `name`.
pub const NAME: &str = "local.swarm.discovery";

/// How long we will wait before we stop sending discovery items
const DISCOVERY_DURATION: Duration = Duration::from_secs(10);

/// Discovery using `swarm-discovery`, a variation on mdns
#[derive(Debug)]
pub struct LocalSwarmDiscovery {
    #[allow(dead_code)]
    handle: AbortOnDropHandle<()>,
    sender: mpsc::Sender<Message>,
    /// When `local_addrs` changes, we re-publish our info.
    local_addrs: Watchable<Option<(Option<RelayUrl>, BTreeSet<SocketAddr>)>>,
}

#[derive(Debug)]
enum Message {
    Discovery(String, Peer),
    Resolve(NodeId, mpsc::Sender<Result<DiscoveryItem>>),
    Timeout(NodeId, usize),
    Subscribe(mpsc::Sender<DiscoveryItem>),
}

/// Manages the list of subscribers that are subscribed to this discovery service.
#[derive(Debug)]
struct Subscribers(Vec<mpsc::Sender<DiscoveryItem>>);

impl Subscribers {
    fn new() -> Self {
        Self(vec![])
    }

    /// Add the subscriber to the list of subscribers
    fn push(&mut self, subscriber: mpsc::Sender<DiscoveryItem>) {
        self.0.push(subscriber);
    }

    /// Sends the `node_id` and `item` to each subscriber.
    ///
    /// Cleans up any subscribers that have been dropped.
    fn send(&mut self, item: DiscoveryItem) {
        let mut clean_up = vec![];
        for (i, subscriber) in self.0.iter().enumerate() {
            // assume subscriber was dropped
            if let Err(err) = subscriber.try_send(item.clone()) {
                match err {
                    TrySendError::Full(_) => {
                        warn!(
                            ?item,
                            idx = i,
                            "local swarm discovery subscriber is blocked, dropping item"
                        )
                    }
                    TrySendError::Closed(_) => clean_up.push(i),
                }
            }
        }
        for i in clean_up.into_iter().rev() {
            self.0.swap_remove(i);
        }
    }
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

        let local_addrs: Watchable<Option<(Option<RelayUrl>, BTreeSet<SocketAddr>)>> =
            Watchable::new(None);
        let mut addrs_change = local_addrs.watch();
        let discovery_fut = async move {
            let mut node_addrs: HashMap<PublicKey, Peer> = HashMap::default();
            let mut subscribers = Subscribers::new();
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
                    Ok(Some((_url, addrs)))= addrs_change.updated() => {
                        tracing::trace!(?addrs, "LocalSwarmDiscovery address changed");
                        discovery.remove_all();
                        let addrs =
                            LocalSwarmDiscovery::socketaddrs_to_addrs(addrs);
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

                        let mut resolved = false;
                        let item = peer_to_discovery_item(&peer_info, &discovered_node_id);
                        if let Some(senders) = senders.get(&discovered_node_id) {
                            trace!(?item, senders = senders.len(), "sending DiscoveryItem");
                            resolved = true;
                            for sender in senders.values() {
                                sender.send(Ok(item.clone())).await.ok();
                            }
                        }
                        entry.or_insert(peer_info);

                        // only send nodes to the `subscriber` if they weren't explicitly resolved
                        // in other words, nodes sent to the `subscribers` should only be the ones that
                        // have been "passively" discovered
                        if !resolved {
                            subscribers.send(item);
                        }
                    }
                    Message::Resolve(node_id, sender) => {
                        let id = last_id + 1;
                        last_id = id;
                        trace!(?node_id, "LocalSwarmDiscovery Message::SendAddrs");
                        if let Some(peer_info) = node_addrs.get(&node_id) {
                            let item = peer_to_discovery_item(peer_info, &node_id);
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
            local_addrs,
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

fn peer_to_discovery_item(peer: &Peer, node_id: &NodeId) -> DiscoveryItem {
    let direct_addresses: BTreeSet<SocketAddr> = peer
        .addrs()
        .iter()
        .map(|(ip, port)| SocketAddr::new(*ip, *port))
        .collect();
    DiscoveryItem {
        node_addr: NodeAddr {
            node_id: *node_id,
            relay_url: None,
            direct_addresses,
        },
        provenance: NAME,
        last_updated: None,
    }
}

impl Discovery for LocalSwarmDiscovery {
    fn resolve(&self, _ep: Endpoint, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem>>> {
        let (send, recv) = mpsc::channel(20);
        let discovery_sender = self.sender.clone();
        let stream = async move {
            discovery_sender
                .send(Message::Resolve(node_id, send))
                .await
                .ok();
            tokio_stream::wrappers::ReceiverStream::new(recv)
        };
        Some(Box::pin(stream.flatten_stream()))
    }

    fn publish(&self, url: Option<&RelayUrl>, addrs: &BTreeSet<SocketAddr>) {
        self.local_addrs
            .set(Some((url.cloned(), addrs.clone())))
            .ok();
    }

    fn subscribe(&self) -> Option<BoxStream<DiscoveryItem>> {
        let (sender, recv) = mpsc::channel(20);
        let discovery_sender = self.sender.clone();
        let stream = async move {
            discovery_sender.send(Message::Subscribe(sender)).await.ok();
            tokio_stream::wrappers::ReceiverStream::new(recv)
        };
        Some(Box::pin(stream.flatten_stream()))
    }
}

#[cfg(test)]
mod tests {

    /// This module's name signals nextest to run test in a single thread (no other concurrent
    /// tests)
    mod run_in_isolation {
        use futures_lite::StreamExt;
        use testresult::TestResult;

        use super::super::*;

        #[tokio::test]
        async fn local_swarm_discovery_publish_resolve() -> TestResult {
            let _guard = iroh_test::logging::setup();
            let (_, discovery_a) = make_discoverer()?;
            let (node_id_b, discovery_b) = make_discoverer()?;

            // make addr info for discoverer b
            let addr_info = (None, BTreeSet::from(["0.0.0.0:11111".parse()?]));

            // pass in endpoint, this is never used
            let ep = crate::endpoint::Builder::default().bind().await?;

            // resolve twice to ensure we can create separate streams for the same node_id
            let mut s1 = discovery_a.resolve(ep.clone(), node_id_b).unwrap();
            let mut s2 = discovery_a.resolve(ep, node_id_b).unwrap();

            tracing::debug!(?node_id_b, "Discovering node id b");
            // publish discovery_b's address
            discovery_b.publish(addr_info.0.as_ref(), &addr_info.1);
            let s1_res = tokio::time::timeout(Duration::from_secs(5), s1.next())
                .await?
                .unwrap()?;
            let s2_res = tokio::time::timeout(Duration::from_secs(5), s2.next())
                .await?
                .unwrap()?;
            assert_eq!(s1_res.node_addr.relay_url, addr_info.0);
            assert_eq!(s1_res.node_addr.direct_addresses, addr_info.1);
            assert_eq!(s2_res.node_addr.relay_url, addr_info.0);
            assert_eq!(s2_res.node_addr.direct_addresses, addr_info.1);

            Ok(())
        }

        #[tokio::test]
        async fn local_swarm_discovery_subscribe() -> TestResult {
            let _guard = iroh_test::logging::setup();

            let num_nodes = 5;
            let mut node_ids = BTreeSet::new();
            let mut discoverers = vec![];

            let (_, discovery) = make_discoverer()?;
            let addr_info = (None, BTreeSet::from(["0.0.0.0:11111".parse()?]));

            for _ in 0..num_nodes {
                let (node_id, discovery) = make_discoverer()?;
                node_ids.insert(node_id);
                discovery.publish(addr_info.0.as_ref(), &addr_info.1);
                discoverers.push(discovery);
            }

            let mut events = discovery.subscribe().unwrap();

            let test = async move {
                let mut got_ids = BTreeSet::new();
                while got_ids.len() != num_nodes {
                    if let Some(item) = events.next().await {
                        if node_ids.contains(&item.node_addr.node_id) {
                            got_ids.insert(item.node_addr.node_id);
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
