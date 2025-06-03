//! A discovery service that uses an mdns-like service to discover local nodes.
//!
//! This allows you to use an mdns-like swarm discovery service to find address information about nodes that are on your local network, no relay or outside internet needed.
//! See the [`swarm-discovery`](https://crates.io/crates/swarm-discovery) crate for more details.
//!
//! When [`MdnsDiscovery`] is enabled, it's possible to get a list of the locally discovered nodes by filtering a list of `RemoteInfo`s.
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
//!                     name == iroh::discovery::mdns::NAME && *duration <= recent
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
};

use derive_more::FromStr;
use iroh_base::{NodeId, PublicKey};
use n0_future::{
    boxed::BoxStream,
    task::{self, AbortOnDropHandle, JoinSet},
    time::{self, Duration},
};
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, error, info_span, trace, warn, Instrument};

use super::{DiscoveryError, IntoDiscovery, IntoDiscoveryError};
use crate::{
    discovery::{Discovery, DiscoveryItem, NodeData, NodeInfo},
    watcher::{Watchable, Watcher as _},
    Endpoint,
};

/// The n0 local swarm node discovery name
const N0_LOCAL_SWARM: &str = "iroh.local.swarm";

/// Name of this discovery service.
///
/// Used as the `provenance` field in [`DiscoveryItem`]s.
///
/// Used in the [`crate::endpoint::Source::Discovery`] enum variant as the `name`.
pub const NAME: &str = "local.swarm.discovery";

/// The key of the attribute under which the `UserData` is stored in
/// the TXT record supported by swarm-discovery.
const USER_DATA_ATTRIBUTE: &str = "user-data";

/// How long we will wait before we stop sending discovery items
const DISCOVERY_DURATION: Duration = Duration::from_secs(10);

/// Discovery using `swarm-discovery`, a variation on mdns
#[derive(Debug)]
pub struct MdnsDiscovery {
    #[allow(dead_code)]
    handle: AbortOnDropHandle<()>,
    sender: mpsc::Sender<Message>,
    /// When `local_addrs` changes, we re-publish our info.
    local_addrs: Watchable<Option<NodeData>>,
}

#[derive(Debug)]
enum Message {
    Discovery(String, Peer),
    Resolve(NodeId, mpsc::Sender<Result<DiscoveryItem, DiscoveryError>>),
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

/// Builder for [`MdnsDiscovery`].
#[derive(Debug)]
pub struct MdnsDiscoveryBuilder;

impl IntoDiscovery for MdnsDiscoveryBuilder {
    fn into_discovery(self, endpoint: &Endpoint) -> Result<impl Discovery, IntoDiscoveryError> {
        MdnsDiscovery::new(endpoint.node_id())
    }
}

impl MdnsDiscovery {
    /// Returns a [`MdnsDiscoveryBuilder`] that implements [`IntoDiscovery`].
    pub fn builder() -> MdnsDiscoveryBuilder {
        MdnsDiscoveryBuilder
    }

    /// Create a new [`MdnsDiscovery`] Service.
    ///
    /// This starts a [`Discoverer`] that broadcasts your addresses and receives addresses from other nodes in your local network.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    pub fn new(node_id: NodeId) -> Result<Self, IntoDiscoveryError> {
        debug!("Creating new MdnsDiscovery service");
        let (send, mut recv) = mpsc::channel(64);
        let task_sender = send.clone();
        let rt = tokio::runtime::Handle::current();
        let discovery =
            MdnsDiscovery::spawn_discoverer(node_id, task_sender.clone(), BTreeSet::new(), &rt)?;

        let local_addrs: Watchable<Option<NodeData>> = Watchable::default();
        let mut addrs_change = local_addrs.watch();
        let discovery_fut = async move {
            let mut node_addrs: HashMap<PublicKey, Peer> = HashMap::default();
            let mut subscribers = Subscribers::new();
            let mut last_id = 0;
            let mut senders: HashMap<
                PublicKey,
                HashMap<usize, mpsc::Sender<Result<DiscoveryItem, DiscoveryError>>>,
            > = HashMap::default();
            let mut timeouts = JoinSet::new();
            loop {
                trace!(?node_addrs, "MdnsDiscovery Service loop tick");
                let msg = tokio::select! {
                    msg = recv.recv() => {
                        msg
                    }
                    Ok(Some(data)) = addrs_change.updated() => {
                        tracing::trace!(?data, "MdnsDiscovery address changed");
                        discovery.remove_all();
                        let addrs =
                            MdnsDiscovery::socketaddrs_to_addrs(data.direct_addresses());
                        for addr in addrs {
                            discovery.add(addr.0, addr.1)
                        }
                        if let Some(user_data) = data.user_data() {
                            if let Err(err) = discovery.set_txt_attribute(USER_DATA_ATTRIBUTE.to_string(), Some(user_data.to_string())) {
                                warn!("Failed to set the user-defined data in local swarm discovery: {err:?}");
                            }
                        }
                        continue;
                    }
                };
                let msg = match msg {
                    None => {
                        error!("MdnsDiscovery channel closed");
                        error!("closing MdnsDiscovery");
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
                            "MdnsDiscovery Message::Discovery"
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
                                "removing node from MdnsDiscovery address book"
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
                            "adding node to MdnsDiscovery address book"
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
                        trace!(?node_id, "MdnsDiscovery Message::SendAddrs");
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
                            time::sleep(DISCOVERY_DURATION).await;
                            trace!(?node_id, "discovery timeout");
                            timeout_sender
                                .send(Message::Timeout(node_id, id))
                                .await
                                .ok();
                        });
                    }
                    Message::Timeout(node_id, id) => {
                        trace!(?node_id, "MdnsDiscovery Message::Timeout");
                        if let Some(senders_for_node_id) = senders.get_mut(&node_id) {
                            senders_for_node_id.remove(&id);
                            if senders_for_node_id.is_empty() {
                                senders.remove(&node_id);
                            }
                        }
                    }
                    Message::Subscribe(subscriber) => {
                        trace!("MdnsDiscovery Message::Subscribe");
                        subscribers.push(subscriber);
                    }
                }
            }
        };
        let handle = task::spawn(discovery_fut.instrument(info_span!("swarm-discovery.actor")));
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
    ) -> Result<DropGuard, IntoDiscoveryError> {
        let spawn_rt = rt.clone();
        let callback = move |node_id: &str, peer: &Peer| {
            trace!(
                node_id,
                ?peer,
                "Received peer information from MdnsDiscovery"
            );

            let sender = sender.clone();
            let node_id = node_id.to_string();
            let peer = peer.clone();
            spawn_rt.spawn(async move {
                sender.send(Message::Discovery(node_id, peer)).await.ok();
            });
        };
        let addrs = MdnsDiscovery::socketaddrs_to_addrs(&socketaddrs);
        let node_id_str = data_encoding::BASE32_NOPAD
            .encode(node_id.as_bytes())
            .to_ascii_lowercase();
        let mut discoverer = Discoverer::new_interactive(N0_LOCAL_SWARM.to_string(), node_id_str)
            .with_callback(callback)
            .with_ip_class(IpClass::Auto);
        for addr in addrs {
            discoverer = discoverer.with_addrs(addr.0, addr.1);
        }
        discoverer
            .spawn(rt)
            .map_err(|e| IntoDiscoveryError::from_err_box("mdns", e.into_boxed_dyn_error()))
    }

    fn socketaddrs_to_addrs(socketaddrs: &BTreeSet<SocketAddr>) -> HashMap<u16, Vec<IpAddr>> {
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
    // Get the user-defined data from the resolved peer info. We expect an attribute with a value
    // that parses as `UserData`. Otherwise, omit.
    let user_data = if let Some(Some(user_data)) = peer.txt_attribute(USER_DATA_ATTRIBUTE) {
        match user_data.parse() {
            Err(err) => {
                debug!("failed to parse user data from TXT attribute: {err}");
                None
            }
            Ok(data) => Some(data),
        }
    } else {
        None
    };
    let node_info = NodeInfo::new(*node_id)
        .with_direct_addresses(direct_addresses)
        .with_user_data(user_data);
    DiscoveryItem::new(node_info, NAME, None)
}

impl Discovery for MdnsDiscovery {
    fn resolve(&self, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        use futures_util::FutureExt;

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

    fn publish(&self, data: &NodeData) {
        self.local_addrs.set(Some(data.clone())).ok();
    }

    fn subscribe(&self) -> Option<BoxStream<DiscoveryItem>> {
        use futures_util::FutureExt;

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
        use iroh_base::SecretKey;
        use n0_future::StreamExt;
        use n0_snafu::{Error, Result, ResultExt};
        use snafu::whatever;
        use tracing_test::traced_test;

        use super::super::*;
        use crate::discovery::UserData;

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_resolve() -> Result {
            let (_, discovery_a) = make_discoverer()?;
            let (node_id_b, discovery_b) = make_discoverer()?;

            // make addr info for discoverer b
            let user_data: UserData = "foobar".parse()?;
            let node_data = NodeData::new(None, BTreeSet::from(["0.0.0.0:11111".parse().unwrap()]))
                .with_user_data(Some(user_data.clone()));
            println!("info {node_data:?}");

            // resolve twice to ensure we can create separate streams for the same node_id
            let mut s1 = discovery_a.resolve(node_id_b).unwrap();
            let mut s2 = discovery_a.resolve(node_id_b).unwrap();

            tracing::debug!(?node_id_b, "Discovering node id b");
            // publish discovery_b's address
            discovery_b.publish(&node_data);
            let s1_res = tokio::time::timeout(Duration::from_secs(5), s1.next())
                .await
                .context("timeout")?
                .unwrap()?;
            let s2_res = tokio::time::timeout(Duration::from_secs(5), s2.next())
                .await
                .context("timeout")?
                .unwrap()?;
            assert_eq!(s1_res.node_info().data, node_data);
            assert_eq!(s2_res.node_info().data, node_data);

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_subscribe() -> Result {
            let num_nodes = 5;
            let mut node_ids = BTreeSet::new();
            let mut discoverers = vec![];

            let (_, discovery) = make_discoverer()?;
            let node_data = NodeData::new(None, BTreeSet::from(["0.0.0.0:11111".parse().unwrap()]));

            for i in 0..num_nodes {
                let (node_id, discovery) = make_discoverer()?;
                let user_data: UserData = format!("node{i}").parse()?;
                let node_data = node_data.clone().with_user_data(Some(user_data.clone()));
                node_ids.insert((node_id, Some(user_data)));
                discovery.publish(&node_data);
                discoverers.push(discovery);
            }

            let mut events = discovery.subscribe().unwrap();

            let test = async move {
                let mut got_ids = BTreeSet::new();
                while got_ids.len() != num_nodes {
                    if let Some(item) = events.next().await {
                        if node_ids.contains(&(item.node_id(), item.user_data())) {
                            got_ids.insert((item.node_id(), item.user_data()));
                        }
                    } else {
                        whatever!(
                            "no more events, only got {} ids, expected {num_nodes}\n",
                            got_ids.len()
                        );
                    }
                }
                assert_eq!(got_ids, node_ids);
                Ok::<_, Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), test)
                .await
                .context("timeout")?
        }

        fn make_discoverer() -> Result<(PublicKey, MdnsDiscovery)> {
            let node_id = SecretKey::generate(rand::thread_rng()).public();
            Ok((node_id, MdnsDiscovery::new(node_id)?))
        }
    }
}
