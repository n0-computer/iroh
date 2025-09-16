use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::AtomicBool},
};

use iroh_base::{NodeAddr, NodeId, PublicKey, RelayUrl};
use n0_future::{
    task::AbortOnDropHandle,
    time::{Duration, Instant},
};
use n0_watcher::Watchable;
use quinn::WeakConnectionHandle;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{Level, debug, event, info, instrument, trace, warn};

use super::{
    IpPort, Source,
    path_state::{PathState, summarize_node_paths},
    udp_paths::{NodeUdpPaths, UdpSendAddr},
};
#[cfg(any(test, feature = "test-utils"))]
use crate::endpoint::PathSelection;
use crate::{
    disco::{self, SendAddr},
    magicsock::{
        AllPathsMappedAddr, HEARTBEAT_INTERVAL, MagicsockMetrics,
        node_map::path_validity::PathValidity,
        transports::{self, OwnedTransmit, TransportsSender},
    },
};

/// Number of addresses that are not active that we keep around per node.
///
/// See [`NodeState::prune_direct_addresses`].
pub(super) const MAX_INACTIVE_DIRECT_ADDRESSES: usize = 20;

/// How long since an endpoint path was last alive before it might be pruned.
const LAST_ALIVE_PRUNE_DURATION: Duration = Duration::from_secs(120);

/// The latency at or under which we don't try to upgrade to a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// How long since the last activity we try to keep an established endpoint peering alive.
/// It's also the idle time at which we stop doing QAD queries to keep NAT mappings alive.
pub(super) const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

/// How often we try to upgrade to a better patheven if we have some non-relay route that works.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub(in crate::magicsock) enum PingAction {
    SendCallMeMaybe {
        relay_url: RelayUrl,
        dst_node: NodeId,
    },
}

/// An iroh node, which we can have connections with.
///
/// The whole point of the magicsock is that we can have multiple **paths** to a particular
/// node.  One of these paths is via the endpoint's home relay node but as we establish a
/// connection we'll hopefully discover more direct paths.
#[derive(Debug)]
pub(super) struct NodeState {
    /// The ID used as index in the [`NodeMap`].
    ///
    /// [`NodeMap`]: super::NodeMap
    id: usize,
    /// The UDP address used on the QUIC-layer to address this node.
    quic_mapped_addr: AllPathsMappedAddr,
    /// The global identifier for this endpoint.
    node_id: NodeId,
    /// The url of relay node that we can relay over to communicate.
    ///
    /// The fallback/bootstrap path, if non-zero (non-zero for well-behaved clients).
    relay_url: Option<(RelayUrl, PathState)>,
    udp_paths: NodeUdpPaths,
    /// Last time this node was used.
    ///
    /// A node is marked as in use when sending datagrams to them, or when having received
    /// datagrams from it. Regardless of whether the datagrams are payload or DISCO, and whether
    /// they go via UDP or the relay.
    ///
    /// Note that sending datagrams to a node does not mean the node receives them.
    last_used: Option<Instant>,
    /// Last time we sent a call-me-maybe.
    ///
    /// When we do not have a direct connection and we try to send some data, we will try to
    /// do a full ping + call-me-maybe.  Usually each side only needs to send one
    /// call-me-maybe to the other for holes to be punched in both directions however.  So
    /// we only try and send one per [`HEARTBEAT_INTERVAL`].  Each [`HEARTBEAT_INTERVAL`]
    /// the [`NodeState::stayin_alive`] function is called, which will trigger new
    /// call-me-maybe messages as backup.
    last_call_me_maybe: Option<Instant>,
    /// The type of connection we have to the node, either direct, relay, mixed, or none.
    conn_type: Watchable<ConnectionType>,
    /// Whether the conn_type was ever observed to be `Direct` at some point.
    ///
    /// Used for metric reporting.
    has_been_direct: AtomicBool,
    /// Configuration for what path selection to use
    #[cfg(any(test, feature = "test-utils"))]
    path_selection: PathSelection,
}

/// Options for creating a new [`NodeState`].
#[derive(Debug)]
pub(super) struct Options {
    pub(super) node_id: NodeId,
    pub(super) relay_url: Option<RelayUrl>,
    /// Is this endpoint currently active (sending data)?
    pub(super) active: bool,
    pub(super) source: super::Source,
    #[cfg(any(test, feature = "test-utils"))]
    pub(super) path_selection: PathSelection,
}

impl NodeState {
    pub(super) fn new(id: usize, options: Options) -> Self {
        let quic_mapped_addr = AllPathsMappedAddr::generate();

        // TODO(frando): I don't think we need to track the `num_relay_conns_added`
        // metric here. We do so in `Self::addr_for_send`.
        // if options.relay_url.is_some() {
        //     // we potentially have a relay connection to the node
        //     inc!(MagicsockMetrics, num_relay_conns_added);
        // }

        let now = Instant::now();

        NodeState {
            id,
            quic_mapped_addr,
            node_id: options.node_id,
            relay_url: options.relay_url.map(|url| {
                (
                    url.clone(),
                    PathState::new(options.node_id, SendAddr::Relay(url), options.source, now),
                )
            }),
            udp_paths: NodeUdpPaths::new(),
            last_used: options.active.then(Instant::now),
            last_call_me_maybe: None,
            conn_type: Watchable::new(ConnectionType::None),
            has_been_direct: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-utils"))]
            path_selection: options.path_selection,
        }
    }

    pub(super) fn public_key(&self) -> &PublicKey {
        &self.node_id
    }

    pub(super) fn all_paths_mapped_addr(&self) -> &AllPathsMappedAddr {
        &self.quic_mapped_addr
    }

    pub(super) fn id(&self) -> usize {
        self.id
    }

    pub(super) fn conn_type(&self) -> n0_watcher::Direct<ConnectionType> {
        self.conn_type.watch()
    }

    /// Returns info about this node.
    pub(super) fn info(&self, now: Instant) -> RemoteInfo {
        let conn_type = self.conn_type.get();
        let latency = None;

        let addrs = self
            .udp_paths
            .paths
            .iter()
            .map(|(addr, path_state)| DirectAddrInfo {
                addr: SocketAddr::from(*addr),
                latency: path_state.validity.latency(),
                last_control: path_state.last_control_msg(now),
                last_payload: path_state
                    .last_payload_msg
                    .as_ref()
                    .map(|instant| now.duration_since(*instant)),
                last_alive: path_state
                    .last_alive()
                    .map(|instant| now.duration_since(instant)),
                sources: path_state
                    .sources
                    .iter()
                    .map(|(source, instant)| (source.clone(), now.duration_since(*instant)))
                    .collect(),
            })
            .collect();

        RemoteInfo {
            node_id: self.node_id,
            relay_url: self.relay_url.clone().map(|r| r.into()),
            addrs,
            conn_type,
            latency,
            last_used: self.last_used.map(|instant| now.duration_since(instant)),
        }
    }

    /// Returns the relay url of this endpoint
    pub(super) fn relay_url(&self) -> Option<RelayUrl> {
        self.relay_url.as_ref().map(|(url, _state)| url.clone())
    }

    /// Returns the address(es) that should be used for sending the next packet.
    ///
    /// This may return to send on one, both or no paths.
    fn addr_for_send(
        &self,
        have_ipv6: bool,
        metrics: &MagicsockMetrics,
    ) -> (Option<SocketAddr>, Option<RelayUrl>) {
        #[cfg(any(test, feature = "test-utils"))]
        if self.path_selection == PathSelection::RelayOnly {
            debug!(
                "in `RelayOnly` mode, giving the relay address as the only viable address for this endpoint"
            );
            return (None, self.relay_url());
        }
        let (best_addr, relay_url) = match self.udp_paths.send_addr(have_ipv6) {
            UdpSendAddr::Valid(addr) => {
                // If we have a valid address we use it.
                trace!(%addr, "UdpSendAddr is valid, use it");
                (Some(*addr), None)
            }
            UdpSendAddr::Outdated(addr) => {
                // If the address is outdated we use it, but send via relay at the same time.
                // We also send disco pings so that it will become valid again if it still
                // works (i.e. we don't need to holepunch again).
                trace!(%addr, "UdpSendAddr is outdated, use it together with relay");
                (Some(*addr), self.relay_url())
            }
            UdpSendAddr::Unconfirmed(addr) => {
                trace!(%addr, "UdpSendAddr is unconfirmed, use it together with relay");
                (Some(*addr), self.relay_url())
            }
            UdpSendAddr::None => {
                trace!("No UdpSendAddr, use relay");
                (None, self.relay_url())
            }
        };
        let typ = match (best_addr, relay_url.clone()) {
            (Some(best_addr), Some(relay_url)) => ConnectionType::Mixed(best_addr, relay_url),
            (Some(best_addr), None) => ConnectionType::Direct(best_addr),
            (None, Some(relay_url)) => ConnectionType::Relay(relay_url),
            (None, None) => ConnectionType::None,
        };
        if matches!(&typ, ConnectionType::Direct(_)) {
            let before = self
                .has_been_direct
                .swap(true, std::sync::atomic::Ordering::Relaxed);
            if !before {
                metrics.nodes_contacted_directly.inc();
            }
        }
        if let Ok(prev_typ) = self.conn_type.set(typ.clone()) {
            // The connection type has changed.
            event!(
                target: "iroh::_events::conn_type::changed",
                Level::DEBUG,
                remote_node = %self.node_id.fmt_short(),
                conn_type = ?typ,
            );
            info!(%typ, "new connection type");

            // Update some metrics
            match (prev_typ, typ) {
                (ConnectionType::Relay(_), ConnectionType::Direct(_))
                | (ConnectionType::Mixed(_, _), ConnectionType::Direct(_)) => {
                    metrics.num_direct_conns_added.inc();
                    metrics.num_relay_conns_removed.inc();
                }
                (ConnectionType::Direct(_), ConnectionType::Relay(_))
                | (ConnectionType::Direct(_), ConnectionType::Mixed(_, _)) => {
                    metrics.num_direct_conns_removed.inc();
                    metrics.num_relay_conns_added.inc();
                }
                (ConnectionType::None, ConnectionType::Direct(_)) => {
                    metrics.num_direct_conns_added.inc();
                }
                (ConnectionType::Direct(_), ConnectionType::None) => {
                    metrics.num_direct_conns_removed.inc();
                }
                (ConnectionType::None, ConnectionType::Relay(_))
                | (ConnectionType::None, ConnectionType::Mixed(_, _)) => {
                    metrics.num_relay_conns_added.inc();
                }
                (ConnectionType::Relay(_), ConnectionType::None)
                | (ConnectionType::Mixed(_, _), ConnectionType::None) => {
                    metrics.num_relay_conns_removed.inc();
                }
                _ => (),
            }
        }
        (best_addr, relay_url)
    }

    /// Removes a direct address for this node.
    ///
    /// If this is also the best address, it will be cleared as well.
    pub(super) fn remove_direct_addr(&mut self, ip_port: &IpPort, now: Instant, why: &'static str) {
        let Some(state) = self.udp_paths.paths.remove(ip_port) else {
            return;
        };

        match state.last_alive().map(|instant| instant.elapsed()) {
            Some(last_alive) => debug!(%ip_port, ?last_alive, why, "pruning address"),
            None => debug!(%ip_port, last_seen=%"never", why, "pruning address"),
        }

        self.udp_paths.update_to_best_addr(now);
    }

    /// Whether we need to send another call-me-maybe to the endpoint.
    ///
    /// Basically we need to send a call-me-maybe if we need to find a better path.  Maybe
    /// we only have a relay path, or our path is expired.
    ///
    /// When a call-me-maybe message is sent we also need to send pings to all known paths
    /// of the endpoint.  The [`NodeState::send_call_me_maybe`] function takes care of this.
    #[cfg(not(wasm_browser))]
    #[instrument("want_call_me_maybe", skip_all)]
    fn want_call_me_maybe(&self, now: &Instant) -> bool {
        trace!("full ping: wanted?");
        match &self.udp_paths.best {
            UdpSendAddr::None | UdpSendAddr::Unconfirmed(_) => {
                debug!("best addr not set: need full ping");
                true
            }
            UdpSendAddr::Outdated(_) => {
                debug!("best addr expired: need full ping");
                true
            }
            UdpSendAddr::Valid(addr) => {
                let latency = self
                    .udp_paths
                    .paths
                    .get(&(*addr).into())
                    .expect("send path not tracked?")
                    .latency()
                    .expect("send_addr marked valid incorrectly");
                if latency > GOOD_ENOUGH_LATENCY {
                    debug!(
                        "full ping interval expired and latency is only {}ms: need full ping",
                        latency.as_millis()
                    );
                    true
                } else {
                    trace!(?now, "best_addr valid: not needed");
                    false
                }
            }
        }
    }

    #[cfg(wasm_browser)]
    fn want_call_me_maybe(&self, _now: &Instant) -> bool {
        trace!("full ping: skipped in browser");
        false
    }

    /// Send a DISCO call-me-maybe message to the peer.
    ///
    /// This takes care of sending the needed pings beforehand.  This ensures that we open
    /// our firewall's port so that when the receiver sends us DISCO pings in response to
    /// our call-me-maybe they will reach us and the other side establishes a direct
    /// connection upon our subsequent pong response.
    ///
    /// For [`SendCallMeMaybe::IfNoRecent`], **no** paths will be pinged if there already
    /// was a recent call-me-maybe sent.
    ///
    /// The caller is responsible for sending the messages.
    #[must_use = "actions must be handled"]
    fn send_call_me_maybe(&mut self, now: Instant, always: SendCallMeMaybe) -> Vec<PingAction> {
        match always {
            SendCallMeMaybe::Always => (),
            SendCallMeMaybe::IfNoRecent => {
                let had_recent_call_me_maybe = self
                    .last_call_me_maybe
                    .map(|when| when.elapsed() < HEARTBEAT_INTERVAL)
                    .unwrap_or(false);
                if had_recent_call_me_maybe {
                    trace!("skipping call-me-maybe, still recent");
                    return Vec::new();
                }
            }
        }
        let mut msgs = Vec::new();

        if let Some(url) = self.relay_url() {
            debug!(%url, "queue call-me-maybe");
            msgs.push(PingAction::SendCallMeMaybe {
                relay_url: url,
                dst_node: self.node_id,
            });
            self.last_call_me_maybe = Some(now);
        } else {
            debug!("can not send call-me-maybe, no relay URL");
        }

        msgs
    }

    pub(super) fn update_from_node_addr(
        &mut self,
        new_relay_url: Option<&RelayUrl>,
        new_addrs: &BTreeSet<SocketAddr>,
        source: super::Source,
        metrics: &MagicsockMetrics,
    ) {
        if matches!(
            self.udp_paths.best,
            UdpSendAddr::None | UdpSendAddr::Unconfirmed(_)
        ) {
            // we do not have a direct connection, so changing the relay information may
            // have an effect on our connection status
            if self.relay_url.is_none() && new_relay_url.is_some() {
                // we did not have a relay connection before, but now we do
                metrics.num_relay_conns_added.inc();
            } else if self.relay_url.is_some() && new_relay_url.is_none() {
                // we had a relay connection before but do not have one now
                metrics.num_relay_conns_removed.inc();
            }
        }

        let now = Instant::now();

        if new_relay_url.is_some() && new_relay_url != self.relay_url().as_ref() {
            debug!(
                "Changing relay node from {:?} to {:?}",
                self.relay_url, new_relay_url
            );
            self.relay_url = new_relay_url.map(|url| {
                (
                    url.clone(),
                    PathState::new(self.node_id, url.clone().into(), source.clone(), now),
                )
            });
        }

        for &addr in new_addrs.iter() {
            self.udp_paths
                .paths
                .entry(addr.into())
                .and_modify(|path_state| {
                    path_state.add_source(source.clone(), now);
                })
                .or_insert_with(|| {
                    PathState::new(self.node_id, SendAddr::from(addr), source.clone(), now)
                });
        }
        let paths = summarize_node_paths(&self.udp_paths.paths);
        debug!(new = ?new_addrs , %paths, "added new direct paths for endpoint");
    }

    /// Prune inactive paths.
    ///
    /// This trims the list of inactive paths for an endpoint.  At most
    /// [`MAX_INACTIVE_DIRECT_ADDRESSES`] are kept.
    pub(super) fn prune_direct_addresses(&mut self, now: Instant) {
        // prune candidates are addresses that are not active
        let mut prune_candidates: Vec<_> = self
            .udp_paths
            .paths
            .iter()
            .filter(|(_ip_port, state)| !state.is_active())
            .map(|(ip_port, state)| (*ip_port, state.last_alive()))
            .filter(|(_ipp, last_alive)| match last_alive {
                Some(last_seen) => last_seen.elapsed() > LAST_ALIVE_PRUNE_DURATION,
                None => true,
            })
            .collect();
        let prune_count = prune_candidates
            .len()
            .saturating_sub(MAX_INACTIVE_DIRECT_ADDRESSES);
        if prune_count == 0 {
            // nothing to do, within limits
            debug!(
                paths = %summarize_node_paths(&self.udp_paths.paths),
                "prune addresses: {prune_count} pruned",
            );
            return;
        }

        // sort leaving the worst addresses first (never contacted) and better ones (most recently
        // used ones) last
        prune_candidates.sort_unstable_by_key(|(_ip_port, last_alive)| *last_alive);
        prune_candidates.truncate(prune_count);
        for (ip_port, _last_alive) in prune_candidates.into_iter() {
            self.remove_direct_addr(&ip_port, now, "inactive");
        }
        debug!(
            paths = %summarize_node_paths(&self.udp_paths.paths),
            "prune addresses: {prune_count} pruned",
        );
    }

    /// Called when connectivity changes enough that we should question our earlier
    /// assumptions about which paths work.
    #[instrument("disco", skip_all, fields(node = %self.node_id.fmt_short()))]
    pub(super) fn note_connectivity_change(&mut self, now: Instant) {
        for es in self.udp_paths.paths.values_mut() {
            es.clear();
        }
        self.udp_paths.update_to_best_addr(now);
    }

    /// Handles a DISCO CallMeMaybe discovery message.
    ///
    /// The contract for use of this message is that the node has already pinged to us via
    /// UDP, so their stateful firewall should be open. Now we can Ping back and make it
    /// through.
    ///
    /// However if the remote side has no direct path information to us, they would not have
    /// had any [`IpPort`]s to send pings to and our pings might end up blocked.  But at
    /// least open the firewalls on our side, giving the other side another change of making
    /// it through when it pings in response.
    pub(super) fn handle_call_me_maybe(&mut self, m: disco::CallMeMaybe) {
        let now = Instant::now();
        let mut call_me_maybe_ipps = BTreeSet::new();

        for peer_sockaddr in &m.my_numbers {
            if let IpAddr::V6(ip) = peer_sockaddr.ip() {
                if netwatch::ip::is_unicast_link_local(ip) {
                    // We send these out, but ignore them for now.
                    // TODO: teach the ping code to ping on all interfaces for these.
                    continue;
                }
            }
            let ipp = IpPort::from(*peer_sockaddr);
            call_me_maybe_ipps.insert(ipp);
            self.udp_paths
                .paths
                .entry(ipp)
                .or_insert_with(|| {
                    PathState::new(
                        self.node_id,
                        SendAddr::from(*peer_sockaddr),
                        Source::Relay,
                        now,
                    )
                })
                .call_me_maybe_time
                .replace(now);
        }

        // Zero out all the last_ping times to force send_pings to send new ones, even if
        // it's been less than 5 seconds ago.  Also clear pongs for direct addresses not
        // included in the updated set.
        for (ipp, st) in self.udp_paths.paths.iter_mut() {
            if !call_me_maybe_ipps.contains(ipp) {
                // TODO: This seems like a weird way to signal that the endpoint no longer
                // thinks it has this IpPort as an available path.
                if !st.validity.is_empty() {
                    debug!(path=?ipp ,"clearing recent pong");
                    st.validity = PathValidity::empty();
                }
            }
        }
        // Clear trust on our best_addr if it is not included in the updated set.
        let changed = self.udp_paths.update_to_best_addr(now);
        if changed {
            // Clear the last call-me-maybe send time so we will send one again.
            self.last_call_me_maybe = None;
        }
        debug!(
            paths = %summarize_node_paths(&self.udp_paths.paths),
            "updated endpoint paths from call-me-maybe",
        );
    }

    /// Marks this node as having received a UDP payload message.
    #[cfg(not(wasm_browser))]
    pub(super) fn receive_udp(&mut self, addr: IpPort, now: Instant) {
        let Some(state) = self.udp_paths.paths.get_mut(&addr) else {
            debug_assert!(false, "node map inconsistency by_ip_port <-> direct addr");
            return;
        };
        state.receive_payload(now);
        self.last_used = Some(now);
        self.udp_paths.update_to_best_addr(now);
    }

    pub(super) fn receive_relay(&mut self, url: &RelayUrl, src: NodeId, now: Instant) {
        match self.relay_url.as_mut() {
            Some((current_home, state)) if current_home == url => {
                // We received on the expected url. update state.
                state.receive_payload(now);
            }
            Some((_current_home, _state)) => {
                // we have a different url. we only update on ping, not on receive_relay.
            }
            None => {
                self.relay_url = Some((
                    url.clone(),
                    PathState::with_last_payload(
                        src,
                        SendAddr::from(url.clone()),
                        Source::Relay,
                        now,
                    ),
                ));
            }
        }
        self.last_used = Some(now);
    }

    /// Checks if this `Endpoint` is currently actively being used.
    pub(super) fn is_active(&self, now: &Instant) -> bool {
        match self.last_used {
            Some(last_active) => now.duration_since(last_active) <= SESSION_ACTIVE_TIMEOUT,
            None => false,
        }
    }

    /// Send a heartbeat to the node to keep the connection alive, or trigger a full ping
    /// if necessary.
    #[instrument("stayin_alive", skip_all, fields(node = %self.node_id.fmt_short()))]
    pub(super) fn stayin_alive(&mut self) -> Vec<PingAction> {
        trace!("stayin_alive");
        let now = Instant::now();
        if !self.is_active(&now) {
            trace!("skipping stayin alive: session is inactive");
            return Vec::new();
        }

        // If we do not have an optimal addr, send pings to all known places.
        if self.want_call_me_maybe(&now) {
            debug!("sending a call-me-maybe");
            return self.send_call_me_maybe(now, SendCallMeMaybe::Always);
        }

        Vec::new()
    }

    /// Returns the addresses on which a payload should be sent right now.
    ///
    /// This is in the hot path of `.poll_send()`.
    // TODO(matheus23): Make this take &self. That's not quite possible yet due to `send_call_me_maybe`
    // eventually calling `prune_direct_addresses` (which needs &mut self)
    #[instrument("get_send_addrs", skip_all, fields(node = %self.node_id.fmt_short()))]
    pub(crate) fn get_send_addrs(
        &mut self,
        have_ipv6: bool,
        metrics: &MagicsockMetrics,
    ) -> (Option<SocketAddr>, Option<RelayUrl>, Vec<PingAction>) {
        let now = Instant::now();
        let prev = self.last_used.replace(now);
        if prev.is_none() {
            // this is the first time we are trying to connect to this node
            metrics.nodes_contacted.inc();
        }
        let (udp_addr, relay_url) = self.addr_for_send(have_ipv6, metrics);

        let ping_msgs = if self.want_call_me_maybe(&now) {
            self.send_call_me_maybe(now, SendCallMeMaybe::IfNoRecent)
        } else {
            Vec::new()
        };
        trace!(
            ?udp_addr,
            ?relay_url,
            pings = %ping_msgs.len(),
            "found send address",
        );
        (udp_addr, relay_url, ping_msgs)
    }

    /// Returns a [`NodeAddr`] with all the currently known direct addresses and the relay URL.
    pub(crate) fn get_current_addr(&self) -> NodeAddr {
        // TODO: more selective?
        let mut node_addr =
            NodeAddr::new(self.node_id).with_direct_addresses(self.udp_paths.addrs());
        if let Some((url, _)) = &self.relay_url {
            node_addr = node_addr.with_relay_url(url.clone());
        }

        node_addr
    }

    /// Get the direct addresses for this endpoint.
    pub(super) fn direct_addresses(&self) -> impl Iterator<Item = IpPort> + '_ {
        self.udp_paths.paths.keys().copied()
    }

    #[cfg(test)]
    pub(super) fn direct_address_states(&self) -> impl Iterator<Item = (&IpPort, &PathState)> + '_ {
        self.udp_paths.paths.iter()
    }

    pub(super) fn last_used(&self) -> Option<Instant> {
        self.last_used
    }
}

/// The state we need to know about a single remote node.
///
/// This actor manages all connections to the remote node.  It will trigger holepunching and
/// select the best path etc.
pub(super) struct NodeStateActor {
    /// The node ID of the remote node.
    node_id: NodeId,
    transports_sender: TransportsSender,
    // TODO: Turn this into a WeakConnectionHandle
    connections: Vec<quinn::Connection>,
    paths: BTreeMap<transports::Addr, NewPathState>,
    metrics: Arc<MagicsockMetrics>,
}

impl NodeStateActor {
    pub(super) fn new(
        node_id: NodeId,
        transports_sender: TransportsSender,
        metrics: Arc<MagicsockMetrics>,
    ) -> Self {
        Self {
            node_id,
            transports_sender,
            connections: Vec::new(),
            paths: BTreeMap::new(),
            metrics,
        }
    }

    pub(super) fn start(mut self) -> NodeStateHandle {
        let (tx, rx) = mpsc::channel(16);

        // No .instrument() on the task, run method has an #[instrument] attribute.
        let task = tokio::spawn(async move {
            self.run(rx).await;
        });
        NodeStateHandle {
            sender: tx,
            _task: AbortOnDropHandle::new(task),
        }
    }

    #[instrument(
        name = "NodeStateActor",
        skip_all,
        fields(node_id = %self.node_id.fmt_short())
    )]
    async fn run(&mut self, mut inbox: mpsc::Receiver<NodeStateMessage>) {
        loop {
            if let Some(msg) = inbox.recv().await {
                match msg {
                    NodeStateMessage::SendDatagram(transmit) => todo!(),
                    NodeStateMessage::AddConnection(handle) => todo!(),
                    NodeStateMessage::PingReceived => todo!(),
                }
            } else {
                break;
            }
        }
        trace!("actor terminating");
    }
}

/// Messages to send to the [`NodeStateActor`].
pub(crate) enum NodeStateMessage {
    /// Send a datagram to all known paths.
    ///
    /// Used to send QUIC Initial packets.  If there is no working direct path this will
    /// trigger holepunching.
    ///
    /// This is not acceptable to use on the normal send path, as it is an async send
    /// operation with a bunch more copying.  So it should only be used for sending QUIC
    /// Initial packets.
    SendDatagram(OwnedTransmit),
    /// Add an active connection to this remote node.
    ///
    /// The connection will now be managed by this actor.  Holepunching will happen when
    /// needed, any new paths discovered via holepunching will be added.  And closed paths
    /// will be removed etc.
    AddConnection(WeakConnectionHandle),
    // TODO: Add the transaction ID.
    PingReceived,
}

/// A handle to a [`NodeStateActor`].
///
/// Dropping this will stop the actor.
#[derive(Debug)]
pub(super) struct NodeStateHandle {
    sender: mpsc::Sender<NodeStateMessage>,
    _task: AbortOnDropHandle<()>,
}

struct NewPathState {
    addr: transports::Addr,
}

impl From<RemoteInfo> for NodeAddr {
    fn from(info: RemoteInfo) -> Self {
        let direct_addresses = info
            .addrs
            .into_iter()
            .map(|info| info.addr)
            .collect::<BTreeSet<_>>();

        NodeAddr {
            node_id: info.node_id,
            relay_url: info.relay_url.map(Into::into),
            direct_addresses,
        }
    }
}

/// Whether to send a call-me-maybe message after sending pings to all known paths.
///
/// `IfNoRecent` will only send a call-me-maybe if no previous one was sent in the last
/// [`HEARTBEAT_INTERVAL`].
#[derive(Debug)]
enum SendCallMeMaybe {
    Always,
    IfNoRecent,
}

/// The reason why a discovery ping message was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoPingPurpose {
    /// The purpose of a ping was to see if a path was valid.
    Discovery,
    /// Ping to ensure the current route is still valid.
    StayinAlive,
    /// When a ping was received and no direct connection exists yet.
    ///
    /// When a ping was received we suspect a direct connection is possible.  If we do not
    /// yet have one that triggers a ping, indicated with this reason.
    PingBack,
}

/// The type of control message we have received.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, derive_more::Display)]
pub enum ControlMsg {
    /// We received a Ping from the node.
    #[display("ping←")]
    Ping,
    /// We received a Pong from the node.
    #[display("pong←")]
    Pong,
    /// We received a CallMeMaybe.
    #[display("call me")]
    CallMeMaybe,
}

/// Information about a *direct address*.
///
/// The *direct addresses* of an iroh node are those that could be used by other nodes to
/// establish direct connectivity, depending on the network situation. Due to NAT configurations,
/// for example, not all direct addresses of a node are usable by all peers.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DirectAddrInfo {
    /// The UDP address reported by the remote node.
    pub addr: SocketAddr,
    /// The latency to the remote node over this network path.
    ///
    /// If there has never been any connectivity via this address no latency will be known.
    pub latency: Option<Duration>,
    /// Last control message received by this node about this address.
    ///
    /// This contains the elapsed duration since the control message was received and the
    /// kind of control message received at that time.  Only the most recent control message
    /// is returned.
    ///
    /// Note that [`ControlMsg::CallMeMaybe`] is received via a relay path, while
    /// [`ControlMsg::Ping`] and [`ControlMsg::Pong`] are received on the path to
    /// [`DirectAddrInfo::addr`] itself and thus convey very different information.
    pub last_control: Option<(Duration, ControlMsg)>,
    /// Elapsed time since the last payload message was received on this network path.
    ///
    /// This indicates how long ago a QUIC datagram was received from the remote node sent
    /// from this [`DirectAddrInfo::addr`].  It indicates the network path was in use to
    /// transport payload data.
    pub last_payload: Option<Duration>,
    /// Elapsed time since this network path was known to exist.
    ///
    /// A network path is considered to exist only because the remote node advertised it.
    /// It may not mean the path is usable.  However, if there was any communication with
    /// the remote node over this network path it also means the path exists.
    ///
    /// The elapsed time since *any* confirmation of the path's existence was received is
    /// returned.  If the remote node moved networks and no longer has this path, this could
    /// be a long duration.  If the path was added via [`Endpoint::add_node_addr`] or some
    /// node discovery the path may never have been known to exist.
    ///
    /// [`Endpoint::add_node_addr`]: crate::endpoint::Endpoint::add_node_addr
    pub last_alive: Option<Duration>,
    /// A [`HashMap`] of [`Source`]s to [`Duration`]s.
    ///
    /// The [`Duration`] indicates the elapsed time since this source last
    /// recorded this address.
    ///
    /// The [`Duration`] will always indicate the most recent time the source
    /// recorded this address.
    pub sources: HashMap<Source, Duration>,
}

/// Information about the network path to a remote node via a relay server.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayUrlInfo {
    /// The relay URL.
    pub relay_url: RelayUrl,
    /// Elapsed time since this relay path last received payload or control data.
    pub last_alive: Option<Duration>,
    /// Latency to the remote node over this relayed network path.
    pub latency: Option<Duration>,
}

impl From<(RelayUrl, PathState)> for RelayUrlInfo {
    fn from(value: (RelayUrl, PathState)) -> Self {
        RelayUrlInfo {
            relay_url: value.0,
            last_alive: value.1.last_alive().map(|i| i.elapsed()),
            latency: None,
        }
    }
}

impl From<RelayUrlInfo> for RelayUrl {
    fn from(value: RelayUrlInfo) -> Self {
        value.relay_url
    }
}

/// Details about a remote iroh node which is known to this node.
///
/// Having details of a node does not mean it can be connected to, nor that it has ever been
/// connected to in the past. There are various reasons a node might be known: it could have
/// been manually added via [`Endpoint::add_node_addr`], it could have been added by some
/// discovery mechanism, the node could have contacted this node, etc.
///
/// [`Endpoint::add_node_addr`]: crate::endpoint::Endpoint::add_node_addr
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteInfo {
    /// The globally unique identifier for this node.
    pub node_id: NodeId,
    /// Relay server information, if available.
    pub relay_url: Option<RelayUrlInfo>,
    /// The addresses at which this node might be reachable.
    ///
    /// Some of these addresses might only be valid for networks we are not part of, but the remote
    /// node might be a part of.
    pub addrs: Vec<DirectAddrInfo>,
    /// The type of connection we have to the node, either direct or over relay.
    pub conn_type: ConnectionType,
    /// The latency of the current network path to the remote node.
    pub latency: Option<Duration>,
    /// Time elapsed time since last we have sent to or received from the node.
    ///
    /// This is the duration since *any* data (payload or control messages) was sent or receive
    /// from the remote node. Note that sending to the remote node does not imply
    /// the remote node received anything.
    pub last_used: Option<Duration>,
}

impl RemoteInfo {
    /// Get the duration since the last activity we received from this endpoint
    /// on any of its direct addresses.
    pub fn last_received(&self) -> Option<Duration> {
        self.addrs
            .iter()
            .filter_map(|addr| addr.last_control.map(|x| x.0).min(addr.last_payload))
            .min()
    }

    /// Whether there is a possible known network path to the remote node.
    ///
    /// Note that this does not provide any guarantees of whether any network path is
    /// usable.
    pub fn has_send_address(&self) -> bool {
        self.relay_url.is_some() || !self.addrs.is_empty()
    }

    /// Returns a deduplicated list of [`Source`]s merged from all address in the [`RemoteInfo`].
    ///
    /// Deduplication is on the (`Source`, `Duration`) tuple, so you will get multiple [`Source`]s
    /// for each `Source` variant, if different addresses were discovered from the same [`Source`]
    /// at different times.
    ///
    /// The list is sorted from least to most recent [`Source`].
    pub fn sources(&self) -> Vec<(Source, Duration)> {
        let mut sources = vec![];
        for addr in &self.addrs {
            for source in &addr.sources {
                let source = (source.0.clone(), *source.1);
                if !sources.contains(&source) {
                    sources.push(source)
                }
            }
        }
        sources.sort_by(|a, b| b.1.cmp(&a.1));
        sources
    }
}

/// The type of connection we have to the endpoint.
#[derive(derive_more::Display, Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConnectionType {
    /// Direct UDP connection
    #[display("direct({_0})")]
    Direct(SocketAddr),
    /// Relay connection over relay
    #[display("relay({_0})")]
    Relay(RelayUrl),
    /// Both a UDP and a relay connection are used.
    ///
    /// This is the case if we do have a UDP address, but are missing a recent confirmation that
    /// the address works.
    #[display("mixed(udp: {_0}, relay: {_1})")]
    Mixed(SocketAddr, RelayUrl),
    /// We have no verified connection to this PublicKey
    #[default]
    #[display("none")]
    None,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use iroh_base::SecretKey;

    use super::*;
    // use crate::magicsock::node_map::{NodeMap, NodeMapInner};

    // #[test]
    // fn test_remote_infos() {
    //     let now = Instant::now();
    //     let elapsed = Duration::from_secs(3);
    //     let later = now + elapsed;
    //     let send_addr: RelayUrl = "https://my-relay.com".parse().unwrap();
    //     let pong_src = SendAddr::Udp("0.0.0.0:1".parse().unwrap());
    //     let latency = Duration::from_millis(50);

    //     let relay_and_state = |node_id: NodeId, url: RelayUrl| {
    //         let relay_state = PathState::with_pong_reply(
    //             node_id,
    //             PongReply {
    //                 latency,
    //                 pong_at: now,
    //                 from: SendAddr::Relay(send_addr.clone()),
    //                 pong_src: pong_src.clone(),
    //             },
    //         );
    //         Some((url, relay_state))
    //     };

    //     // endpoint with a `best_addr` that has a latency but no relay
    //     let (a_endpoint, a_socket_addr) = {
    //         let key = SecretKey::generate(rand::thread_rng());
    //         let node_id = key.public();
    //         let ip_port = IpPort {
    //             ip: Ipv4Addr::UNSPECIFIED.into(),
    //             port: 10,
    //         };
    //         let endpoint_state = BTreeMap::from([(
    //             ip_port,
    //             PathState::with_pong_reply(
    //                 node_id,
    //                 PongReply {
    //                     latency,
    //                     pong_at: now,
    //                     from: SendAddr::Udp(ip_port.into()),
    //                     pong_src: pong_src.clone(),
    //                 },
    //             ),
    //         )]);
    //         (
    //             NodeState {
    //                 id: 0,
    //                 quic_mapped_addr: NodeIdMappedAddr::generate(),
    //                 node_id: key.public(),
    //                 last_full_ping: None,
    //                 relay_url: None,
    //                 udp_paths: NodeUdpPaths::from_parts(
    //                     endpoint_state,
    //                     BestAddr::from_parts(
    //                         ip_port.into(),
    //                         latency,
    //                         now,
    //                         now + Duration::from_secs(100),
    //                     ),
    //                 ),
    //                 sent_pings: HashMap::new(),
    //                 last_used: Some(now),
    //                 last_call_me_maybe: None,
    //                 conn_type: Watchable::new(ConnectionType::Direct(ip_port.into())),
    //                 has_been_direct: true,
    //                 #[cfg(any(test, feature = "test-utils"))]
    //                 path_selection: PathSelection::default(),
    //             },
    //             ip_port.into(),
    //         )
    //     };
    //     // endpoint w/ no best addr but a relay w/ latency
    //     let b_endpoint = {
    //         // let socket_addr = "0.0.0.0:9".parse().unwrap();
    //         let key = SecretKey::generate(rand::thread_rng());
    //         NodeState {
    //             id: 1,
    //             quic_mapped_addr: NodeIdMappedAddr::generate(),
    //             node_id: key.public(),
    //             last_full_ping: None,
    //             relay_url: relay_and_state(key.public(), send_addr.clone()),
    //             udp_paths: NodeUdpPaths::new(),
    //             sent_pings: HashMap::new(),
    //             last_used: Some(now),
    //             last_call_me_maybe: None,
    //             conn_type: Watchable::new(ConnectionType::Relay(send_addr.clone())),
    //             has_been_direct: false,
    //             #[cfg(any(test, feature = "test-utils"))]
    //             path_selection: PathSelection::default(),
    //         }
    //     };

    //     // endpoint w/ no best addr but a relay w/ no latency
    //     let c_endpoint = {
    //         // let socket_addr = "0.0.0.0:8".parse().unwrap();
    //         let key = SecretKey::generate(rand::thread_rng());
    //         NodeState {
    //             id: 2,
    //             quic_mapped_addr: NodeIdMappedAddr::generate(),
    //             node_id: key.public(),
    //             last_full_ping: None,
    //             relay_url: Some((
    //                 send_addr.clone(),
    //                 PathState::new(
    //                     key.public(),
    //                     SendAddr::from(send_addr.clone()),
    //                     Source::App,
    //                     now,
    //                 ),
    //             )),
    //             udp_paths: NodeUdpPaths::new(),
    //             sent_pings: HashMap::new(),
    //             last_used: Some(now),
    //             last_call_me_maybe: None,
    //             conn_type: Watchable::new(ConnectionType::Relay(send_addr.clone())),
    //             has_been_direct: false,
    //             #[cfg(any(test, feature = "test-utils"))]
    //             path_selection: PathSelection::default(),
    //         }
    //     };

    //     // endpoint w/ expired best addr and relay w/ latency
    //     let (d_endpoint, d_socket_addr) = {
    //         let socket_addr: SocketAddr = "0.0.0.0:7".parse().unwrap();
    //         let expired = now.checked_sub(Duration::from_secs(100)).unwrap();
    //         let key = SecretKey::generate(rand::thread_rng());
    //         let node_id = key.public();
    //         let endpoint_state = BTreeMap::from([(
    //             IpPort::from(socket_addr),
    //             PathState::with_pong_reply(
    //                 node_id,
    //                 PongReply {
    //                     latency,
    //                     pong_at: now,
    //                     from: SendAddr::Udp(socket_addr),
    //                     pong_src: pong_src.clone(),
    //                 },
    //             ),
    //         )]);
    //         (
    //             NodeState {
    //                 id: 3,
    //                 quic_mapped_addr: NodeIdMappedAddr::generate(),
    //                 node_id: key.public(),
    //                 last_full_ping: None,
    //                 relay_url: relay_and_state(key.public(), send_addr.clone()),
    //                 udp_paths: NodeUdpPaths::from_parts(
    //                     endpoint_state,
    //                     BestAddr::from_parts(socket_addr, Duration::from_millis(80), now, expired),
    //                 ),
    //                 sent_pings: HashMap::new(),
    //                 last_used: Some(now),
    //                 last_call_me_maybe: None,
    //                 conn_type: Watchable::new(ConnectionType::Mixed(
    //                     socket_addr,
    //                     send_addr.clone(),
    //                 )),
    //                 has_been_direct: false,
    //                 #[cfg(any(test, feature = "test-utils"))]
    //                 path_selection: PathSelection::default(),
    //             },
    //             socket_addr,
    //         )
    //     };

    //     let mut expect = Vec::from([
    //         RemoteInfo {
    //             node_id: a_endpoint.node_id,
    //             relay_url: None,
    //             addrs: Vec::from([DirectAddrInfo {
    //                 addr: a_socket_addr,
    //                 latency: Some(latency),
    //                 last_control: Some((elapsed, ControlMsg::Pong)),
    //                 last_payload: None,
    //                 last_alive: Some(elapsed),
    //                 sources: HashMap::new(),
    //             }]),
    //             conn_type: ConnectionType::Direct(a_socket_addr),
    //             latency: Some(latency),
    //             last_used: Some(elapsed),
    //         },
    //         RemoteInfo {
    //             node_id: b_endpoint.node_id,
    //             relay_url: Some(RelayUrlInfo {
    //                 relay_url: b_endpoint.relay_url.as_ref().unwrap().0.clone(),
    //                 last_alive: None,
    //                 latency: Some(latency),
    //             }),
    //             addrs: Vec::new(),
    //             conn_type: ConnectionType::Relay(send_addr.clone()),
    //             latency: Some(latency),
    //             last_used: Some(elapsed),
    //         },
    //         RemoteInfo {
    //             node_id: c_endpoint.node_id,
    //             relay_url: Some(RelayUrlInfo {
    //                 relay_url: c_endpoint.relay_url.as_ref().unwrap().0.clone(),
    //                 last_alive: None,
    //                 latency: None,
    //             }),
    //             addrs: Vec::new(),
    //             conn_type: ConnectionType::Relay(send_addr.clone()),
    //             latency: None,
    //             last_used: Some(elapsed),
    //         },
    //         RemoteInfo {
    //             node_id: d_endpoint.node_id,
    //             relay_url: Some(RelayUrlInfo {
    //                 relay_url: d_endpoint.relay_url.as_ref().unwrap().0.clone(),
    //                 last_alive: None,
    //                 latency: Some(latency),
    //             }),
    //             addrs: Vec::from([DirectAddrInfo {
    //                 addr: d_socket_addr,
    //                 latency: Some(latency),
    //                 last_control: Some((elapsed, ControlMsg::Pong)),
    //                 last_payload: None,
    //                 last_alive: Some(elapsed),
    //                 sources: HashMap::new(),
    //             }]),
    //             conn_type: ConnectionType::Mixed(d_socket_addr, send_addr.clone()),
    //             latency: Some(Duration::from_millis(50)),
    //             last_used: Some(elapsed),
    //         },
    //     ]);

    //     let node_map = NodeMap::from_inner(NodeMapInner {
    //         by_node_key: HashMap::from([
    //             (a_endpoint.node_id, a_endpoint.id),
    //             (b_endpoint.node_id, b_endpoint.id),
    //             (c_endpoint.node_id, c_endpoint.id),
    //             (d_endpoint.node_id, d_endpoint.id),
    //         ]),
    //         by_ip_port: HashMap::from([
    //             (a_socket_addr.into(), a_endpoint.id),
    //             (d_socket_addr.into(), d_endpoint.id),
    //         ]),
    //         by_quic_mapped_addr: HashMap::from([
    //             (a_endpoint.quic_mapped_addr, a_endpoint.id),
    //             (b_endpoint.quic_mapped_addr, b_endpoint.id),
    //             (c_endpoint.quic_mapped_addr, c_endpoint.id),
    //             (d_endpoint.quic_mapped_addr, d_endpoint.id),
    //         ]),
    //         by_id: HashMap::from([
    //             (a_endpoint.id, a_endpoint),
    //             (b_endpoint.id, b_endpoint),
    //             (c_endpoint.id, c_endpoint),
    //             (d_endpoint.id, d_endpoint),
    //         ]),
    //         next_id: 5,
    //         path_selection: PathSelection::default(),
    //     });
    //     let mut got = node_map.list_remote_infos(later);
    //     got.sort_by_key(|p| p.node_id);
    //     expect.sort_by_key(|p| p.node_id);
    //     remove_non_deterministic_fields(&mut got);
    //     assert_eq!(expect, got);
    // }

    fn remove_non_deterministic_fields(infos: &mut [RemoteInfo]) {
        for info in infos.iter_mut() {
            if info.relay_url.is_some() {
                info.relay_url.as_mut().unwrap().last_alive = None;
            }
        }
    }

    #[test]
    fn test_prune_direct_addresses() {
        // When we handle a call-me-maybe with more than MAX_INACTIVE_DIRECT_ADDRESSES we do
        // not want to prune them right away but send pings to all of them.

        let key = SecretKey::generate(rand::thread_rng());
        let opts = Options {
            node_id: key.public(),
            relay_url: None,
            active: true,
            source: crate::magicsock::Source::NamedApp {
                name: "test".into(),
            },
            path_selection: PathSelection::default(),
        };
        let mut ep = NodeState::new(0, opts);

        let my_numbers_count: u16 = (MAX_INACTIVE_DIRECT_ADDRESSES + 5).try_into().unwrap();
        let my_numbers = (0u16..my_numbers_count)
            .map(|i| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1000 + i))
            .collect();
        let call_me_maybe = disco::CallMeMaybe { my_numbers };

        ep.handle_call_me_maybe(call_me_maybe);
    }
}
