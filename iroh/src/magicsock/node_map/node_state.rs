use data_encoding::HEXLOWER;
use iroh_base::{WebRtcPort, NodeAddr, NodeId, PublicKey, RelayUrl, ChannelId};
use n0_future::{
    task::{self, AbortOnDropHandle},
    time::{self, Duration, Instant},
};
use n0_watcher::Watchable;
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::{
    collections::{BTreeSet, HashMap, btree_map::Entry},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::atomic::AtomicBool,
};
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
    disco::{self, SendAddr, WebRtcAnswer},
    magicsock::{
        node_map::path_validity::PathValidity, ActorMessage, MagicsockMetrics, NodeIdMappedAddr, HEARTBEAT_INTERVAL
    },
};
use crate::disco::WebRtcOffer;

/// Number of addresses that are not active that we keep around per node.
///
/// See [`NodeState::prune_direct_addresses`].
pub(super) const MAX_INACTIVE_DIRECT_ADDRESSES: usize = 20;

/// How long since an endpoint path was last alive before it might be pruned.
const LAST_ALIVE_PRUNE_DURATION: Duration = Duration::from_secs(120);

/// How long we wait for a pong reply before assuming it's never coming.
const PING_TIMEOUT_DURATION: Duration = Duration::from_secs(5);

/// The latency at or under which we don't try to upgrade to a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// How long since the last activity we try to keep an established endpoint peering alive.
/// It's also the idle time at which we stop doing QAD queries to keep NAT mappings alive.
pub(super) const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

/// How often we try to upgrade to a better patheven if we have some non-relay route that works.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

/// How long until we send a stayin alive ping
const STAYIN_ALIVE_MIN_ELAPSED: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(in crate::magicsock) enum PingAction {
    SendCallMeMaybe {
        relay_url: RelayUrl,
        dst_node: NodeId,
    },
    SendPing(SendPing),
    ReceiveWebRtcOffer(ReceiveOffer),
    ReceiveWebRtcAnswer(ReceiveAnswer),
    SendWebRtcOffer(SendOffer),
    SendWebRtcAnswer(SendAnswer)
}


#[derive(Debug, Clone)]
pub(in crate::magicsock) struct ReceiveAnswer {
    pub id: usize,
    pub dst: SendAddr,
    pub dst_node: NodeId,
    pub tx_id: stun_rs::TransactionId,
    pub purpose: DiscoPingPurpose,
    pub answer: WebRtcAnswer
}

#[derive(Debug, Clone)]
pub(in crate::magicsock) struct SendAnswer {
    pub id: usize,
    pub dst: SendAddr,
    pub dst_node: NodeId,
    pub tx_id: stun_rs::TransactionId,
    pub purpose: DiscoPingPurpose,
    pub received_offer: WebRtcOffer
}

#[derive(Debug, Clone)]
pub(in crate::magicsock) struct ReceiveOffer {
    pub id: usize,
    pub dst: SendAddr,
    pub dst_node: NodeId,
    pub tx_id: stun_rs::TransactionId,
    pub purpose: DiscoPingPurpose,
    pub offer: WebRtcOffer
}


#[derive(Debug, Clone)]
pub(in crate::magicsock) struct SendOffer {
    pub id: usize,
    pub dst: SendAddr,
    pub dst_node: NodeId,
    pub tx_id: stun_rs::TransactionId,
    pub purpose: DiscoPingPurpose,
}

#[derive(Debug, Clone)]
pub(in crate::magicsock) struct SendPing {
    pub id: usize,
    pub dst: SendAddr,
    pub dst_node: NodeId,
    pub tx_id: stun_rs::TransactionId,
    pub purpose: DiscoPingPurpose,
}

/// Indicating an [`NodeState`] has handled a ping.
#[derive(Debug)]
pub struct PingHandled {
    /// What this ping did to the [`NodeState`].
    pub role: PingRole,
    /// Whether the sender path should also be pinged.
    ///
    /// This is the case if an [`NodeState`] does not yet have a direct path, i.e. it has no
    /// best_addr.  In this case we want to ping right back to open the direct path in this
    /// direction as well.
    pub needs_ping_back: Option<SendPing>,
}

#[derive(Debug)]
pub enum PingRole {
    Duplicate,
    NewPath,
    LikelyHeartbeat,
    Activate,
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
    quic_mapped_addr: NodeIdMappedAddr,
    /// The global identifier for this endpoint.
    node_id: NodeId,
    /// The last time we pinged all endpoints.
    last_full_ping: Option<Instant>,
    /// The url of relay node that we can relay over to communicate.
    ///
    /// The fallback/bootstrap path, if non-zero (non-zero for well-behaved clients).
    relay_url: Option<(RelayUrl, PathState)>,
    webrtc_channel: Option<(ChannelId, PathState)>,
    udp_paths: NodeUdpPaths,
    sent_pings: HashMap<stun_rs::TransactionId, SentPing>,
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
    pub(super) webrtc_channel: Option<ChannelId>,
    /// Is this endpoint currently active (sending data)?
    pub(super) active: bool,
    pub(super) source: super::Source,
    #[cfg(any(test, feature = "test-utils"))]
    pub(super) path_selection: PathSelection,
}

impl NodeState {
    pub(super) fn new(id: usize, options: Options) -> Self {
        let quic_mapped_addr = NodeIdMappedAddr::generate();

        // TODO(frando): I don't think we need to track the `num_relay_conns_added`
        // metric here. We do so in `Self::addr_for_send`.
        // if options.relay_url.is_some() {
        //     // we potentially have a relay connection to the node
        //     inc!(MagicsockMetrics, num_relay_conns_added);
        // }

        let now = Instant::now();
        let source = options.source.clone();
        let relay_url = options.relay_url.map(|url| {
            (
                url.clone(),
                PathState::new(options.node_id, SendAddr::Relay(url), source.clone(), now),
            )
        });
        let webrtc_channel = options.webrtc_channel.map(|channel_id| {
            (
                channel_id.clone(),
                PathState::new(
                    options.node_id,
                    SendAddr::WebRtc(WebRtcPort::new(options.node_id, channel_id)),
                    source,
                    now,
                ),
            )
        });
        NodeState {
            id,
            quic_mapped_addr,
            node_id: options.node_id,
            last_full_ping: None,
            relay_url,
            webrtc_channel,
            udp_paths: NodeUdpPaths::new(),
            sent_pings: HashMap::new(),
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

    pub(super) fn quic_mapped_addr(&self) -> &NodeIdMappedAddr {
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
        let latency = match conn_type {
            ConnectionType::Direct(addr) => self
                .udp_paths
                .paths()
                .get(&addr.into())
                .and_then(|state| state.latency()),
            ConnectionType::Relay(ref url) => self
                .relay_url
                .as_ref()
                .filter(|(relay_url, _)| relay_url == url)
                .and_then(|(_, state)| state.latency()),
            ConnectionType::Mixed(addr, ref url) => {
                let addr_latency = self
                    .udp_paths
                    .paths()
                    .get(&addr.into())
                    .and_then(|state| state.latency());
                let relay_latency = self
                    .relay_url
                    .as_ref()
                    .filter(|(relay_url, _)| relay_url == url)
                    .and_then(|(_, state)| state.latency());
                addr_latency.min(relay_latency)
            }
            ConnectionType::None => None,
        };

        let addrs = self
            .udp_paths
            .paths()
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
            channel_id: None,
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
                trace!(%addr, ?have_ipv6, "UdpSendAddr is valid, use it");
                (Some(*addr), None)
            }
            UdpSendAddr::Outdated(addr) => {
                // If the address is outdated we use it, but send via relay at the same time.
                // We also send disco pings so that it will become valid again if it still
                // works (i.e. we don't need to holepunch again).
                trace!(%addr, ?have_ipv6, "UdpSendAddr is outdated, use it together with relay");
                (Some(*addr), self.relay_url())
            }
            UdpSendAddr::Unconfirmed(addr) => {
                trace!(%addr, ?have_ipv6, "UdpSendAddr is unconfirmed, use it together with relay");
                (Some(*addr), self.relay_url())
            }
            UdpSendAddr::None => {
                trace!(?have_ipv6, "No UdpSendAddr, use relay");
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
        let Some(state) = self.udp_paths.access_mut(now).paths().remove(ip_port) else {
            return;
        };

        match state.last_alive().map(|instant| instant.elapsed()) {
            Some(last_alive) => debug!(%ip_port, ?last_alive, why, "pruning address"),
            None => debug!(%ip_port, last_seen=%"never", why, "pruning address"),
        }
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
    fn want_call_me_maybe(&self, now: &Instant, have_ipv6: bool) -> bool {
        trace!("full ping: wanted?");
        let Some(last_full_ping) = self.last_full_ping else {
            debug!("no previous full ping: need full ping");
            return true;
        };
        match &self.udp_paths.send_addr(have_ipv6) {
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
                    .paths()
                    .get(&(*addr).into())
                    .expect("send path not tracked?")
                    .latency()
                    .expect("send_addr marked valid incorrectly");
                if latency > GOOD_ENOUGH_LATENCY && *now - last_full_ping >= UPGRADE_INTERVAL {
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
    fn want_call_me_maybe(&self, _now: &Instant, _have_ipv6: bool) -> bool {
        trace!("full ping: skipped in browser");
        false
    }

    /// Cleanup the expired ping for the passed in txid.
    #[instrument("disco", skip_all, fields(node = %self.node_id.fmt_short()))]
    pub(super) fn ping_timeout(&mut self, txid: stun_rs::TransactionId, now: Instant) {
        if let Some(sp) = self.sent_pings.remove(&txid) {
            debug!(tx = %HEXLOWER.encode(&txid), addr = %sp.to, "pong not received in timeout");
            match sp.to {
                SendAddr::Udp(addr) => {
                    if let Some(path_state) =
                        self.udp_paths.access_mut(now).paths().get_mut(&addr.into())
                    {
                        path_state.last_ping = None;
                        let consider_alive = path_state
                            .last_alive()
                            .map(|last_alive| last_alive.elapsed() <= PING_TIMEOUT_DURATION)
                            .unwrap_or(false);
                        if !consider_alive {
                            // If there was no sign of life from this path during the time
                            // which we should have received the pong, clear best addr and
                            // pong.  Both are used to select this path again, but we know
                            // it's not a usable path now.
                            path_state.validity = PathValidity::empty();
                        }
                    }
                }
                SendAddr::Relay(ref url) => {
                    if let Some((home_relay, relay_state)) = self.relay_url.as_mut() {
                        if home_relay == url {
                            // lost connectivity via relay
                            relay_state.last_ping = None;
                        }
                    }
                }
                SendAddr::WebRtc(port) => {
                    if let Some((home_channel_id, port_state)) = self.webrtc_channel.as_mut() {
                        if *home_channel_id == port.channel_id {
                            port_state.last_ping = None
                        }
                    }
                }
            }
        }
    }

    #[must_use = "pings must be handled"]
    fn start_ping(&self, dst: SendAddr, purpose: DiscoPingPurpose) -> Option<SendPing> {
        #[cfg(any(test, feature = "test-utils"))]
        if self.path_selection == PathSelection::RelayOnly && !dst.is_relay() {
            // don't attempt any hole punching in relay only mode
            warn!("in `RelayOnly` mode, ignoring request to start a hole punching attempt.");
            return None;
        }
        #[cfg(wasm_browser)]
        if !dst.is_relay() {
            return None; // Similar to `RelayOnly` mode, we don't send UDP pings for hole-punching.
        }

        let tx_id = stun_rs::TransactionId::default();
        trace!(tx = %HEXLOWER.encode(&tx_id), %dst, ?purpose,
               dst = %self.node_id.fmt_short(), "start ping");
        event!(
            target: "iroh::_events::ping::sent",
            Level::DEBUG,
            remote_node = %self.node_id.fmt_short(),
            ?dst,
            txn = ?tx_id,
            ?purpose,
        );
        Some(SendPing {
            id: self.id,
            dst,
            dst_node: self.node_id,
            tx_id,
            purpose,
        })
    }

    /// Record the fact that a ping has been sent out.
    pub(super) fn ping_sent(
        &mut self,
        to: SendAddr,
        tx_id: stun_rs::TransactionId,
        purpose: DiscoPingPurpose,
        sender: mpsc::Sender<ActorMessage>,
    ) {
        trace!(%to, tx = %HEXLOWER.encode(&tx_id), ?purpose, "record ping sent");

        let now = Instant::now();
        let mut path_found = false;
        match to {
            SendAddr::Udp(addr) => {
                if let Some(st) = self.udp_paths.access_mut(now).paths().get_mut(&addr.into()) {
                    st.last_ping.replace(now);
                    path_found = true
                }
            }
            SendAddr::Relay(ref url) => {
                if let Some((home_relay, relay_state)) = self.relay_url.as_mut() {
                    if home_relay == url {
                        relay_state.last_ping.replace(now);
                        path_found = true
                    }
                }
            }
            SendAddr::WebRtc(port) => {
                if let Some((home_channel_id, state)) = self.webrtc_channel.as_mut() {
                    if port.channel_id == *home_channel_id {
                        state.last_ping.replace(now);
                        path_found = true
                    }
                }
            }
        }
        if !path_found {
            // Shouldn't happen. But don't ping an endpoint that's not active for us.
            warn!(%to, ?purpose, "unexpected attempt to ping no longer live path");
            return;
        }

        let id = self.id;
        let _expiry_task = AbortOnDropHandle::new(task::spawn(async move {
            time::sleep(PING_TIMEOUT_DURATION).await;
            sender
                .send(ActorMessage::EndpointPingExpired(id, tx_id))
                .await
                .ok();
        }));
        self.sent_pings.insert(
            tx_id,
            SentPing {
                to,
                at: now,
                purpose,
                _expiry_task,
            },
        );
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
        // We send pings regardless of whether we have a RelayUrl.  If we were given any
        // direct address paths to contact but no RelayUrl, we still need to send a DISCO
        // ping to the direct address paths so that the other node will learn about us and
        // accepts the connection.
        let mut msgs = self.send_pings(now);

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

    /// Send DISCO Pings to all the paths of this node.
    ///
    /// Any paths to the node which have not been recently pinged will be sent a disco
    /// ping.
    ///
    /// The caller is responsible for sending the messages.
    #[must_use = "actions must be handled"]
    fn send_pings(&mut self, now: Instant) -> Vec<PingAction> {
        // We allocate +1 in case the caller wants to add a call-me-maybe message.
        let mut ping_msgs = Vec::with_capacity(self.udp_paths.paths().len() + 1);

        if let Some((url, state)) = self.relay_url.as_ref() {
            if state.needs_ping(&now) {
                debug!(%url, "relay path needs ping");
                if let Some(msg) =
                    self.start_ping(SendAddr::Relay(url.clone()), DiscoPingPurpose::Discovery)
                {
                    ping_msgs.push(PingAction::SendPing(msg.clone()));

                    let offer = SendOffer {
                        id: msg.id,
                        dst: SendAddr::Relay(url.clone()),
                        dst_node: msg.dst_node,
                        tx_id: msg.tx_id,
                        purpose: DiscoPingPurpose::Discovery,
                    };
                    ping_msgs.push(PingAction::SendWebRtcOffer(offer));
                }
            }
        }

        #[cfg(any(test, feature = "test-utils"))]
        if self.path_selection == PathSelection::RelayOnly {
            warn!("in `RelayOnly` mode, ignoring request to respond to a hole punching attempt.");
            return ping_msgs;
        }

        self.prune_direct_addresses(now);
        let mut ping_dsts = String::from("[");
        self.udp_paths
            .paths()
            .iter()
            .filter_map(|(ipp, state)| state.needs_ping(&now).then_some(*ipp))
            .filter_map(|ipp| {
                self.start_ping(SendAddr::Udp(ipp.into()), DiscoPingPurpose::Discovery)
            })
            .for_each(|msg| {
                use std::fmt::Write;
                write!(&mut ping_dsts, " {} ", msg.dst).ok();
                ping_msgs.push(PingAction::SendPing(msg.clone()));
            });
        ping_dsts.push(']');
        debug!(
            %ping_dsts,
            dst = %self.node_id.fmt_short(),
            paths = %summarize_node_paths(self.udp_paths.paths()),
            "sending pings to node",
        );

        self.last_full_ping.replace(now);


        ping_msgs
    }

    fn should_initiate_webrtc(&self, now: Instant) -> bool {
        true
    }

    pub(super) fn update_from_node_addr(
        &mut self,
        new_relay_url: Option<&RelayUrl>,
        new_addrs: &BTreeSet<SocketAddr>,
        source: super::Source,
        have_ipv6: bool,
        metrics: &MagicsockMetrics,
    ) {
        if matches!(
            self.udp_paths.send_addr(have_ipv6),
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

        let mut access = self.udp_paths.access_mut(now);
        for &addr in new_addrs.iter() {
            access
                .paths()
                .entry(addr.into())
                .and_modify(|path_state| {
                    path_state.add_source(source.clone(), now);
                })
                .or_insert_with(|| {
                    PathState::new(self.node_id, SendAddr::from(addr), source.clone(), now)
                });
        }
        drop(access);
        let paths = summarize_node_paths(self.udp_paths.paths());
        debug!(new = ?new_addrs , %paths, "added new direct paths for endpoint");
    }

    /// Handle a received Disco Ping.
    ///
    /// - Ensures the paths the ping was received on is a known path for this endpoint.
    ///
    /// - If there is no best_addr for this endpoint yet, sends a ping itself to try and
    ///   establish one.
    ///
    /// This is called once we've already verified that we got a valid discovery message
    /// from `self` via ep.
    pub(super) fn handle_ping(
        &mut self,
        path: SendAddr,
        tx_id: stun_rs::TransactionId,
    ) -> PingHandled {
        let now = Instant::now();

        let role = match path {
            SendAddr::Udp(addr) => {
                match self.udp_paths.access_mut(now).paths().entry(addr.into()) {
                    Entry::Occupied(mut occupied) => occupied.get_mut().handle_ping(tx_id, now),
                    Entry::Vacant(vacant) => {
                        info!(%addr, "new direct addr for node");
                        vacant.insert(PathState::with_ping(
                            self.node_id,
                            path.clone(),
                            tx_id,
                            Source::Udp,
                            now,
                        ));
                        PingRole::NewPath
                    }
                }
            }
            SendAddr::Relay(ref url) => {
                match self.relay_url.as_mut() {
                    Some((home_url, _state)) if home_url != url => {
                        // either the node changed relays or we didn't have a relay address for the
                        // node. In both cases, trust the new confirmed url
                        info!(%url, "new relay addr for node");
                        self.relay_url = Some((
                            url.clone(),
                            PathState::with_ping(
                                self.node_id,
                                path.clone(),
                                tx_id,
                                Source::Relay,
                                now,
                            ),
                        ));
                        PingRole::NewPath
                    }
                    Some((_home_url, state)) => state.handle_ping(tx_id, now),
                    None => {
                        info!(%url, "new relay addr for node");
                        self.relay_url = Some((
                            url.clone(),
                            PathState::with_ping(
                                self.node_id,
                                path.clone(),
                                tx_id,
                                Source::Relay,
                                now,
                            ),
                        ));
                        PingRole::NewPath
                    }
                }
            }
            SendAddr::WebRtc(src_port) => {
                let WebRtcPort {
                    node_id,
                    channel_id,
                } = src_port;

                match self.webrtc_channel.as_mut() {
                    Some((channel_id, _state)) if src_port.channel_id != *channel_id => {
                        // either the node changed relays or we didn't have a relay address for the node
                        self.webrtc_channel = Some((
                            channel_id.clone(),
                            PathState::with_ping(
                                self.node_id,
                                path.clone(),
                                tx_id,
                                Source::WebRtc,
                                now,
                            ),
                        ));
                        PingRole::NewPath
                    }
                    Some((_home_url, state)) => state.handle_ping(tx_id, now),
                    None => {
                        info!("new webrtc addr for node");
                        self.webrtc_channel = Some((
                            channel_id.clone(),
                            PathState::with_ping(
                                self.node_id,
                                path.clone(),
                                tx_id,
                                Source::WebRtc,
                                now,
                            ),
                        ));
                        PingRole::NewPath
                    }
                }
            }
        };
        event!(
            target: "iroh::_events::ping::recv",
            Level::DEBUG,
            remote_node = %self.node_id.fmt_short(),
            src = ?path,
            txn = ?tx_id,
            ?role,
        );

        if matches!(path, SendAddr::Udp(_)) && matches!(role, PingRole::NewPath) {
            self.prune_direct_addresses(now);
        }

        // if the endpoint does not yet have a best_addr
        let needs_ping_back = if matches!(path, SendAddr::Udp(_))
            && matches!(
                self.udp_paths.send_addr(true),
                UdpSendAddr::None | UdpSendAddr::Unconfirmed(_) | UdpSendAddr::Outdated(_)
            ) {
            // We also need to send a ping to make this path available to us as well.  This
            // is always sent together with a pong.  So in the worst case the pong gets lost
            // and this ping does not.  In that case we ping-pong until both sides have
            // received at least one pong.  Once both sides have received one pong they both
            // have a best_addr and this ping will stop being sent.
            self.start_ping(path, DiscoPingPurpose::PingBack)
        } else {
            None
        };

        debug!(
            ?role,
            needs_ping_back = ?needs_ping_back.is_some(),
            paths = %summarize_node_paths(self.udp_paths.paths()),
            "endpoint handled ping",
        );
        PingHandled {
            role,
            needs_ping_back,
        }
    }

    /// Prune inactive paths.
    ///
    /// This trims the list of inactive paths for an endpoint.  At most
    /// [`MAX_INACTIVE_DIRECT_ADDRESSES`] are kept.
    pub(super) fn prune_direct_addresses(&mut self, now: Instant) {
        // prune candidates are addresses that are not active
        let mut prune_candidates: Vec<_> = self
            .udp_paths
            .paths()
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
                paths = %summarize_node_paths(self.udp_paths.paths()),
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
            paths = %summarize_node_paths(self.udp_paths.paths()),
            "prune addresses: {prune_count} pruned",
        );
    }

    /// Called when connectivity changes enough that we should question our earlier
    /// assumptions about which paths work.
    #[instrument("disco", skip_all, fields(node = %self.node_id.fmt_short()))]
    pub(super) fn note_connectivity_change(&mut self, now: Instant) {
        let mut guard = self.udp_paths.access_mut(now);
        for es in guard.paths().values_mut() {
            es.clear();
        }
    }

    /// Handles a Pong message (a reply to an earlier ping).
    ///
    /// It reports the address and key that should be inserted for the endpoint if any.
    #[instrument(skip(self))]
    pub(super) fn handle_pong(
        &mut self,
        m: &disco::Pong,
        src: SendAddr,
    ) -> Option<(SocketAddr, PublicKey)> {
        event!(
            target: "iroh::_events::pong::recv",
            Level::DEBUG,
            remote_node = %self.node_id.fmt_short(),
            ?src,
            txn = ?m.tx_id,
        );
        let is_relay = src.is_relay();
        match self.sent_pings.remove(&m.tx_id) {
            None => {
                // This is not a pong for a ping we sent.  In reality however we probably
                // did send this ping but it has timed-out by the time we receive this pong
                // so we removed the state already.
                debug!(tx = %HEXLOWER.encode(&m.tx_id), "received unknown pong (did it timeout?)");
                None
            }
            Some(sp) => {
                let mut node_map_insert = None;

                let now = Instant::now();
                let latency = now - sp.at;

                debug!(
                    tx = %HEXLOWER.encode(&m.tx_id),
                    src = %src,
                    reported_ping_src = %m.ping_observed_addr,
                    ping_dst = %sp.to,
                    is_relay = %src.is_relay(),
                    latency = %latency.as_millis(),
                    "received pong",
                );

                match src {
                    SendAddr::Udp(addr) => {
                        match self.udp_paths.access_mut(now).paths().get_mut(&addr.into()) {
                            None => {
                                warn!("ignoring pong: no state for src addr");
                                // This is no longer an endpoint we care about.
                                return node_map_insert;
                            }
                            Some(st) => {
                                node_map_insert = Some((addr, self.node_id));
                                st.add_pong_reply(PongReply {
                                    latency,
                                    pong_at: now,
                                    from: src,
                                    pong_src: m.ping_observed_addr.clone(),
                                });
                            }
                        }
                        debug!(
                            paths = %summarize_node_paths(self.udp_paths.paths()),
                            "handled pong",
                        );
                    }
                    SendAddr::Relay(ref url) => match self.relay_url.as_mut() {
                        Some((home_url, state)) if home_url == url => {
                            state.add_pong_reply(PongReply {
                                latency,
                                pong_at: now,
                                from: src,
                                pong_src: m.ping_observed_addr.clone(),
                            });
                        }
                        other => {
                            // if we are here then we sent this ping, but the url changed
                            // waiting for the response. It was either set to None or changed to
                            // another relay. This should either never happen or be extremely
                            // unlikely. Log and ignore for now
                            warn!(
                                stored=?other,
                                received=?url,
                                "ignoring pong via relay for different relay from last one",
                            );
                        }
                    },
                    SendAddr::WebRtc(port) => match self.webrtc_channel.as_mut() {
                        None => {
                            warn!("ignoring pong via relay for different relay from last one",);
                        }
                        Some((home_port, state)) => {
                            state.add_pong_reply(PongReply {
                                latency,
                                pong_at: now,
                                from: src,
                                pong_src: m.ping_observed_addr.clone(),
                            });
                        }
                    },
                }

                // Promote this pong response to our current best address if it's lower latency.
                // TODO(bradfitz): decide how latency vs. preference order affects decision
                if let SendAddr::Udp(_to) = sp.to {
                    debug_assert!(!is_relay, "mismatching relay & udp");
                }

                node_map_insert
            }
        }
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
    pub(super) fn handle_call_me_maybe(&mut self, m: disco::CallMeMaybe) -> Vec<PingAction> {
        let now = Instant::now();
        let mut call_me_maybe_ipps = BTreeSet::new();

        let mut guard = self.udp_paths.access_mut(now);

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
            guard
                .paths()
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
        for (ipp, st) in guard.paths().iter_mut() {
            st.last_ping = None;
            if !call_me_maybe_ipps.contains(ipp) {
                // TODO: This seems like a weird way to signal that the endpoint no longer
                // thinks it has this IpPort as an available path.
                if !st.validity.is_empty() {
                    debug!(path=?ipp ,"clearing recent pong");
                    st.validity = PathValidity::empty();
                }
            }
        }
        if guard.has_best_addr_changed() {
            // Clear the last call-me-maybe send time so we will send one again.
            self.last_call_me_maybe = None;
        }
        debug!(
            paths = %summarize_node_paths(self.udp_paths.paths()),
            "updated endpoint paths from call-me-maybe",
        );
        self.send_pings(now)
    }


    pub(crate) fn handle_webrtc_offer(
        &mut self,
        _sender: NodeId,
        answer: WebRtcOffer
    ) -> Vec<PingAction>{

        let now = Instant::now();

        println!("1192: got webrtc offer: {:?}", answer);
        self.send_webrtc_answer(now, answer)



    }

    pub(crate) fn send_webrtc_answer(
        &mut self,
        now: Instant,
        offer: WebRtcOffer
    ) -> Vec<PingAction> {
        // We allocate +1 in case the caller wants to add a call-me-maybe message.
        let mut ping_msgs = Vec::with_capacity(self.udp_paths.paths().len() + 1);

        if let Some((url, state)) = self.relay_url.as_ref() {
            if state.needs_ping(&now) {
                debug!(%url, "relay path needs ping");
                if let Some(msg) =
                    self.start_ping(SendAddr::Relay(url.clone()), DiscoPingPurpose::Discovery)
                {
                        let msg = SendAnswer { id: msg.id, dst: msg.dst, dst_node: msg.dst_node, tx_id: msg.tx_id, purpose: msg.purpose, received_offer: offer };
                        ping_msgs.push(PingAction::SendWebRtcAnswer(msg));
                }
            }
        }

        #[cfg(any(test, feature = "test-utils"))]
        if self.path_selection == PathSelection::RelayOnly {
            warn!("in `RelayOnly` mode, ignoring request to respond to a hole punching attempt.");
            return ping_msgs;
        }

        self.prune_direct_addresses(now);
        let mut ping_dsts = String::from("[");
        ping_dsts.push(']');
        debug!(
            %ping_dsts,
            dst = %self.node_id.fmt_short(),
            paths = %summarize_node_paths(self.udp_paths.paths()),
            "sending pings to node",
        );

        self.last_full_ping.replace(now);

        ping_msgs

    }

    /// Marks this node as having received a UDP payload message.
    #[cfg(not(wasm_browser))]
    pub(super) fn receive_udp(&mut self, addr: IpPort, now: Instant) {
        let mut guard = self.udp_paths.access_mut(now);
        let Some(state) = guard.paths().get_mut(&addr) else {
            debug_assert!(false, "node map inconsistency by_ip_port <-> direct addr");
            return;
        };
        state.receive_payload(now);
        self.last_used = Some(now);
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

    pub(super) fn receive_webrtc(&mut self, port: WebRtcPort, now: Instant) {
        let WebRtcPort {
            node_id,
            channel_id,
        } = port;

        match self.webrtc_channel.as_mut() {
            Some((current_channel, state)) if *current_channel == channel_id => {
                // We received on the expected channel. update state.
                state.receive_payload(now);
            }
            Some((_current_channel, _state)) => {
                // we have a different channel. we only update on ping, not on receive_webrtc.
            }
            None => {
                self.webrtc_channel = Some((
                    channel_id,
                    PathState::with_last_payload(
                        node_id,
                        SendAddr::WebRtc(WebRtcPort::new(node_id, channel_id)),
                        Source::WebRtc,
                        now,
                    ),
                ));
            }
        }
        self.last_used = Some(now);
    }



    pub(super) fn last_ping(&self, addr: &SendAddr) -> Option<Instant> {
        match addr {
            SendAddr::Udp(addr) => self
                .udp_paths
                .paths()
                .get(&(*addr).into())
                .and_then(|ep| ep.last_ping),
            SendAddr::Relay(url) => self
                .relay_url
                .as_ref()
                .filter(|(home_url, _state)| home_url == url)
                .and_then(|(_home_url, state)| state.last_ping),
            SendAddr::WebRtc(node) => self
                .webrtc_channel
                .as_ref()
                .filter(|(channel_id, _state)| node.channel_id == *channel_id)
                .and_then(|(_addr, state)| state.last_ping),
        }
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
    pub(super) fn stayin_alive(&mut self, have_ipv6: bool) -> Vec<PingAction> {
        trace!("stayin_alive");
        let now = Instant::now();
        if !self.is_active(&now) {
            trace!("skipping stayin alive: session is inactive");
            return Vec::new();
        }

        // If we do not have an optimal addr, send pings to all known places.
        if self.want_call_me_maybe(&now, have_ipv6) {
            debug!("sending a call-me-maybe");
            println!("stayin_-alive=----------------------");
            return self.send_call_me_maybe(now, SendCallMeMaybe::Always);
        }

        // Send heartbeat ping to keep the current addr going as long as we need it.
        if let Some(udp_addr) = self.udp_paths.send_addr(have_ipv6).get_addr() {
            let elapsed = self.last_ping(&SendAddr::Udp(udp_addr)).map(|l| now - l);
            // Send a ping if the last ping is older than 2 seconds.
            let needs_ping = match elapsed {
                Some(e) => e >= STAYIN_ALIVE_MIN_ELAPSED,
                None => false,
            };

            if needs_ping {
                debug!(
                    dst = %udp_addr,
                    since_last_ping=?elapsed,
                    "send stayin alive ping",
                );
                if let Some(msg) =
                    self.start_ping(SendAddr::Udp(udp_addr), DiscoPingPurpose::StayinAlive)
                {
                    return vec![PingAction::SendPing(msg)];
                }
            }
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

        let ping_msgs = if self.want_call_me_maybe(&now, have_ipv6) {
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

    /// Get the direct addresses for this endpoint.
    pub(super) fn direct_addresses(&self) -> impl Iterator<Item = IpPort> + '_ {
        self.udp_paths.paths().keys().copied()
    }

    #[cfg(test)]
    pub(super) fn direct_address_states(&self) -> impl Iterator<Item = (&IpPort, &PathState)> + '_ {
        self.udp_paths.paths().iter()
    }

    pub(super) fn last_used(&self) -> Option<Instant> {
        self.last_used
    }
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
            channel_id: info.channel_id,
            webrtc_info: None,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PongReply {
    pub(super) latency: Duration,
    /// When we received the pong.
    pub(super) pong_at: Instant,
    /// The pong's src (usually same as endpoint map key).
    pub(super) from: SendAddr,
    /// What they reported they heard.
    pub(super) pong_src: SendAddr,
}

#[derive(Debug)]
pub(super) struct SentPing {
    pub(super) to: SendAddr,
    pub(super) at: Instant,
    #[allow(dead_code)]
    pub(super) purpose: DiscoPingPurpose,
    pub(super) _expiry_task: AbortOnDropHandle<()>,
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
            latency: value.1.latency(),
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

    /// Channel id
    pub channel_id: Option<ChannelId>,
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
    use std::{collections::BTreeMap, net::Ipv4Addr};

    use iroh_base::SecretKey;

    use super::*;
    use crate::magicsock::node_map::{NodeMap, NodeMapInner};

    #[test]
    fn test_remote_infos() {
        let now = Instant::now();
        let elapsed = Duration::from_secs(3);
        let later = now + elapsed;
        let send_addr: RelayUrl = "https://my-relay.com".parse().unwrap();
        let pong_src = SendAddr::Udp("0.0.0.0:1".parse().unwrap());
        let latency = Duration::from_millis(50);

        let relay_and_state = |node_id: NodeId, url: RelayUrl| {
            let relay_state = PathState::with_pong_reply(
                node_id,
                PongReply {
                    latency,
                    pong_at: now,
                    from: SendAddr::Relay(send_addr.clone()),
                    pong_src: pong_src.clone(),
                },
            );
            Some((url, relay_state))
        };

        // endpoint with a `best_addr` that has a latency but no relay
        let (a_endpoint, a_socket_addr) = {
            let key = SecretKey::generate(rand::thread_rng());
            let node_id = key.public();
            let ip_port = IpPort {
                ip: Ipv4Addr::UNSPECIFIED.into(),
                port: 10,
            };
            let endpoint_state = BTreeMap::from([(
                ip_port,
                PathState::with_pong_reply(
                    node_id,
                    PongReply {
                        latency,
                        pong_at: now,
                        from: SendAddr::Udp(ip_port.into()),
                        pong_src: pong_src.clone(),
                    },
                ),
            )]);
            (
                NodeState {
                    id: 0,
                    quic_mapped_addr: NodeIdMappedAddr::generate(),
                    node_id: key.public(),
                    last_full_ping: None,
                    relay_url: None,
                    webrtc_channel: None,
                    udp_paths: NodeUdpPaths::from_parts(
                        endpoint_state,
                        UdpSendAddr::Valid(ip_port.into()),
                    ),
                    sent_pings: HashMap::new(),
                    last_used: Some(now),
                    last_call_me_maybe: None,
                    conn_type: Watchable::new(ConnectionType::Direct(ip_port.into())),
                    has_been_direct: AtomicBool::new(true),
                    #[cfg(any(test, feature = "test-utils"))]
                    path_selection: PathSelection::default(),
                },
                ip_port.into(),
            )
        };
        // endpoint w/ no best addr but a relay w/ latency
        let b_endpoint = {
            // let socket_addr = "0.0.0.0:9".parse().unwrap();
            let key = SecretKey::generate(rand::thread_rng());
            NodeState {
                id: 1,
                quic_mapped_addr: NodeIdMappedAddr::generate(),
                node_id: key.public(),
                last_full_ping: None,
                relay_url: relay_and_state(key.public(), send_addr.clone()),
                webrtc_channel: None,
                udp_paths: NodeUdpPaths::new(),
                sent_pings: HashMap::new(),
                last_used: Some(now),
                last_call_me_maybe: None,
                conn_type: Watchable::new(ConnectionType::Relay(send_addr.clone())),
                has_been_direct: AtomicBool::new(false),
                #[cfg(any(test, feature = "test-utils"))]
                path_selection: PathSelection::default(),
            }
        };

        // endpoint w/ no best addr but a relay w/ no latency
        let c_endpoint = {
            // let socket_addr = "0.0.0.0:8".parse().unwrap();
            let key = SecretKey::generate(rand::thread_rng());
            NodeState {
                id: 2,
                quic_mapped_addr: NodeIdMappedAddr::generate(),
                node_id: key.public(),
                last_full_ping: None,
                webrtc_channel: None,
                relay_url: Some((
                    send_addr.clone(),
                    PathState::new(
                        key.public(),
                        SendAddr::from(send_addr.clone()),
                        Source::App,
                        now,
                    ),
                )),
                udp_paths: NodeUdpPaths::new(),
                sent_pings: HashMap::new(),
                last_used: Some(now),
                last_call_me_maybe: None,
                conn_type: Watchable::new(ConnectionType::Relay(send_addr.clone())),
                has_been_direct: AtomicBool::new(false),
                #[cfg(any(test, feature = "test-utils"))]
                path_selection: PathSelection::default(),
            }
        };

        // endpoint w/ expired best addr and relay w/ latency
        let (d_endpoint, d_socket_addr) = {
            let socket_addr: SocketAddr = "0.0.0.0:7".parse().unwrap();
            let key = SecretKey::generate(rand::thread_rng());
            let node_id = key.public();
            let endpoint_state = BTreeMap::from([(
                IpPort::from(socket_addr),
                PathState::with_pong_reply(
                    node_id,
                    PongReply {
                        latency,
                        pong_at: now,
                        from: SendAddr::Udp(socket_addr),
                        pong_src: pong_src.clone(),
                    },
                ),
            )]);
            (
                NodeState {
                    id: 3,
                    quic_mapped_addr: NodeIdMappedAddr::generate(),
                    node_id: key.public(),
                    last_full_ping: None,
                    relay_url: relay_and_state(key.public(), send_addr.clone()),
                    webrtc_channel: None,
                    udp_paths: NodeUdpPaths::from_parts(
                        endpoint_state,
                        UdpSendAddr::Outdated(socket_addr),
                    ),
                    sent_pings: HashMap::new(),
                    last_used: Some(now),
                    last_call_me_maybe: None,
                    conn_type: Watchable::new(ConnectionType::Mixed(
                        socket_addr,
                        send_addr.clone(),
                    )),
                    has_been_direct: AtomicBool::new(false),
                    #[cfg(any(test, feature = "test-utils"))]
                    path_selection: PathSelection::default(),
                },
                socket_addr,
            )
        };

        let mut expect = Vec::from([
            RemoteInfo {
                node_id: a_endpoint.node_id,
                relay_url: None,
                addrs: Vec::from([DirectAddrInfo {
                    addr: a_socket_addr,
                    latency: Some(latency),
                    last_control: Some((elapsed, ControlMsg::Pong)),
                    last_payload: None,
                    last_alive: Some(elapsed),
                    sources: HashMap::new(),
                }]),
                conn_type: ConnectionType::Direct(a_socket_addr),
                latency: Some(latency),
                last_used: Some(elapsed),
                channel_id: None,
            },
            RemoteInfo {
                node_id: b_endpoint.node_id,
                relay_url: Some(RelayUrlInfo {
                    relay_url: b_endpoint.relay_url.as_ref().unwrap().0.clone(),
                    last_alive: None,
                    latency: Some(latency),
                }),
                addrs: Vec::new(),
                conn_type: ConnectionType::Relay(send_addr.clone()),
                latency: Some(latency),
                last_used: Some(elapsed),
                channel_id: None,
            },
            RemoteInfo {
                node_id: c_endpoint.node_id,
                relay_url: Some(RelayUrlInfo {
                    relay_url: c_endpoint.relay_url.as_ref().unwrap().0.clone(),
                    last_alive: None,
                    latency: None,
                }),
                addrs: Vec::new(),
                conn_type: ConnectionType::Relay(send_addr.clone()),
                latency: None,
                last_used: Some(elapsed),
                channel_id: None,
            },
            RemoteInfo {
                node_id: d_endpoint.node_id,
                relay_url: Some(RelayUrlInfo {
                    relay_url: d_endpoint.relay_url.as_ref().unwrap().0.clone(),
                    last_alive: None,
                    latency: Some(latency),
                }),
                addrs: Vec::from([DirectAddrInfo {
                    addr: d_socket_addr,
                    latency: Some(latency),
                    last_control: Some((elapsed, ControlMsg::Pong)),
                    last_payload: None,
                    last_alive: Some(elapsed),
                    sources: HashMap::new(),
                }]),
                conn_type: ConnectionType::Mixed(d_socket_addr, send_addr.clone()),
                latency: Some(Duration::from_millis(50)),
                last_used: Some(elapsed),
                channel_id: None,
            },
        ]);

        let node_map = NodeMap::from_inner(NodeMapInner {
            by_node_key: HashMap::from([
                (a_endpoint.node_id, a_endpoint.id),
                (b_endpoint.node_id, b_endpoint.id),
                (c_endpoint.node_id, c_endpoint.id),
                (d_endpoint.node_id, d_endpoint.id),
            ]),
            by_ip_port: HashMap::from([
                (a_socket_addr.into(), a_endpoint.id),
                (d_socket_addr.into(), d_endpoint.id),
            ]),
            by_quic_mapped_addr: HashMap::from([
                (a_endpoint.quic_mapped_addr, a_endpoint.id),
                (b_endpoint.quic_mapped_addr, b_endpoint.id),
                (c_endpoint.quic_mapped_addr, c_endpoint.id),
                (d_endpoint.quic_mapped_addr, d_endpoint.id),
            ]),
            by_webrtc_port: HashMap::from([]),
            by_id: HashMap::from([
                (a_endpoint.id, a_endpoint),
                (b_endpoint.id, b_endpoint),
                (c_endpoint.id, c_endpoint),
                (d_endpoint.id, d_endpoint),
            ]),
            next_id: 5,
            path_selection: PathSelection::default(),
        });
        let mut got = node_map.list_remote_infos(later);
        got.sort_by_key(|p| p.node_id);
        expect.sort_by_key(|p| p.node_id);
        remove_non_deterministic_fields(&mut got);
        assert_eq!(expect, got);
    }

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
            webrtc_channel: None,
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

        let ping_messages = ep.handle_call_me_maybe(call_me_maybe);

        // We have no relay server and no previous direct addresses, so we should get the same
        // number of pings as direct addresses in the call-me-maybe.
        assert_eq!(ping_messages.len(), my_numbers_count as usize);
    }
}
