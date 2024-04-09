use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet, HashMap},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use iroh_metrics::inc;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{debug, info, instrument, trace, warn};

use crate::{
    disco::{self, SendAddr},
    key::PublicKey,
    magic_endpoint::AddrInfo,
    magicsock::{Timer, HEARTBEAT_INTERVAL},
    net::ip::is_unicast_link_local,
    relay::RelayUrl,
    stun,
    util::relay_only_mode,
    NodeAddr, NodeId,
};

use crate::magicsock::{metrics::Metrics as MagicsockMetrics, ActorMessage, QuicMappedAddr};

use super::best_addr::{self, BestAddr, ClearReason};
use super::IpPort;

/// Number of addresses that are not active that we keep around per node.
///
/// See [`Endpoint::prune_direct_addresses`].
pub(super) const MAX_INACTIVE_DIRECT_ADDRESSES: usize = 20;

/// How long since an endpoint path was last active before it might be pruned.
const LAST_ALIVE_PRUNE_DURATION: Duration = Duration::from_secs(120);

/// How long we wait for a pong reply before assuming it's never coming.
const PING_TIMEOUT_DURATION: Duration = Duration::from_secs(5);

/// The minimum time between pings to an endpoint. (Except in the case of CallMeMaybe frames
/// resetting the counter, as the first pings likely didn't through the firewall)
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);

/// The latency at or under which we don't try to upgrade to a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// How long since the last activity we try to keep an established endpoint peering alive.
/// It's also the idle time at which we stop doing STUN queries to keep NAT mappings alive.
const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

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
}

#[derive(Debug)]
pub(in crate::magicsock) struct SendPing {
    pub id: usize,
    pub dst: SendAddr,
    pub dst_node: NodeId,
    pub tx_id: stun::TransactionId,
    pub purpose: DiscoPingPurpose,
}

/// Indicating an [`Endpoint`] has handled a ping.
#[derive(Debug)]
pub struct PingHandled {
    /// What this ping did to the [`Endpoint`].
    pub role: PingRole,
    /// Whether the sender path should also be pinged.
    ///
    /// This is the case if an [`Endpoint`] does not yet have a direct path, i.e. it has no
    /// best_addr.  In this case we want to ping right back to open the direct path in this
    /// direction as well.
    pub needs_ping_back: Option<SendPing>,
}

#[derive(Debug)]
pub enum PingRole {
    Duplicate,
    // TODO: Clean up this naming, this is a new path to an endpoint.
    NewEndpoint,
    LikelyHeartbeat,
    Reactivate,
}

/// An endpoint, think [`MagicEndpoint`], which we can have connections with.
///
/// Each endpoint is also known as a "Node" in the "(iroh) network", but this is a bit of a
/// looser term.
///
/// The whole point of the magicsock is that we can have multiple **paths** to a particular
/// endpoint.  One of these paths is via the endpoint's home relay node but as we establish a
/// connection we'll hopefully discover more direct paths.
///
/// [`MagicEndpoint`]: crate::MagicEndpoint
#[derive(Debug)]
pub(super) struct Endpoint {
    /// The ID used as index in the [`NodeMap`].
    ///
    /// [`NodeMap`]: super::NodeMap
    id: usize,
    /// The UDP address used on the QUIC-layer to address this node.
    quic_mapped_addr: QuicMappedAddr,
    /// The global identifier for this endpoint.
    node_id: NodeId,
    /// The last time we pinged all endpoints.
    last_full_ping: Option<Instant>,
    /// The url of relay node that we can relay over to communicate.
    ///
    /// The fallback/bootstrap path, if non-zero (non-zero for well-behaved clients).
    relay_url: Option<(RelayUrl, PathState)>,
    /// Best non-relay path, i.e. a UDP address.
    best_addr: BestAddr,
    /// State for each of this node's direct paths.
    direct_addr_state: BTreeMap<IpPort, PathState>,
    sent_pings: HashMap<stun::TransactionId, SentPing>,
    /// Last time this node was used.
    ///
    /// A node is marked as in use when an endpoint to contact them is requested or if UDP activity
    /// is registered.
    last_used: Option<Instant>,
    /// Last time we sent a call-me-maybe.
    ///
    /// When we do not have a direct connection and we try to send some data, we will try to
    /// do a full ping + call-me-maybe.  Usually each side only needs to send one
    /// call-me-maybe to the other for holes to be punched in both directions however.  So
    /// we only try and send one per [`HEARTBEAT_INTERVAL`].  Each [`HEARTBEAT_INTERVAL`]
    /// the [`Endpoint::stayin_alive`] function is called, which will trigger new
    /// call-me-maybe messages as backup.
    last_call_me_maybe: Option<Instant>,
    /// List of senders that want to know if we obtain a valid `best_addr` for this endpoint.
    ///
    /// This should only have entries if we don't currently have a valid `best_addr`,
    /// since we should have immediately alerted the receiver if a valid `best_addr`
    /// already existed.
    has_valid_best_addr_senders: Vec<oneshot::Sender<()>>,
}

#[derive(Debug)]
pub(super) struct Options {
    pub(super) public_key: PublicKey,
    pub(super) relay_url: Option<RelayUrl>,
    /// Is this endpoint currently active (sending data)?
    pub(super) active: bool,
}

impl Endpoint {
    pub(super) fn new(id: usize, options: Options) -> Self {
        let quic_mapped_addr = QuicMappedAddr::generate();

        if options.relay_url.is_some() {
            // we potentially have a relay connection to the node
            inc!(MagicsockMetrics, num_relay_conns_added);
        }

        Endpoint {
            id,
            quic_mapped_addr,
            node_id: options.public_key,
            last_full_ping: None,
            relay_url: options.relay_url.map(|url| (url, PathState::default())),
            best_addr: Default::default(),
            sent_pings: HashMap::new(),
            direct_addr_state: BTreeMap::new(),
            last_used: options.active.then(Instant::now),
            last_call_me_maybe: None,
            has_valid_best_addr_senders: Vec::default(),
        }
    }

    pub(super) fn public_key(&self) -> &PublicKey {
        &self.node_id
    }

    pub(super) fn quic_mapped_addr(&self) -> &QuicMappedAddr {
        &self.quic_mapped_addr
    }

    pub(super) fn id(&self) -> usize {
        self.id
    }

    /// Returns info about this endpoint
    pub(super) fn info(&self, now: Instant) -> EndpointInfo {
        use best_addr::State::*;
        // Report our active connection. This replicates the logic of [`Endpoint::addr_for_send`]
        // without choosing a random candidate address if no best_addr is set.
        let (conn_type, latency) = match (self.best_addr.state(now), self.relay_url.as_ref()) {
            (Valid(addr), _) | (Outdated(addr), None) => {
                (ConnectionType::Direct(addr.addr), Some(addr.latency))
            }
            (Outdated(addr), Some((url, relay_state))) => {
                let latency = relay_state
                    .latency()
                    .map(|l| l.min(addr.latency))
                    .unwrap_or(addr.latency);
                (ConnectionType::Mixed(addr.addr, url.clone()), Some(latency))
            }
            (Empty, Some((url, relay_state))) => {
                (ConnectionType::Relay(url.clone()), relay_state.latency())
            }
            (Empty, None) => (ConnectionType::None, None),
        };
        let addrs = self
            .direct_addr_state
            .iter()
            .map(|(addr, endpoint_state)| DirectAddrInfo {
                addr: SocketAddr::from(*addr),
                latency: endpoint_state.recent_pong().map(|pong| pong.latency),
                last_control: endpoint_state.last_control_msg(now),
                last_payload: endpoint_state
                    .last_payload_msg
                    .as_ref()
                    .map(|instant| now.duration_since(*instant)),
            })
            .collect();

        EndpointInfo {
            id: self.id,
            node_id: self.node_id,
            relay_url: self.relay_url(),
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
    /// Any or all of the UDP and relay addrs may be non-zero.
    fn addr_for_send(
        &mut self,
        now: &Instant,
        have_ipv6: bool,
    ) -> (Option<SocketAddr>, Option<RelayUrl>) {
        if relay_only_mode() {
            debug!("in `DEV_relay_ONLY` mode, giving the relay address as the only viable address for this endpoint");
            return (None, self.relay_url());
        }
        // Update our best addr from candidate addresses (only if it is empty and if we have
        // recent pongs).
        self.assign_best_addr_from_candidates_if_empty();
        match self.best_addr.state(*now) {
            best_addr::State::Valid(best_addr) => {
                // If we have a valid address we use it.
                trace!(addr = %best_addr.addr, latency = ?best_addr.latency,
                       "best_addr is set and valid, use best_addr only");
                (Some(best_addr.addr), None)
            }
            best_addr::State::Outdated(best_addr) => {
                // If the address is outdated we use it, but send via relay at the same time.
                // We also send disco pings so that it will become valid again if it still
                // works (i.e. we don't need to holepunch again).
                trace!(addr = %best_addr.addr, latency = ?best_addr.latency,
                       "best_addr is set but outdated, use best_addr and relay");
                (Some(best_addr.addr), self.relay_url())
            }
            best_addr::State::Empty => {
                // No direct connection has been used before.  If we know of any possible
                // candidate addresses, randomly try to use one while also sending via relay
                // at the same time.
                let addr = self
                    .direct_addr_state
                    .keys()
                    .filter(|ipp| match ipp.ip() {
                        IpAddr::V4(_) => true,
                        IpAddr::V6(_) => have_ipv6,
                    })
                    .choose_stable(&mut rand::thread_rng())
                    .map(|ipp| SocketAddr::from(*ipp));
                trace!(udp_addr = ?addr, "best_addr is unset, use candidate addr and relay");
                (addr, self.relay_url())
            }
        }
    }

    /// Returns a [`oneshot::Receiver`] that will be alerted once we have a valid `best_addr`
    ///
    /// If we already have a valid `best_addr` for this endpoint, the [`oneshot::Receiver`]
    /// will recv immediately.
    ///
    /// It is possible we will never have a viable `best_addr`, in which case
    /// no alert will ever be issued.
    pub fn notify_has_best_addr(&mut self) -> oneshot::Receiver<()> {
        self.assign_best_addr_from_candidates_if_empty();
        let already_holepunched = matches!(
            self.best_addr.state(std::time::Instant::now()),
            best_addr::State::Valid(_)
        );
        let (s, r) = oneshot::channel();
        if already_holepunched {
            s.send(()).ok();
        } else {
            self.has_valid_best_addr_senders.push(s);
        }
        r
    }

    /// Fixup best_addr from candidates.
    ///
    /// If somehow we end up in a state where we failed to set a best_addr, while we do have
    /// valid candidates, this will chose a candidate and set best_addr again.  Most likely
    /// this is a bug elsewhere though.
    fn assign_best_addr_from_candidates_if_empty(&mut self) {
        if !self.best_addr.is_empty() {
            return;
        }

        // The highest acceptable latency for an endpoint path.  If the latency is higher
        // then this the path will be ignored.
        const MAX_LATENCY: Duration = Duration::from_secs(60 * 60);
        let best_pong = self
            .direct_addr_state
            .iter()
            .fold(None, |best_pong, (ipp, state)| {
                let best_latency = best_pong
                    .map(|p: &PongReply| p.latency)
                    .unwrap_or(MAX_LATENCY);
                match state.recent_pong() {
                    // This pong is better if it has a lower latency, or if it has the same
                    // latency but on an IPv6 path.
                    Some(pong)
                        if pong.latency < best_latency
                            || (pong.latency == best_latency && ipp.ip().is_ipv6()) =>
                    {
                        Some(pong)
                    }
                    _ => best_pong,
                }
            });

        // If we found a candidate, set to best addr
        if let Some(pong) = best_pong {
            if let SendAddr::Udp(addr) = pong.from {
                warn!(%addr, "No best_addr was set, choose candidate with lowest latency");
                self.maybe_update_best_addr(
                    addr,
                    pong.latency,
                    best_addr::Source::BestCandidate,
                    pong.pong_at,
                    self.relay_url.is_some(),
                )
            }
        }
    }

    /// Inserts or replaces the `BestAddr` if the new candidate has a lower
    /// latency.
    /// Sends out alerts to any waiting channels that we have successfully hole-punched.
    fn maybe_update_best_addr(
        &mut self,
        addr: SocketAddr,
        latency: Duration,
        source: best_addr::Source,
        confirmed_at: Instant,
        has_relay: bool,
    ) {
        self.best_addr.insert_if_better_or_reconfirm(
            addr,
            latency,
            source,
            confirmed_at,
            has_relay,
        );
        // Alert any waiting channels that we have successfully holepunched
        while let Some(sender) = self.has_valid_best_addr_senders.pop() {
            sender.send(()).ok();
        }
    }

    /// Whether we need to send another call-me-maybe to the endpoint.
    ///
    /// Basically we need to send a call-me-maybe if we need to find a better path.  Maybe
    /// we only have a relay path, or our path is expired.
    ///
    /// When a call-me-maybe message is sent we also need to send pings to all known paths
    /// of the endpoint.  The [`Endpoint::send_call_me_maybe`] function takes care of this.
    #[instrument("want_call_me_maybe", skip_all)]
    fn want_call_me_maybe(&self, now: &Instant) -> bool {
        trace!("full ping: wanted?");
        let Some(last_full_ping) = self.last_full_ping else {
            debug!("no previous full ping: need full ping");
            return true;
        };
        match self.best_addr.state(*now) {
            best_addr::State::Empty => {
                debug!("best addr not set: need full ping");
                true
            }
            best_addr::State::Outdated(_) => {
                debug!("best addr expired: need full ping");
                true
            }
            best_addr::State::Valid(addr) => {
                if addr.latency > GOOD_ENOUGH_LATENCY && *now - last_full_ping >= UPGRADE_INTERVAL {
                    debug!(
                        "full ping interval expired and latency is only {}ms: need full ping",
                        addr.latency.as_millis()
                    );
                    true
                } else {
                    trace!(?now, "not needed");
                    false
                }
            }
        }
    }

    /// Cleanup the expired ping for the passed in txid.
    #[instrument("disco", skip_all, fields(node = %self.node_id.fmt_short()))]
    pub(super) fn ping_timeout(&mut self, txid: stun::TransactionId) {
        if let Some(sp) = self.sent_pings.remove(&txid) {
            debug!(tx = %hex::encode(txid), addr = %sp.to, "pong not received in timeout");
            match sp.to {
                SendAddr::Udp(addr) => {
                    if let Some(ep_state) = self.direct_addr_state.get_mut(&addr.into()) {
                        ep_state.last_ping = None;
                    }

                    // If we fail to ping our current best addr, it is not that good anymore.
                    self.best_addr.clear_if_addr_older(
                        addr,
                        sp.at,
                        ClearReason::PongTimeout,
                        self.relay_url.is_some(),
                    );
                }
                SendAddr::Relay(ref url) => {
                    if let Some((home_relay, relay_state)) = self.relay_url.as_mut() {
                        if home_relay == url {
                            // lost connectivity via relay
                            relay_state.last_ping = None;
                        }
                    }
                }
            }
        }
    }

    #[must_use = "pings must be handled"]
    fn start_ping(&self, dst: SendAddr, purpose: DiscoPingPurpose) -> Option<SendPing> {
        if relay_only_mode() && !dst.is_relay() {
            // don't attempt any hole punching in relay only mode
            warn!("in `DEV_relay_ONLY` mode, ignoring request to start a hole punching attempt.");
            return None;
        }
        let tx_id = stun::TransactionId::default();
        trace!(tx = %hex::encode(tx_id), %dst, ?purpose,
               dst = %self.node_id.fmt_short(), "start ping");
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
        tx_id: stun::TransactionId,
        purpose: DiscoPingPurpose,
        sender: mpsc::Sender<ActorMessage>,
    ) {
        trace!(%to, tx = %hex::encode(tx_id), ?purpose, "record ping sent");

        let now = Instant::now();
        let mut path_found = false;
        match to {
            SendAddr::Udp(addr) => {
                if let Some(st) = self.direct_addr_state.get_mut(&addr.into()) {
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
        }
        if !path_found {
            // Shouldn't happen. But don't ping an endpoint that's not active for us.
            warn!(%to, ?purpose, "unexpected attempt to ping no longer live path");
            return;
        }

        let id = self.id;
        let timer = Timer::after(PING_TIMEOUT_DURATION, async move {
            sender
                .send(ActorMessage::EndpointPingExpired(id, tx_id))
                .await
                .ok();
        });
        self.sent_pings.insert(
            tx_id,
            SentPing {
                to,
                at: now,
                purpose,
                timer,
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

    /// Send DISCO Pings to all the paths of this endpoint.
    ///
    /// Any paths to the endpoint which have not been recently pinged will be sent a disco
    /// ping.
    ///
    /// The caller is responsible for sending the messages.
    #[must_use = "actions must be handled"]
    fn send_pings(&mut self, now: Instant) -> Vec<PingAction> {
        // We allocate +1 in case the caller wants to add a call-me-maybe message.
        let mut ping_msgs = Vec::with_capacity(self.direct_addr_state.len() + 1);

        if let Some((url, state)) = self.relay_url.as_ref() {
            if state.needs_ping(&now) {
                debug!(%url, "relay path needs ping");
                if let Some(msg) =
                    self.start_ping(SendAddr::Relay(url.clone()), DiscoPingPurpose::Discovery)
                {
                    ping_msgs.push(PingAction::SendPing(msg))
                }
            }
        }
        if relay_only_mode() {
            warn!(
                "in `DEV_relay_ONLY` mode, ignoring request to respond to a hole punching attempt."
            );
            return ping_msgs;
        }
        self.prune_direct_addresses();
        let mut ping_dsts = String::from("[");
        self.direct_addr_state
            .iter()
            .filter_map(|(ipp, state)| state.needs_ping(&now).then_some(*ipp))
            .filter_map(|ipp| {
                self.start_ping(SendAddr::Udp(ipp.into()), DiscoPingPurpose::Discovery)
            })
            .for_each(|msg| {
                use std::fmt::Write;
                write!(&mut ping_dsts, " {} ", msg.dst).ok();
                ping_msgs.push(PingAction::SendPing(msg));
            });
        ping_dsts.push(']');
        debug!(
            %ping_dsts,
            dst = %self.node_id.fmt_short(),
            paths = %summarize_endpoint_paths(&self.direct_addr_state),
            "sending pings to endpoint",
        );
        self.last_full_ping.replace(now);
        ping_msgs
    }

    pub(super) fn update_from_node_addr(&mut self, n: &AddrInfo) {
        if self.best_addr.is_empty() {
            // we do not have a direct connection, so changing the relay information may
            // have an effect on our connection status
            if self.relay_url.is_none() && n.relay_url.is_some() {
                // we did not have a relay connection before, but now we do
                inc!(MagicsockMetrics, num_relay_conns_added)
            } else if self.relay_url.is_some() && n.relay_url.is_none() {
                // we had a relay connection before but do not have one now
                inc!(MagicsockMetrics, num_relay_conns_removed)
            }
        }

        if n.relay_url.is_some() && n.relay_url != self.relay_url() {
            debug!(
                "Changing relay node from {:?} to {:?}",
                self.relay_url, n.relay_url
            );
            self.relay_url = n
                .relay_url
                .as_ref()
                .map(|url| (url.clone(), PathState::default()));
        }

        for &addr in n.direct_addresses.iter() {
            //TODOFRZ
            self.direct_addr_state.entry(addr.into()).or_default();
        }
        let paths = summarize_endpoint_paths(&self.direct_addr_state);
        debug!(new = ?n.direct_addresses , %paths, "added new direct paths for endpoint");
    }

    /// Clears all the endpoint's p2p state, reverting it to a relay-only endpoint.
    #[instrument(skip_all, fields(node = %self.node_id.fmt_short()))]
    pub(super) fn reset(&mut self) {
        self.last_full_ping = None;
        self.best_addr
            .clear(ClearReason::Reset, self.relay_url.is_some());

        for es in self.direct_addr_state.values_mut() {
            es.last_ping = None;
        }
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
        tx_id: stun::TransactionId,
    ) -> PingHandled {
        let now = Instant::now();

        let role = match path {
            SendAddr::Udp(addr) => match self.direct_addr_state.entry(addr.into()) {
                Entry::Occupied(mut occupied) => occupied.get_mut().handle_ping(tx_id, now),
                Entry::Vacant(vacant) => {
                    info!(%addr, "new direct addr for node");
                    vacant.insert(PathState::with_ping(tx_id, now));
                    PingRole::NewEndpoint
                }
            },
            SendAddr::Relay(ref url) => {
                match self.relay_url.as_mut() {
                    Some((home_url, _state)) if home_url != url => {
                        // either the node changed relays or we didn't have a relay address for the
                        // node. In both cases, trust the new confirmed url
                        info!(%url, "new relay addr for node");
                        self.relay_url = Some((url.clone(), PathState::with_ping(tx_id, now)));
                        PingRole::NewEndpoint
                    }
                    Some((_home_url, state)) => state.handle_ping(tx_id, now),
                    None => {
                        info!(%url, "new relay addr for node");
                        self.relay_url = Some((url.clone(), PathState::with_ping(tx_id, now)));
                        PingRole::NewEndpoint
                    }
                }
            }
        };

        if matches!(path, SendAddr::Udp(_)) && matches!(role, PingRole::NewEndpoint) {
            self.prune_direct_addresses();
        }

        // if the endpoint does not yet have a best_addrr
        let needs_ping_back = if matches!(path, SendAddr::Udp(_))
            && matches!(
                self.best_addr.state(now),
                best_addr::State::Empty | best_addr::State::Outdated(_)
            ) {
            // We also need to send a ping to make this path available to us as well.  This
            // is always sent togehter with a pong.  So in the worst case the pong gets lost
            // and this ping does not.  In that case we ping-pong until both sides have
            // received at least one pong.  Once both sides have received one pong they both
            // have a best_addr and this ping will stop being sent.
            self.start_ping(path, DiscoPingPurpose::Discovery)
        } else {
            None
        };

        debug!(
            ?role,
            needs_ping_back = ?needs_ping_back.is_some(),
            paths = %summarize_endpoint_paths(&self.direct_addr_state),
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
    pub(super) fn prune_direct_addresses(&mut self) {
        // prune candidates are addresses that are not active
        let mut prune_candidates: Vec<_> = self
            .direct_addr_state
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
                paths = %summarize_endpoint_paths(&self.direct_addr_state),
                "prune addresses: {prune_count} pruned",
            );
            return;
        }

        // sort leaving the worst addresses first (never contacted) and better ones (most recently
        // used ones) last
        prune_candidates.sort_unstable_by_key(|(_ip_port, last_alive)| *last_alive);
        prune_candidates.truncate(prune_count);
        for (ip_port, last_alive) in prune_candidates.into_iter() {
            self.direct_addr_state.remove(&ip_port);

            match last_alive.map(|instant| instant.elapsed()) {
                Some(last_alive) => debug!(%ip_port, ?last_alive, "pruning address"),
                None => debug!(%ip_port, last_seen=%"never", "pruning address"),
            }

            self.best_addr.clear_if_equals(
                ip_port.into(),
                ClearReason::Inactive,
                self.relay_url.is_some(),
            );
        }
        debug!(
            paths = %summarize_endpoint_paths(&self.direct_addr_state),
            "prune addresses: {prune_count} pruned",
        );
    }

    /// Called when connectivity changes enough that we should question our earlier
    /// assumptions about which paths work.
    #[instrument("disco", skip_all, fields(node = %self.node_id.fmt_short()))]
    pub(super) fn note_connectivity_change(&mut self) {
        self.best_addr.clear_trust("connectivity changed");
        for es in self.direct_addr_state.values_mut() {
            es.clear();
        }
    }

    /// Handles a Pong message (a reply to an earlier ping).
    ///
    /// It reports the address and key that should be inserted for the endpoint if any.
    pub(super) fn handle_pong(
        &mut self,
        m: &disco::Pong,
        src: SendAddr,
    ) -> Option<(SocketAddr, PublicKey)> {
        let is_relay = src.is_relay();

        trace!(
            tx = %hex::encode(m.tx_id),
            pong_src = %src,
            pong_ping_src = %m.src,
            is_relay = %src.is_relay(),
            "received pong"
        );
        match self.sent_pings.remove(&m.tx_id) {
            None => {
                // This is not a pong for a ping we sent.
                warn!(tx = %hex::encode(m.tx_id), "received pong with unknown transaction id");
                None
            }
            Some(sp) => {
                sp.timer.abort();

                let mut node_map_insert = None;

                let now = Instant::now();
                let latency = now - sp.at;

                debug!(
                    tx = %hex::encode(m.tx_id),
                    src = %src,
                    reported_ping_src = %m.src,
                    ping_dst = %sp.to,
                    is_relay = %src.is_relay(),
                    latency = %latency.as_millis(),
                    "received pong",
                );

                match src {
                    SendAddr::Udp(addr) => {
                        match self.direct_addr_state.get_mut(&addr.into()) {
                            None => {
                                info!("ignoring pong: no state for src addr");
                                // This is no longer an endpoint we care about.
                                return node_map_insert;
                            }
                            Some(st) => {
                                node_map_insert = Some((addr, self.node_id));
                                st.add_pong_reply(PongReply {
                                    latency,
                                    pong_at: now,
                                    from: src,
                                    pong_src: m.src.clone(),
                                });
                            }
                        }
                        debug!(
                            paths = %summarize_endpoint_paths(&self.direct_addr_state),
                            "handled pong",
                        );
                    }
                    SendAddr::Relay(ref url) => match self.relay_url.as_mut() {
                        Some((home_url, state)) if home_url == url => {
                            state.add_pong_reply(PongReply {
                                latency,
                                pong_at: now,
                                from: src,
                                pong_src: m.src.clone(),
                            });
                        }
                        other => {
                            // if we are here then we sent this ping, but the url changed
                            // waiting for the response. It was either set to None or changed to
                            // another relay. This should either never happen or be extremely
                            // unlikely. Log and ignore for now
                            warn!(stored=?other, received=?url, "disco: ignoring pong via relay for different relay to the last one stored");
                        }
                    },
                }

                // Promote this pong response to our current best address if it's lower latency.
                // TODO(bradfitz): decide how latency vs. preference order affects decision
                if let SendAddr::Udp(to) = sp.to {
                    debug_assert!(!is_relay, "mismatching relay & udp");
                    self.maybe_update_best_addr(
                        to,
                        latency,
                        best_addr::Source::ReceivedPong,
                        now,
                        self.relay_url.is_some(),
                    );
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

        for peer_sockaddr in &m.my_numbers {
            if let IpAddr::V6(ip) = peer_sockaddr.ip() {
                if is_unicast_link_local(ip) {
                    // We send these out, but ignore them for now.
                    // TODO: teach the ping code to ping on all interfaces for these.
                    continue;
                }
            }
            let ipp = IpPort::from(*peer_sockaddr);
            call_me_maybe_ipps.insert(ipp);
            self.direct_addr_state
                .entry(ipp)
                .or_default()
                .call_me_maybe_time
                .replace(now);
        }

        // Zero out all the last_ping times to force send_pings to send new ones,
        // even if it's been less than 5 seconds ago.
        // Also clear pongs for endpoints not included in the updated set.
        for (ipp, st) in self.direct_addr_state.iter_mut() {
            st.last_ping = None;
            if !call_me_maybe_ipps.contains(ipp) {
                // TODO: This seems like a weird way to signal that the endpoint no longer
                // thinks it has this IpPort as an avaialable path.
                if st.recent_pong.is_some() {
                    debug!(path=?ipp ,"clearing recent pong");
                    st.recent_pong = None;
                }
            }
        }
        // Clear trust on our best_addr if it is not included in the updated set.  Also
        // clear the last call-me-maybe send time so we will send one again.
        if let Some(addr) = self.best_addr.addr() {
            let ipp: IpPort = addr.into();
            if !call_me_maybe_ipps.contains(&ipp) {
                self.best_addr
                    .clear_trust("best_addr not in new call-me-maybe");
                self.last_call_me_maybe = None;
            }
        }
        debug!(
            paths = %summarize_endpoint_paths(&self.direct_addr_state),
            "updated endpoint paths from call-me-maybe",
        );
        self.send_pings(now)
    }

    /// Marks this endpoint as having received a UDP payload message.
    pub(super) fn receive_udp(&mut self, addr: IpPort, now: Instant) {
        let Some(state) = self.direct_addr_state.get_mut(&addr) else {
            debug_assert!(false, "node map inconsistency by_ip_port <-> direct addr");
            return;
        };
        state.last_payload_msg = Some(now);
        self.last_used = Some(now);
    }

    pub(super) fn receive_relay(&mut self, url: &RelayUrl, _src: &PublicKey, now: Instant) {
        match self.relay_url.as_mut() {
            Some((current_home, state)) if current_home == url => {
                // We received on the expected url. update state.
                state.last_payload_msg = Some(now);
            }
            Some((_current_home, _state)) => {
                // we have a different url. we only update on ping, not on receive_relay.
            }
            None => {
                self.relay_url = Some((url.clone(), PathState::with_last_payload(now)));
            }
        }
        self.last_used = Some(now);
    }

    pub(super) fn last_ping(&self, addr: &SendAddr) -> Option<Instant> {
        match addr {
            SendAddr::Udp(addr) => self
                .direct_addr_state
                .get(&(*addr).into())
                .and_then(|ep| ep.last_ping),
            SendAddr::Relay(url) => self
                .relay_url
                .as_ref()
                .filter(|(home_url, _state)| home_url == url)
                .and_then(|(_home_url, state)| state.last_ping),
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

        // Send heartbeat ping to keep the current addr going as long as we need it.
        if let Some(udp_addr) = self.best_addr.addr() {
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
    #[instrument("get_send_addrs", skip_all, fields(node = %self.node_id.fmt_short()))]
    pub(crate) fn get_send_addrs(
        &mut self,
        have_ipv6: bool,
    ) -> (Option<SocketAddr>, Option<RelayUrl>, Vec<PingAction>) {
        let now = Instant::now();
        self.last_used.replace(now);
        let (udp_addr, relay_url) = self.addr_for_send(&now, have_ipv6);
        let mut ping_msgs = Vec::new();

        if self.want_call_me_maybe(&now) {
            ping_msgs = self.send_call_me_maybe(now, SendCallMeMaybe::IfNoRecent);
        }

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
        self.direct_addr_state.keys().copied()
    }

    /// Get the addressing information of this endpoint.
    pub(super) fn node_addr(&self) -> NodeAddr {
        let direct_addresses = self.direct_addresses().map(SocketAddr::from).collect();
        NodeAddr {
            node_id: self.node_id,
            info: AddrInfo {
                relay_url: self.relay_url(),
                direct_addresses,
            },
        }
    }

    #[cfg(test)]
    pub(super) fn direct_address_states(&self) -> impl Iterator<Item = (&IpPort, &PathState)> + '_ {
        self.direct_addr_state.iter()
    }

    pub(super) fn last_used(&self) -> Option<Instant> {
        self.last_used
    }
}

/// State about a particular path to another [`Endpoint`].
///
/// This state is used for both the relay path and any direct UDP paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub(super) struct PathState {
    /// The last (outgoing) ping time.
    last_ping: Option<Instant>,

    // TODO: merge last_got_ping and last_got_ping_tx_id into one field and one Option
    /// If non-zero, means that this was an endpoint
    /// that we learned about at runtime (from an incoming ping)
    /// and that is not in the network map. If so, we keep the time
    /// updated and use it to discard old candidates.
    last_got_ping: Option<Instant>,

    /// Contains the TxID for the last incoming ping. This is
    /// used to de-dup incoming pings that we may see on both the raw disco
    /// socket on Linux, and UDP socket. We cannot rely solely on the raw socket
    /// disco handling due to <https://github.com/tailscale/tailscale/issues/7078>.
    last_got_ping_tx_id: Option<stun::TransactionId>,

    /// If non-zero, is the time this endpoint was advertised last via a call-me-maybe disco message.
    call_me_maybe_time: Option<Instant>,

    /// Last [`PongReply`] received.
    pub(super) recent_pong: Option<PongReply>,
    /// When was this endpoint last used to transmit payload data (removing ping, pong, etc).
    pub(super) last_payload_msg: Option<Instant>,
}

impl PathState {
    pub(super) fn with_last_payload(now: Instant) -> Self {
        PathState {
            last_payload_msg: Some(now),
            ..Default::default()
        }
    }

    pub(super) fn with_ping(tx_id: stun::TransactionId, now: Instant) -> Self {
        PathState {
            last_got_ping: Some(now),
            last_got_ping_tx_id: Some(tx_id),
            ..Default::default()
        }
    }

    pub(super) fn add_pong_reply(&mut self, r: PongReply) {
        self.recent_pong = Some(r);
    }

    #[cfg(test)]
    pub(super) fn with_pong_reply(r: PongReply) -> Self {
        PathState {
            recent_pong: Some(r),
            ..Default::default()
        }
    }

    /// Check whether this path is considered active.
    ///
    /// Active means the path has received payload messages within the lat
    /// [`SESSION_ACTIVE_TIMEOUT`].
    ///
    /// Note that an endpoint might be alive but not active if it's contactable but not in
    /// use.
    pub(super) fn is_active(&self) -> bool {
        self.last_payload_msg
            .as_ref()
            .map(|instant| instant.elapsed() <= SESSION_ACTIVE_TIMEOUT)
            .unwrap_or(false)
    }

    /// Reports the last instant this path was considered alive.
    ///
    /// Alive means the path is considered in use by the remote endpoint.  Either because we
    /// received a payload message, a DISCO message (ping, pong) or it was advertised in a
    /// call-me-maybe message.
    ///
    /// This is the most recent instant between:
    /// - when last pong was received.
    /// - when the last CallMeMaybe was received.
    /// - When the last payload transmission occurred.
    /// - when the last ping from them was received.
    pub(super) fn last_alive(&self) -> Option<Instant> {
        self.recent_pong()
            .map(|pong| &pong.pong_at)
            .into_iter()
            .chain(self.last_payload_msg.as_ref())
            .chain(self.call_me_maybe_time.as_ref())
            .chain(self.last_got_ping.as_ref())
            .max()
            .copied()
    }

    pub(super) fn last_control_msg(&self, now: Instant) -> Option<(Duration, ControlMsg)> {
        // get every control message and assign it its kind
        let last_pong = self
            .recent_pong()
            .map(|pong| (pong.pong_at, ControlMsg::Pong));
        let last_call_me_maybe = self
            .call_me_maybe_time
            .as_ref()
            .map(|call_me| (*call_me, ControlMsg::CallMeMaybe));
        let last_ping = self
            .last_got_ping
            .as_ref()
            .map(|ping| (*ping, ControlMsg::Ping));

        last_pong
            .into_iter()
            .chain(last_call_me_maybe)
            .chain(last_ping)
            .max_by_key(|(instant, _kind)| *instant)
            .map(|(instant, kind)| (now.duration_since(instant), kind))
    }

    /// Returns the most recent pong if available.
    fn recent_pong(&self) -> Option<&PongReply> {
        self.recent_pong.as_ref()
    }

    /// Returns the latency from the most recent pong, if available.
    fn latency(&self) -> Option<Duration> {
        self.recent_pong.as_ref().map(|p| p.latency)
    }

    fn needs_ping(&self, now: &Instant) -> bool {
        match self.last_ping {
            None => true,
            Some(last_ping) => {
                let elapsed = now.duration_since(last_ping);

                // TODO: remove!
                // This logs "ping is too new" for each send whenever the endpoint does *not* need
                // a ping. Pretty sure this is not a useful log, but maybe there was a reason?
                // if !needs_ping {
                //     debug!("ping is too new: {}ms", elapsed.as_millis());
                // }
                elapsed > DISCO_PING_INTERVAL
            }
        }
    }

    fn handle_ping(&mut self, tx_id: stun::TransactionId, now: Instant) -> PingRole {
        if Some(tx_id) == self.last_got_ping_tx_id {
            PingRole::Duplicate
        } else {
            self.last_got_ping_tx_id.replace(tx_id);
            let last = self.last_got_ping.replace(now);
            match last {
                None => PingRole::Reactivate,
                Some(last) => {
                    if now.duration_since(last) <= HEARTBEAT_INTERVAL {
                        PingRole::LikelyHeartbeat
                    } else {
                        PingRole::Reactivate
                    }
                }
            }
        }
    }

    fn clear(&mut self) {
        self.last_ping = None;
        self.last_got_ping = None;
        self.last_got_ping_tx_id = None;
        self.call_me_maybe_time = None;
        self.recent_pong = None;
    }

    fn summary(&self, mut w: impl std::fmt::Write) -> std::fmt::Result {
        write!(w, "{{ ")?;
        if self.is_active() {
            write!(w, "active ")?;
        }
        if let Some(ref pong) = self.recent_pong {
            write!(w, "pong-received({:?} ago)", pong.pong_at.elapsed())?;
        }
        if let Some(ref when) = self.last_got_ping {
            write!(w, "ping-received({:?} ago) ", when.elapsed())?;
        }
        if let Some(ref when) = self.last_ping {
            write!(w, "ping-sent({:?} ago) ", when.elapsed())?;
        }
        write!(w, "}}")
    }
}

// TODO: Make an `EndpointPaths` struct and do things nicely.
fn summarize_endpoint_paths(paths: &BTreeMap<IpPort, PathState>) -> String {
    use std::fmt::Write;

    let mut w = String::new();
    write!(&mut w, "[").ok();
    for (i, (ipp, state)) in paths.iter().enumerate() {
        if i > 0 {
            write!(&mut w, ", ").ok();
        }
        write!(&mut w, "{ipp}").ok();
        state.summary(&mut w).ok();
    }
    write!(&mut w, "]").ok();
    w
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
    pub(super) timer: Timer,
}

/// The reason why a discovery ping message was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoPingPurpose {
    /// The purpose of a ping was to see if a path was valid.
    Discovery,
    /// Ping to ensure the current route is still valid.
    StayinAlive,
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

/// Information about a direct address.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DirectAddrInfo {
    /// The address reported.
    pub addr: SocketAddr,
    /// The latency to the address, if any.
    pub latency: Option<Duration>,
    /// Last control message received by this node.
    pub last_control: Option<(Duration, ControlMsg)>,
    /// How long ago was the last payload message for this node.
    pub last_payload: Option<Duration>,
}

/// Details about an Endpoint.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EndpointInfo {
    /// The id in the node_map
    pub id: usize,
    /// The public key of the endpoint.
    pub node_id: NodeId,
    /// relay server, if available.
    pub relay_url: Option<RelayUrl>,
    /// List of addresses at which this node might be reachable, plus any latency information we
    /// have about that address and the last time the address was used.
    pub addrs: Vec<DirectAddrInfo>,
    /// The type of connection we have to the node, either direct or over relay.
    pub conn_type: ConnectionType,
    /// The latency of the `conn_type`.
    pub latency: Option<Duration>,
    /// Duration since the last time this node was used.
    pub last_used: Option<Duration>,
}

impl EndpointInfo {
    /// Get the duration since the last activity we received from this endpoint
    /// on any of its direct addresses.
    pub fn last_received(&self) -> Option<Duration> {
        self.addrs
            .iter()
            .filter_map(|addr| addr.last_control.map(|x| x.0).min(addr.last_payload))
            .min()
    }
}

/// The type of connection we have to the endpoint.
#[derive(derive_more::Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConnectionType {
    /// Direct UDP connection
    #[display("direct")]
    Direct(SocketAddr),
    /// Relay connection over relay
    #[display("relay")]
    Relay(RelayUrl),
    /// Both a UDP and a relay connection are used.
    ///
    /// This is the case if we do have a UDP address, but are missing a recent confirmation that
    /// the address works.
    #[display("mixed")]
    Mixed(SocketAddr, RelayUrl),
    /// We have no verified connection to this PublicKey
    #[display("none")]
    None,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        super::{NodeMap, NodeMapInner},
        *,
    };
    use crate::key::SecretKey;

    #[test]
    fn test_endpoint_infos() {
        let new_relay_and_state =
            |url: Option<RelayUrl>| url.map(|url| (url, PathState::default()));

        let now = Instant::now();
        let elapsed = Duration::from_secs(3);
        let later = now + elapsed;
        let send_addr: RelayUrl = "https://my-relay.com".parse().unwrap();
        // endpoint with a `best_addr` that has a latency
        let pong_src = SendAddr::Udp("0.0.0.0:1".parse().unwrap());
        let latency = Duration::from_millis(50);
        let (a_endpoint, a_socket_addr) = {
            let ip_port = IpPort {
                ip: Ipv4Addr::UNSPECIFIED.into(),
                port: 10,
            };
            let endpoint_state = BTreeMap::from([(
                ip_port,
                PathState::with_pong_reply(PongReply {
                    latency,
                    pong_at: now,
                    from: SendAddr::Udp(ip_port.into()),
                    pong_src: pong_src.clone(),
                }),
            )]);
            let key = SecretKey::generate();
            (
                Endpoint {
                    id: 0,
                    quic_mapped_addr: QuicMappedAddr::generate(),
                    node_id: key.public(),
                    last_full_ping: None,
                    relay_url: new_relay_and_state(Some(send_addr.clone())),
                    best_addr: BestAddr::from_parts(
                        ip_port.into(),
                        latency,
                        now,
                        now + Duration::from_secs(100),
                    ),
                    direct_addr_state: endpoint_state,
                    sent_pings: HashMap::new(),
                    last_used: Some(now),
                    last_call_me_maybe: None,
                    has_valid_best_addr_senders: Vec::default(),
                },
                ip_port.into(),
            )
        };
        // endpoint w/ no best addr but a relay w/ latency
        let b_endpoint = {
            // let socket_addr = "0.0.0.0:9".parse().unwrap();
            let relay_state = PathState::with_pong_reply(PongReply {
                latency,
                pong_at: now,
                from: SendAddr::Relay(send_addr.clone()),
                pong_src: pong_src.clone(),
            });
            let key = SecretKey::generate();
            Endpoint {
                id: 1,
                quic_mapped_addr: QuicMappedAddr::generate(),
                node_id: key.public(),
                last_full_ping: None,
                relay_url: Some((send_addr.clone(), relay_state)),
                best_addr: BestAddr::default(),
                direct_addr_state: BTreeMap::default(),
                sent_pings: HashMap::new(),
                last_used: Some(now),
                last_call_me_maybe: None,
                has_valid_best_addr_senders: Vec::default(),
            }
        };

        // endpoint w/ no best addr but a relay w/ no latency
        let c_endpoint = {
            // let socket_addr = "0.0.0.0:8".parse().unwrap();
            let endpoint_state = BTreeMap::new();
            let key = SecretKey::generate();
            Endpoint {
                id: 2,
                quic_mapped_addr: QuicMappedAddr::generate(),
                node_id: key.public(),
                last_full_ping: None,
                relay_url: new_relay_and_state(Some(send_addr.clone())),
                best_addr: BestAddr::default(),
                direct_addr_state: endpoint_state,
                sent_pings: HashMap::new(),
                last_used: Some(now),
                last_call_me_maybe: None,
                has_valid_best_addr_senders: Vec::default(),
            }
        };

        // endpoint w/ expired best addr
        let (d_endpoint, d_socket_addr) = {
            let socket_addr: SocketAddr = "0.0.0.0:7".parse().unwrap();
            let expired = now.checked_sub(Duration::from_secs(100)).unwrap();
            let endpoint_state = BTreeMap::from([(
                IpPort::from(socket_addr),
                PathState::with_pong_reply(PongReply {
                    latency,
                    pong_at: now,
                    from: SendAddr::Udp(socket_addr),
                    pong_src: pong_src.clone(),
                }),
            )]);
            let relay_state = PathState::with_pong_reply(PongReply {
                latency,
                pong_at: now,
                from: SendAddr::Relay(send_addr.clone()),
                pong_src,
            });
            let key = SecretKey::generate();
            (
                Endpoint {
                    id: 3,
                    quic_mapped_addr: QuicMappedAddr::generate(),
                    node_id: key.public(),
                    last_full_ping: None,
                    relay_url: Some((send_addr.clone(), relay_state)),
                    best_addr: BestAddr::from_parts(
                        socket_addr,
                        Duration::from_millis(80),
                        now,
                        expired,
                    ),
                    direct_addr_state: endpoint_state,
                    sent_pings: HashMap::new(),
                    last_used: Some(now),
                    last_call_me_maybe: None,
                    has_valid_best_addr_senders: Vec::default(),
                },
                socket_addr,
            )
        };
        let expect = Vec::from([
            EndpointInfo {
                id: a_endpoint.id,
                node_id: a_endpoint.node_id,
                relay_url: a_endpoint.relay_url(),
                addrs: Vec::from([DirectAddrInfo {
                    addr: a_socket_addr,
                    latency: Some(latency),
                    last_control: Some((elapsed, ControlMsg::Pong)),
                    last_payload: None,
                }]),
                conn_type: ConnectionType::Direct(a_socket_addr),
                latency: Some(latency),
                last_used: Some(elapsed),
            },
            EndpointInfo {
                id: b_endpoint.id,
                node_id: b_endpoint.node_id,
                relay_url: b_endpoint.relay_url(),
                addrs: Vec::new(),
                conn_type: ConnectionType::Relay(send_addr.clone()),
                latency: Some(latency),
                last_used: Some(elapsed),
            },
            EndpointInfo {
                id: c_endpoint.id,
                node_id: c_endpoint.node_id,
                relay_url: c_endpoint.relay_url(),
                addrs: Vec::new(),
                conn_type: ConnectionType::Relay(send_addr.clone()),
                latency: None,
                last_used: Some(elapsed),
            },
            EndpointInfo {
                id: d_endpoint.id,
                node_id: d_endpoint.node_id,
                relay_url: d_endpoint.relay_url(),
                addrs: Vec::from([DirectAddrInfo {
                    addr: d_socket_addr,
                    latency: Some(latency),
                    last_control: Some((elapsed, ControlMsg::Pong)),
                    last_payload: None,
                }]),
                conn_type: ConnectionType::Mixed(d_socket_addr, send_addr.clone()),
                latency: Some(Duration::from_millis(50)),
                last_used: Some(elapsed),
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
            by_id: HashMap::from([
                (a_endpoint.id, a_endpoint),
                (b_endpoint.id, b_endpoint),
                (c_endpoint.id, c_endpoint),
                (d_endpoint.id, d_endpoint),
            ]),
            next_id: 5,
        });
        let mut got = node_map.endpoint_infos(later);
        got.sort_by_key(|p| p.id);
        assert_eq!(expect, got);
    }

    #[test]
    fn test_prune_direct_addresses() {
        // When we handle a call-me-maybe with more than MAX_INACTIVE_DIRECT_ADDRESSES we do
        // not want to prune them right away but send pings to all of them.

        let key = SecretKey::generate();
        let opts = Options {
            public_key: key.public(),
            relay_url: None,
            active: true,
        };
        let mut ep = Endpoint::new(0, opts);

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
