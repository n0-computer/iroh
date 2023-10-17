use std::{
    collections::{hash_map::Entry, HashMap},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::{Duration, Instant},
};

use anyhow::Context;
use futures::future::BoxFuture;
use iroh_metrics::inc;
use parking_lot::Mutex;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use crate::{
    config, disco, key::PublicKey, magic_endpoint::AddrInfo, magicsock::Timer,
    net::ip::is_unicast_link_local, stun, util::derp_only_mode, PeerAddr,
};

use super::{metrics::Metrics as MagicsockMetrics, ActorMessage, QuicMappedAddr, SendAddr};

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

/// How often we try to upgrade to a better patheven if we have some non-DERP route that works.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

/// How long we trust a UDP address as the exclusive path (without using DERP) without having heard a Pong reply.
const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(super) enum PingAction {
    EnqueueCallMeMaybe {
        derp_region: u16,
        endpoint_id: usize,
    },
    SendPing {
        id: usize,
        dst: SendAddr,
        dst_key: PublicKey,
        tx_id: stun::TransactionId,
        purpose: DiscoPingPurpose,
    },
}

/// A conneciton endpoint that picks the best available path to communicate with a peer,
/// based on network conditions and what the peer supports.
#[derive(Debug)]
pub(super) struct Endpoint {
    pub(super) id: usize,
    /// The UDP address used on the QUIC-layer to address this peer.
    pub(super) quic_mapped_addr: QuicMappedAddr,
    /// Peer public key (for UDP + DERP)
    pub(super) public_key: PublicKey,
    /// Last time we pinged all endpoints
    last_full_ping: Option<Instant>,
    /// The region id of DERP node that we can relay over to communicate.
    /// The fallback/bootstrap path, if non-zero (non-zero for well-behaved clients).
    derp_region: Option<(u16, EndpointState)>,
    /// Best non-DERP path.
    best_addr: Option<AddrLatency>,
    /// Time best address re-confirmed.
    best_addr_at: Option<Instant>,
    /// Time when best_addr expires.
    trust_best_addr_until: Option<Instant>,
    /// [`EndpointState`] for this peer's direct addresses.
    direct_addr_state: HashMap<IpPort, EndpointState>,
    is_call_me_maybe_ep: HashMap<SocketAddr, bool>,

    /// Any outstanding "tailscale ping" commands running
    pending_cli_pings: Vec<PendingCliPing>,

    sent_ping: HashMap<stun::TransactionId, SentPing>,

    /// Last time this endpoint was used. If set to `None` it is inactive.
    last_active: Option<Instant>,
}

#[derive(derive_more::Debug)]
pub struct PendingCliPing {
    pub res: config::PingResult,
    #[debug("cb: Box<..>")]
    pub cb: Box<dyn Fn(config::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static>,
}

#[derive(Debug)]
pub(super) struct Options {
    pub(super) public_key: PublicKey,
    pub(super) derp_region: Option<u16>,
    /// Is this endpoint currently active (sending data)?
    pub(super) active: bool,
}

impl Endpoint {
    pub fn new(id: usize, options: Options) -> Self {
        let quic_mapped_addr = QuicMappedAddr::generate();

        if options.derp_region.is_some() {
            // we potentially have a relay connection to the peer
            inc!(MagicsockMetrics, num_relay_conns_added);
        }

        Endpoint {
            id,
            quic_mapped_addr,
            public_key: options.public_key,
            last_full_ping: None,
            derp_region: options
                .derp_region
                .map(|region| (region, EndpointState::default())),
            best_addr: None,
            best_addr_at: None,
            trust_best_addr_until: None,
            sent_ping: HashMap::new(),
            direct_addr_state: HashMap::new(),
            is_call_me_maybe_ep: HashMap::new(),
            pending_cli_pings: Vec::new(),
            last_active: options.active.then(Instant::now),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns info about this endpoint
    pub fn info(&self) -> EndpointInfo {
        let (conn_type, latency) = if self.is_best_addr_valid(Instant::now()) {
            let addr_info = self.best_addr.as_ref().expect("checked");
            (ConnectionType::Direct(addr_info.addr), addr_info.latency)
        } else if let Some((region_id, relay_state)) = self.derp_region.as_ref() {
            let latency = relay_state.recent_pong().map(|pong| pong.latency);
            (ConnectionType::Relay(*region_id), latency)
        } else {
            (ConnectionType::None, None)
        };
        let addrs = self
            .direct_addr_state
            .iter()
            .map(|(addr, endpoint_state)| {
                (
                    SocketAddr::from(*addr),
                    endpoint_state.recent_pong().map(|pong| pong.latency),
                )
            })
            .collect();

        EndpointInfo {
            id: self.id,
            public_key: self.public_key,
            derp_region: self.derp_region(),
            addrs,
            conn_type,
            latency,
        }
    }

    /// Returns the derp region of this endpoint
    pub fn derp_region(&self) -> Option<u16> {
        self.derp_region
            .as_ref()
            .map(|(region_id, _state)| *region_id)
    }

    /// Sets the derp region for this endpoint
    pub fn set_derp_region(&mut self, region: u16) {
        info!(%region, peer=%self.public_key.fmt_short(), "derp region updated for peer");
        self.derp_region = Some((region, EndpointState::default()));
    }

    /// Returns the address(es) that should be used for sending the next packet.
    /// Zero, one, or both of UDP address and DERP addr may be non-zero.
    fn addr_for_send(&mut self, now: &Instant) -> (Option<SocketAddr>, Option<u16>, bool) {
        if derp_only_mode() {
            debug!("in `DEV_DERP_ONLY` mode, giving the DERP address as the only viable address for this endpoint");
            return (None, self.derp_region(), false);
        }
        match self.best_addr {
            Some(ref best_addr) => {
                if !self.is_best_addr_valid(*now) {
                    // We had a best_addr but it expired so send both to it and DERP.
                    debug!(
                        "best addr is outdated {:?} {:?} - {:?}",
                        now, best_addr, self.trust_best_addr_until
                    );

                    (Some(best_addr.addr), self.derp_region(), true)
                } else {
                    // Address is current and can be used
                    (Some(best_addr.addr), None, false)
                }
            }
            None => {
                let (addr, should_ping) = self.get_candidate_udp_addr();

                // Provide backup derp region if no known latency or no addr.
                let derp_region = if should_ping || addr.is_none() {
                    self.derp_region()
                } else {
                    None
                };

                debug!("using candidate addr {addr:?}, derp addr: {derp_region:?}");
                (addr, derp_region, should_ping)
            }
        }
    }

    /// Determines a potential best addr for this endpoint. And if the endpoint needs a ping.
    fn get_candidate_udp_addr(&mut self) -> (Option<SocketAddr>, bool) {
        let mut lowest_latency = Duration::from_secs(60 * 60);
        let mut last_pong = None;
        for (ipp, state) in self.direct_addr_state.iter() {
            if let Some(pong) = state.recent_pong() {
                // Lower latency, or when equal, prefer IPv6.
                if pong.latency < lowest_latency
                    || (pong.latency == lowest_latency && ipp.ip().is_ipv6())
                {
                    lowest_latency = pong.latency;
                    last_pong.replace(pong);
                }
            }
        }

        // If we found a candidate, set to best addr
        if let Some(pong) = last_pong {
            if self.best_addr.is_none() {
                // we now have a direct connection, adjust direct connection count
                inc!(MagicsockMetrics, num_direct_conns_added);
                if self.derp_region.is_some() {
                    // we no longer rely on the relay connection, decrease the relay connection
                    // count
                    inc!(MagicsockMetrics, num_relay_conns_removed);
                }
            }

            self.best_addr = Some(AddrLatency {
                addr: pong.from.as_socket_addr(),
                latency: Some(lowest_latency),
            });
            self.trust_best_addr_until
                .replace(pong.pong_at + Duration::from_secs(60 * 60));

            // No need to ping, we already have a latency.
            return (Some(pong.from.as_socket_addr()), false);
        }

        // Randomly select an address to use until we retrieve latency information.
        let udp_addr = self
            .direct_addr_state
            .keys()
            .choose_stable(&mut rand::thread_rng())
            .copied()
            .map(SocketAddr::from);

        (udp_addr, udp_addr.is_some())
    }

    /// Reports whether we should ping to all our peers looking for a better path.
    fn want_full_ping(&self, now: &Instant) -> bool {
        debug!("want full ping? {:?}", now);
        if self.last_full_ping.is_none() {
            debug!("full ping: no full ping done");
            return true;
        }
        if !self.is_best_addr_valid(*now) {
            debug!("full ping: best addr expired");
            return true;
        }

        if self
            .best_addr
            .as_ref()
            .and_then(|addr| addr.latency)
            .map(|l| l > GOOD_ENOUGH_LATENCY)
            .unwrap_or(true)
            && *now - *self.last_full_ping.as_ref().unwrap() >= UPGRADE_INTERVAL
        {
            debug!(
                "full ping: full ping interval expired and latency is only {}ms",
                self.best_addr
                    .as_ref()
                    .unwrap()
                    .latency
                    .map(|l| l.as_millis())
                    .unwrap_or_default()
            );
            return true;
        }

        false
    }

    /// Starts a ping for the "ping" command.
    /// `res` is value to call cb with, already partially filled.
    #[allow(unused)]
    pub async fn cli_ping<F>(&mut self, mut res: config::PingResult, cb: F) -> Vec<PingAction>
    where
        F: Fn(config::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        self.pending_cli_pings.push(PendingCliPing {
            res,
            cb: Box::new(cb),
        });

        let now = Instant::now();
        let mut msgs = Vec::new();
        let (udp_addr, derp_region, _should_ping) = self.addr_for_send(&now);
        if let Some(derp_region) = derp_region {
            if let Some(msg) = self.start_ping(SendAddr::Derp(derp_region), DiscoPingPurpose::Cli) {
                msgs.push(msg);
            }
        }
        if let Some(udp_addr) = udp_addr {
            if self.is_best_addr_valid(now) {
                // Already have an active session, so just ping the address we're using.
                // Otherwise "tailscale ping" results to a node on the local network
                // can look like they're bouncing between, say 10.0.0.0/9 and the peer's
                // IPv6 address, both 1ms away, and it's random who replies first.
                if let Some(msg) = self.start_ping(SendAddr::Udp(udp_addr), DiscoPingPurpose::Cli) {
                    msgs.push(msg);
                }
            } else {
                let eps: Vec<_> = self.direct_addr_state.keys().cloned().collect();
                for ep in eps {
                    if let Some(msg) =
                        self.start_ping(SendAddr::Udp(ep.into()), DiscoPingPurpose::Cli)
                    {
                        msgs.push(msg);
                    }
                }
            }
        }
        // NOTE: this should be checked for before dialing
        // In our current set up, there is no way to report an error.
        // TODO(ramfox): figure out method of reporting dial errors this far down into the stack
        if udp_addr.is_none() && derp_region.is_none() {
            tracing::error!(
                "unable to ping endpoint {} {:?}, no UDP or DERP addresses known.",
                self.id,
                self.public_key
            );
        }

        msgs
    }

    /// Cleanup the expired ping for the passed in txid.
    pub(super) fn ping_timeout(&mut self, txid: stun::TransactionId) {
        if let Some(sp) = self.sent_ping.remove(&txid) {
            warn!(
                "disco: timeout waiting for pong {:?} from {:?} ({:?})",
                txid, sp.to, self.public_key,
            );
            match sp.to {
                SendAddr::Udp(addr) => {
                    if let Some(ep_state) = self.direct_addr_state.get_mut(&addr.into()) {
                        ep_state.last_ping = None;
                    }
                }
                SendAddr::Derp(region) => {
                    if let Some((home_derp, relay_state)) = self.derp_region.as_mut() {
                        if *home_derp == region {
                            // lost connectivity via relay
                            relay_state.last_ping = None;
                        }
                    }
                }
            }

            // If we fail to ping our current best addr, it is not that good anymore.
            if let Some(ref addr) = self.best_addr {
                if sp.to == addr.addr {
                    // we had a direct connection that is no longer valid
                    inc!(MagicsockMetrics, num_direct_conns_removed);
                    if self.derp_region.is_some() {
                        // we can only connect through a relay connection
                        inc!(MagicsockMetrics, num_relay_conns_added);
                    }
                    self.best_addr = None;
                    self.trust_best_addr_until = None;
                }
            }
        }
    }

    fn start_ping(&mut self, dst: SendAddr, purpose: DiscoPingPurpose) -> Option<PingAction> {
        if derp_only_mode() && !dst.is_derp() {
            // don't attempt any hole punching in derp only mode
            warn!("in `DEV_DERP_ONLY` mode, ignoring request to start a hole punching attempt.");
            return None;
        }
        info!("start ping to {}: {:?}", dst, purpose);
        let tx_id = stun::TransactionId::default();
        Some(PingAction::SendPing {
            id: self.id,
            dst,
            dst_key: self.public_key,
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
        debug!("disco: sent ping [{}]", tx_id);

        let now = Instant::now();
        if purpose != DiscoPingPurpose::Cli {
            let mut ep_found = false;
            match to {
                SendAddr::Udp(addr) => {
                    if let Some(st) = self.direct_addr_state.get_mut(&addr.into()) {
                        st.last_ping.replace(now);
                        ep_found = true
                    }
                }
                SendAddr::Derp(region) => {
                    if let Some((home_derp, relay_state)) = self.derp_region.as_mut() {
                        if *home_derp == region {
                            relay_state.last_ping.replace(now);
                            ep_found = true
                        }
                    }
                }
            }
            if !ep_found {
                // Shouldn't happen. But don't ping an endpoint that's not active for us.
                warn!(
                    "disco: [unexpected] attempt to ping no longer live endpoint {:?}",
                    to
                );
                return;
            }
        }

        let id = self.id;
        let timer = Timer::after(PING_TIMEOUT_DURATION, async move {
            sender
                .send(ActorMessage::EndpointPingExpired(id, tx_id))
                .await
                .ok();
        });
        self.sent_ping.insert(
            tx_id,
            SentPing {
                to,
                at: now,
                purpose,
                timer,
            },
        );
    }

    fn send_pings(&mut self, now: Instant, send_call_me_maybe: bool) -> Vec<PingAction> {
        let mut msgs = Vec::new();

        if let Some((region, state)) = self.derp_region.as_ref() {
            if state.needs_ping(&now) {
                if let Some(msg) =
                    self.start_ping(SendAddr::Derp(*region), DiscoPingPurpose::Discovery)
                {
                    msgs.push(msg)
                }
            }
        }

        if derp_only_mode() {
            // don't send or respond to any hole punching pings if we are in
            // derp only mode
            warn!(
                "in `DEV_DERP_ONLY` mode, ignoring request to respond to a hole punching attempt."
            );
            return msgs;
        }
        self.last_full_ping.replace(now);
        self.cleanup_endpoint_state();

        let pings: Vec<_> = self
            .direct_addr_state
            .iter()
            .filter_map(|(ep, st)| {
                if st.needs_ping(&now) {
                    return Some(*ep);
                }

                None
            })
            .collect();
        let sent_any = !pings.is_empty();
        let have_endpoints = !self.direct_addr_state.is_empty();

        if sent_any {
            debug!("sending pings to {:?}", pings);
        }

        for (i, ep) in pings.into_iter().enumerate() {
            if i == 0 && send_call_me_maybe {
                debug!("disco: send, starting discovery for {:?}", self.public_key);
            }

            if let Some(msg) =
                self.start_ping(SendAddr::Udp(ep.into()), DiscoPingPurpose::Discovery)
            {
                msgs.push(msg);
            }
        }

        if send_call_me_maybe && (sent_any || !have_endpoints) {
            // If we have no endpoints, we use the CallMeMaybe to trigger an exchange
            // of potential UDP addresses.
            //
            // Otherwise it is used for hole punching, as described below.
            if let Some(derp_region) = self.derp_region() {
                // Have our magicsock.Conn figure out its STUN endpoint (if
                // it doesn't know already) and then send a CallMeMaybe
                // message to our peer via DERP informing them that we've
                // sent so our firewall ports are probably open and now
                // would be a good time for them to connect.
                let id = self.id;
                msgs.push(PingAction::EnqueueCallMeMaybe {
                    derp_region,
                    endpoint_id: id,
                });
            }
        }

        msgs
    }

    pub fn update_from_node_addr(&mut self, n: &AddrInfo) {
        if self.best_addr.is_none() {
            // we do not have a direct connection, so changing the derp information may
            // have an effect on our connection status
            if self.derp_region.is_none() && n.derp_region.is_some() {
                // we did not have a relay connection before, but now we do
                inc!(MagicsockMetrics, num_relay_conns_added)
            } else if self.derp_region.is_some() && n.derp_region.is_none() {
                // we had a relay connection before but do not have one now
                inc!(MagicsockMetrics, num_relay_conns_removed)
            }
        }

        if n.derp_region.is_some() && n.derp_region != self.derp_region() {
            debug!(
                "Changing derp region for {:?} from {:?} to {:?}",
                self.public_key, self.derp_region, n.derp_region
            );
            self.derp_region = n
                .derp_region
                .map(|region| (region, EndpointState::default()));
        }

        for &addr in n.direct_addresses.iter() {
            self.direct_addr_state.entry(addr.into()).or_default();
        }

        // Delete outdated endpoints
        self.cleanup_endpoint_state();
    }

    /// Clears all the endpoint's p2p state, reverting it to a DERP-only endpoint.
    fn reset(&mut self) {
        if self.best_addr.is_some() {
            // we no longer rely on a direct connection
            inc!(MagicsockMetrics, num_relay_conns_removed);
            if self.derp_region.is_some() {
                // we are now relying on a relay connection
                inc!(MagicsockMetrics, num_direct_conns_added);
            }
        }
        self.last_full_ping = None;
        self.best_addr = None;
        self.best_addr_at = None;
        self.trust_best_addr_until = None;

        for es in self.direct_addr_state.values_mut() {
            es.last_ping = None;
        }
    }

    /// Adds ep as an endpoint to which we should send future pings. If there is an
    /// existing endpoint_state for ep, and for_rx_ping_tx_id matches the last received
    /// ping TransactionId, this function reports `true`, otherwise `false`.
    ///
    /// This is called once we've already verified that we got a valid discovery message from `self` via ep.
    pub fn endpoint_confirmed(
        &mut self,
        ep: SendAddr,
        for_rx_ping_tx_id: stun::TransactionId,
    ) -> bool {
        // creates a new endpoint for adding
        let new_endpoint = || EndpointState {
            last_got_ping: Some(Instant::now()),
            last_got_ping_tx_id: Some(for_rx_ping_tx_id),
            ..Default::default()
        };

        // updates the endpoint to acknowledge a received ping. Returns whether any update was made
        let update_endpoint = |st: &mut EndpointState| {
            let duplicate_ping = Some(for_rx_ping_tx_id) == st.last_got_ping_tx_id;
            if !duplicate_ping {
                st.last_got_ping_tx_id.replace(for_rx_ping_tx_id);
            }
            if st.last_got_ping.is_none() {
                // Already-known endpoint from the network map.
                return duplicate_ping;
            }
            st.last_got_ping.replace(Instant::now());
            duplicate_ping
        };

        match ep {
            SendAddr::Udp(addr) => match self.direct_addr_state.entry(addr.into()) {
                Entry::Occupied(mut occupied) => return update_endpoint(occupied.get_mut()),
                Entry::Vacant(vacant) => {
                    let addr = vacant.key();
                    let peer = self.public_key.fmt_short();
                    info!(%peer, %addr, "disco: new direct addr for peer");

                    vacant.insert(new_endpoint());
                }
            },
            SendAddr::Derp(region) => {
                if self.derp_region() != Some(region) {
                    // either the peer changed regions or we didn't have a relay address for the
                    // peer. In both cases, trust the new confirmed region
                    let peer = self.public_key.fmt_short();
                    info!(%peer, %region, "disco: new relay addr for peer");

                    self.derp_region = Some((region, new_endpoint()));
                    // ping txid didn't match and no new endpoint was added, return early since
                    // endpoint cleanup is not necessary
                    return false;
                } else if let Some((_region, state)) = self.derp_region.as_mut() {
                    return update_endpoint(state);
                }
            }
        };

        // if we landed here, a new endpoint was added

        // If for some reason this gets very large, do some cleanup.
        let size = self.direct_addr_state.len();
        if size > 100 {
            self.cleanup_endpoint_state();
            let size2 = self.direct_addr_state.len();
            info!(
                "disco: addConfirmedEndpoint pruned candidate set from {} to {} entries",
                size, size2
            )
        }

        false
    }

    fn cleanup_endpoint_state(&mut self) {
        self.direct_addr_state.retain(|ep, st| {
            if st.should_delete() {
                if let Some(best_addr) = self.best_addr.take() {
                    let ep: SocketAddr = (*ep).into();
                    if ep == best_addr.addr {
                        // no longer relying on a direct connection, remove conn count
                        inc!(MagicsockMetrics, num_direct_conns_removed);
                        if self.derp_region.is_some() {
                            // we now rely on a relay connection, add a relay count
                            inc!(MagicsockMetrics, num_relay_conns_added);
                        }
                    }
                }
                false
            } else {
                true
            }
        });
    }

    /// Called when connectivity changes enough that we should question our earlier
    /// assumptions about which paths work.
    pub(super) fn note_connectivity_change(&mut self) {
        trace!("connectivity changed");
        self.trust_best_addr_until = None;
    }

    /// Handles a Pong message (a reply to an earlier ping).
    ///
    /// It reports the address and key that should be inserted for the endpoint if any.
    pub(super) fn handle_pong_conn(
        &mut self,
        conn_disco_public: &PublicKey,
        m: &disco::Pong,
        src: SendAddr,
    ) -> Option<(SocketAddr, PublicKey)> {
        let is_derp = src.is_derp();

        info!(
            "disco: received pong [{}] from {} (is_derp: {}) {}",
            m.tx_id, src, is_derp, m.src
        );
        match self.sent_ping.remove(&m.tx_id) {
            None => {
                // This is not a pong for a ping we sent.
                info!(
                    "disco: received unexpected pong {:?} from {:?}",
                    m.tx_id, src,
                );
                None
            }
            Some(sp) => {
                sp.timer.abort();

                let mut peer_map_insert = None;

                let now = Instant::now();
                let latency = now - sp.at;

                match src {
                    SendAddr::Udp(addr) => {
                        let key = self.public_key;
                        match self.direct_addr_state.get_mut(&addr.into()) {
                            None => {
                                info!("disco: ignoring pong: {}", sp.to);
                                // This is no longer an endpoint we care about.
                                return peer_map_insert;
                            }
                            Some(st) => {
                                peer_map_insert = Some((addr, key));
                                st.add_pong_reply(PongReply {
                                    latency,
                                    pong_at: now,
                                    from: src,
                                    pong_src: m.src,
                                });
                            }
                        }
                    }
                    SendAddr::Derp(region) => match self.derp_region.as_mut() {
                        Some((home_region, state)) if *home_region == region => {
                            state.add_pong_reply(PongReply {
                                latency,
                                pong_at: now,
                                from: src,
                                pong_src: m.src,
                            });
                        }
                        other => {
                            // if we are here then we sent this ping, but the region changed
                            // waiting for the response. It was either set to None or changed to
                            // another region. This should either never happen or be extremely
                            // unlikely. Log and ignore for now
                            warn!(stored=?other, received=?region, "disco: ignoring pong via derp for region different to last one stored");
                        }
                    },
                }

                info!(
                    "disco: {:?}<-{:?} ({:?})  got pong tx=%x latency={:?} pong.src={:?}{}{}",
                    conn_disco_public,
                    self.public_key,
                    src,
                    m.tx_id,
                    latency.as_millis(),
                    m.src,
                    if sp.to != src {
                        format!(" ping.to={}", sp.to)
                    } else {
                        String::new()
                    }
                );

                if !self.pending_cli_pings.is_empty() {
                    let ep = sp.to;
                    // FIXME: this creates a deadlock as it needs to interact with the run loop in the conn::Actor
                    // let region_code = self.get_derp_region(region_id).await.map(|r| r.region_code);

                    for PendingCliPing { mut res, cb } in self.pending_cli_pings.drain(..) {
                        res.latency_seconds = Some(latency.as_secs_f64());
                        match ep {
                            SendAddr::Udp(addr) => {
                                res.endpoint = Some(addr);
                            }
                            SendAddr::Derp(region) => {
                                res.derp_region_id = Some(region);
                                // res.derp_region_code = region_code.clone();
                            }
                        }
                        tokio::task::spawn(async move {
                            cb(res).await;
                        });
                    }
                }

                // Promote this pong response to our current best address if it's lower latency.
                // TODO(bradfitz): decide how latency vs. preference order affects decision
                if let SendAddr::Udp(to) = sp.to {
                    debug_assert!(!is_derp, "missmatching derp & udp");
                    let this_pong = AddrLatency {
                        addr: to,
                        latency: Some(latency),
                    };
                    let is_better = self.best_addr.is_none()
                        || this_pong.is_better_than(self.best_addr.as_ref().unwrap());

                    if is_better {
                        info!("disco: node {:?} now using {:?}", self.public_key, sp.to);
                        if self.best_addr.is_none() {
                            // we now have direct connection!
                            inc!(MagicsockMetrics, num_direct_conns_added);
                            if self.derp_region.is_some() {
                                // no long relying on a relay connection, remove a relay conn
                                inc!(MagicsockMetrics, num_relay_conns_removed);
                            }
                        }
                        self.best_addr.replace(this_pong.clone());
                    }
                    let best_addr = self.best_addr.as_mut().expect("just set");
                    if best_addr.addr == this_pong.addr {
                        trace!("updating best addr trust {}", best_addr.addr);
                        best_addr.latency.replace(latency);
                        self.best_addr_at.replace(now);
                        self.trust_best_addr_until
                            .replace(now + TRUST_UDP_ADDR_DURATION);
                    }
                }

                peer_map_insert
            }
        }
    }

    /// Handles a CallMeMaybe discovery message via DERP. The contract for use of
    /// this message is that the peer has already sent to us via UDP, so their stateful firewall should be
    /// open. Now we can Ping back and make it through.
    pub fn handle_call_me_maybe(&mut self, m: disco::CallMeMaybe) -> Vec<PingAction> {
        let now = Instant::now();
        for el in self.is_call_me_maybe_ep.values_mut() {
            *el = false;
        }

        let mut new_eps = Vec::new();

        for ep in &m.my_number {
            if let IpAddr::V6(ip) = ep.ip() {
                if is_unicast_link_local(ip) {
                    // We send these out, but ignore them for now.
                    // TODO: teach the ping code to ping on all interfaces for these.
                    continue;
                }
            }
            self.is_call_me_maybe_ep.insert(*ep, true);
            let ep = IpPort::from(*ep);
            if let Some(es) = self.direct_addr_state.get_mut(&ep) {
                es.call_me_maybe_time.replace(now);
            } else {
                self.direct_addr_state.insert(
                    ep,
                    EndpointState {
                        call_me_maybe_time: Some(now),
                        ..Default::default()
                    },
                );
                new_eps.push(ep);
            }
        }
        if !new_eps.is_empty() {
            debug!(
                "disco: call-me-maybe from {:?} added new endpoints: {:?}",
                self.public_key, new_eps,
            );
        }

        // Delete any prior CallMeMaybe endpoints that weren't included in this message.
        self.is_call_me_maybe_ep.retain(|ep, want| {
            if !*want {
                if let Some(best_addr) = self.best_addr.take() {
                    if *ep == best_addr.addr {
                        // no longer relying on the direct connection
                        inc!(MagicsockMetrics, num_direct_conns_removed);
                        if self.derp_region.is_some() {
                            // we are now relying on the relay connection, add a relay conn
                            inc!(MagicsockMetrics, num_relay_conns_added);
                        }
                    }
                }
                false
            } else {
                true
            }
        });

        // Zero out all the last_ping times to force send_pings to send new ones,
        // even if it's been less than 5 seconds ago.
        for st in self.direct_addr_state.values_mut() {
            st.last_ping = None;
        }
        self.send_pings(Instant::now(), false)
    }

    /// Stops timers associated with de and resets its state back to zero.
    /// It's called when a discovery endpoint is no longer present in the
    /// NetworkMap, or when magicsock is transitioning from running to
    /// stopped state (via `set_secret_key(None)`).
    pub fn stop_and_reset(&mut self) {
        self.reset();
        self.pending_cli_pings.clear();
    }

    fn last_ping(&self, addr: &SendAddr) -> Option<Instant> {
        match addr {
            SendAddr::Udp(addr) => self
                .direct_addr_state
                .get(&(*addr).into())
                .and_then(|ep| ep.last_ping),
            SendAddr::Derp(region) => self
                .derp_region
                .as_ref()
                .filter(|(home_region, _state)| home_region == region)
                .and_then(|(_home_region, state)| state.last_ping),
        }
    }

    /// Checks if this `Endpoint` is currently actively being used.
    fn is_active(&self, now: &Instant) -> bool {
        match self.last_active {
            Some(last_active) => now.duration_since(last_active) <= SESSION_ACTIVE_TIMEOUT,
            None => false,
        }
    }

    /// Send a heartbeat to the peer to keep the connection alive, or trigger a full ping
    /// if necessary.
    pub(super) fn stayin_alive(&mut self) -> Vec<PingAction> {
        trace!("stayin_alive");
        let now = Instant::now();
        if !self.is_active(&now) {
            trace!("skipping stayin alive: session is inactive");
            return Vec::new();
        }

        // If we do not have an optimal addr, send pings to all known places.
        if self.want_full_ping(&now) {
            debug!("send pings all");
            return self.send_pings(now, true);
        }

        // Send heartbeat ping to keep the current addr going as long as we need it.
        let udp_addr = self.best_addr.as_ref().map(|a| a.addr);
        if let Some(udp_addr) = udp_addr {
            let elapsed = self.last_ping(&SendAddr::Udp(udp_addr)).map(|l| now - l);
            // Send a ping if the last ping is older than 2 seconds.
            let needs_ping = match elapsed {
                Some(e) => e >= Duration::from_secs(2),
                None => false,
            };

            if needs_ping {
                debug!(
                    "stayin alive ping for {}: {:?} {:?}",
                    udp_addr, elapsed, now
                );
                if let Some(msg) =
                    self.start_ping(SendAddr::Udp(udp_addr), DiscoPingPurpose::StayinAlive)
                {
                    return vec![msg];
                }
            }
        }

        Vec::new()
    }

    pub(crate) fn get_send_addrs(&mut self) -> (Option<SocketAddr>, Option<u16>, Vec<PingAction>) {
        let now = Instant::now();
        self.last_active.replace(now);
        let (udp_addr, derp_region, should_ping) = self.addr_for_send(&now);
        let mut msgs = Vec::new();

        // Trigger a round of pings if we haven't had any full pings yet.
        if should_ping && self.want_full_ping(&now) {
            msgs = self.send_pings(now, true);
        }

        debug!(
            "sending UDP: {:?}, DERP: {:?}, #pings: {}",
            udp_addr,
            derp_region,
            msgs.len()
        );

        (udp_addr, derp_region, msgs)
    }

    fn is_best_addr_valid(&self, instant: Instant) -> bool {
        trace!(
            "is_best_addr_valid: best_addr: {:?}, trust_best: {:?}",
            self.best_addr,
            self.trust_best_addr_until
        );
        match self.best_addr {
            None => false,
            Some(_) => match self.trust_best_addr_until {
                Some(expiry) => instant < expiry,
                None => false,
            },
        }
    }

    /// Get the direct addresses for this endpoint.
    pub fn direct_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.direct_addr_state
            .keys()
            .map(|ip_port| SocketAddr::from(*ip_port))
    }

    /// Get the adressing information of this endpoint.
    pub fn peer_addr(&self) -> PeerAddr {
        let direct_addresses = self.direct_addresses().collect();
        PeerAddr {
            peer_id: self.public_key,
            info: AddrInfo {
                derp_region: self.derp_region(),
                direct_addresses,
            },
        }
    }
}

/// A `SocketAddr` with an associated latency.
#[derive(Debug, Clone)]
pub struct AddrLatency {
    pub addr: SocketAddr,
    pub latency: Option<Duration>,
}

/// An (Ip, Port) pair.
///
/// NOTE: storing an [`IpPort`] is safer than storing a [`SocketAddr`] because for IPv6 socket
/// addresses include fields that can't be assumed consistent even within a single connection.
#[derive(Debug, derive_more::Display, Clone, Copy, Hash, PartialEq, Eq)]
#[display("{}", SocketAddr::from(*self))]
pub struct IpPort {
    ip: IpAddr,
    port: u16,
}

impl From<SocketAddr> for IpPort {
    fn from(socket_addr: SocketAddr) -> Self {
        Self {
            ip: socket_addr.ip(),
            port: socket_addr.port(),
        }
    }
}

impl From<IpPort> for SocketAddr {
    fn from(ip_port: IpPort) -> Self {
        let IpPort { ip, port } = ip_port;
        (ip, port).into()
    }
}

impl IpPort {
    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Map of the [`Endpoint`] information for all the known peers.
///
/// The peers can be looked up by:
///
/// - The peer's ID in this map, only useful if you know the ID from an insert or lookup.
///   This is static and never changes.
///
/// - The [`QuicMappedAddr`] which internally identifies the peer to the QUIC stack.  This
///   is static and never changes.
///
/// - The peers's public key, aka `PublicKey` or "node_key".  This is static and never changes,
///   however a peer could be added when this is not yet known.  To set this after creation
///   use [`PeerMap::set_node_key_for_ip_port`].
///
/// - A public socket address on which they are reachable on the internet, known as ip-port.
///   These come and go as the peer moves around on the internet
///
/// An index of peerInfos by node key, QuicMappedAddr, and discovered ip:port endpoints.
#[derive(Default, Debug)]
pub(super) struct PeerMap {
    inner: Mutex<PeerMapInner>,
}

#[derive(Default, Debug)]
pub(super) struct PeerMapInner {
    by_node_key: HashMap<PublicKey, usize>,
    by_ip_port: HashMap<IpPort, usize>,
    by_quic_mapped_addr: HashMap<QuicMappedAddr, usize>,
    by_id: HashMap<usize, Endpoint>,
    next_id: usize,
}

impl PeerMap {
    /// Create a new [`PeerMap`] from data stored in `path`.
    pub fn load_from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Ok(Self::from_inner(PeerMapInner::load_from_file(path)?))
    }

    fn from_inner(inner: PeerMapInner) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Get the known peer addresses stored in the map. Peers with empty addressing information are
    /// filtered out.
    #[cfg(test)]
    pub fn known_peer_addresses(&self) -> Vec<PeerAddr> {
        self.inner.lock().known_peer_addresses().collect()
    }

    /// Add the contact information for a peer.
    pub fn add_peer_addr(&self, peer_addr: PeerAddr) {
        self.inner.lock().add_peer_addr(peer_addr)
    }

    /// Number of nodes currently listed.
    pub(super) fn node_count(&self) -> usize {
        self.inner.lock().node_count()
    }

    pub(super) fn write<T>(&self, f: impl FnOnce(&mut PeerMapInner) -> T) -> T {
        let mut inner = self.inner.lock();
        f(&mut inner)
    }

    pub(super) fn read<T>(&self, f: impl FnOnce(&PeerMapInner) -> T) -> T {
        let inner = self.inner.lock();
        f(&inner)
    }

    pub fn get_quic_mapped_addr_for_ip_port(
        &self,
        ipp: impl Into<IpPort>,
    ) -> Option<QuicMappedAddr> {
        self.inner
            .lock()
            .endpoint_for_ip_port(ipp)
            .map(|ep| ep.quic_mapped_addr)
    }

    pub fn get_quic_mapped_addr_for_node_key(&self, nk: &PublicKey) -> Option<QuicMappedAddr> {
        self.inner
            .lock()
            .endpoint_for_node_key(nk)
            .map(|ep| ep.quic_mapped_addr)
    }

    #[allow(clippy::type_complexity)]
    pub fn get_send_addrs_for_quic_mapped_addr(
        &self,
        addr: &QuicMappedAddr,
    ) -> Option<(PublicKey, Option<SocketAddr>, Option<u16>, Vec<PingAction>)> {
        let mut inner = self.inner.lock();
        let ep = inner.endpoint_for_quic_mapped_addr_mut(addr)?;
        let public_key = *ep.public_key();
        let (udp_addr, derp_region, msgs) = ep.get_send_addrs();
        Some((public_key, udp_addr, derp_region, msgs))
    }

    pub(super) fn notify_shutdown(&self) {
        let mut inner = self.inner.lock();
        for (_, ep) in inner.endpoints_mut() {
            ep.stop_and_reset();
        }
    }

    pub(super) fn reset_endpoint_states(&self) {
        let mut inner = self.inner.lock();
        for (_, ep) in inner.endpoints_mut() {
            ep.note_connectivity_change();
        }
    }

    pub(super) fn endpoints_stayin_alive(&self) -> Vec<PingAction> {
        let mut msgs = Vec::new();
        let mut inner = self.inner.lock();
        for (_, ep) in inner.endpoints_mut() {
            msgs.extend(ep.stayin_alive());
        }
        msgs
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    pub(super) fn endpoint_infos(&self) -> Vec<EndpointInfo> {
        self.inner.lock().endpoint_infos()
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    pub(super) fn endpoint_info(&self, public_key: &PublicKey) -> Option<EndpointInfo> {
        self.inner.lock().endpoint_info(public_key)
    }

    /// Saves the known peer info to the given path, returning the number of peers persisted.
    pub(super) async fn save_to_file(&self, path: &Path) -> anyhow::Result<usize> {
        // TODO: No allocation. But also cannot hold inner across await point.
        // So, not sure what to do here.
        let mut known_peers = self
            .inner
            .lock()
            .known_peer_addresses()
            .collect::<Vec<_>>()
            .into_iter()
            .peekable();
        if known_peers.peek().is_none() {
            // prevent file handling if unnecesary
            return Ok(0);
        }
        let (tmp_file, tmp_path) = tempfile::NamedTempFile::new()
            .context("cannot create temp file to save peer data")?
            .into_parts();

        let mut tmp = tokio::fs::File::from_std(tmp_file);

        let mut count = 0;
        for peer_addr in known_peers {
            let ser = postcard::to_stdvec(&peer_addr).context("failed to serialize peer data")?;
            tmp.write_all(&ser)
                .await
                .context("failed to persist peer data")?;
            count += 1;
        }
        tmp.flush().await.context("failed to flush peer data")?;
        drop(tmp);

        // move the file
        tokio::fs::rename(tmp_path, path)
            .await
            .context("failed renaming peer data file")?;
        Ok(count)
    }
}

impl PeerMapInner {
    /// Get the known peer addresses stored in the map. Peers with empty addressing information are
    /// filtered out.
    pub fn known_peer_addresses(&self) -> impl Iterator<Item = PeerAddr> + '_ {
        self.by_id.values().filter_map(|endpoint| {
            let peer_addr = endpoint.peer_addr();
            (!peer_addr.info.is_empty()).then_some(peer_addr)
        })
    }

    /// Create a new [`PeerMap`] from data stored in `path`.
    pub fn load_from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut me = PeerMapInner::default();
        let contents = std::fs::read(path)?;
        let mut slice: &[u8] = &contents;
        while !slice.is_empty() {
            let (peer_addr, next_contents) =
                postcard::take_from_bytes(slice).context("failed to load peer data")?;
            me.add_peer_addr(peer_addr);
            slice = next_contents;
        }
        Ok(me)
    }

    /// Add the contact information for a peer.
    pub fn add_peer_addr(&mut self, peer_addr: PeerAddr) {
        let PeerAddr { peer_id, info } = peer_addr;

        if self.endpoint_for_node_key(&peer_id).is_none() {
            info!(%peer_id, ?info.derp_region, "inserting peer's endpoint in PeerMap");
            self.insert_endpoint(Options {
                public_key: peer_id,
                derp_region: info.derp_region,
                active: false,
            });
        }

        if let Some(ep) = self.endpoint_for_node_key_mut(&peer_id) {
            ep.update_from_node_addr(&info);
            let id = ep.id;
            for endpoint in &info.direct_addresses {
                self.set_endpoint_for_ip_port(*endpoint, id);
            }
        }
    }

    /// Number of nodes currently listed.
    pub(super) fn node_count(&self) -> usize {
        self.by_id.len()
    }

    pub(super) fn by_id(&self, id: &usize) -> Option<&Endpoint> {
        self.by_id.get(id)
    }

    pub(super) fn by_id_mut(&mut self, id: &usize) -> Option<&mut Endpoint> {
        self.by_id.get_mut(id)
    }

    /// Returns the endpoint for nk, or None if nk is not known to us.
    pub(super) fn endpoint_for_node_key(&self, nk: &PublicKey) -> Option<&Endpoint> {
        self.by_node_key.get(nk).and_then(|id| self.by_id(id))
    }

    pub(super) fn endpoint_for_node_key_mut(&mut self, nk: &PublicKey) -> Option<&mut Endpoint> {
        self.by_node_key
            .get(nk)
            .and_then(|id| self.by_id.get_mut(id))
    }

    /// Returns the endpoint for the peer we believe to be at ipp, or nil if we don't know of any such peer.
    pub(super) fn endpoint_for_ip_port(&self, ipp: impl Into<IpPort>) -> Option<&Endpoint> {
        self.by_ip_port
            .get(&ipp.into())
            .and_then(|id| self.by_id(id))
    }

    pub fn endpoint_for_quic_mapped_addr_mut(
        &mut self,
        addr: &QuicMappedAddr,
    ) -> Option<&mut Endpoint> {
        self.by_quic_mapped_addr
            .get(addr)
            .and_then(|id| self.by_id.get_mut(id))
    }

    pub(super) fn endpoints(&self) -> impl Iterator<Item = (&usize, &Endpoint)> {
        self.by_id.iter()
    }

    pub(super) fn endpoints_mut(&mut self) -> impl Iterator<Item = (&usize, &mut Endpoint)> {
        self.by_id.iter_mut()
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    pub(super) fn endpoint_infos(&self) -> Vec<EndpointInfo> {
        self.endpoints().map(|(_, ep)| ep.info()).collect()
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    pub(super) fn endpoint_info(&self, public_key: &PublicKey) -> Option<EndpointInfo> {
        self.endpoint_for_node_key(public_key).map(|ep| ep.info())
    }

    /// Inserts a new endpoint into the [`PeerMap`].
    pub(super) fn insert_endpoint(&mut self, options: Options) -> usize {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let ep = Endpoint::new(id, options);

        // update indices
        self.by_quic_mapped_addr.insert(ep.quic_mapped_addr, id);
        self.by_node_key.insert(ep.public_key, id);

        self.by_id.insert(id, ep);
        id
    }

    /// Makes future peer lookups by ipp return the same endpoint as a lookup by nk.
    ///
    /// This should only be called with a fully verified mapping of ipp to
    /// nk, because calling this function defines the endpoint we hand to
    /// WireGuard for packets received from ipp.
    pub(super) fn set_node_key_for_ip_port(&mut self, ipp: impl Into<IpPort>, nk: &PublicKey) {
        let ipp = ipp.into();
        if let Some(id) = self.by_ip_port.get(&ipp) {
            if !self.by_node_key.contains_key(nk) {
                self.by_node_key.insert(*nk, *id);
            }
            self.by_ip_port.remove(&ipp);
        }
        if let Some(id) = self.by_node_key.get(nk) {
            trace!("insert ip -> id: {:?} -> {}", ipp, id);
            self.by_ip_port.insert(ipp, *id);
        }
    }

    pub(super) fn set_endpoint_for_ip_port(&mut self, ipp: impl Into<IpPort>, id: usize) {
        let ipp = ipp.into();
        trace!("insert ip -> id: {:?} -> {}", ipp, id);
        self.by_ip_port.insert(ipp, id);
    }

    // TODO: When do we want to remove endpoints?
    // Dead code at the moment. This was already never called before, because entries were never
    // removed from the now-removed NetworkMap.
    // /// Deletes the endpoint.
    // pub(super) fn delete_endpoint(&mut self, id: usize) {
    //     if let Some(mut ep) = self.by_id.remove(&id) {
    //         ep.stop_and_reset();
    //         self.by_node_key.remove(ep.public_key());
    //     }
    //
    //     self.by_ip_port.retain(|_, v| *v != id);
    // }
}

/// Some state and history for a specific endpoint of a endpoint.
/// (The subject is the endpoint.endpointState map key)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
struct EndpointState {
    /// The last (outgoing) ping time.
    last_ping: Option<Instant>,

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
    recent_pong: Option<PongReply>,
}

/// The type of connection we have to the endpoint.
#[derive(derive_more::Display, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConnectionType {
    /// Direct UDP connection
    #[display("direct")]
    Direct(SocketAddr),
    /// Relay connection over DERP
    #[display("relay")]
    Relay(u16),
    /// We have no verified connection to this PublicKey
    #[display("none")]
    None,
}

/// Details about an Endpoint
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EndpointInfo {
    /// The id in the peer_map
    pub id: usize,
    /// The public key of the endpoint.
    pub public_key: PublicKey,
    /// Derp region, if available.
    pub derp_region: Option<u16>,
    /// List of addresses at which this node might be reachable, plus any latency information we
    /// have about that address.
    pub addrs: Vec<(SocketAddr, Option<Duration>)>,
    /// The type of connection we have to the peer, either direct or over relay.
    pub conn_type: ConnectionType,
    /// The latency of the `conn_type`.
    pub latency: Option<Duration>,
}

impl EndpointState {
    fn add_pong_reply(&mut self, r: PongReply) {
        self.recent_pong = Some(r);
    }

    /// Reports whether we should delete this endpoint.
    fn should_delete(&self) -> bool {
        if self.call_me_maybe_time.is_some() {
            return false;
        }
        if let Some(last_got_ping) = self.last_got_ping {
            // Receiving no pings anymore, probably gone
            return last_got_ping.elapsed() > SESSION_ACTIVE_TIMEOUT;
        }

        // keep by default
        false
    }

    /// Returns the most recent pong if available.
    fn recent_pong(&self) -> Option<&PongReply> {
        self.recent_pong.as_ref()
    }

    fn needs_ping(&self, now: &Instant) -> bool {
        match self.last_ping {
            None => true,
            Some(last_ping) => {
                let elapsed = now.duration_since(last_ping);
                let needs_ping = elapsed > DISCO_PING_INTERVAL;
                if !needs_ping {
                    debug!("ping is too new: {}ms", elapsed.as_millis());
                }
                needs_ping
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PongReply {
    latency: Duration,
    /// When we received the pong.
    pong_at: Instant,
    /// The pong's src (usually same as endpoint map key).
    from: SendAddr,
    /// What they reported they heard.
    pong_src: SocketAddr,
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
    /// The user is running "tailscale ping" from the CLI. These types of pings can go over DERP.
    Cli,
    /// Ping to ensure the current route is still valid.
    StayinAlive,
}

impl AddrLatency {
    /// Reports whether `self` is a better addr to use than `other`.
    fn is_better_than(&self, other: &Self) -> bool {
        if self.addr == other.addr {
            return false;
        }
        if self.addr.is_ipv6() && other.addr.is_ipv4() {
            // Prefer IPv6 for being a bit more robust, as long as
            // the latencies are roughly equivalent.
            match (self.latency, other.latency) {
                (Some(latency), Some(other_latency)) => {
                    if latency / 10 * 9 < other_latency {
                        return true;
                    }
                }
                (Some(_), None) => {
                    // If we have latency and the other doesn't prefer us
                    return true;
                }
                _ => {}
            }
        } else if self.addr.is_ipv4() && other.addr.is_ipv6() && other.is_better_than(self) {
            return false;
        }
        self.latency < other.latency
    }
}

#[cfg(test)]
mod tests {
    use std::{env::temp_dir, net::Ipv4Addr};

    use super::*;
    use crate::key::SecretKey;

    #[test]
    fn test_endpoint_infos() {
        let new_relay_and_state = |region_id: Option<u16>| {
            region_id.map(|region_id| (region_id, EndpointState::default()))
        };

        // endpoint with a `best_addr` that has a latency
        let pong_src = "0.0.0.0:1".parse().unwrap();
        let latency = Duration::from_millis(50);
        let (a_endpoint, a_socket_addr) = {
            let ip_port = IpPort {
                ip: Ipv4Addr::UNSPECIFIED.into(),
                port: 10,
            };
            let now = Instant::now();
            let endpoint_state = HashMap::from([(
                ip_port,
                EndpointState {
                    last_ping: None,
                    last_got_ping: None,
                    last_got_ping_tx_id: None,
                    call_me_maybe_time: None,
                    recent_pong: Some(PongReply {
                        latency,
                        pong_at: now,
                        from: SendAddr::Udp(ip_port.into()),
                        pong_src,
                    }),
                },
            )]);
            let key = SecretKey::generate();
            (
                Endpoint {
                    id: 0,
                    quic_mapped_addr: QuicMappedAddr::generate(),
                    public_key: key.public(),
                    last_full_ping: None,
                    derp_region: new_relay_and_state(Some(0)),
                    best_addr: Some(AddrLatency {
                        addr: ip_port.into(),
                        latency: Some(latency),
                    }),
                    best_addr_at: Some(now),
                    trust_best_addr_until: now.checked_add(Duration::from_secs(100)),
                    direct_addr_state: endpoint_state,
                    is_call_me_maybe_ep: HashMap::new(),
                    pending_cli_pings: Vec::new(),
                    sent_ping: HashMap::new(),
                    last_active: Some(now),
                },
                ip_port.into(),
            )
        };
        // endpoint w/ no best addr but a derp  w/ latency
        let b_endpoint = {
            // let socket_addr = "0.0.0.0:9".parse().unwrap();
            let now = Instant::now();
            let relay_state = EndpointState {
                last_ping: None,
                last_got_ping: None,
                last_got_ping_tx_id: None,
                call_me_maybe_time: None,
                recent_pong: Some(PongReply {
                    latency,
                    pong_at: now,
                    from: SendAddr::Derp(0),
                    pong_src,
                }),
            };
            let key = SecretKey::generate();
            Endpoint {
                id: 1,
                quic_mapped_addr: QuicMappedAddr::generate(),
                public_key: key.public(),
                last_full_ping: None,
                derp_region: Some((0, relay_state)),
                best_addr: None,
                best_addr_at: None,
                trust_best_addr_until: now.checked_sub(Duration::from_secs(100)),
                direct_addr_state: HashMap::default(),
                is_call_me_maybe_ep: HashMap::new(),
                pending_cli_pings: Vec::new(),
                sent_ping: HashMap::new(),
                last_active: Some(now),
            }
        };

        // endpoint w/ no best addr but a derp  w/ no latency
        let c_endpoint = {
            // let socket_addr = "0.0.0.0:8".parse().unwrap();
            let now = Instant::now();
            let endpoint_state = HashMap::new();
            let key = SecretKey::generate();
            Endpoint {
                id: 2,
                quic_mapped_addr: QuicMappedAddr::generate(),
                public_key: key.public(),
                last_full_ping: None,
                derp_region: new_relay_and_state(Some(0)),
                best_addr: None,
                best_addr_at: None,
                trust_best_addr_until: now.checked_sub(Duration::from_secs(100)),
                direct_addr_state: endpoint_state,
                is_call_me_maybe_ep: HashMap::new(),
                pending_cli_pings: Vec::new(),
                sent_ping: HashMap::new(),
                last_active: Some(now),
            }
        };

        // endpoint w/ expired best addr
        let (d_endpoint, d_socket_addr) = {
            let socket_addr: SocketAddr = "0.0.0.0:7".parse().unwrap();
            let now = Instant::now();
            let expired = now.checked_sub(Duration::from_secs(100)).unwrap();
            let endpoint_state = HashMap::from([(
                IpPort::from(socket_addr),
                EndpointState {
                    last_ping: None,
                    last_got_ping: None,
                    last_got_ping_tx_id: None,
                    call_me_maybe_time: None,
                    recent_pong: Some(PongReply {
                        latency,
                        pong_at: now,
                        from: SendAddr::Udp(socket_addr),
                        pong_src,
                    }),
                },
            )]);
            let relay_state = EndpointState {
                last_ping: None,
                last_got_ping: None,
                last_got_ping_tx_id: None,
                call_me_maybe_time: None,
                recent_pong: Some(PongReply {
                    latency,
                    pong_at: now,
                    from: SendAddr::Derp(0),
                    pong_src,
                }),
            };
            let key = SecretKey::generate();
            (
                Endpoint {
                    id: 3,
                    quic_mapped_addr: QuicMappedAddr::generate(),
                    public_key: key.public(),
                    last_full_ping: None,
                    derp_region: Some((0, relay_state)),
                    best_addr: Some(AddrLatency {
                        addr: socket_addr,
                        latency: Some(Duration::from_millis(80)),
                    }),
                    best_addr_at: Some(now),
                    trust_best_addr_until: Some(expired),
                    direct_addr_state: endpoint_state,
                    is_call_me_maybe_ep: HashMap::new(),
                    pending_cli_pings: Vec::new(),
                    sent_ping: HashMap::new(),
                    last_active: Some(now),
                },
                socket_addr,
            )
        };
        let expect = Vec::from([
            EndpointInfo {
                id: a_endpoint.id,
                public_key: a_endpoint.public_key,
                derp_region: a_endpoint.derp_region(),
                addrs: Vec::from([(a_socket_addr, Some(latency))]),
                conn_type: ConnectionType::Direct(a_socket_addr),
                latency: Some(latency),
            },
            EndpointInfo {
                id: b_endpoint.id,
                public_key: b_endpoint.public_key,
                derp_region: b_endpoint.derp_region(),
                addrs: Vec::new(),
                conn_type: ConnectionType::Relay(0),
                latency: Some(latency),
            },
            EndpointInfo {
                id: c_endpoint.id,
                public_key: c_endpoint.public_key,
                derp_region: c_endpoint.derp_region(),
                addrs: Vec::new(),
                conn_type: ConnectionType::Relay(0),
                latency: None,
            },
            EndpointInfo {
                id: d_endpoint.id,
                public_key: d_endpoint.public_key,
                derp_region: d_endpoint.derp_region(),
                addrs: Vec::from([(d_socket_addr, Some(latency))]),
                conn_type: ConnectionType::Relay(0),
                latency: Some(latency),
            },
        ]);

        let peer_map = PeerMap::from_inner(PeerMapInner {
            by_node_key: HashMap::from([
                (a_endpoint.public_key, a_endpoint.id),
                (b_endpoint.public_key, b_endpoint.id),
                (c_endpoint.public_key, c_endpoint.id),
                (d_endpoint.public_key, d_endpoint.id),
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
        let mut got = peer_map.endpoint_infos();
        got.sort_by_key(|p| p.id);
        assert_eq!(expect, got);
    }

    /// Test persisting and loading of known peers.
    #[tokio::test]
    async fn load_save_peer_data() {
        let peer_map = PeerMap::default();

        let peer_a = SecretKey::generate().public();
        let peer_b = SecretKey::generate().public();
        let peer_c = SecretKey::generate().public();
        let peer_d = SecretKey::generate().public();

        let region_x = 1;
        let region_y = 2;

        fn addr(port: u16) -> SocketAddr {
            (std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), port).into()
        }

        let direct_addresses_a = [addr(4000), addr(4001)];
        let direct_addresses_c = [addr(5000)];

        let peer_addr_a = PeerAddr::new(peer_a)
            .with_derp_region(region_x)
            .with_direct_addresses(direct_addresses_a);
        let peer_addr_b = PeerAddr::new(peer_b).with_derp_region(region_y);
        let peer_addr_c = PeerAddr::new(peer_c).with_direct_addresses(direct_addresses_c);
        let peer_addr_d = PeerAddr::new(peer_d);

        peer_map.add_peer_addr(peer_addr_a);
        peer_map.add_peer_addr(peer_addr_b);
        peer_map.add_peer_addr(peer_addr_c);
        peer_map.add_peer_addr(peer_addr_d);

        let path = temp_dir().join("peers.postcard");
        peer_map.save_to_file(&path).await.unwrap();

        let loaded_peer_map = PeerMap::load_from_file(&path).unwrap();
        let loaded: HashMap<PublicKey, AddrInfo> = loaded_peer_map
            .known_peer_addresses()
            .into_iter()
            .map(|PeerAddr { peer_id, info }| (peer_id, info))
            .collect();

        let og: HashMap<PublicKey, AddrInfo> = peer_map
            .known_peer_addresses()
            .into_iter()
            .map(|PeerAddr { peer_id, info }| (peer_id, info))
            .collect();
        // compare the peer maps via their known peers
        assert_eq!(og, loaded);
    }
}
