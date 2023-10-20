use std::{
    collections::{hash_map::Entry, HashMap},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{ensure, Context};
use futures::future::BoxFuture;
use iroh_metrics::inc;
use parking_lot::Mutex;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, info, instrument, trace, warn};

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

/// How long until we send a stayin alive ping
const STAYIN_ALIVE_MIN_ELAPSED: Duration = Duration::from_secs(2);

/// Number of addresses that are not active that we keep around per peer.
///
/// See [`Endpoint::prune_direct_addresses`].
const MAX_INACTIVE_DIRECT_ADDRESSES: usize = 5;

/// Number of peers that are inactive for which we keep info about. This limit is enforced
/// periodically via [`PeerMap::prune_inactive`].
const MAX_INACTIVE_PEERS: usize = 30;

#[derive(Debug)]
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
    /// Last time this peer was used.
    ///
    /// A peer is marked as in use when an endpoint to contact them is requested or if UDP activity
    /// is registered.
    last_used: Option<Instant>,
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
            last_used: options.active.then(Instant::now),
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
                    trace!(addr = %best_addr.addr, latency = ?best_addr.latency, "best_addr is set but outdated, use best_addr and derp");
                    (Some(best_addr.addr), self.derp_region(), true)
                } else {
                    trace!(addr = %best_addr.addr, latency = ?best_addr.latency, "best_addr is set and valid, use best_addr only");
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

                trace!(udp_addr = ?addr, derp_region = ?derp_region, ?should_ping, "best_addr is unset, use candidate addr and derp");
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

            let addr = pong.from.as_socket_addr();
            let trust_best_addr_until = pong.pong_at + Duration::from_secs(60 * 60);

            info!(
               %addr,
               latency = ?lowest_latency,
               trust_for = ?trust_best_addr_until.duration_since(Instant::now()),
               "new best_addr (candidate address with most recent pong)"
            );

            self.best_addr = Some(AddrLatency {
                addr,
                latency: Some(lowest_latency),
            });
            self.trust_best_addr_until.replace(trust_best_addr_until);

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

    /// Reports whether we should ping to all our direct addresses looking for a better path.
    fn want_full_ping(&self, now: &Instant) -> bool {
        trace!("full ping: wanted?");
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
        trace!(?now, "full ping: not needed");

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
    #[instrument("disco", skip_all, fields(peer = %self.public_key.fmt_short()))]
    pub(super) fn ping_timeout(&mut self, txid: stun::TransactionId) {
        if let Some(sp) = self.sent_ping.remove(&txid) {
            // TODO: not warn?
            warn!(tx = %hex::encode(txid), addr = %sp.to, "pong not received in timeout");
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
                    debug!(addr = %sp.to, tx = %hex::encode(txid), "drop best_addr (no pong received in timeout)");
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
        let tx_id = stun::TransactionId::default();
        info!(tx = %hex::encode(tx_id), %dst, ?purpose, "start ping");
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
        debug!(%to, tx = %hex::encode(tx_id), ?purpose, "ping sent");

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
                warn!(%to, ?purpose, "unexpected attempt to ping no longer live endpoint");
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

        // queue a ping to our derper, if needed.
        if let Some((region, state)) = self.derp_region.as_ref() {
            if state.needs_ping(&now) {
                debug!(?region, "peer's derp region needs ping");
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
        self.prune_direct_addresses();

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
        let ping_needed = !pings.is_empty();
        let have_endpoints = !self.direct_addr_state.is_empty();

        if !ping_needed {
            trace!("no ping needed");
        }

        for ep in pings.into_iter() {
            if let Some(msg) =
                self.start_ping(SendAddr::Udp(ep.into()), DiscoPingPurpose::Discovery)
            {
                msgs.push(msg);
            }
        }

        if send_call_me_maybe && (ping_needed || !have_endpoints) {
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
                info!(?derp_region, "enqueue call-me-maybe");
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
                "Changing derp region from {:?} to {:?}",
                self.derp_region, n.derp_region
            );
            self.derp_region = n
                .derp_region
                .map(|region| (region, EndpointState::default()));
        }

        for &addr in n.direct_addresses.iter() {
            self.direct_addr_state.entry(addr.into()).or_default();
        }

        // Delete outdated endpoints
        self.prune_direct_addresses();
    }

    /// Clears all the endpoint's p2p state, reverting it to a DERP-only endpoint.
    #[instrument(skip_all, fields(peer = %self.public_key.fmt_short()))]
    fn reset(&mut self) {
        if self.best_addr.is_some() {
            // we no longer rely on a direct connection
            inc!(MagicsockMetrics, num_relay_conns_removed);
            if self.derp_region.is_some() {
                // we are now relying on a relay connection
                inc!(MagicsockMetrics, num_direct_conns_added);
            }
        }
        warn!("drop best_addr (reset state)");
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
                    info!(%addr, "new direct addr for peer");

                    vacant.insert(new_endpoint());
                }
            },
            SendAddr::Derp(region) => {
                if self.derp_region() != Some(region) {
                    // either the peer changed regions or we didn't have a relay address for the
                    // peer. In both cases, trust the new confirmed region
                    info!(%region, "new relay addr for peer");

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
        self.prune_direct_addresses();

        false
    }

    /// Keep any direct address that is currently active. From those that aren't active, prune
    /// first those that are not alive, then those alive but not active in order to keep at most
    /// [`MAX_INACTIVE_DIRECT_ADDRESSES`].
    fn prune_direct_addresses(&mut self) {
        // prune candidates are addresses that are not active
        let mut prune_candidates: Vec<_> = self
            .direct_addr_state
            .iter()
            .filter(|(_ip_port, state)| !state.is_active())
            .map(|(ip_port, state)| (*ip_port, state.last_alive()))
            .collect();
        let prune_count = prune_candidates
            .len()
            .saturating_sub(MAX_INACTIVE_DIRECT_ADDRESSES);
        if prune_count == 0 {
            // nothing to do, within limits
            return;
        }

        // sort leaving the worst addresses first (never contacted) and better ones (most recently
        // used ones) last
        prune_candidates.sort_unstable_by_key(|(_ip_port, last_active)| *last_active);
        prune_candidates.truncate(prune_count);
        let peer = self.public_key.fmt_short();
        for (ip_port, last_seen) in prune_candidates.into_iter() {
            self.direct_addr_state.remove(&ip_port);

            match last_seen.map(|instant| instant.elapsed()) {
                Some(last_seen) => trace!(%peer, %ip_port, ?last_seen, "pruning address"),
                None => trace!(%peer, %ip_port, last_seen=%"never", "pruning address"),
            }

            if let Some(addr_and_latency) = self.best_addr.as_ref() {
                if addr_and_latency.addr == ip_port.into() {
                    warn!(addr = %addr_and_latency.addr, "drop best_addr (prune for inactivity)");
                    self.best_addr = None;
                    // no longer relying on a direct connection, remove conn count
                    inc!(MagicsockMetrics, num_direct_conns_removed);
                    if self.derp_region.is_some() {
                        // we now rely on a relay connection, add a relay count
                        inc!(MagicsockMetrics, num_relay_conns_added);
                    }
                }
            }
        }
    }

    /// Called when connectivity changes enough that we should question our earlier
    /// assumptions about which paths work.
    #[instrument("disco", skip_all, fields(peer = %self.public_key.fmt_short()))]
    pub(super) fn note_connectivity_change(&mut self) {
        trace!("connectivity changed");
        self.trust_best_addr_until = None;
    }

    /// Handles a Pong message (a reply to an earlier ping).
    ///
    /// It reports the address and key that should be inserted for the endpoint if any.
    pub(super) fn handle_pong_conn(
        &mut self,
        m: &disco::Pong,
        src: SendAddr,
    ) -> Option<(SocketAddr, PublicKey)> {
        let is_derp = src.is_derp();

        trace!(
            tx = %hex::encode(m.tx_id),
            pong_src = %src,
            pong_ping_src = %m.src,
            is_derp = %src.is_derp(),
            "received pong"
        );
        match self.sent_ping.remove(&m.tx_id) {
            None => {
                // This is not a pong for a ping we sent.
                info!(tx = %hex::encode(m.tx_id), "received pong with unknown transaction id");
                None
            }
            Some(sp) => {
                sp.timer.abort();

                let mut peer_map_insert = None;

                let now = Instant::now();
                let latency = now - sp.at;

                // TODO: degrade to debug.
                info!(
                    tx = %hex::encode(m.tx_id),
                    src = %src,
                    reported_ping_src = %m.src,
                    ping_dst = %sp.to,
                    is_derp = %src.is_derp(),
                    latency = %latency.as_millis(),
                    "received pong",
                );

                match src {
                    SendAddr::Udp(addr) => {
                        let key = self.public_key;
                        match self.direct_addr_state.get_mut(&addr.into()) {
                            None => {
                                info!("ignoring pong: no state for src addr");
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
                        if self.best_addr.is_none() {
                            // we now have direct connection!
                            inc!(MagicsockMetrics, num_direct_conns_added);
                            if self.derp_region.is_some() {
                                // no long relying on a relay connection, remove a relay conn
                                inc!(MagicsockMetrics, num_relay_conns_removed);
                            }
                        }
                        info!(addr = %sp.to, "new best_addr (from pong)");
                        self.best_addr.replace(this_pong.clone());
                    }
                    let best_addr = self.best_addr.as_mut().expect("just set");
                    if best_addr.addr == this_pong.addr {
                        trace!(addr = %best_addr.addr, trust_for = ?TRUST_UDP_ADDR_DURATION, "best_addr: update trust time");
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
                ?new_eps,
                "received call-me-maybe, add new endpoints and reset state"
            );
        }

        // Delete any prior CallMeMaybe endpoints that weren't included in this message.
        self.is_call_me_maybe_ep.retain(|ep, want| {
            if !*want {
                if Some(ep)
                    == self
                        .best_addr
                        .as_ref()
                        .map(|addr_and_latency| addr_and_latency.addr)
                        .as_ref()
                {
                    warn!("drop best_addr (received call-me-maybe)");
                    self.best_addr = None;
                    // no longer relying on the direct connection
                    inc!(MagicsockMetrics, num_direct_conns_removed);
                    if self.derp_region.is_some() {
                        // we are now relying on the relay connection, add a relay conn
                        inc!(MagicsockMetrics, num_relay_conns_added);
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
        match self.last_used {
            Some(last_active) => now.duration_since(last_active) <= SESSION_ACTIVE_TIMEOUT,
            None => false,
        }
    }

    /// Send a heartbeat to the peer to keep the connection alive, or trigger a full ping
    /// if necessary.
    #[instrument("disco", skip_all, fields(peer = %self.public_key.fmt_short()))]
    pub(super) fn stayin_alive(&mut self) -> Vec<PingAction> {
        trace!("stayin_alive");
        let now = Instant::now();
        if !self.is_active(&now) {
            trace!("skipping stayin alive: session is inactive");
            return Vec::new();
        }

        // If we do not have an optimal addr, send pings to all known places.
        if self.want_full_ping(&now) {
            debug!("send full pings to all endpoints");
            return self.send_pings(now, true);
        }

        // Send heartbeat ping to keep the current addr going as long as we need it.
        let udp_addr = self.best_addr.as_ref().map(|a| a.addr);
        if let Some(udp_addr) = udp_addr {
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
                    return vec![msg];
                }
            }
        }

        Vec::new()
    }

    #[instrument("get_send_addrs", skip_all, fields(peer = %self.public_key.fmt_short()))]
    pub(crate) fn get_send_addrs(&mut self) -> (Option<SocketAddr>, Option<u16>, Vec<PingAction>) {
        let now = Instant::now();
        self.last_used.replace(now);
        let (udp_addr, derp_region, should_ping) = self.addr_for_send(&now);
        let mut msgs = Vec::new();

        // Trigger a round of pings if we haven't had any full pings yet.
        if should_ping && self.want_full_ping(&now) {
            msgs = self.send_pings(now, true);
        }

        trace!(
            ?udp_addr,
            ?derp_region,
            pings = %msgs.len(),
            "found send address",
        );

        (udp_addr, derp_region, msgs)
    }

    fn is_best_addr_valid(&self, now: Instant) -> bool {
        match &self.best_addr {
            None => {
                trace!("best_addr invalid: not set");
                false
            }
            Some(addr) => match self.trust_best_addr_until {
                Some(expiry) => {
                    if now < expiry {
                        trace!(addr = %addr.addr, remaining=?expiry.duration_since(now), "best_addr valid");
                        true
                    } else {
                        trace!(addr = %addr.addr, since=?expiry.duration_since(now), "best_addr invalid: expired");
                        false
                    }
                }
                None => {
                    trace!(addr = %addr.addr, "best_addr invalid: trust_best_addr_until not set");
                    false
                }
            },
        }
    }

    /// Get the direct addresses for this endpoint.
    pub fn direct_addresses(&self) -> impl Iterator<Item = IpPort> + '_ {
        self.direct_addr_state.keys().copied()
    }

    /// Get the adressing information of this endpoint.
    pub fn peer_addr(&self) -> PeerAddr {
        let direct_addresses = self.direct_addresses().map(SocketAddr::from).collect();
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
///   use [`PeerMap::write`] with `set_node_key_for_ip_port`.
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
            .receive_ip(ipp)
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
        ensure!(!path.is_dir(), "{} must be a file", path.display());

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

        let mut ext = path.extension().map(|s| s.to_owned()).unwrap_or_default();
        ext.push(".tmp");
        let tmp_path = path.with_extension(ext);

        if tokio::fs::try_exists(&tmp_path).await.unwrap_or(false) {
            tokio::fs::remove_file(&tmp_path)
                .await
                .context("failed deleting existing tmp file")?;
        }
        if let Some(parent) = tmp_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut tmp = tokio::fs::File::create(&tmp_path)
            .await
            .context("failed creating tmp file")?;

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

    /// Prunes peers without recent activity so that at most [`MAX_INACTIVE_PEERS`] are kept.
    pub(super) fn prune_inactive(&self) {
        self.inner.lock().prune_inactive();
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
        let path = path.as_ref();
        ensure!(path.is_file(), "{} is not a file", path.display());
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
    #[instrument(skip_all, fields(peer = %peer_addr.peer_id.fmt_short()))]
    pub fn add_peer_addr(&mut self, peer_addr: PeerAddr) {
        let PeerAddr { peer_id, info } = peer_addr;

        if self.endpoint_for_node_key(&peer_id).is_none() {
            info!(derp_region = ?info.derp_region, "inserting new peer endpoint in PeerMap");
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

    /// Marks the peer we believe to be at `ipp` as recently used, returning the [`Endpoint`] if found.
    pub(super) fn receive_ip(&mut self, ipp: impl Into<IpPort>) -> Option<&Endpoint> {
        let ip_port = ipp.into();
        // search by IpPort to get the Id
        let id = *self.by_ip_port.get(&ip_port)?;
        // search by Id to get the endpoint. This should never fail
        let Some(endpoint) = self.by_id_mut(&id) else {
            debug_assert!(false, "peer map inconsistency by_ip_port <-> by_id");
            return None;
        };
        // the endpoint we found must have the original address among its direct udp addresses if
        // the peer map maintains consistency
        let Some(state) = endpoint.direct_addr_state.get_mut(&ip_port) else {
            debug_assert!(false, "peer map inconsistency by_ip_port <-> direct addr");
            return None;
        };
        // record this peer and this address being in use
        let now = Instant::now();
        endpoint.last_used = Some(now);
        state.last_payload_msg = Some(now);
        Some(endpoint)
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
        trace!(?ipp, ?id, "set endpoint for ip:port");
        self.by_ip_port.insert(ipp, id);
    }

    /// Prunes peers without recent activity so that at most [`MAX_INACTIVE_PEERS`] are kept.
    fn prune_inactive(&mut self) {
        let now = Instant::now();
        let mut prune_candidates: Vec<_> = self
            .by_id
            .values()
            .filter(|peer| !peer.is_active(&now))
            .map(|peer| (*peer.public_key(), peer.last_used))
            .collect();

        let prune_count = prune_candidates.len().saturating_sub(MAX_INACTIVE_PEERS);
        if prune_count == 0 {
            // within limits
            return;
        }

        prune_candidates.sort_unstable_by_key(|(_pk, last_used)| *last_used);
        prune_candidates.truncate(prune_count);
        for (public_key, last_used) in prune_candidates.into_iter() {
            let peer = public_key.fmt_short();
            match last_used.map(|instant| instant.elapsed()) {
                Some(last_used) => trace!(%peer, ?last_used, "pruning inactive"),
                None => trace!(%peer, last_used=%"never", "pruning inactive"),
            }

            let Some(id) = self.by_node_key.remove(&public_key) else {
                debug_assert!(false, "missing by_node_key entry for pk in by_id");
                continue;
            };

            let Some(ep) = self.by_id.remove(&id) else {
                debug_assert!(false, "missing by_id entry for id in by_node_key");
                continue;
            };

            for ip_port in ep.direct_addresses() {
                self.by_ip_port.remove(&ip_port);
            }

            self.by_quic_mapped_addr.remove(&ep.quic_mapped_addr);
        }
    }
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
    /// When was this endpoint last used to transmit payload data (removing ping, pong, etc).
    last_payload_msg: Option<Instant>,
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

    /// Check whether this endpoint is considered active.
    ///
    /// An endpoint is considered alive if we have received payload messages from it within the
    /// last [`SESSION_ACTIVE_TIMEOUT`]. Note that an endpoint might be alive but not active if
    /// it's contactable but not in use.
    pub fn is_active(&self) -> bool {
        self.last_payload_msg
            .as_ref()
            .map(|instant| instant.elapsed() <= SESSION_ACTIVE_TIMEOUT)
            .unwrap_or(false)
    }

    /// Reports the last instant this endpoint was considered active.
    ///
    /// This is the most recent instant between:
    /// - when last pong was received.
    /// - when the last CallMeMaybe was received.
    /// - When the last payload transmission occurred.
    /// - when the last ping from them was received.
    pub fn last_alive(&self) -> Option<Instant> {
        self.recent_pong()
            .map(|pong| &pong.pong_at)
            .into_iter()
            .chain(self.last_payload_msg.as_ref())
            .chain(self.call_me_maybe_time.as_ref())
            .chain(self.last_got_ping.as_ref())
            .max()
            .copied()
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
    use std::net::Ipv4Addr;

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
                    recent_pong: Some(PongReply {
                        latency,
                        pong_at: now,
                        from: SendAddr::Udp(ip_port.into()),
                        pong_src,
                    }),
                    ..Default::default()
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
                    last_used: Some(now),
                },
                ip_port.into(),
            )
        };
        // endpoint w/ no best addr but a derp  w/ latency
        let b_endpoint = {
            // let socket_addr = "0.0.0.0:9".parse().unwrap();
            let now = Instant::now();
            let relay_state = EndpointState {
                recent_pong: Some(PongReply {
                    latency,
                    pong_at: now,
                    from: SendAddr::Derp(0),
                    pong_src,
                }),
                ..Default::default()
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
                last_used: Some(now),
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
                last_used: Some(now),
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
                    recent_pong: Some(PongReply {
                        latency,
                        pong_at: now,
                        from: SendAddr::Udp(socket_addr),
                        pong_src,
                    }),
                    ..Default::default()
                },
            )]);
            let relay_state = EndpointState {
                recent_pong: Some(PongReply {
                    latency,
                    pong_at: now,
                    from: SendAddr::Derp(0),
                    pong_src,
                }),
                ..Default::default()
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
                    last_used: Some(now),
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
        let _guard = iroh_test::logging::setup();

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

        let root = testdir::testdir!();
        let path = root.join("peers.postcard");
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

    #[test]
    fn test_prune_direct_addresses() {
        let _guard = iroh_test::logging::setup();

        let peer_map = PeerMap::default();
        let public_key = SecretKey::generate().public();
        let id = peer_map.inner.lock().insert_endpoint(Options {
            public_key,
            derp_region: None,
            active: false,
        });

        const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        // add [`MAX_INACTIVE_DIRECT_ADDRESSES`] active direct addresses and double
        // [`MAX_INACTIVE_DIRECT_ADDRESSES`] that are inactive

        // active adddresses
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SocketAddr::new(LOCALHOST, 5000 + i as u16);
            let peer_addr = PeerAddr::new(public_key).with_direct_addresses([addr]);
            // add address
            peer_map.add_peer_addr(peer_addr);
            // make it active
            peer_map.inner.lock().receive_ip(addr);
        }

        // offline adddresses
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SocketAddr::new(LOCALHOST, 6000 + i as u16);
            let peer_addr = PeerAddr::new(public_key).with_direct_addresses([addr]);
            peer_map.add_peer_addr(peer_addr);
        }

        let mut peer_map_inner = peer_map.inner.lock();
        let endpoint = peer_map_inner.by_id.get_mut(&id).unwrap();

        // online but inactive addresses discovered via ping
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SendAddr::Udp(SocketAddr::new(LOCALHOST, 7000 + i as u16));
            let txid = stun::TransactionId::from([i as u8; 12]);
            endpoint.endpoint_confirmed(addr, txid);
        }

        endpoint.prune_direct_addresses();

        assert_eq!(
            endpoint.direct_addresses().count(),
            MAX_INACTIVE_DIRECT_ADDRESSES * 2
        );

        assert_eq!(
            endpoint
                .direct_addr_state
                .values()
                .filter(|state| !state.is_active())
                .count(),
            MAX_INACTIVE_DIRECT_ADDRESSES
        )
    }

    #[test]
    fn test_prune_inactive() {
        let peer_map = PeerMap::default();
        // add one active peer and more than MAX_INACTIVE_PEERS inactive peers
        let active_peer = SecretKey::generate().public();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 167);
        peer_map.add_peer_addr(PeerAddr::new(active_peer).with_direct_addresses([addr]));
        peer_map.inner.lock().receive_ip(addr).expect("registered");

        for _ in 0..MAX_INACTIVE_PEERS + 1 {
            let peer = SecretKey::generate().public();
            peer_map.add_peer_addr(PeerAddr::new(peer));
        }

        assert_eq!(peer_map.node_count(), MAX_INACTIVE_PEERS + 2);
        peer_map.prune_inactive();
        assert_eq!(peer_map.node_count(), MAX_INACTIVE_PEERS + 1);
        peer_map
            .inner
            .lock()
            .endpoint_for_node_key(&active_peer)
            .expect("should not be pruned");
    }
}
