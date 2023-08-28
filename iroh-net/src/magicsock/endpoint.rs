use std::{
    collections::HashMap,
    hash::Hash,
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use futures::future::BoxFuture;
use iroh_metrics::inc;
use rand::seq::IteratorRandom;
use tokio::{sync::mpsc, time::Instant};
use tracing::{debug, info, trace, warn};

use crate::{
    config, disco, key::PublicKey, magicsock::Timer, net::ip::is_unicast_link_local, stun,
};

use super::{
    metrics::Metrics as MagicsockMetrics, ActorMessage, DiscoInfo, QuicMappedAddr, SendAddr,
};

/// How long we wait for a pong reply before assuming it's never coming.
const PING_TIMEOUT_DURATION: Duration = Duration::from_secs(5);

/// The minimum time between pings to an endpoint. (Except in the case of CallMeMaybe frames
/// resetting the counter, as the first pings likely didn't through the firewall)
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);

/// How many `PongReply` values we keep per `EndpointState`.
const PONG_HISTORY_COUNT: usize = 64;

/// The latency at or under which we don't try to upgrade to a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// How long since the last activity we try to keep an established endpoint peering alive.
/// It's also the idle time at which we stop doing STUN queries to keep NAT mappings alive.
const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

/// How often we try to upgrade to a better patheven if we have some non-DERP route that works.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

/// How long we trust a UDP address as the exclusive path (without using DERP) without having heard a Pong reply.
const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);

/// A conneciton endpoint that picks the best available path to communicate with a peer,
/// based on network conditions and what the peer supports.
#[derive(Debug)]
pub(super) struct Endpoint {
    pub(super) id: usize,
    conn_sender: mpsc::Sender<ActorMessage>,
    /// The UDP address used on the QUIC-layer to address this peer.
    pub(super) quic_mapped_addr: QuicMappedAddr,
    /// Public key for this node/connection.
    conn_public_key: PublicKey,
    /// Peer public key (for UDP + DERP)
    pub(super) public_key: PublicKey,
    /// Last time we pinged all endpoints
    last_full_ping: Option<Instant>,
    /// Fallback/bootstrap path, if non-zero (non-zero for well-behaved clients)
    /// Only the region_id/port of the mapped derp addr.
    derp_addr: Option<u16>,
    /// Best non-DERP path.
    best_addr: Option<AddrLatency>,
    /// Time best address re-confirmed.
    best_addr_at: Option<Instant>,
    /// Time when best_addr expires.
    trust_best_addr_until: Option<Instant>,
    endpoint_state: HashMap<SendAddr, EndpointState>,
    is_call_me_maybe_ep: HashMap<SocketAddr, bool>,

    /// Any outstanding "tailscale ping" commands running
    pending_cli_pings: Vec<PendingCliPing>,

    /// Whether the node has expired.
    expired: bool,

    sent_ping: HashMap<stun::TransactionId, SentPing>,

    /// Last time this endpoint was used.
    last_active: Instant,
}

#[derive(derive_more::Debug)]
pub struct PendingCliPing {
    pub res: config::PingResult,
    #[debug("cb: Box<..>")]
    pub cb: Box<dyn Fn(config::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static>,
}

#[derive(Debug)]
pub(super) struct Options {
    pub(super) msock_sender: mpsc::Sender<ActorMessage>,
    pub(super) msock_public_key: PublicKey,
    pub(super) public_key: PublicKey,
    pub(super) derp_addr: Option<u16>,
}

impl Endpoint {
    pub fn new(id: usize, options: Options) -> Self {
        let quic_mapped_addr = QuicMappedAddr::generate();

        if options.derp_addr.is_some() {
            // we potentially have a relay connection to the peer
            inc!(MagicsockMetrics, num_relay_conns_added);
        }

        warn!(
            "Endpoint::new, derp addr for {:?} set to {:?}",
            options.public_key, options.derp_addr
        );
        Endpoint {
            id,
            conn_sender: options.msock_sender,
            quic_mapped_addr,
            conn_public_key: options.msock_public_key,
            public_key: options.public_key,
            last_full_ping: None,
            derp_addr: options.derp_addr,
            best_addr: None,
            best_addr_at: None,
            trust_best_addr_until: None,
            sent_ping: HashMap::new(),
            endpoint_state: HashMap::new(),
            is_call_me_maybe_ep: HashMap::new(),
            pending_cli_pings: Vec::new(),
            expired: false,
            last_active: Instant::now(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns info about this endpoint
    pub fn info(&self) -> EndpointInfo {
        let addrs = self
            .endpoint_state
            .keys()
            .filter_map(|addr| match addr {
                SendAddr::Udp(addr) => Some(*addr),
                _ => None,
            })
            .collect();

        EndpointInfo {
            public_key: self.public_key,
            derp_addr: self.derp_addr,
            addrs,
            has_direct_connection: self.is_best_addr_valid(Instant::now()),
            latency: self.best_addr.as_ref().and_then(|a| a.latency),
        }
    }

    /// Returns the derp addr of this endpoint
    pub fn derp_addr(&self) -> Option<u16> {
        self.derp_addr
    }

    /// Adds a derp addr for this endpoint
    pub fn add_derp_addr(&mut self, region: u16) {
        self.derp_addr = Some(region);
    }

    /// Returns the address(es) that should be used for sending the next packet.
    /// Zero, one, or both of UDP address and DERP addr may be non-zero.
    fn addr_for_send(&mut self, now: &Instant) -> (Option<SocketAddr>, Option<u16>, bool) {
        if std::option_env!("DEV_DERP_ONLY").is_some() {
            trace!("in `DEV_DERP_ONLY` mode, giving the DERP address as the only viable address for this endpoint");
            return (None, self.derp_addr, false);
        }
        match self.best_addr {
            Some(ref best_addr) => {
                if !self.is_best_addr_valid(*now) {
                    // We had a best_addr but it expired so send both to it and DERP.
                    debug!(
                        "best addr is outdated {:?} {:?} - {:?}",
                        now, best_addr, self.trust_best_addr_until
                    );

                    (Some(best_addr.addr), self.derp_addr, true)
                } else {
                    // Address is current and can be used
                    (Some(best_addr.addr), None, false)
                }
            }
            None => {
                let (addr, should_ping) = self.get_candidate_udp_addr();

                // Provide backup derp addr if no known latency or no addr.
                let derp_addr = if should_ping || addr.is_none() {
                    self.derp_addr
                } else {
                    None
                };

                debug!("using candidate addr {addr:?}, derp addr: {derp_addr:?}");
                (addr, derp_addr, should_ping)
            }
        }
    }

    /// Determines a potential best addr for this endpoint. And if the endpoint needs a ping.
    fn get_candidate_udp_addr(&mut self) -> (Option<SocketAddr>, bool) {
        let mut lowest_latency = Duration::from_secs(60 * 60);
        let mut last_pong = None;
        for (ipp, state) in self.endpoint_state.iter() {
            if let SendAddr::Udp(ipp) = ipp {
                if let Some(pong) = state.recent_pong() {
                    // Lower latency, or when equal, prever IPv6.
                    if pong.latency < lowest_latency
                        || (pong.latency == lowest_latency && ipp.is_ipv6())
                    {
                        lowest_latency = pong.latency;
                        last_pong.replace(pong);
                    }
                }
            }
        }

        // If we found a candidate, set to best addr
        if let Some(pong) = last_pong {
            if self.best_addr.is_none() {
                // we now have a direct connection, adjust direct connection count
                inc!(MagicsockMetrics, num_direct_conns_added);
                if self.derp_addr.is_some() {
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
            .endpoint_state
            .keys()
            .filter_map(|k| k.as_udp())
            .choose_stable(&mut rand::thread_rng())
            .copied();

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
    pub async fn cli_ping<F>(&mut self, mut res: config::PingResult, cb: F)
    where
        F: Fn(config::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        if self.expired {
            res.err = Some("endpoint expired".to_string());
            cb(res);
            return;
        }

        self.pending_cli_pings.push(PendingCliPing {
            res,
            cb: Box::new(cb),
        });

        let now = Instant::now();
        let (udp_addr, derp_addr, _should_ping) = self.addr_for_send(&now);
        if let Some(derp_addr) = derp_addr {
            self.start_ping(SendAddr::Derp(derp_addr), now, DiscoPingPurpose::Cli)
                .await;
        }
        if let Some(udp_addr) = udp_addr {
            if self.is_best_addr_valid(now) {
                // Already have an active session, so just ping the address we're using.
                // Otherwise "tailscale ping" results to a node on the local network
                // can look like they're bouncing between, say 10.0.0.0/9 and the peer's
                // IPv6 address, both 1ms away, and it's random who replies first.
                self.start_ping(SendAddr::Udp(udp_addr), now, DiscoPingPurpose::Cli)
                    .await;
            } else {
                let eps: Vec<_> = self.endpoint_state.keys().cloned().collect();
                for ep in eps {
                    self.start_ping(ep, now, DiscoPingPurpose::Cli).await;
                }
            }
        }
        // NOTE: this should be checked for before dialing
        // In our current set up, there is no way to report an error.
        // TODO(ramfox): figure out method of reporting dial errors this far down into the stack
        if udp_addr.is_none() && derp_addr.is_none() {
            tracing::error!(
                "unable to ping endpoint {} {:?}, no UDP or DERP addresses known.",
                self.id,
                self.public_key
            );
        }
    }

    /// Cleanup the expired ping for the passed in txid.
    pub(super) fn ping_timeout(&mut self, txid: stun::TransactionId) {
        if let Some(sp) = self.sent_ping.remove(&txid) {
            warn!(
                "disco: timeout waiting for pong {:?} from {:?} ({:?})",
                txid, sp.to, self.public_key,
            );
            if let Some(ep_state) = self.endpoint_state.get_mut(&sp.to) {
                ep_state.last_ping = None;
            }

            // If we fail to ping our current best addr, it is not that good anymore.
            if let Some(ref addr) = self.best_addr {
                if sp.to == addr.addr {
                    // we had a direct connection that is no longer valid
                    inc!(MagicsockMetrics, num_direct_conns_removed);
                    if self.derp_addr.is_some() {
                        // we can only connect through a relay connection
                        inc!(MagicsockMetrics, num_relay_conns_added);
                    }
                    self.best_addr = None;
                    self.trust_best_addr_until = None;
                }
            }
        }
    }

    /// Called by a timer when a ping either fails to send or has taken too long to get a pong reply.
    async fn forget_ping(&mut self, tx_id: stun::TransactionId) {
        if let Some(ping) = self.sent_ping.remove(&tx_id) {
            ping.timer.stop().await;
        }
    }

    /// Sends a ping with the provided txid to ep using self's disco_key.
    ///
    /// The caller (start_ping) should've already recorded the ping in
    /// sent_ping and set up the timer.
    ///
    /// The caller should use de.disco_key as the disco_key argument.
    /// It is passed in so that send_disco_ping doesn't need to lock de.mu.
    async fn send_disco_ping(
        &mut self,
        ep: SendAddr,
        public_key: Option<PublicKey>,
        tx_id: stun::TransactionId,
    ) {
        debug!("send disco ping: start");
        let mut sent = false;
        if let Some(pub_key) = public_key {
            sent = self
                .conn_sender
                .send(ActorMessage::SendDiscoMessage {
                    dst: ep,
                    dst_key: pub_key,
                    msg: disco::Message::Ping(disco::Ping {
                        tx_id,
                        node_key: self.conn_public_key,
                    }),
                })
                .await
                .map(|_| true)
                .unwrap_or_default();
        }

        debug!("send disco ping: done: sent? {}", sent);
        if !sent {
            self.forget_ping(tx_id).await;
        }
    }

    async fn start_ping(&mut self, ep: SendAddr, now: Instant, purpose: DiscoPingPurpose) {
        if std::option_env!("DEV_DERP_ONLY").is_some() {
            // don't attempt any hole punching in derp only mode
            trace!("in `DEV_DERP_ONLY` mode, ignoring request to start a hole punching attempt.");
            return;
        }
        info!("start ping to {}: {:?}", ep, purpose);
        if purpose != DiscoPingPurpose::Cli {
            if let Some(st) = self.endpoint_state.get_mut(&ep) {
                st.last_ping.replace(now);
            } else {
                // Shouldn't happen. But don't ping an endpoint that's not active for us.
                warn!(
                    "disco: [unexpected] attempt to ping no longer live endpoint {:?}",
                    ep
                );
                return;
            }
        }

        let txid = stun::TransactionId::default();
        debug!("disco: sent ping [{}]", txid);

        let id = self.id;
        let sender = self.conn_sender.clone();
        let timer = Timer::after(PING_TIMEOUT_DURATION, async move {
            sender
                .send(ActorMessage::EndpointPingExpired(id, txid))
                .await
                .ok();
        });
        self.sent_ping.insert(
            txid,
            SentPing {
                to: ep,
                at: now,
                purpose,
                timer,
            },
        );
        self.send_disco_ping(ep, Some(self.public_key), txid).await;
    }

    async fn send_pings(&mut self, now: Instant, send_call_me_maybe: bool) {
        if std::option_env!("DEV_DERP_ONLY").is_some() {
            // don't send or respond to any hole punching pings if we are in
            // derp only mode
            trace!(
                "in `DEV_DERP_ONLY` mode, ignoring request to respond to a hole punching attempt."
            );
            return;
        }
        self.last_full_ping.replace(now);

        // first cleanout out all old endpoints
        self.endpoint_state.retain(|ep, st| {
            if st.should_delete() {
                // Inlined delete_endpoint
                if self
                    .best_addr
                    .as_ref()
                    .map(|a| ep == &a.addr)
                    .unwrap_or_default()
                {
                    // we no longer rely on a direct connection
                    if self.best_addr.is_some() {
                        inc!(MagicsockMetrics, num_direct_conns_removed);
                        if self.derp_addr.is_some() {
                            inc!(MagicsockMetrics, num_relay_conns_added);
                        }
                    }
                    self.best_addr = None;
                }
                return false;
            }
            true
        });

        let pings: Vec<_> = self
            .endpoint_state
            .iter()
            .filter_map(|(ep, st)| {
                if st.last_ping.is_some()
                    && now - *st.last_ping.as_ref().unwrap() < DISCO_PING_INTERVAL
                {
                    debug!(
                        "disco: [{:?}] skipping ping, too new {:?} {:?}",
                        ep, now, st.last_ping
                    );
                    return None;
                }
                Some(*ep)
            })
            .collect();
        debug!("sending pings to {:?}", pings);

        let sent_any = !pings.is_empty();
        let have_endpoints = !self.endpoint_state.is_empty();

        for (i, ep) in pings.into_iter().enumerate() {
            if i == 0 && send_call_me_maybe {
                debug!("disco: send, starting discovery for {:?}", self.public_key);
            }

            self.start_ping(ep, now, DiscoPingPurpose::Discovery).await;
        }

        let derp_addr = self.derp_addr;

        if send_call_me_maybe && (sent_any || !have_endpoints) {
            // If we have no endpoints, we use the CallMeMaybe to trigger an exchange
            // of potential UDP addresses.
            //
            // Otherwise it is used for hole punching, as described below.
            if let Some(derp_addr) = derp_addr {
                // Have our magicsock.Conn figure out its STUN endpoint (if
                // it doesn't know already) and then send a CallMeMaybe
                // message to our peer via DERP informing them that we've
                // sent so our firewall ports are probably open and now
                // would be a good time for them to connect.
                let id = self.id;
                let sender = self.conn_sender.clone();
                if let Err(err) = sender
                    .send(ActorMessage::EnqueueCallMeMaybe {
                        derp_addr,
                        endpoint_id: id,
                    })
                    .await
                {
                    warn!("failed to send enqueue call me maybe: {:?}", err);
                }
            }
        }
    }

    pub fn update_from_node(&mut self, n: &config::Node) {
        if self.best_addr.is_none() {
            // we do not have a direct connection, so changing the derp information may
            // have an effect on our connection status
            if self.derp_addr.is_none() && n.derp.is_some() {
                // we did not have a relay connection before, but now we do
                inc!(MagicsockMetrics, num_relay_conns_added)
            } else if self.derp_addr.is_some() && n.derp.is_none() {
                // we had a relay connection before but do not have one now
                inc!(MagicsockMetrics, num_relay_conns_removed)
            }
        }
        warn!(
            "update_from_node changing derp addr for {:?} to {:?} from {:?}",
            self.public_key, self.derp_addr, n.derp
        );
        self.derp_addr = n.derp;

        for st in self.endpoint_state.values_mut() {
            st.index = Index::Deleted; // assume deleted until updated in next loop
        }
        for (i, ep) in n.endpoints.iter().take(u16::MAX as usize).enumerate() {
            let index = Index::Some(i);
            let ep = SendAddr::Udp(*ep);
            if let Some(st) = self.endpoint_state.get_mut(&ep) {
                st.index = index
            } else {
                self.endpoint_state.insert(
                    ep,
                    EndpointState {
                        index,
                        ..Default::default()
                    },
                );
            }
        }

        // Now delete anything unless it's still in the network map or was a recently discovered endpoint.
        self.endpoint_state.retain(|ep, st| {
            if st.should_delete() {
                // Inlined delete_endpoint
                if self
                    .best_addr
                    .as_ref()
                    .map(|a| ep == &a.addr)
                    .unwrap_or_default()
                {
                    if self.best_addr.is_some() {
                        // we no long rely on a direct connection
                        inc!(MagicsockMetrics, num_direct_conns_removed);
                        if self.derp_addr.is_some() {
                            // we only have a relay connection to the peer
                            inc!(MagicsockMetrics, num_relay_conns_added);
                        }
                    }
                    self.best_addr = None;
                }
                return false;
            }
            true
        });
    }

    /// Clears all the endpoint's p2p state, reverting it to a DERP-only endpoint.
    fn reset(&mut self) {
        if self.best_addr.is_some() {
            // we no longer rely on a direct connection
            inc!(MagicsockMetrics, num_relay_conns_removed);
            if self.derp_addr.is_some() {
                // we are now relying on a relay connection
                inc!(MagicsockMetrics, num_direct_conns_added);
            }
        }
        self.last_full_ping = None;
        self.best_addr = None;
        self.best_addr_at = None;
        self.trust_best_addr_until = None;
        for es in self.endpoint_state.values_mut() {
            es.last_ping = None;
        }
    }

    /// Adds ep as an endpoint to which we should send future pings. If there is an
    /// existing endpoint_state for ep, and for_rx_ping_tx_id matches the last received
    /// ping TransactionId, this function reports `true`, otherwise `false`.
    ///
    /// This is called once we've already verified that we got a valid discovery message from `self` via ep.
    pub fn add_candidate_endpoint(
        &mut self,
        ep: SendAddr,
        for_rx_ping_tx_id: stun::TransactionId,
    ) -> bool {
        if let Some(st) = self.endpoint_state.get_mut(&ep) {
            let duplicate_ping = Some(for_rx_ping_tx_id) == st.last_got_ping_tx_id;
            if !duplicate_ping {
                st.last_got_ping_tx_id.replace(for_rx_ping_tx_id);
            }
            if st.last_got_ping.is_none() {
                // Already-known endpoint from the network map.
                return duplicate_ping;
            }
            st.last_got_ping.replace(Instant::now());
            return duplicate_ping;
        }

        // Newly discovered endpoint. Exciting!
        info!(
            "disco: adding {:?} as candidate endpoint for {:?}",
            ep, self.public_key
        );
        self.endpoint_state.insert(
            ep,
            EndpointState {
                last_got_ping: Some(Instant::now()),
                last_got_ping_tx_id: Some(for_rx_ping_tx_id),
                ..Default::default()
            },
        );

        // If for some reason this gets very large, do some cleanup.
        let size = self.endpoint_state.len();
        if size > 100 {
            self.endpoint_state.retain(|ep, st| {
                if st.should_delete() {
                    // Inlined delete_endpoint
                    if self
                        .best_addr
                        .as_ref()
                        .map(|a| ep == &a.addr)
                        .unwrap_or_default()
                    {
                        // no longer relying on a direct connection, remove conn count
                        if self.best_addr.is_some() {
                            inc!(MagicsockMetrics, num_direct_conns_removed);
                            if self.derp_addr.is_some() {
                                // we now rely on a relay connection, add a relay count
                                inc!(MagicsockMetrics, num_relay_conns_added);
                            }
                        }
                        self.best_addr = None;
                    }
                    return false;
                }
                true
            });
            let size2 = self.endpoint_state.len();
            info!(
                "disco: addCandidateEndpoint pruned candidate set from {} to {} entries",
                size, size2
            )
        }

        false
    }

    /// Called when connectivity changes enough that we should question our earlier
    /// assumptions about which paths work.
    pub(super) fn note_connectivity_change(&mut self) {
        trace!("connectivity changed");
        self.trust_best_addr_until = None;
    }

    /// Handles a Pong message (a reply to an earlier ping).
    ///
    /// It reports whether m.tx_id corresponds to a ping that this endpoint sent.
    pub(super) async fn handle_pong_conn(
        &mut self,
        conn_disco_public: &PublicKey,
        m: &disco::Pong,
        _di: &mut DiscoInfo,
        src: SendAddr,
    ) -> (bool, Option<(SendAddr, PublicKey)>) {
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
                (false, None)
            }
            Some(sp) => {
                sp.timer.stop().await;

                let known_tx_id = true;
                let mut peer_map_insert = None;

                let now = Instant::now();
                let latency = now - sp.at;

                if !is_derp {
                    let key = self.public_key;
                    match self.endpoint_state.get_mut(&sp.to) {
                        None => {
                            info!("disco: ignoring pong: {}", sp.to);
                            // This is no longer an endpoint we care about.
                            return (known_tx_id, peer_map_insert);
                        }
                        Some(st) => {
                            peer_map_insert = Some((src, key));
                            st.add_pong_reply(PongReply {
                                latency,
                                pong_at: now,
                                from: src,
                                pong_src: m.src,
                            });
                        }
                    }
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
                            if self.derp_addr.is_some() {
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

                (known_tx_id, peer_map_insert)
            }
        }
    }

    /// Handles a CallMeMaybe discovery message via DERP. The contract for use of
    /// this message is that the peer has already sent to us via UDP, so their stateful firewall should be
    /// open. Now we can Ping back and make it through.
    pub async fn handle_call_me_maybe(&mut self, m: disco::CallMeMaybe) {
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
            let ep = SendAddr::Udp(*ep);
            if let Some(es) = self.endpoint_state.get_mut(&ep) {
                es.call_me_maybe_time.replace(now);
            } else {
                self.endpoint_state.insert(
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
                if self.best_addr.as_ref().map(|a| &a.addr) == Some(ep) {
                    if self.best_addr.is_some() {
                        // no longer relying on the direct connection
                        inc!(MagicsockMetrics, num_direct_conns_removed);
                        if self.derp_addr.is_some() {
                            // we are now relying on the relay connection, add a relay conn
                            inc!(MagicsockMetrics, num_relay_conns_added);
                        }
                    }
                    self.best_addr = None;
                }
                return false;
            }
            true
        });

        // Zero out all the last_ping times to force send_pings to send new ones,
        // even if it's been less than 5 seconds ago.
        for st in self.endpoint_state.values_mut() {
            st.last_ping = None;
        }
        self.send_pings(Instant::now(), false).await;
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
        self.endpoint_state.get(addr).and_then(|ep| ep.last_ping)
    }

    /// Send a heartbeat to the peer to keep the connection alive, or trigger a full ping
    /// if necessary.
    pub(super) async fn stayin_alive(&mut self) {
        trace!("stayin_alive");
        let now = Instant::now();
        if now.duration_since(self.last_active) > SESSION_ACTIVE_TIMEOUT {
            debug!("skipping stayin alive: session is inactive");
            return;
        }

        // If we do not have an optimal addr, send pings to all known places.
        if self.want_full_ping(&now) {
            debug!("send pings all");
            return self.send_pings(now, true).await;
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
                self.start_ping(SendAddr::Udp(udp_addr), now, DiscoPingPurpose::StayinAlive)
                    .await;
            }
        }
    }

    pub(crate) async fn get_send_addrs(&mut self) -> io::Result<(Option<SocketAddr>, Option<u16>)> {
        if self.expired {
            return Err(io::Error::new(io::ErrorKind::Other, "endpoint expired"));
        }

        let now = Instant::now();
        self.last_active = now;
        let (udp_addr, derp_addr, should_ping) = self.addr_for_send(&now);

        // Trigger a round of pings if we haven't had any full pings yet.
        if should_ping && self.want_full_ping(&now) {
            self.send_pings(now, true).await;
        }

        debug!("sending UDP: {:?}, DERP: {:?}", udp_addr, derp_addr);

        Ok((udp_addr, derp_addr))
    }

    fn is_best_addr_valid(&self, instant: Instant) -> bool {
        match self.best_addr {
            None => false,
            Some(_) => match self.trust_best_addr_until {
                Some(expiry) => instant < expiry,
                None => false,
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
    by_node_key: HashMap<PublicKey, usize>,
    by_ip_port: HashMap<SendAddr, usize>,
    by_quic_mapped_addr: HashMap<QuicMappedAddr, usize>,
    by_id: HashMap<usize, Endpoint>,
    next_id: usize,
}

impl PeerMap {
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
    pub(super) fn endpoint_for_ip_port(&self, ipp: &SendAddr) -> Option<&Endpoint> {
        self.by_ip_port.get(ipp).and_then(|id| self.by_id(id))
    }

    pub fn endpoint_for_ip_port_mut(&mut self, ipp: &SendAddr) -> Option<&mut Endpoint> {
        self.by_ip_port
            .get(ipp)
            .and_then(|id| self.by_id.get_mut(id))
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
    pub(super) fn set_node_key_for_ip_port(&mut self, ipp: &SendAddr, nk: &PublicKey) {
        if let Some(id) = self.by_ip_port.get(ipp) {
            if !self.by_node_key.contains_key(nk) {
                self.by_node_key.insert(*nk, *id);
            }
            self.by_ip_port.remove(ipp);
        }
        if let Some(id) = self.by_node_key.get(nk) {
            trace!("insert ip -> id: {:?} -> {}", ipp, id);
            self.by_ip_port.insert(*ipp, *id);
        }
    }

    pub(super) fn set_endpoint_for_ip_port(&mut self, ipp: &SendAddr, id: usize) {
        trace!("insert ip -> id: {:?} -> {}", ipp, id);
        self.by_ip_port.insert(*ipp, id);
    }

    /// Deletes the endpoint.
    pub(super) fn delete_endpoint(&mut self, id: usize) {
        if let Some(mut ep) = self.by_id.remove(&id) {
            ep.stop_and_reset();
            self.by_node_key.remove(ep.public_key());
        }

        self.by_ip_port.retain(|_, v| *v != id);
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

    /// Ring buffer up to PongHistoryCount entries
    recent_pongs: Vec<PongReply>,
    /// Index into recentPongs of most recent; older before, wrapped
    recent_pong: usize,

    /// Index in nodecfg.Node.Endpoints; meaningless if last_got_ping non-zero.
    index: Index,
}

/// Details about an Endpoint
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    /// The public key of the endpoint.
    pub public_key: PublicKey,
    /// Derp region, if available.
    pub derp_addr: Option<u16>,
    /// List of addresses this node might be reachable under.
    pub addrs: Vec<SocketAddr>,
    /// Is this node currently direcly reachable?
    pub has_direct_connection: bool,
    /// Current latency information, for a direct connection if available.
    pub latency: Option<Duration>,
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum Index {
    #[default]
    Deleted,
    Some(usize),
}

impl EndpointState {
    fn add_pong_reply(&mut self, r: PongReply) {
        let n = self.recent_pongs.len();
        if n < PONG_HISTORY_COUNT {
            self.recent_pong = n;
            self.recent_pongs.push(r);
        } else {
            let mut i = self.recent_pong + 1;
            if i == PONG_HISTORY_COUNT {
                i = 0;
            }
            self.recent_pongs[i] = r;
            self.recent_pong = i;
        }
    }

    /// Reports whether we should delete this endpoint.
    fn should_delete(&self) -> bool {
        if self.call_me_maybe_time.is_some() {
            return false;
        }
        if self.last_got_ping.is_none() {
            // This was an endpoint from the network map. Is it still in the network map?
            return self.index == Index::Deleted;
        }

        // This was an endpoint discovered at runtime.
        self.last_got_ping.as_ref().unwrap().elapsed() > SESSION_ACTIVE_TIMEOUT
    }

    /// Returns the most recent pong if available.
    fn recent_pong(&self) -> Option<&PongReply> {
        self.recent_pongs.get(self.recent_pong)
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
