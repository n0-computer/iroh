use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    hash::Hash,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use futures::future::BoxFuture;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::{
    hp::{
        cfg::{self, DERP_MAGIC_IP},
        derp::DerpRegion,
        disco, key, stun,
    },
    net::ip::is_unicast_link_local,
};

use super::{
    conn::{ActorMessage, DiscoInfo},
    DISCO_PING_INTERVAL, GOOD_ENOUGH_LATENCY, PING_TIMEOUT_DURATION, PONG_HISTORY_COUNT,
    SESSION_ACTIVE_TIMEOUT, TRUST_UDP_ADDR_DURATION, UPGRADE_INTERVAL,
};

impl Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MagicsockEndpoint({:?}, {}, {})",
            self.public_key.as_ref().map(crate::util::encode),
            self.id,
            self.fake_wg_addr,
        )
    }
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self,)
    }
}

impl Hash for Endpoint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_string().hash(state);
    }
}

impl PartialEq for Endpoint {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
            && self.id == other.id
            && self.fake_wg_addr == other.fake_wg_addr
    }
}

impl Eq for Endpoint {}

/// A conneciton endpoint that picks the best available path to communicate with a peer,
/// based on network conditions and what the peer supports.
pub(super) struct Endpoint {
    pub(super) id: usize,
    conn_sender: flume::Sender<ActorMessage>,
    /// The UDP address we tell wireguard-go we're using
    pub(super) fake_wg_addr: SocketAddr,
    /// Public key for this node/conection.
    conn_public_key: key::node::PublicKey,
    /// Peer public key (for WireGuard + DERP)
    pub(super) public_key: Option<key::node::PublicKey>,
    /// Last time we pinged all endpoints
    last_full_ping: Option<Instant>,
    /// fallback/bootstrap path, if non-zero (non-zero for well-behaved clients)
    derp_addr: Option<SocketAddr>,
    /// Best non-DERP path.
    best_addr: Option<AddrLatency>,
    /// Time best address re-confirmed.
    best_addr_at: Option<Instant>,
    /// Time when best_addr expires.
    trust_best_addr_until: Option<Instant>,
    endpoint_state: HashMap<SocketAddr, EndpointState>,
    is_call_me_maybe_ep: HashMap<SocketAddr, bool>,

    /// Any outstanding "tailscale ping" commands running
    pending_cli_pings: Vec<PendingCliPing>,

    /// Whether the node has expired.
    expired: bool,

    sent_ping: HashMap<stun::TransactionId, SentPing>,
}

pub struct PendingCliPing {
    pub res: cfg::PingResult,
    pub cb: Box<dyn Fn(cfg::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static>,
}

#[derive(Debug)]
pub(super) struct Options {
    pub(super) conn_sender: flume::Sender<ActorMessage>,
    pub(super) conn_public_key: key::node::PublicKey,
    pub(super) public_key: Option<key::node::PublicKey>,
    pub(super) derp_addr: Option<SocketAddr>,
}

impl Endpoint {
    pub fn new(id: usize, options: Options) -> Self {
        let fake_wg_addr = init_fake_udp_addr();

        Endpoint {
            id,
            conn_sender: options.conn_sender,
            fake_wg_addr,
            conn_public_key: options.conn_public_key,
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
        }
    }

    pub fn public_key(&self) -> Option<key::node::PublicKey> {
        self.public_key.clone()
    }

    pub fn set_public_key(&mut self, key: key::node::PublicKey) {
        self.public_key.replace(key);
    }

    /// Returns the address(es) that should be used for sending the next packet.
    /// Zero, one, or both of UDP address and DERP addr may be non-zero.
    fn addr_for_send(&self, now: &Instant) -> (Option<SocketAddr>, Option<SocketAddr>) {
        let udp_addr = self.best_addr.as_ref().map(|a| a.addr);
        let mut derp_addr = None;
        if udp_addr.is_none() || !self.is_best_addr_valid(*now) {
            debug!(
                "no good udp addr {:?} {:?} - {:?}",
                now, udp_addr, self.trust_best_addr_until
            );
            // We had a best_addr but it expired so send both to it and DERP.
            derp_addr = self.derp_addr;
        }

        (udp_addr, derp_addr)
    }

    /// Reports whether we should ping to all our peers looking for a better path.
    fn want_full_ping(&self, now: &Instant) -> bool {
        debug!("want full ping? {:?}", now);
        if self.last_full_ping.is_none() {
            info!("full ping: no full ping done");
            return true;
        }
        if !self.is_best_addr_valid(*now) {
            info!("full ping: best addr expired");
            return true;
        }

        if self.best_addr.as_ref().unwrap().latency > GOOD_ENOUGH_LATENCY
            && *now - *self.last_full_ping.as_ref().unwrap() >= UPGRADE_INTERVAL
        {
            info!(
                "full ping: full ping interval expired and latency is only {}ms",
                self.best_addr.as_ref().unwrap().latency.as_millis()
            );
            return true;
        }

        false
    }

    /// Starts a ping for the "ping" command.
    /// `res` is value to call cb with, already partially filled.
    pub async fn cli_ping<F>(&mut self, mut res: cfg::PingResult, cb: F)
    where
        F: Fn(cfg::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static,
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
        let (udp_addr, derp_addr) = self.addr_for_send(&now);
        if let Some(derp_addr) = derp_addr {
            self.start_ping(derp_addr, now, DiscoPingPurpose::Cli).await;
        }
        if let Some(udp_addr) = udp_addr {
            if self.is_best_addr_valid(now) {
                // Already have an active session, so just ping the address we're using.
                // Otherwise "tailscale ping" results to a node on the local network
                // can look like they're bouncing between, say 10.0.0.0/9 and the peer's
                // IPv6 address, both 1ms away, and it's random who replies first.
                self.start_ping(udp_addr, now, DiscoPingPurpose::Cli).await;
            } else {
                let eps: Vec<_> = self.endpoint_state.keys().cloned().collect();
                for ep in eps {
                    self.start_ping(ep, now, DiscoPingPurpose::Cli).await;
                }
            }
        }
    }

    fn ping_timeout(&mut self, txid: stun::TransactionId) {
        if let Some(sp) = self.sent_ping.remove(&txid) {
            if !self.is_best_addr_valid(Instant::now()) {
                debug!(
                    "disco: timeout waiting for pong {:?} from {:?} ({:?})",
                    txid, sp.to, self.public_key,
                );
            }
            if let Some(ep_state) = self.endpoint_state.get_mut(&sp.to) {
                ep_state.last_ping = None;
            }
        }
    }

    /// Called by a timer when a ping either fails to send or has taken too long to get a pong reply.
    fn forget_ping(&mut self, tx_id: stun::TransactionId) {
        self.sent_ping.remove(&tx_id);
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
        ep: SocketAddr,
        public_key: Option<key::node::PublicKey>,
        tx_id: stun::TransactionId,
    ) {
        debug!("send disco ping: start");
        let mut sent = false;
        if let Some(pub_key) = public_key {
            sent = self
                .conn_sender
                .send_async(ActorMessage::SendDiscoMessage {
                    dst: ep,
                    dst_key: pub_key,
                    msg: disco::Message::Ping(disco::Ping {
                        tx_id,
                        node_key: self.conn_public_key.clone(),
                    }),
                })
                .await
                .map(|_| true)
                .unwrap_or_default();
        }

        debug!("send disco ping: done: sent? {}", sent);
        if !sent {
            self.forget_ping(tx_id);
        }
    }

    async fn start_ping(&mut self, ep: SocketAddr, now: Instant, purpose: DiscoPingPurpose) {
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

        // Cleanup expired pings
        let mut to_remove = Vec::new();
        for (id, ping) in self.sent_ping.iter() {
            if now - ping.at > PING_TIMEOUT_DURATION {
                debug!(
                    "disco: ping timeout [{}]: (elapsed: {:?} - started: {:?})",
                    id,
                    now - ping.at,
                    ping.at
                );
                to_remove.push(*id);
            }
        }
        for id in to_remove {
            self.ping_timeout(id);
        }

        let txid = stun::TransactionId::default();
        debug!("disco: sent ping [{}]", txid);

        self.sent_ping.insert(
            txid,
            SentPing {
                to: ep,
                at: now,
                purpose,
            },
        );
        let public_key = self.public_key.clone();
        self.send_disco_ping(ep, public_key, txid).await;
    }

    async fn send_pings(&mut self, now: Instant, send_call_me_maybe: bool) {
        self.last_full_ping.replace(now);

        // first cleanout out all old endpoints
        self.endpoint_state.retain(|ep, st| {
            if st.should_delete() {
                // Inlined delete_endpoint
                if self.best_addr.as_ref().map(|a| &a.addr) == Some(ep) {
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
                Some(ep.clone())
            })
            .collect();
        debug!("sending pings to {:?}", pings);

        let sent_any = !pings.is_empty();
        for (i, ep) in pings.into_iter().enumerate() {
            if i == 0 && send_call_me_maybe {
                debug!("disco: send, starting discovery for {:?}", self.public_key);
            }

            self.start_ping(ep, now, DiscoPingPurpose::Discovery).await;
        }

        let derp_addr = self.derp_addr.clone();
        if sent_any && send_call_me_maybe {
            if let Some(derp_addr) = derp_addr {
                // Have our magicsock.Conn figure out its STUN endpoint (if
                // it doesn't know already) and then send a CallMeMaybe
                // message to our peer via DERP informing them that we've
                // sent so our firewall ports are probably open and now
                // would be a good time for them to connect.
                let id = self.id;
                let sender = self.conn_sender.clone();
                if let Err(err) = sender
                    .send_async(ActorMessage::EnqueueCallMeMaybe {
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

    pub fn update_from_node(&mut self, n: &cfg::Node) {
        // Try first addr as potential best
        if let Some(addr) = n.endpoints.first() {
            if addr.ip() != DERP_MAGIC_IP {
                self.maybe_add_best_addr(*addr);
            }
        }

        self.expired = n.expired;
        self.derp_addr = n.derp;

        for (_, st) in &mut self.endpoint_state {
            st.index = Index::Deleted; // assume deleted until updated in next loop
        }
        for (i, ep) in n.endpoints.iter().take(u16::MAX as usize).enumerate() {
            let index = Index::Some(i);
            if let Some(st) = self.endpoint_state.get_mut(ep) {
                st.index = index
            } else {
                self.endpoint_state.insert(
                    *ep,
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
                if self.best_addr.as_ref().map(|a| &a.addr) == Some(ep) {
                    self.best_addr = None;
                }
                return false;
            }
            true
        });
    }

    /// Clears all the endpoint's p2p state, reverting it to a DERP-only endpoint.
    fn reset(&mut self) {
        self.last_full_ping = None;
        self.best_addr = None;
        self.best_addr_at = None;
        self.trust_best_addr_until = None;
        for (_, es) in &mut self.endpoint_state {
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
        ep: SocketAddr,
        for_rx_ping_tx_id: stun::TransactionId,
    ) -> bool {
        if let Some(st) = self.endpoint_state.get_mut(&ep) {
            let duplicate_ping = for_rx_ping_tx_id == st.last_got_ping_tx_id;
            if !duplicate_ping {
                st.last_got_ping_tx_id = for_rx_ping_tx_id;
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
                last_got_ping_tx_id: for_rx_ping_tx_id,
                ..Default::default()
            },
        );

        // If for some reason this gets very large, do some cleanup.
        let size = self.endpoint_state.len();
        if size > 100 {
            self.endpoint_state.retain(|ep, st| {
                if st.should_delete() {
                    // Inlined delete_endpoint
                    if self.best_addr.as_ref().map(|a| &a.addr) == Some(ep) {
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
        self.trust_best_addr_until = None;
    }

    /// Note that we have a potential best addr.
    pub(super) fn maybe_add_best_addr(&mut self, addr: SocketAddr) {
        if self.best_addr.is_none() {
            self.best_addr = Some(AddrLatency {
                addr,
                latency: Duration::from_secs(1), // assume bad latency for now
            });

            // Update paths
            self.trust_best_addr_until = None;
        }
    }

    /// Handles a Pong message (a reply to an earlier ping).
    ///
    /// It reports whether m.tx_id corresponds to a ping that this endpoint sent.
    pub(super) async fn handle_pong_conn(
        &mut self,
        conn_disco_public: &key::node::PublicKey,
        m: &disco::Pong,
        di: &mut DiscoInfo,
        src: SocketAddr,
    ) -> (bool, Option<(SocketAddr, key::node::PublicKey)>) {
        let is_derp = src.ip() == DERP_MAGIC_IP;

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
                return (false, None);
            }
            Some(sp) => {
                let known_tx_id = true;
                let mut peer_map_insert = None;

                let now = Instant::now();
                let latency = now - sp.at;

                if !is_derp {
                    let key = self
                        .public_key
                        .clone()
                        .unwrap_or_else(|| di.node_key.clone());
                    match self.endpoint_state.get_mut(&sp.to) {
                        None => {
                            info!("disco: ignoring pong: {}", sp.to);
                            // This is no longer an endpoint we care about.
                            return (known_tx_id, peer_map_insert);
                        }
                        Some(st) => {
                            peer_map_insert = Some((src, key.clone()));
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
                    let region_id = usize::from(ep.port());
                    // FIXME: this creates a deadlock as it needs to interact with the run loop in the conn::Actor
                    let region_code = self
                        .get_derp_region(region_id)
                        .await
                        .map(|r| r.region_code.clone());

                    for PendingCliPing { mut res, cb } in self.pending_cli_pings.drain(..) {
                        res.latency_seconds = Some(latency.as_secs_f64());
                        if ep.ip() != DERP_MAGIC_IP {
                            res.endpoint = Some(ep);
                        } else {
                            res.derp_region_id = Some(region_id);
                            res.derp_region_code = region_code.clone();
                        }
                        tokio::task::spawn(async move {
                            cb(res).await;
                        });
                    }
                }

                // Promote this pong response to our current best address if it's lower latency.
                // TODO(bradfitz): decide how latency vs. preference order affects decision
                if !is_derp {
                    let this_pong = AddrLatency {
                        addr: sp.to,
                        latency,
                    };
                    let is_better = self.best_addr.is_none()
                        || this_pong.is_better_than(self.best_addr.as_ref().unwrap());

                    if is_better {
                        info!("disco: node {:?} now using {:?}", self.public_key, sp.to);
                        self.best_addr.replace(this_pong.clone());
                    }
                    let best_addr = self.best_addr.as_mut().expect("just set");
                    if best_addr.addr == this_pong.addr {
                        best_addr.latency = latency;
                        self.best_addr_at.replace(now);
                        self.trust_best_addr_until
                            .replace(now + TRUST_UDP_ADDR_DURATION);
                    }
                }

                (known_tx_id, peer_map_insert)
            }
        }
    }

    async fn get_derp_region(&self, region: usize) -> Option<DerpRegion> {
        let (s, r) = tokio::sync::oneshot::channel();
        self.conn_sender
            .send_async(ActorMessage::GetDerpRegion(region, s))
            .await
            .ok()?;
        r.await.ok()?
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
            if let Some(es) = self.endpoint_state.get_mut(ep) {
                es.call_me_maybe_time.replace(now);
            } else {
                self.endpoint_state.insert(
                    *ep,
                    EndpointState {
                        call_me_maybe_time: Some(now),
                        ..Default::default()
                    },
                );
                new_eps.push(*ep);
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
    /// stopped state (via `set_private_key(None)`).
    pub fn stop_and_reset(&mut self) {
        self.reset();
        self.pending_cli_pings.clear();
    }

    fn last_ping(&self, addr: &SocketAddr) -> Option<Instant> {
        self.endpoint_state.get(addr).and_then(|ep| ep.last_ping)
    }

    /// Send a heartbeat to the peer to keep the connection alive, or trigger a full ping
    /// if necessary.
    pub(super) async fn stayin_alive(&mut self) {
        let now = Instant::now();
        let udp_addr = self.best_addr.as_ref().map(|a| a.addr);

        // Send heartbeat ping to keep the current addr going as long as we need it.
        if let Some(udp_addr) = udp_addr {
            let elapsed = self.last_ping(&udp_addr).map(|l| now - l);
            // Send a ping if the last ping is either older than 2 seconds or we don't have one.
            let needs_ping = elapsed.map(|e| e >= Duration::from_secs(2)).unwrap_or(true);

            if needs_ping {
                debug!(
                    "stayin alive ping for {}: {:?} {:?}",
                    udp_addr, elapsed, now
                );
                self.start_ping(udp_addr, now, DiscoPingPurpose::StayinAlive)
                    .await;
                return;
            }
        }

        // If we do not have an optimal addr, send pings to all known places.
        if self.want_full_ping(&now) {
            debug!("send pings all");
            self.send_pings(now, true).await;
        }
    }

    pub(crate) async fn get_send_addrs(
        &mut self,
    ) -> io::Result<(Option<SocketAddr>, Option<SocketAddr>)> {
        if self.expired {
            return Err(io::Error::new(io::ErrorKind::Other, "endpoint expired"));
        }

        let now = Instant::now();
        let (udp_addr, derp_addr) = self.addr_for_send(&now);

        debug!(
            "sending UDP: {}, DERP: {}",
            udp_addr.is_some(),
            derp_addr.is_some()
        );

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
    pub latency: Duration,
}

/// An index of peerInfos by node (WireGuard) key, disco key, and discovered ip:port endpoints.
#[derive(Default, Debug)]
pub(super) struct PeerMap {
    by_node_key: HashMap<key::node::PublicKey, usize>,
    by_ip_port: HashMap<SocketAddr, usize>,
    by_id: HashMap<usize, Endpoint>,
    next_id: usize,
}

impl PeerMap {
    /// Number of nodes currently listed.
    pub(super) fn node_count(&self) -> usize {
        self.by_id.len()
    }

    pub(super) fn by_id(&self, id: &usize) -> Option<&Endpoint> {
        self.by_id.get(&id)
    }

    pub(super) fn by_id_mut(&mut self, id: &usize) -> Option<&mut Endpoint> {
        self.by_id.get_mut(&id)
    }

    /// Returns the endpoint for nk, or None if nk is not known to us.
    pub(super) fn endpoint_for_node_key(&self, nk: &key::node::PublicKey) -> Option<&Endpoint> {
        self.by_node_key.get(nk).and_then(|id| self.by_id(id))
    }

    pub(super) fn endpoint_for_node_key_mut(
        &mut self,
        nk: &key::node::PublicKey,
    ) -> Option<&mut Endpoint> {
        self.by_node_key
            .get(nk)
            .and_then(|id| self.by_id.get_mut(id))
    }

    /// Returns the endpoint for the peer we believe to be at ipp, or nil if we don't know of any such peer.
    pub(super) fn endpoint_for_ip_port(&self, ipp: &SocketAddr) -> Option<&Endpoint> {
        self.by_ip_port.get(ipp).and_then(|id| self.by_id(id))
    }

    pub fn endpoint_for_ip_port_mut(&mut self, ipp: &SocketAddr) -> Option<&mut Endpoint> {
        self.by_ip_port
            .get(ipp)
            .and_then(|id| self.by_id.get_mut(id))
    }

    pub(super) fn endpoints(&self) -> impl Iterator<Item = (&usize, &Endpoint)> {
        self.by_id.iter()
    }

    pub(super) fn endpoints_mut(&mut self) -> impl Iterator<Item = (&usize, &mut Endpoint)> {
        self.by_id.iter_mut()
    }

    pub(super) fn store_node_key_mapping(&mut self, id: usize, public_key: key::node::PublicKey) {
        if !self.by_node_key.contains_key(&public_key) {
            self.by_node_key.insert(public_key, id);
            // allow lookups by the fake addr
            let fake_wg_addr = self.by_id(&id).unwrap().fake_wg_addr;
            self.by_ip_port.insert(fake_wg_addr, id);
        }
    }

    /// Stores endpoint, with a public key.
    pub(super) fn upsert_endpoint(&mut self, options: Options) -> Option<usize> {
        if let Some(public_key) = options.public_key.clone() {
            if !self.by_node_key.contains_key(&public_key) {
                let id = self.insert_endpoint(options);
                self.by_node_key.insert(public_key, id);
                // allow lookups by the fake addr
                let fake_wg_addr = self.by_id(&id).unwrap().fake_wg_addr;
                self.by_ip_port.insert(fake_wg_addr, id);
                return Some(id);
            }
        }
        None
    }

    pub(super) fn insert_endpoint(&mut self, options: Options) -> usize {
        let id = self.next_id;
        let ep = Endpoint::new(id, options);
        self.next_id = self.next_id.wrapping_add(1);
        self.by_id.insert(id, ep);
        id
    }

    /// Makes future peer lookups by ipp return the same endpoint as a lookup by nk.
    ///
    /// This should only be called with a fully verified mapping of ipp to
    /// nk, because calling this function defines the endpoint we hand to
    /// WireGuard for packets received from ipp.
    pub(super) fn set_node_key_for_ip_port(&mut self, ipp: &SocketAddr, nk: &key::node::PublicKey) {
        if let Some(id) = self.by_ip_port.get(ipp) {
            if !self.by_node_key.contains_key(nk) {
                self.by_node_key.insert(nk.clone(), *id);
            }
            self.by_ip_port.remove(ipp);
        }
        if let Some(id) = self.by_node_key.get(nk) {
            self.by_ip_port.insert(*ipp, *id);
        }
    }

    pub(super) fn set_endpoint_for_ip_port(&mut self, ipp: &SocketAddr, id: usize) {
        self.by_ip_port.insert(*ipp, id);
    }

    /// Deletes the endpoint.
    pub(super) fn delete_endpoint(&mut self, id: usize) {
        if let Some(mut ep) = self.by_id.remove(&id) {
            ep.stop_and_reset();

            if let Some(public_key) = ep.public_key() {
                self.by_node_key.remove(&public_key);
            }
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
    /// disco handling due to https://github.com/tailscale/tailscale/issues/7078.
    last_got_ping_tx_id: stun::TransactionId,

    /// If non-zero, is the time this endpoint was advertised last via a call-me-maybe disco message.
    call_me_maybe_time: Option<Instant>,

    /// Ring buffer up to PongHistoryCount entries
    recent_pongs: Vec<PongReply>,
    /// Index into recentPongs of most recent; older before, wrapped
    recent_pong: usize,

    /// Index in nodecfg.Node.Endpoints; meaningless if last_got_ping non-zero.
    index: Index,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum Index {
    Deleted,
    Some(usize),
}

impl Default for Index {
    fn default() -> Self {
        Index::Deleted
    }
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PongReply {
    latency: Duration,
    /// When we received the pong.
    pong_at: Instant,
    // The pong's src (usually same as endpoint map key).
    from: SocketAddr,
    // What they reported they heard.
    pong_src: SocketAddr,
}

#[derive(Debug)]
pub struct SentPing {
    pub to: SocketAddr,
    pub at: Instant,
    pub purpose: DiscoPingPurpose,
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

static ADDR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generates a globally unique fake UDPAddr.
pub(super) fn init_fake_udp_addr() -> SocketAddr {
    let mut addr = [0u8; 16];
    addr[0] = 0xfd;
    addr[1] = 0x00;

    let counter = ADDR_COUNTER.fetch_add(1, Ordering::Relaxed);
    addr[2..10].copy_from_slice(&counter.to_le_bytes());

    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), 12345)
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
            if self.latency / 10 * 9 < other.latency {
                return true;
            }
        } else if self.addr.is_ipv4() && other.addr.is_ipv6() {
            if other.is_better_than(self) {
                return false;
            }
        }
        self.latency < other.latency
    }
}
