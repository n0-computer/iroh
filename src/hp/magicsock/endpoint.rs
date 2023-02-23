use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::Hash,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use futures::{future::BoxFuture, Future};
use tokio::{
    sync::{Mutex, RwLock},
    time::Instant,
};
use tracing::{info, warn};

use crate::hp::{
    cfg::{self, DERP_MAGIC_IP},
    disco, key, stun,
};

use super::{
    conn::DiscoInfo, Conn, DiscoPingPurpose, PeerInfo, PongReply, SentPing, Timer,
    DISCO_PING_INTERVAL, GOOD_ENOUGH_LATENCY, HEARTBEAT_INTERVAL, PING_TIMEOUT_DURATION,
    PONG_HISTORY_COUNT, SESSION_ACTIVE_TIMEOUT, TRUST_UDP_ADDR_DURATION, UPGRADE_INTERVAL,
};

/// A wireguard/conn.Endpoint that picks the best available path to communicate with a peer,
/// based on network conditions and what the peer supports.
#[derive(Clone)]
pub struct Endpoint(Arc<InnerEndpoint>);

impl Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MagicsockEndpoint({}, {})",
            crate::util::encode(&self.public_key),
            crate::util::encode(self.disco_key())
        )
    }
}

impl Hash for Endpoint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_string().hash(state);
    }
}

impl PartialEq for Endpoint {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.disco_key() == other.disco_key()
    }
}

impl Eq for Endpoint {}

impl Deref for Endpoint {
    type Target = InnerEndpoint;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct InnerEndpoint {
    // Atomically accessed; declared first for alignment reasons
    pub last_recv: RwLock<Option<Instant>>,
    pub num_stop_and_reset_atomic: AtomicU64,
    // These fields are initialized once and never modified.
    pub c: Conn,
    /// Peer public key (for WireGuard + DERP)
    pub public_key: key::node::PublicKey,
    /// The UDP address we tell wireguard-go we're using
    pub fake_wg_addr: SocketAddr,
    /// The node's first tailscale address; used for logging & wireguard rate-limiting (Issue 6686)
    pub node_addr: Option<IpAddr>,

    // Lock ordering: Conn.state, then Endpoint.state
    pub state: Mutex<InnerMutEndpoint>,
}

pub struct InnerMutEndpoint {
    /// For discovery messages.
    pub disco_key: key::disco::PublicKey,

    /// None when idle
    pub heart_beat_timer: Option<Timer>,
    /// Last time there was outgoing packets sent to this peer (from wireguard-go)
    pub last_send: Option<Instant>,
    /// Last time we pinged all endpoints
    pub last_full_ping: Option<Instant>,
    /// fallback/bootstrap path, if non-zero (non-zero for well-behaved clients)
    pub derp_addr: Option<SocketAddr>,

    /// Best non-DERP path.
    pub best_addr: Option<AddrLatency>,
    /// Time best address re-confirmed
    pub best_addr_at: Option<Instant>,
    /// Time when best_addr expires
    pub trust_best_addr_until: Option<Instant>,
    pub endpoint_state: HashMap<SocketAddr, EndpointState>,
    pub is_call_me_maybe_ep: HashMap<SocketAddr, bool>,

    /// Any outstanding "tailscale ping" commands running
    pub pending_cli_pings: Vec<PendingCliPing>,

    /// Whether the node has expired.
    pub expired: bool,

    pub sent_ping: HashMap<stun::TransactionId, SentPing>,
}

pub struct PendingCliPing {
    pub res: cfg::PingResult,
    pub cb: Box<dyn Fn(cfg::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static>,
}

impl Endpoint {
    pub fn new(conn: Conn, n: &cfg::Node) -> Self {
        let fake_wg_addr = init_fake_udp_addr();
        Endpoint(Arc::new(InnerEndpoint {
            c: conn,
            public_key: n.key.clone(),
            node_addr: n.addresses.first().copied(),
            fake_wg_addr,
            last_recv: Default::default(),
            num_stop_and_reset_atomic: Default::default(),
            state: Mutex::new(InnerMutEndpoint {
                disco_key: n.disco_key.clone(),
                heart_beat_timer: None,
                last_send: None,
                last_full_ping: None,
                derp_addr: None,
                best_addr: None,
                best_addr_at: None,
                trust_best_addr_until: None,
                sent_ping: HashMap::new(),
                endpoint_state: HashMap::new(),
                is_call_me_maybe_ep: HashMap::new(),
                pending_cli_pings: Vec::new(),
                expired: false,
            }),
        }))
    }

    pub fn disco_key(&self) -> key::disco::PublicKey {
        self.state.blocking_lock().disco_key.clone()
    }

    /// Records receive activity on this endpoint.
    pub fn note_recv_activity(&self) {
        if let Some(ref on_recv) = self.c.on_note_recv_activity {
            let now = Instant::now();
            if let Some(last_recv) = &*self.last_recv.blocking_read() {
                if last_recv.elapsed() > Duration::from_secs(10) {
                    drop(last_recv);
                    self.last_recv.blocking_write().replace(now);
                    on_recv(&self.public_key);
                }
            }
        }
    }

    /// Returns the address(es) that should be used for sending the next packet.
    /// Zero, one, or both of UDP address and DERP addr may be non-zero.
    fn addr_for_send_locked(
        &self,
        state: &InnerMutEndpoint,
        now: &Instant,
    ) -> (Option<SocketAddr>, Option<SocketAddr>) {
        let udp_addr = state.best_addr.as_ref().map(|a| a.addr);
        let derp_addr = if udp_addr.is_none()
            || state.trust_best_addr_until.is_some()
                && state.trust_best_addr_until.as_ref().unwrap() > now
        {
            // We had a best_addr but it expired so send both to it and DERP.
            state.derp_addr
        } else {
            None
        };

        (udp_addr, derp_addr)
    }

    /// Called every heartbeat_interval to keep the best UDP path alive, or kick off discovery of other paths.
    fn heartbeat(&self) -> Pin<Box<dyn Future<Output = ()> + Send + Sync + '_>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            state.heart_beat_timer = None;

            if state.last_send.is_none() {
                // Shouldn't happen.
                return;
            }
            let last_send = state.last_send.as_ref().unwrap();

            if last_send.elapsed() > SESSION_ACTIVE_TIMEOUT {
                // Session's idle. Stop heartbeating.
                info!(
                    "disco: ending heartbeats for idle session to {:?} ({:?})",
                    self.public_key, state.disco_key
                );
                return;
            }

            let now = Instant::now();
            let (udp_addr, _) = self.addr_for_send_locked(&state, &now);
            if let Some(udp_addr) = udp_addr {
                // We have a preferred path. Ping that every 2 seconds.
                self.start_ping_locked(&mut state, udp_addr, now, DiscoPingPurpose::Heartbeat);
            }

            if self.want_full_ping_locked(&state, &now) {
                self.send_pings_locked(&mut state, now, true);
            }

            let this = self.clone();
            state
                .heart_beat_timer
                .replace(Timer::after(HEARTBEAT_INTERVAL, async move {
                    this.heartbeat().await;
                }));
        })
    }

    /// Reports whether we should ping to all our peers looking for a better path.
    fn want_full_ping_locked(&self, state: &InnerMutEndpoint, now: &Instant) -> bool {
        if state.best_addr.is_none() || state.last_full_ping.is_none() {
            return true;
        }
        if state.trust_best_addr_until.is_some()
            && state.trust_best_addr_until.as_ref().unwrap() > now
        {
            return true;
        }
        if state.best_addr.as_ref().unwrap().latency <= GOOD_ENOUGH_LATENCY {
            return false;
        }

        if state.last_full_ping.as_ref().unwrap().duration_since(*now) >= UPGRADE_INTERVAL {
            return true;
        }
        false
    }

    fn note_active_locked(&self, state: &mut InnerMutEndpoint) {
        state.last_send.replace(Instant::now());
        if state.heart_beat_timer.is_none() {
            let this = self.clone();
            state
                .heart_beat_timer
                .replace(Timer::after(HEARTBEAT_INTERVAL, async move {
                    this.heartbeat().await;
                }));
        }
    }

    /// Starts a ping for the "ping" command.
    /// `res` is value to call cb with, already partially filled.
    pub async fn cli_ping<F>(&self, mut res: cfg::PingResult, cb: F)
    where
        F: Fn(cfg::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        let mut state = self.state.lock().await;
        if state.expired {
            res.err = Some("endpoint expired".to_string());
            cb(res);
            return;
        }

        state.pending_cli_pings.push(PendingCliPing {
            res,
            cb: Box::new(cb),
        });

        let now = Instant::now();
        let (udp_addr, derp_addr) = self.addr_for_send_locked(&state, &now);
        if let Some(derp_addr) = derp_addr {
            self.start_ping_locked(&mut state, derp_addr, now, DiscoPingPurpose::Cli);
        }
        if let Some(udp_addr) = udp_addr {
            if state.trust_best_addr_until.is_some()
                && now < *state.trust_best_addr_until.as_ref().unwrap()
            {
                // Already have an active session, so just ping the address we're using.
                // Otherwise "tailscale ping" results to a node on the local network
                // can look like they're bouncing between, say 10.0.0.0/9 and the peer's
                // IPv6 address, both 1ms away, and it's random who replies first.
                self.start_ping_locked(&mut state, udp_addr, now, DiscoPingPurpose::Cli);
            } else {
                let eps: Vec<_> = state.endpoint_state.keys().cloned().collect();
                for ep in eps {
                    self.start_ping_locked(&mut state, ep, now, DiscoPingPurpose::Cli);
                }
            }
        }
        self.note_active_locked(&mut state);
    }

    async fn ping_timeout(&self, txid: stun::TransactionId) {
        let mut state = self.state.lock().await;

        if let Some(sp) = state.sent_ping.remove(&txid) {
            if state.best_addr.is_none()
                || (state.trust_best_addr_until.is_some()
                    && Instant::now() > *state.trust_best_addr_until.as_ref().unwrap())
            {
                info!(
                    "[v1] disco: timeout waiting for pong {:?} from {:?} ({:?}, {:?})",
                    txid, sp.to, self.public_key, state.disco_key
                );
            }

            sp.timer.stop().await;
        }
    }

    /// Called by a timer when a ping either fails to send or has taken too long to get a pong reply.
    async fn forget_ping(&self, tx_id: stun::TransactionId) {
        let mut state = self.state.lock().await;

        if let Some(sp) = state.sent_ping.remove(&tx_id) {
            sp.timer.stop().await;
        }
    }

    /// Sends a ping with the provided txid to ep using self's disco_key.
    ///
    /// The caller (start_ping_locked) should've already recorded the ping in
    /// sent_ping and set up the timer.
    ///
    /// The caller should use de.disco_key as the disco_key argument.
    /// It is passed in so that send_disco_ping doesn't need to lock de.mu.
    async fn send_disco_ping(
        &self,
        ep: SocketAddr,
        disco_key: &key::disco::PublicKey,
        tx_id: stun::TransactionId,
    ) {
        let sent = if let Some(node_key) = self.c.public_key_atomic.read().await.clone() {
            self.c
                .send_disco_message(
                    ep,
                    Some(&self.public_key),
                    disco_key,
                    disco::Message::Ping(disco::Ping { tx_id, node_key }),
                )
                .await
                .unwrap_or_default()
        } else {
            false
        };
        if !sent {
            self.forget_ping(tx_id).await;
        }
    }

    fn start_ping_locked(
        &self,
        state: &mut InnerMutEndpoint,
        ep: SocketAddr,
        now: Instant,
        purpose: DiscoPingPurpose,
    ) {
        if purpose != DiscoPingPurpose::Cli {
            if let Some(st) = state.endpoint_state.get_mut(&ep) {
                st.last_ping.replace(now);
            } else {
                // Shouldn't happen. But don't ping an endpoint that's  not active for us.
                warn!(
                    "disco: [unexpected] attempt to ping no longer live endpoint {:?}",
                    ep
                );
                return;
            }
        }

        let txid = stun::TransactionId::default();
        let this = self.clone();
        state.sent_ping.insert(
            txid,
            SentPing {
                to: ep,
                at: now,
                timer: Timer::after(PING_TIMEOUT_DURATION, async move {
                    this.ping_timeout(txid).await;
                }),
                purpose,
            },
        );

        let this = self.clone();
        tokio::task::spawn(async move {
            let disco_key = this.disco_key();
            this.send_disco_ping(ep, &disco_key, txid).await;
        });
    }

    fn send_pings_locked(
        &self,
        state: &mut InnerMutEndpoint,
        now: Instant,
        send_call_me_maybe: bool,
    ) {
        state.last_full_ping.replace(now);

        // first cleanout out all old endpoints
        state.endpoint_state.retain(|ep, st| {
            if st.should_delete() {
                // Inlined delete_endpoint
                if state.best_addr.as_ref().map(|a| &a.addr) == Some(ep) {
                    state.best_addr = None;
                }
                return false;
            }
            true
        });

        let mut pings = Vec::new();
        for (ep, st) in &state.endpoint_state {
            if st.last_ping.is_some()
                && st.last_ping.as_ref().unwrap().duration_since(now) < DISCO_PING_INTERVAL
            {
                continue;
            }
            pings.push(ep.clone());
        }

        let sent_any = !pings.is_empty();
        let mut first_ping = true;
        for ep in pings {
            if first_ping && send_call_me_maybe {
                info!(
                    "disco: send, starting discovery for {:?} ({:?})",
                    self.public_key, state.disco_key,
                );
            }
            if first_ping {
                first_ping = false;
            }

            self.start_ping_locked(state, ep, now, DiscoPingPurpose::Discovery);
        }

        let derp_addr = state.derp_addr.clone();
        if sent_any && send_call_me_maybe {
            if let Some(derp_addr) = derp_addr {
                // Have our magicsock.Conn figure out its STUN endpoint (if
                // it doesn't know already) and then send a CallMeMaybe
                // message to our peer via DERP informing them that we've
                // sent so our firewall ports are probably open and now
                // would be a good time for them to connect.
                let this = self.clone();
                tokio::task::spawn(async move {
                    this.c.enqueue_call_me_maybe(derp_addr, this.clone()).await;
                });
            }
        }
    }

    pub async fn update_from_node(&self, n: &cfg::Node) {
        let mut state = &mut *self.state.lock().await;
        state.expired = n.expired;

        if state.disco_key != n.disco_key {
            info!(
                "disco: node {:?} changed from discokey {:?} to {:?}",
                self.public_key, state.disco_key, n.disco_key
            );
            state.disco_key = n.disco_key.clone();
            self.reset_locked(&mut state).await;
        }
        state.derp_addr = n.derp;

        for (_, st) in &mut state.endpoint_state {
            st.index = Index::Deleted; // assume deleted until updated in next loop
        }
        for (i, ep) in n.endpoints.iter().enumerate() {
            if i > u16::MAX as usize {
                // Seems unlikely.
                continue;
            }
            let index = Index::Some(i);
            if let Some(st) = state.endpoint_state.get_mut(ep) {
                st.index = index
            } else {
                state.endpoint_state.insert(
                    *ep,
                    EndpointState {
                        index,
                        ..Default::default()
                    },
                );
            }
        }
        // Now delete anything unless it's still in the network map or was a recently discovered endpoint.

        state.endpoint_state.retain(|ep, st| {
            if st.should_delete() {
                // Inlined delete_endpoint
                if state.best_addr.as_ref().map(|a| &a.addr) == Some(ep) {
                    state.best_addr = None;
                }
                return false;
            }
            true
        });
    }

    // Clears all the endpoint's p2p state, reverting it to a
    // DERP-only endpoint. It does not stop the endpoint's heartbeat
    // timer, if one is running.
    async fn reset_locked(&self, state: &mut InnerMutEndpoint) {
        state.last_send = None;
        state.last_full_ping = None;
        state.best_addr = None;
        state.best_addr_at = None;
        state.trust_best_addr_until = None;
        for (_, es) in &mut state.endpoint_state {
            es.last_ping = None;
        }
        for (_, sp) in state.sent_ping.drain() {
            sp.timer.stop().await;
        }
    }

    /// Adds ep as an endpoint to which we should send future pings. If there is an
    /// existing endpointState for ep, and for_rx_ping_tx_id matches the last received
    /// ping TransactionId, this function reports `true`, otherwise `false`.
    ///
    /// This is called once we've already verified that we got a valid discovery message from `self` via ep.
    pub fn add_candidate_endpoint(
        &self,
        ep: SocketAddr,
        for_rx_ping_tx_id: stun::TransactionId,
    ) -> bool {
        // (duplicatePing bool) {
        let state = &mut *self.state.blocking_lock();

        if let Some(st) = state.endpoint_state.get_mut(&ep) {
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
            "disco: adding {:?} as candidate endpoint for {:?} ({:?})",
            ep, state.disco_key, self.public_key
        );
        state.endpoint_state.insert(
            ep,
            EndpointState {
                last_got_ping: Some(Instant::now()),
                last_got_ping_tx_id: for_rx_ping_tx_id,
                ..Default::default()
            },
        );

        // If for some reason this gets very large, do some cleanup.
        let size = state.endpoint_state.len();
        if size > 100 {
            state.endpoint_state.retain(|ep, st| {
                if st.should_delete() {
                    // Inlined delete_endpoint
                    if state.best_addr.as_ref().map(|a| &a.addr) == Some(ep) {
                        state.best_addr = None;
                    }
                    return false;
                }
                true
            });
            let size2 = state.endpoint_state.len();
            info!(
                "disco: addCandidateEndpoint pruned candidate set from {} to {} entries",
                size, size2
            )
        }

        false
    }

    /// Called when connectivity changes enough
    /// that we should question our earlier assumptions about which paths work.
    pub(super) async fn note_connectivity_change(&self) {
        let mut state = self.state.lock().await;
        state.trust_best_addr_until = None;
    }

    /// Handles a Pong message (a reply to an earlier ping).
    /// It should be called with the Conn.mu held.
    ///
    /// It reports whether m.TxID corresponds to a ping that this endpoint sent.
    pub(super) fn handle_pong_conn_locked(
        &self,
        peer_map: &mut PeerMap,
        conn_disco_public: &key::disco::PublicKey,
        m: &disco::Pong,
        di: &mut DiscoInfo,
        src: SocketAddr,
    ) -> bool {
        // -> (knownTxID bool) {
        let mut state = self.state.blocking_lock();
        let is_derp = src.ip() == DERP_MAGIC_IP;

        match state.sent_ping.remove(&m.tx_id) {
            None => {
                // This is not a pong for a ping we sent.
                return false;
            }
            Some(sp) => {
                let known_tx_id = true;
                tokio::task::spawn(async move {
                    sp.timer.stop().await;
                });
                di.set_node_key(self.public_key.clone());

                let now = Instant::now();
                let latency = sp.at.duration_since(now);

                if !is_derp {
                    match state.endpoint_state.get_mut(&sp.to) {
                        None => {
                            // This is no longer an endpoint we care about.
                            return known_tx_id;
                        }
                        Some(st) => {
                            peer_map.set_node_key_for_ip_port(&src, &self.public_key);
                            st.add_pong_reply(PongReply {
                                latency,
                                pong_at: now,
                                from: src,
                                pong_src: m.src,
                            });
                        }
                    }
                }

                if sp.purpose != DiscoPingPurpose::Heartbeat {
                    info!("disco: {:?}<-{:?} ({:?}, {:?})  got pong tx=%x latency={:?} pong.src={:?}{}{}",
                          conn_disco_public,
                          state.disco_key,
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
                }

                for PendingCliPing { mut res, cb } in state.pending_cli_pings.drain(..) {
                    self.c
                        .populate_cli_ping_response_locked(&mut res, latency, sp.to);
                    tokio::task::spawn(async move {
                        cb(res).await;
                    });
                }

                // Promote this pong response to our current best address if it's lower latency.
                // TODO(bradfitz): decide how latency vs. preference order affects decision
                if !is_derp {
                    let this_pong = AddrLatency {
                        addr: sp.to,
                        latency,
                    };
                    let is_better = state.best_addr.is_none()
                        || this_pong.is_better_than(state.best_addr.as_ref().unwrap());

                    if is_better {
                        info!(
                            "disco: node {:?} {:?} now using {:?}",
                            self.public_key, state.disco_key, sp.to
                        );
                        state.best_addr.replace(this_pong.clone());
                    }
                    let best_addr = state.best_addr.as_mut().expect("just set");
                    if best_addr.addr == this_pong.addr {
                        best_addr.latency = latency;
                        state.best_addr_at.replace(now);
                        state
                            .trust_best_addr_until
                            .replace(now + TRUST_UDP_ADDR_DURATION);
                    }
                }
                known_tx_id
            }
        }
    }

    /// Handles a CallMeMaybe discovery message via DERP. The contract for use of
    /// this message is that the peer has already sent to us via UDP, so their stateful firewall should be
    /// open. Now we can Ping back and make it through.
    pub async fn handle_call_me_maybe(&self, m: disco::CallMeMaybe) {
        let state = &mut *self.state.lock().await;

        let now = Instant::now();
        for el in state.is_call_me_maybe_ep.values_mut() {
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
            state.is_call_me_maybe_ep.insert(*ep, true);
            if let Some(es) = state.endpoint_state.get_mut(ep) {
                es.call_me_maybe_time.replace(now);
            } else {
                state.endpoint_state.insert(
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
            info!(
                "disco: call-me-maybe from {:?} {:?} added new endpoints: {:?}",
                self.public_key, state.disco_key, new_eps,
            );
        }

        // Delete any prior CallMeMaybe endpoints that weren't included in this message.
        state.is_call_me_maybe_ep.retain(|ep, want| {
            if !*want {
                if state.best_addr.as_ref().map(|a| &a.addr) == Some(ep) {
                    state.best_addr = None;
                }
                return false;
            }
            true
        });

        // Zero out all the last_ping times to force send_pings_locked to send new ones,
        // even if it's been less than 5 seconds ago.
        for st in state.endpoint_state.values_mut() {
            st.last_ping = None;
        }
        self.send_pings_locked(state, Instant::now(), false);
    }

    /// Stops timers associated with de and resets its state back to zero.
    /// It's called when a discovery endpoint is no longer present in the
    /// NetworkMap, or when magicsock is transitioning from running to
    /// stopped state (via `set_private_key(None)`).
    pub async fn stop_and_reset(&self) {
        self.num_stop_and_reset_atomic
            .fetch_add(1, Ordering::Relaxed);
        let mut state = self.state.lock().await;

        if !self.c.is_closing() {
            info!("doing cleanup for discovery key {:?}", state.disco_key);
        }

        state.reset().await;
        if let Some(timer) = state.heart_beat_timer.take() {
            timer.stop().await;
        }
        state.pending_cli_pings.clear();
    }

    pub fn num_stop_and_reset(&self) -> u64 {
        self.num_stop_and_reset_atomic.load(Ordering::Relaxed)
    }
}

impl InnerMutEndpoint {
    /// Clears all the endpoint's p2p state, reverting it to a
    // DERP-only endpoint. It does not stop the endpoint's heartbeat
    // timer, if one is running.
    async fn reset(&mut self) {
        self.last_send = None;
        self.last_full_ping = None;
        self.best_addr = None;
        self.best_addr_at = None;
        self.trust_best_addr_until = None;

        for es in self.endpoint_state.values_mut() {
            es.last_ping = None;
        }

        for (_txid, sp) in self.sent_ping.drain() {
            // Inlined remove_sent_ping due to borrowing issues

            // Stop the timer for the case where sendPing failed to write to UDP.
            // In the case of a timer already having fired, this is a no-op:
            sp.timer.stop().await;
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
/// Doesn't do any locking, all access must be done with Conn.mu held.
#[derive(Default)]
pub struct PeerMap {
    pub by_node_key: HashMap<key::node::PublicKey, PeerInfo>,
    pub by_ip_port: HashMap<SocketAddr, PeerInfo>,

    /// Contains the set of nodes that are using a DiscoKey. Usually those sets will be just one node.
    pub nodes_of_disco: HashMap<key::disco::PublicKey, HashSet<key::node::PublicKey>>,
}

impl PeerMap {
    /// Number of nodes currently listed.
    pub fn node_count(&self) -> usize {
        self.by_node_key.len()
    }

    /// Reports whether there exists any peers in the netmap with dk as their DiscoKey.
    pub fn any_endpoint_for_disco_key(&self, dk: &key::disco::PublicKey) -> bool {
        self.nodes_of_disco.contains_key(dk)
    }

    /// Returns the endpoint for nk, or nil if nk is not known to us.
    pub fn endpoint_for_node_key(&self, nk: &key::node::PublicKey) -> Option<&Endpoint> {
        self.by_node_key.get(nk).map(|i| &i.ep)
    }

    /// Returns the endpoint for the peer we believe to be at ipp, or nil if we don't know of any such peer.
    pub fn endpoint_for_ip_port(&self, ipp: &SocketAddr) -> Option<&Endpoint> {
        self.by_ip_port.get(ipp).map(|i| &i.ep)
    }

    pub fn endpoints(&self) -> impl Iterator<Item = &Endpoint> {
        self.by_node_key.values().map(|pi| &pi.ep)
    }

    /// Invokes f on every endpoint in m that has the provided DiscoKey until
    /// f returns false or there are no endpoints left to iterate.
    pub fn endpoints_with_disco_key(
        &self,
        dk: &key::disco::PublicKey,
    ) -> impl Iterator<Item = &Endpoint> {
        self.nodes_of_disco
            .get(dk)
            .into_iter()
            .flat_map(|n| n)
            .flat_map(|nk| self.by_node_key.get(nk).map(|pi| &pi.ep))
    }

    /// Stores endpoint in the peerInfo for ep.publicKey, and updates indexes. m must already have a
    /// tailcfg.Node for ep.publicKey.
    pub async fn upsert_endpoint(
        &mut self,
        ep: Endpoint,
        old_disco_key: Option<&key::disco::PublicKey>,
    ) {
        let disco_key = ep.0.state.lock().await.disco_key.clone();

        if let Some(old_disco_key) = old_disco_key {
            if old_disco_key != &disco_key {
                if let Some(v) = self.nodes_of_disco.get_mut(old_disco_key) {
                    v.remove(&ep.public_key);
                }
            }
            let set = self.nodes_of_disco.entry(disco_key).or_default();
            set.insert(ep.public_key.clone());
        }
        if !self.by_node_key.contains_key(&ep.public_key) {
            self.by_node_key
                .insert(ep.public_key.clone(), PeerInfo::new(ep));
        }
    }

    /// Makes future peer lookups by ipp return the same endpoint as a lookup by nk.
    ///
    /// This should only be called with a fully verified mapping of ipp to
    /// nk, because calling this function defines the endpoint we hand to
    /// WireGuard for packets received from ipp.
    pub fn set_node_key_for_ip_port(&mut self, ipp: &SocketAddr, nk: &key::node::PublicKey) {
        if let Some(pi) = self.by_ip_port.get_mut(ipp) {
            pi.ip_ports.remove(ipp);
            self.by_ip_port.remove(ipp);
        }
        if let Some(pi) = self.by_node_key.get_mut(nk) {
            pi.ip_ports.insert(ipp.clone());
            self.by_ip_port.insert(*ipp, pi.clone());
        }
    }

    /// Deletes the peerInfo associated with ep, and updates indexes.
    pub async fn delete_endpoint(&mut self, ep: &Endpoint) {
        ep.stop_and_reset().await;
        self.nodes_of_disco.remove(&ep.state.lock().await.disco_key);
        if let Some(pi) = self.by_node_key.remove(&ep.public_key) {
            for ip in &pi.ip_ports {
                self.by_ip_port.remove(ip);
            }
        }
    }
}

/// Some state and history for a specific endpoint of a endpoint.
/// (The subject is the endpoint.endpointState map key)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct EndpointState {
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

const ADDR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generates a globally unique fake UDPAddr.
fn init_fake_udp_addr() -> SocketAddr {
    let mut addr = [0u8; 16];
    addr[0] = 0xfd;
    addr[1] = 0x00;
    addr[2..10].copy_from_slice(&ADDR_COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());

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

// Copied from std lib, not stable yet
pub const fn is_unicast_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}
