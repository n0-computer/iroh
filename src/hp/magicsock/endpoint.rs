use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    ops::Deref,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Result;
use tokio::{
    sync::{Mutex, RwLock},
    time::Instant,
};
use tracing::info;

use crate::hp::{cfg, key, stun};

use super::{Conn, PeerInfo, PongReply, SentPing, Timer};

/// A wireguard/conn.Endpoint that picks the best available path to communicate with a peer,
/// based on network conditions and what the peer supports.
#[derive(Clone)]
pub struct Endpoint(Arc<InnerEndpoint>);

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
    /// A function that writes encrypted Wireguard payloads from
    /// WireGuard to a peer. It might write via UDP, DERP, both, or neither.
    ///
    /// What these funcs should NOT do is too much work. Minimize use of mutexes, map
    /// lookups, etc. The idea is that selecting the path to use is done infrequently
    /// and mostly async from sending packets. When conditions change (including the
    /// passing of time and loss of confidence in certain routes), then a new send
    /// func gets set on an sendpoint.
    ///
    /// A nil value means the current fast path has expired and needs to be recalculated.
    pub send_func:
        RwLock<Option<Box<dyn Fn(&[&[u8]]) -> std::io::Result<()> + Send + Sync + 'static>>>, // syncs.AtomicValue[endpointSendFunc] // nil or unset means unused

    // These fields are initialized once and never modified.
    pub c: Conn,
    /// Peer public key (for WireGuard + DERP)
    pub public_key: key::node::PublicKey,
    /// The UDP address we tell wireguard-go we're using
    pub fake_wg_addr: SocketAddr,
    /// The node's first tailscale address; used for logging & wireguard rate-limiting (Issue 6686)
    pub node_addr: IpAddr,

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
    pub sent_ping: HashMap<stun::TransactionId, SentPing>,
    pub endpoint_state: HashMap<SocketAddr, EndpointState>,
    pub is_call_me_maybe_ep: HashSet<SocketAddr>,

    /// Any outstanding "tailscale ping" commands running
    pub pending_cli_pings: Vec<PendingCliPing>,

    /// Whether the node has expired.
    pub expired: bool,
}

pub struct PendingCliPing {
    pub res: cfg::PingResult,
    pub cb: Box<dyn Fn(&cfg::PingResult) + Send + Sync + 'static>,
}

impl Endpoint {
    // // initFakeUDPAddr populates fakeWGAddr with a globally unique fake UDPAddr.
    // // The current implementation just uses the pointer value of de jammed into an IPv6
    // // address, but it could also be, say, a counter.
    // func (de *endpoint) initFakeUDPAddr() {
    // 	var addr [16]byte
    // 	addr[0] = 0xfd
    // 	addr[1] = 0x00
    // 	binary.BigEndian.PutUint64(addr[2:], uint64(reflect.ValueOf(de).Pointer()))
    // 	de.fakeWGAddr = netip.AddrPortFrom(netip.AddrFrom16(addr).Unmap(), 12345)
    // }

    // // noteRecvActivity records receive activity on de, and invokes
    // // Conn.noteRecvActivity no more than once every 10s.
    // func (de *endpoint) noteRecvActivity() {
    // 	if de.c.noteRecvActivity == nil {
    // 		return
    // 	}
    // 	now := mono.Now()
    // 	elapsed := now.Sub(de.lastRecv.LoadAtomic())
    // 	if elapsed > 10*time.Second {
    // 		de.lastRecv.StoreAtomic(now)
    // 		de.c.noteRecvActivity(de.publicKey)
    // 	}
    // }

    // // String exists purely so wireguard-go internals can log.Printf("%v")
    // // its internal conn.Endpoints and we don't end up with data races
    // // from fmt (via log) reading mutex fields and such.
    // func (de *endpoint) String() string {
    // 	return fmt.Sprintf("magicsock.endpoint{%v, %v}", de.publicKey.ShortString(), de.discoShort)
    // }

    // func (de *endpoint) ClearSrc()           {}
    // func (de *endpoint) SrcToString() string { panic("unused") } // unused by wireguard-go
    // func (de *endpoint) SrcIP() netip.Addr   { panic("unused") } // unused by wireguard-go
    // func (de *endpoint) DstToString() string { return de.publicKeyHex }
    // func (de *endpoint) DstIP() netip.Addr   { return de.nodeAddr } // see tailscale/tailscale#6686
    // func (de *endpoint) DstToBytes() []byte  { return packIPPort(de.fakeWGAddr) }

    // // addrForSendLocked returns the address(es) that should be used for
    // // sending the next packet. Zero, one, or both of UDP address and DERP
    // // addr may be non-zero.
    // //
    // // de.mu must be held.
    // func (de *endpoint) addrForSendLocked(now mono.Time) (udpAddr, derpAddr netip.AddrPort) {
    // 	udpAddr = de.bestAddr.AddrPort
    // 	if !udpAddr.IsValid() || now.After(de.trustBestAddrUntil) {
    // 		// We had a bestAddr but it expired so send both to it
    // 		// and DERP.
    // 		derpAddr = de.derpAddr
    // 	}
    // 	return
    // }

    // // heartbeat is called every heartbeatInterval to keep the best UDP path alive,
    // // or kick off discovery of other paths.
    // func (de *endpoint) heartbeat() {
    // 	de.mu.Lock()
    // 	defer de.mu.Unlock()

    // 	de.heartBeatTimer = nil

    // 	if de.heartbeatDisabled {
    // 		// If control override to disable heartBeatTimer set, return early.
    // 		return
    // 	}

    // 	if de.lastSend.IsZero() {
    // 		// Shouldn't happen.
    // 		return
    // 	}

    // 	if mono.Since(de.lastSend) > sessionActiveTimeout {
    // 		// Session's idle. Stop heartbeating.
    // 		de.c.dlogf("[v1] magicsock: disco: ending heartbeats for idle session to %v (%v)", de.publicKey.ShortString(), de.discoShort)
    // 		return
    // 	}

    // 	now := mono.Now()
    // 	udpAddr, _ := de.addrForSendLocked(now)
    // 	if udpAddr.IsValid() {
    // 		// We have a preferred path. Ping that every 2 seconds.
    // 		de.startPingLocked(udpAddr, now, pingHeartbeat)
    // 	}

    // 	if de.wantFullPingLocked(now) {
    // 		de.sendPingsLocked(now, true)
    // 	}

    // 	de.heartBeatTimer = time.AfterFunc(heartbeatInterval, de.heartbeat)
    // }

    // // wantFullPingLocked reports whether we should ping to all our peers looking for
    // // a better path.
    // //
    // // de.mu must be held.
    // func (de *endpoint) wantFullPingLocked(now mono.Time) bool {
    // 	if runtime.GOOS == "js" {
    // 		return false
    // 	}
    // 	if !de.bestAddr.IsValid() || de.lastFullPing.IsZero() {
    // 		return true
    // 	}
    // 	if now.After(de.trustBestAddrUntil) {
    // 		return true
    // 	}
    // 	if de.bestAddr.latency <= goodEnoughLatency {
    // 		return false
    // 	}
    // 	if now.Sub(de.lastFullPing) >= upgradeInterval {
    // 		return true
    // 	}
    // 	return false
    // }

    // func (de *endpoint) noteActiveLocked() {
    // 	de.lastSend = mono.Now()
    // 	if de.heartBeatTimer == nil && !de.heartbeatDisabled {
    // 		de.heartBeatTimer = time.AfterFunc(heartbeatInterval, de.heartbeat)
    // 	}
    // }

    /// Starts a ping for the "ping" command.
    /// `res` is value to call cb with, already partially filled.
    pub fn cli_ping<F>(&self, res: cfg::PingResult, cb: F)
    where
        F: Fn(cfg::PingResult),
    {
        // 	de.mu.Lock()
        // 	defer de.mu.Unlock()

        // 	if de.expired {
        // 		res.Err = errExpired.Error()
        // 		cb(res)
        // 		return
        // 	}

        // 	de.pendingCLIPings = append(de.pendingCLIPings, pendingCLIPing{res, cb})

        // 	now := mono.Now()
        // 	udpAddr, derpAddr := de.addrForSendLocked(now)
        // 	if derpAddr.IsValid() {
        // 		de.startPingLocked(derpAddr, now, pingCLI)
        // 	}
        // 	if udpAddr.IsValid() && now.Before(de.trustBestAddrUntil) {
        // 		// Already have an active session, so just ping the address we're using.
        // 		// Otherwise "tailscale ping" results to a node on the local network
        // 		// can look like they're bouncing between, say 10.0.0.0/9 and the peer's
        // 		// IPv6 address, both 1ms away, and it's random who replies first.
        // 		de.startPingLocked(udpAddr, now, pingCLI)
        // 	} else {
        // 		for ep := range de.endpointState {
        // 			de.startPingLocked(ep, now, pingCLI)
        // 		}
        // 	}
        // 	de.noteActiveLocked()
    }

    // var (
    // 	errExpired     = errors.New("peer's node key has expired")
    // 	errNoUDPOrDERP = errors.New("no UDP or DERP addr")
    // )

    pub async fn send(&self, buffs: &[&[u8]]) -> Result<()> {
        todo!()
        // 	if fn := de.sendFunc.Load(); fn != nil {
        // 		return fn(buffs)
        // 	}

        // 	de.mu.Lock()
        // 	if de.expired {
        // 		de.mu.Unlock()
        // 		return errExpired
        // 	}

        // 	// if heartbeat disabled, kick off pathfinder
        // 	if de.heartbeatDisabled {
        // 		if !de.pathFinderRunning {
        // 			de.startPathFinder()
        // 		}
        // 	}

        // 	now := mono.Now()
        // 	udpAddr, derpAddr := de.addrForSendLocked(now)
        // 	if !udpAddr.IsValid() || now.After(de.trustBestAddrUntil) {
        // 		de.sendPingsLocked(now, true)
        // 	}
        // 	de.noteActiveLocked()
        // 	de.mu.Unlock()

        // 	if !udpAddr.IsValid() && !derpAddr.IsValid() {
        // 		return errNoUDPOrDERP
        // 	}
        // 	var err error
        // 	if udpAddr.IsValid() {
        // 		_, err = de.c.sendUDPBatch(udpAddr, buffs)
        // 		// TODO(raggi): needs updating for accuracy, as in error conditions we may have partial sends.
        // 		if stats := de.c.stats.Load(); err == nil && stats != nil {
        // 			var txBytes int
        // 			for _, b := range buffs {
        // 				txBytes += len(b)
        // 			}
        // 			stats.UpdateTxPhysical(de.nodeAddr, udpAddr, txBytes)
        // 		}
        // 	}
        // 	if derpAddr.IsValid() {
        // 		allOk := true
        // 		for _, buff := range buffs {
        // 			ok, _ := de.c.sendAddr(derpAddr, de.publicKey, buff)
        // 			if stats := de.c.stats.Load(); stats != nil {
        // 				stats.UpdateTxPhysical(de.nodeAddr, derpAddr, len(buff))
        // 			}
        // 			if !ok {
        // 				allOk = false
        // 			}
        // 		}
        // 		if allOk {
        // 			return nil
        // 		}
        // 	}
        // 	return err
    }

    // func (de *endpoint) pingTimeout(txid stun.TxID) {
    // 	de.mu.Lock()
    // 	defer de.mu.Unlock()
    // 	sp, ok := de.sentPing[txid]
    // 	if !ok {
    // 		return
    // 	}
    // 	if debugDisco() || !de.bestAddr.IsValid() || mono.Now().After(de.trustBestAddrUntil) {
    // 		de.c.dlogf("[v1] magicsock: disco: timeout waiting for pong %x from %v (%v, %v)", txid[:6], sp.to, de.publicKey.ShortString(), de.discoShort)
    // 	}
    // 	de.removeSentPingLocked(txid, sp)
    // }

    // // forgetPing is called by a timer when a ping either fails to send or
    // // has taken too long to get a pong reply.
    // func (de *endpoint) forgetPing(txid stun.TxID) {
    // 	de.mu.Lock()
    // 	defer de.mu.Unlock()
    // 	if sp, ok := de.sentPing[txid]; ok {
    // 		de.removeSentPingLocked(txid, sp)
    // 	}
    // }

    // // sendDiscoPing sends a ping with the provided txid to ep using de's discoKey.
    // //
    // // The caller (startPingLocked) should've already recorded the ping in
    // // sentPing and set up the timer.
    // //
    // // The caller should use de.discoKey as the discoKey argument.
    // // It is passed in so that sendDiscoPing doesn't need to lock de.mu.
    // func (de *endpoint) sendDiscoPing(ep netip.AddrPort, discoKey key.DiscoPublic, txid stun.TxID, logLevel discoLogLevel) {
    // 	sent, _ := de.c.sendDiscoMessage(ep, de.publicKey, discoKey, &disco.Ping{
    // 		TxID:    [12]byte(txid),
    // 		NodeKey: de.c.publicKeyAtomic.Load(),
    // 	}, logLevel)
    // 	if !sent {
    // 		de.forgetPing(txid)
    // 	}
    // }

    // func (de *endpoint) startPingLocked(ep netip.AddrPort, now mono.Time, purpose discoPingPurpose) {
    // 	if runtime.GOOS == "js" {
    // 		return
    // 	}
    // 	if purpose != pingCLI {
    // 		st, ok := de.endpointState[ep]
    // 		if !ok {
    // 			// Shouldn't happen. But don't ping an endpoint that's
    // 			// not active for us.
    // 			de.c.logf("magicsock: disco: [unexpected] attempt to ping no longer live endpoint %v", ep)
    // 			return
    // 		}
    // 		st.lastPing = now
    // 	}

    // 	txid := stun.NewTxID()
    // 	de.sentPing[txid] = sentPing{
    // 		to:      ep,
    // 		at:      now,
    // 		timer:   time.AfterFunc(pingTimeoutDuration, func() { de.pingTimeout(txid) }),
    // 		purpose: purpose,
    // 	}
    // 	logLevel := discoLog
    // 	if purpose == pingHeartbeat {
    // 		logLevel = discoVerboseLog
    // 	}
    // 	go de.sendDiscoPing(ep, de.discoKey, txid, logLevel)
    // }

    // func (de *endpoint) sendPingsLocked(now mono.Time, sendCallMeMaybe bool) {
    // 	de.lastFullPing = now
    // 	var sentAny bool
    // 	for ep, st := range de.endpointState {
    // 		if st.shouldDeleteLocked() {
    // 			de.deleteEndpointLocked(ep)
    // 			continue
    // 		}
    // 		if runtime.GOOS == "js" {
    // 			continue
    // 		}
    // 		if !st.lastPing.IsZero() && now.Sub(st.lastPing) < discoPingInterval {
    // 			continue
    // 		}

    // 		firstPing := !sentAny
    // 		sentAny = true

    // 		if firstPing && sendCallMeMaybe {
    // 			de.c.dlogf("[v1] magicsock: disco: send, starting discovery for %v (%v)", de.publicKey.ShortString(), de.discoShort)
    // 		}

    // 		de.startPingLocked(ep, now, pingDiscovery)
    // 	}
    // 	derpAddr := de.derpAddr
    // 	if sentAny && sendCallMeMaybe && derpAddr.IsValid() {
    // 		// Have our magicsock.Conn figure out its STUN endpoint (if
    // 		// it doesn't know already) and then send a CallMeMaybe
    // 		// message to our peer via DERP informing them that we've
    // 		// sent so our firewall ports are probably open and now
    // 		// would be a good time for them to connect.
    // 		go de.c.enqueueCallMeMaybe(derpAddr, de)
    // 	}
    // }

    // func (de *endpoint) updateFromNode(n *tailcfg.Node, heartbeatDisabled bool) {
    // 	if n == nil {
    // 		panic("nil node when updating disco ep")
    // 	}
    // 	de.mu.Lock()
    // 	defer de.mu.Unlock()

    // 	de.heartbeatDisabled = heartbeatDisabled
    // 	de.expired = n.Expired

    // 	if de.discoKey != n.DiscoKey {
    // 		de.c.logf("[v1] magicsock: disco: node %s changed from discokey %s to %s", de.publicKey.ShortString(), de.discoKey, n.DiscoKey)
    // 		de.discoKey = n.DiscoKey
    // 		de.discoShort = de.discoKey.ShortString()
    // 		de.resetLocked()
    // 	}
    // 	if n.DERP == "" {
    // 		de.derpAddr = netip.AddrPort{}
    // 	} else {
    // 		de.derpAddr, _ = netip.ParseAddrPort(n.DERP)
    // 	}

    // 	for _, st := range de.endpointState {
    // 		st.index = indexSentinelDeleted // assume deleted until updated in next loop
    // 	}
    // 	for i, epStr := range n.Endpoints {
    // 		if i > math.MaxInt16 {
    // 			// Seems unlikely.
    // 			continue
    // 		}
    // 		ipp, err := netip.ParseAddrPort(epStr)
    // 		if err != nil {
    // 			de.c.logf("magicsock: bogus netmap endpoint %q", epStr)
    // 			continue
    // 		}
    // 		if st, ok := de.endpointState[ipp]; ok {
    // 			st.index = int16(i)
    // 		} else {
    // 			de.endpointState[ipp] = &endpointState{index: int16(i)}
    // 		}
    // 	}

    // 	// Now delete anything unless it's still in the network map or
    // 	// was a recently discovered endpoint.
    // 	for ep, st := range de.endpointState {
    // 		if st.shouldDeleteLocked() {
    // 			de.deleteEndpointLocked(ep)
    // 		}
    // 	}

    // 	// Node changed. Invalidate its sending fast path, if any.
    // 	de.sendFunc.Store(nil)
    // }

    // // addCandidateEndpoint adds ep as an endpoint to which we should send
    // // future pings. If there is an existing endpointState for ep, and forRxPingTxID
    // // matches the last received ping TxID, this function reports true, otherwise
    // // false.
    // //
    // // This is called once we've already verified that we got a valid
    // // discovery message from de via ep.
    // func (de *endpoint) addCandidateEndpoint(ep netip.AddrPort, forRxPingTxID stun.TxID) (duplicatePing bool) {
    // 	de.mu.Lock()
    // 	defer de.mu.Unlock()

    // 	if st, ok := de.endpointState[ep]; ok {
    // 		duplicatePing = forRxPingTxID == st.lastGotPingTxID
    // 		if !duplicatePing {
    // 			st.lastGotPingTxID = forRxPingTxID
    // 		}
    // 		if st.lastGotPing.IsZero() {
    // 			// Already-known endpoint from the network map.
    // 			return duplicatePing
    // 		}
    // 		st.lastGotPing = time.Now()
    // 		return duplicatePing
    // 	}

    // 	// Newly discovered endpoint. Exciting!
    // 	de.c.dlogf("[v1] magicsock: disco: adding %v as candidate endpoint for %v (%s)", ep, de.discoShort, de.publicKey.ShortString())
    // 	de.endpointState[ep] = &endpointState{
    // 		lastGotPing:     time.Now(),
    // 		lastGotPingTxID: forRxPingTxID,
    // 	}

    // 	// If for some reason this gets very large, do some cleanup.
    // 	if size := len(de.endpointState); size > 100 {
    // 		for ep, st := range de.endpointState {
    // 			if st.shouldDeleteLocked() {
    // 				de.deleteEndpointLocked(ep)
    // 			}
    // 		}
    // 		size2 := len(de.endpointState)
    // 		de.c.dlogf("[v1] magicsock: disco: addCandidateEndpoint pruned %v candidate set from %v to %v entries", size, size2)
    // 	}
    // 	return false
    // }

    /// Called when connectivity changes enough
    /// that we should question our earlier assumptions about which paths work.
    pub(super) async fn note_connectivity_change(&self) {
        let mut state = self.state.lock().await;
        state.trust_best_addr_until = None;
    }

    // // handlePongConnLocked handles a Pong message (a reply to an earlier ping).
    // // It should be called with the Conn.mu held.
    // //
    // // It reports whether m.TxID corresponds to a ping that this endpoint sent.
    // func (de *endpoint) handlePongConnLocked(m *disco.Pong, di *discoInfo, src netip.AddrPort) (knownTxID bool) {
    // 	de.mu.Lock()
    // 	defer de.mu.Unlock()

    // 	isDerp := src.Addr() == derpMagicIPAddr

    // 	sp, ok := de.sentPing[m.TxID]
    // 	if !ok {
    // 		// This is not a pong for a ping we sent.
    // 		return false
    // 	}
    // 	knownTxID = true // for naked returns below
    // 	de.removeSentPingLocked(m.TxID, sp)
    // 	di.setNodeKey(de.publicKey)

    // 	now := mono.Now()
    // 	latency := now.Sub(sp.at)

    // 	if !isDerp {
    // 		st, ok := de.endpointState[sp.to]
    // 		if !ok {
    // 			// This is no longer an endpoint we care about.
    // 			return
    // 		}

    // 		de.c.peerMap.setNodeKeyForIPPort(src, de.publicKey)

    // 		st.addPongReplyLocked(pongReply{
    // 			latency: latency,
    // 			pongAt:  now,
    // 			from:    src,
    // 			pongSrc: m.Src,
    // 		})
    // 	}

    // 	if sp.purpose != pingHeartbeat {
    // 		de.c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v)  got pong tx=%x latency=%v pong.src=%v%v", de.c.discoShort, de.discoShort, de.publicKey.ShortString(), src, m.TxID[:6], latency.Round(time.Millisecond), m.Src, logger.ArgWriter(func(bw *bufio.Writer) {
    // 			if sp.to != src {
    // 				fmt.Fprintf(bw, " ping.to=%v", sp.to)
    // 			}
    // 		}))
    // 	}

    // 	for _, pp := range de.pendingCLIPings {
    // 		de.c.populateCLIPingResponseLocked(pp.res, latency, sp.to)
    // 		go pp.cb(pp.res)
    // 	}
    // 	de.pendingCLIPings = nil

    // 	// Promote this pong response to our current best address if it's lower latency.
    // 	// TODO(bradfitz): decide how latency vs. preference order affects decision
    // 	if !isDerp {
    // 		thisPong := addrLatency{sp.to, latency}
    // 		if betterAddr(thisPong, de.bestAddr) {
    // 			de.c.logf("magicsock: disco: node %v %v now using %v", de.publicKey.ShortString(), de.discoShort, sp.to)
    // 			de.bestAddr = thisPong
    // 		}
    // 		if de.bestAddr.AddrPort == thisPong.AddrPort {
    // 			de.bestAddr.latency = latency
    // 			de.bestAddrAt = now
    // 			de.trustBestAddrUntil = now.Add(trustUDPAddrDuration)
    // 		}
    // 	}
    // 	return
    // }

    // // betterAddr reports whether a is a better addr to use than b.
    // func betterAddr(a, b addrLatency) bool {
    // 	if a.AddrPort == b.AddrPort {
    // 		return false
    // 	}
    // 	if !b.IsValid() {
    // 		return true
    // 	}
    // 	if !a.IsValid() {
    // 		return false
    // 	}
    // 	if a.Addr().Is6() && b.Addr().Is4() {
    // 		// Prefer IPv6 for being a bit more robust, as long as
    // 		// the latencies are roughly equivalent.
    // 		if a.latency/10*9 < b.latency {
    // 			return true
    // 		}
    // 	} else if a.Addr().Is4() && b.Addr().Is6() {
    // 		if betterAddr(b, a) {
    // 			return false
    // 		}
    // 	}
    // 	return a.latency < b.latency
    // }

    // // handleCallMeMaybe handles a CallMeMaybe discovery message via
    // // DERP. The contract for use of this message is that the peer has
    // // already sent to us via UDP, so their stateful firewall should be
    // // open. Now we can Ping back and make it through.
    // func (de *endpoint) handleCallMeMaybe(m *disco.CallMeMaybe) {
    // 	if runtime.GOOS == "js" {
    // 		// Nothing to do on js/wasm if we can't send UDP packets anyway.
    // 		return
    // 	}
    // 	de.mu.Lock()
    // 	defer de.mu.Unlock()

    // 	now := time.Now()
    // 	for ep := range de.isCallMeMaybeEP {
    // 		de.isCallMeMaybeEP[ep] = false // mark for deletion
    // 	}
    // 	var newEPs []netip.AddrPort
    // 	for _, ep := range m.MyNumber {
    // 		if ep.Addr().Is6() && ep.Addr().IsLinkLocalUnicast() {
    // 			// We send these out, but ignore them for now.
    // 			// TODO: teach the ping code to ping on all interfaces
    // 			// for these.
    // 			continue
    // 		}
    // 		mak.Set(&de.isCallMeMaybeEP, ep, true)
    // 		if es, ok := de.endpointState[ep]; ok {
    // 			es.callMeMaybeTime = now
    // 		} else {
    // 			de.endpointState[ep] = &endpointState{callMeMaybeTime: now}
    // 			newEPs = append(newEPs, ep)
    // 		}
    // 	}
    // 	if len(newEPs) > 0 {
    // 		de.c.dlogf("[v1] magicsock: disco: call-me-maybe from %v %v added new endpoints: %v",
    // 			de.publicKey.ShortString(), de.discoShort,
    // 			logger.ArgWriter(func(w *bufio.Writer) {
    // 				for i, ep := range newEPs {
    // 					if i > 0 {
    // 						w.WriteString(", ")
    // 					}
    // 					w.WriteString(ep.String())
    // 				}
    // 			}))
    // 	}

    // 	// Delete any prior CallMeMaybe endpoints that weren't included
    // 	// in this message.
    // 	for ep, want := range de.isCallMeMaybeEP {
    // 		if !want {
    // 			delete(de.isCallMeMaybeEP, ep)
    // 			de.deleteEndpointLocked(ep)
    // 		}
    // 	}

    // 	// Zero out all the lastPing times to force sendPingsLocked to send new ones,
    // 	// even if it's been less than 5 seconds ago.
    // 	for _, st := range de.endpointState {
    // 		st.lastPing = 0
    // 	}
    // 	de.sendPingsLocked(mono.Now(), false)
    // }

    // func (de *endpoint) populatePeerStatus(ps *ipnstate.PeerStatus) {
    // 	de.mu.Lock()
    // 	defer de.mu.Unlock()

    // 	ps.Relay = de.c.derpRegionCodeOfIDLocked(int(de.derpAddr.Port()))

    // 	if de.lastSend.IsZero() {
    // 		return
    // 	}

    // 	now := mono.Now()
    // 	ps.LastWrite = de.lastSend.WallTime()
    // 	ps.Active = now.Sub(de.lastSend) < sessionActiveTimeout

    // 	if udpAddr, derpAddr := de.addrForSendLocked(now); udpAddr.IsValid() && !derpAddr.IsValid() {
    // 		ps.CurAddr = udpAddr.String()
    // 	}
    // }

    /// Stops timers associated with de and resets its state back to zero.
    /// It's called when a discovery endpoint is no longer present in the
    /// NetworkMap, or when magicsock is transitioning from running to
    /// stopped state (via `set_private_key(None)`).
    async fn stop_and_reset(&self) {
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

    // func (de *endpoint) numStopAndReset() int64 {
    // 	return atomic.LoadInt64(&de.numStopAndResetAtomic)
    // }

    // func (de *endpoint) deleteEndpointLocked(ep netip.AddrPort) {
    // 	delete(de.endpointState, ep)
    // 	if de.bestAddr.AddrPort == ep {
    // 		de.bestAddr = addrLatency{}
    // 	}
    // }
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

        for (txid, sp) in self.sent_ping.drain() {
            // Inlined remove_sent_ping due to borrowing issues

            // Stop the timer for the case where sendPing failed to write to UDP.
            // In the case of a timer already having fired, this is a no-op:
            sp.timer.stop().await;
        }
    }

    async fn remove_sent_ping(&mut self, txid: &stun::TransactionId, sp: SentPing) {
        // Stop the timer for the case where sendPing failed to write to UDP.
        // In the case of a timer already having fired, this is a no-op:
        // TODO: figure out

        sp.timer.stop().await;
        self.sent_ping.remove(txid);
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
    fn for_each_endpoint_with_disco_key<F>(&self, dk: &key::disco::PublicKey, f: F)
    where
        F: Fn(&Endpoint) -> bool,
    {
        if let Some(nodes) = self.nodes_of_disco.get(dk) {
            for nk in nodes {
                if let Some(pi) = self.by_node_key.get(nk) {
                    if !f(&pi.ep) {
                        return;
                    }
                }
            }
        }
    }

    /// Stores endpoint in the peerInfo for ep.publicKey, and updates indexes. m must already have a
    /// tailcfg.Node for ep.publicKey.
    async fn upsert_endpoint(&mut self, ep: &Endpoint, old_disco_key: &key::disco::PublicKey) {
        if !self.by_node_key.contains_key(&ep.public_key) {
            self.by_node_key
                .insert(ep.public_key.clone(), PeerInfo::new(ep.clone()));
        }
        let disco_key = ep.0.state.lock().await.disco_key.clone();
        if old_disco_key != &disco_key {
            if let Some(v) = self.nodes_of_disco.get_mut(old_disco_key) {
                v.remove(&ep.public_key);
            }
        }
        let set = self.nodes_of_disco.entry(disco_key).or_default();
        set.insert(ep.public_key.clone());
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
    async fn delete_endpoint(&mut self, ep: &Endpoint) {
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    index: usize,
}

// // indexSentinelDeleted is the temporary value that endpointState.index takes while
// // a endpoint's endpoints are being updated from a new network map.
// const indexSentinelDeleted = -1

impl EndpointState {
    // // endpoint.mu must be held.
    // func (st *endpointState) addPongReplyLocked(r pongReply) {
    // 	if n := len(st.recentPongs); n < pongHistoryCount {
    // 		st.recentPong = uint16(n)
    // 		st.recentPongs = append(st.recentPongs, r)
    // 		return
    // 	}
    // 	i := st.recentPong + 1
    // 	if i == pongHistoryCount {
    // 		i = 0
    // 	}
    // 	st.recentPongs[i] = r
    // 	st.recentPong = i
    // }

    // // shouldDeleteLocked reports whether we should delete this endpoint.
    // func (st *endpointState) shouldDeleteLocked() bool {
    // 	switch {
    // 	case !st.callMeMaybeTime.IsZero():
    // 		return false
    // 	case st.lastGotPing.IsZero():
    // 		// This was an endpoint from the network map. Is it still in the network map?
    // 		return st.index == indexSentinelDeleted
    // 	default:
    // 		// This was an endpoint discovered at runtime.
    // 		return time.Since(st.lastGotPing) > sessionActiveTimeout
    // 	}
    // }
}
