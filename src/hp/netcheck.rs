//! Checks the network conditions from the current host.
//! Based on https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go

// The various default timeouts for things.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

use tokio::{
    sync::{mpsc, Mutex},
    time::Timeout,
};
use tracing::{debug, info};

use crate::hp::stun;

use super::{
    derp::{DerpMap, DerpNode, DerpRegion},
    interfaces,
    ping::Pinger,
};

// TODO: better type
pub trait PacketConn {}

// The interface required by the netcheck Client when reusing an existing UDP connection.
pub trait StunConn {
    // WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
    //     WriteTo([]byte, net.Addr) (int, error)
    //     ReadFrom([]byte) (int, net.Addr, error)
}

/// The maximum amount of time netcheck will spend gathering a single report.
const OVERALL_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The maximum amount of time netcheck will spend probing with STUN packets without getting a
/// reply before switching to HTTP probing, on the assumption that outbound UDP is blocked.
const STUN_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// The maximum amount of time netcheck will spend probing with ICMP packets.
const ICMP_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// The amount of time we wait for a hairpinned packet to come back.
const HAIRPIN_CHECK_TIMEOUT: Duration = Duration::from_millis(100);

/// The retransmit interval we use for STUN probes when we're in steady state (not in start-up),
/// but don't have previous latency information for a DERP node. This is a somewhat conservative
/// guess because if we have no data, likely the DERP node is very far away and we have no
/// data because we timed out the last time we probed it.
const DEFAULT_ACTIVE_RETRANSMIT_TIME: Duration = Duration::from_millis(200);

/// The retransmit interval used when netcheck first runs. We have no past context to work with,
/// and we want answers relatively quickly, so it's biased slightly more aggressive than
/// [`DEFAULT_ACTIVE_RETRANSMIT_TIME`]. A few extra packets at startup is fine.
const DEFAULT_INITIAL_RETRANSMIT: Duration = Duration::from_millis(100);

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// A UDP STUN round trip completed.
    pub udp: bool,
    /// An IPv6 STUN round trip completed.
    pub ipv6: bool,
    /// An IPv4 STUN round trip completed.
    pub ipv4: bool,
    /// An IPv6 packet was able to be sent
    pub ipv6_can_send: bool,
    /// an IPv4 packet was able to be sent
    pub ipv4_can_send: bool,
    /// could bind a socket to ::1
    pub os_has_ipv6: bool,
    /// an ICMPv4 round trip completed
    pub icmpv4: bool,

    /// Wwhether STUN results depend which STUN server you're talking to (on IPv4).
    pub mapping_varies_by_dest_ip: Option<bool>,

    /// Whether the router supports communicating between two local devices through the NATted
    /// public IP address (on IPv4).
    pub hair_pinning: Option<bool>,

    /// Whether UPnP appears present on the LAN.
    /// None means not checked.
    pub upnp: Option<bool>,
    /// Whether NAT-PMP appears present on the LAN.
    /// None means not checked.
    pub pmp: Option<bool>,
    /// Whether PCP appears present on the LAN.
    /// None means not checked.
    pub pcp: Option<bool>,

    /// or 0 for unknown
    pub preferred_derp: usize,
    /// keyed by DERP Region ID
    pub region_latency: HashMap<usize, Duration>,
    /// keyed by DERP Region ID
    pub region_v4_latency: HashMap<usize, Duration>,
    /// keyed by DERP Region ID
    pub region_v6_latency: HashMap<i32, Duration>,

    /// ip:port of global IPv4
    pub global_v4: String,
    /// [ip]:port of global IPv6
    pub global_v6: String,

    /// CaptivePortal is set when we think there's a captive portal that is
    /// intercepting HTTP traffic.
    pub captive_portal: Option<bool>,
}

impl Report {
    /// Reports whether any of UPnP, PMP, or PCP are non-empty.
    pub fn any_port_mapping_checked(&self) -> bool {
        self.upnp.is_some() || self.pmp.is_some() || self.pcp.is_some()
    }
}

/// Generates a netcheck [`Report`].
pub struct Client {
    /// Enables verbose logging.
    pub verbose: bool,

    /// Controls whether the client should not try
    /// to reach things other than localhost. This is set to true
    /// in tests to avoid probing the local LAN's router, etc.
    pub skip_external_network: bool,

    /// If set, is the address to listen on for UDP.
    /// It defaults to ":0".
    pub udp_bind_addr: Option<String>,

    // Used for portmap queries.
    // If `None`, portmap discovery is not done.
    pub port_mapper: Option<()>, // TODO*portmapper.Client // lazily initialized on first use

    reports: Mutex<Reports>,
}

struct Reports {
    /// Do a full region scan, even if last is `Some`.
    next_full: bool,
    /// Some previous reports.
    prev: HashMap<SystemTime, Report>,
    /// Most recent report.
    last: Option<Report>,
    /// Time of last full (non-incremental) report.
    last_full: SystemTime,
    /// `Some` if we're in a call to `get_report`.
    cur_state: Option<ReportState>,
}

impl Client {
    fn enough_regions(&self) -> usize {
        if self.verbose {
            // Abuse verbose a bit here so netcheck can show all region latencies
            // in verbose mode.
            return 100;
        }
        3
    }

    fn captive_portal_delay(&self) -> Duration {
        // Chosen semi-arbitrarily
        Duration::from_millis(200)
    }

    /// Reports whether `pkt` (from `src`) was our magic hairpin probe packet that we sent to ourselves.
    async fn handle_hair_stun_locked(&self, pkt: &[u8], src: IpAddr) -> bool {
        let reports = &*self.reports.lock().await;
        if let Some(ref rs) = reports.cur_state {
            if let Ok(tx) = stun::parse_binding_request(pkt) {
                if tx == rs.hair_tx {
                    // TODO:
                    // rs.gotHairSTUN <- src:
                    return true;
                }
            }
        }
        false
    }

    /// Forces the next `get_report` call to be a full (non-incremental) probe of all DERP regions.
    async fn make_next_report_full(&self) {
        self.reports.lock().await.next_full = true;
    }

    async fn receive_stun_packet(&self, pkt: &[u8], src: IpAddr) {
        debug!("received STUN packet from {}", src);

        if src.is_ipv4() {
            // TODO:
            // metricSTUNRecv4.Add(1)
        } else if src.is_ipv6() {
            // TODO:
            // metricSTUNRecv6.Add(1)
        }

        if self.handle_hair_stun_locked(pkt, src).await {
            return;
        }
        if self.reports.lock().await.cur_state.is_none() {
            return;
        }

        match stun::parse_response(pkt) {
            Ok((tx, addr_port)) => {
                let reports = &mut *self.reports.lock().await;
                if let Some(ref mut rs) = reports.cur_state {
                    // TODO: avoid lock
                    let mut rs_state = rs.state.lock().await;
                    if let Some(on_done) = rs_state.in_flight.remove(&tx) {
                        drop(rs_state);
                        drop(reports);
                        on_done(addr_port);
                    }
                }
            }
            Err(err) => {
                if stun::parse_binding_request(pkt).is_ok() {
                    // This was probably our own netcheck hairpin
                    // check probe coming in late. Ignore.
                    return;
                }
                info!(
                    "netcheck: received unexpected STUN message response from {}: {:?}",
                    src, err
                );
            }
        }
    }

    /// Reads STUN packets from pc until there's an error or ctx is done.
    /// In either case, it closes pc.
    fn read_packets(&self, /*ctx context.Context,*/ pc: impl PacketConn) {
        todo!()
        // 	done := make(chan struct{})
        // 	defer close(done)

        // 	go func() {
        // 		select {
        // 		case <-ctx.Done():
        // 		case <-done:
        // 		}
        // 		pc.Close()
        // 	}()

        // 	var buf [64 << 10]byte
        // 	for {
        // 		n, addr, err := pc.ReadFrom(buf[:])
        // 		if err != nil {
        // 			if ctx.Err() != nil {
        // 				return
        // 			}
        // 			c.logf("ReadFrom: %v", err)
        // 			return
        // 		}
        // 		ua, ok := addr.(*net.UDPAddr)
        // 		if !ok {
        // 			c.logf("ReadFrom: unexpected addr %T", addr)
        // 			continue
        // 		}
        // 		pkt := buf[:n]
        // 		if !stun.Is(pkt) {
        // 			continue
        // 		}
        // 		if ap := netaddr.Unmap(ua.AddrPort()); ap.IsValid() {
        // 			c.ReceiveSTUNPacket(pkt, ap)
        // 		}
        // 	}
    }

    fn udp_bind_addr(&self) -> &str {
        self.udp_bind_addr
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or(":0")
    }

    /// Gets a report.
    ///
    ///It may not be called concurrently with itself.
    pub fn get_report(&self, /*ctx context.Context,*/ dm: &DerpMap) -> Result<Report, ()> {
        todo!()
        // 	defer func() {
        // 		if reterr != nil {
        // 			metricNumGetReportError.Add(1)
        // 		}
        // 	}()
        // 	metricNumGetReport.Add(1)
        // 	// Mask user context with ours that we guarantee to cancel so
        // 	// we can depend on it being closed in goroutines later.
        // 	// (User ctx might be context.Background, etc)
        // 	ctx, cancel := context.WithTimeout(ctx, overallProbeTimeout)
        // 	defer cancel()

        // 	if dm == nil {
        // 		return nil, errors.New("netcheck: GetReport: DERP map is nil")
        // 	}

        // 	c.mu.Lock()
        // 	if c.curState != nil {
        // 		c.mu.Unlock()
        // 		return nil, errors.New("invalid concurrent call to GetReport")
        // 	}
        // 	rs := &reportState{
        // 		c:           c,
        // 		report:      newReport(),
        // 		inFlight:    map[stun.TxID]func(netip.AddrPort){},
        // 		hairTX:      stun.NewTxID(), // random payload
        // 		gotHairSTUN: make(chan netip.AddrPort, 1),
        // 		hairTimeout: make(chan struct{}),
        // 		stopProbeCh: make(chan struct{}, 1),
        // 	}
        // 	c.curState = rs
        // 	last := c.last

        // 	// Even if we're doing a non-incremental update, we may want to try our
        // 	// preferred DERP region for captive portal detection. Save that, if we
        // 	// have it.
        // 	var preferredDERP int
        // 	if last != nil {
        // 		preferredDERP = last.PreferredDERP
        // 	}

        // 	now := c.timeNow()

        // 	doFull := false
        // 	if c.nextFull || now.Sub(c.lastFull) > 5*time.Minute {
        // 		doFull = true
        // 	}
        // 	// If the last report had a captive portal and reported no UDP access,
        // 	// it's possible that we didn't get a useful netcheck due to the
        // 	// captive portal blocking us. If so, make this report a full
        // 	// (non-incremental) one.
        // 	if !doFull && last != nil {
        // 		doFull = !last.UDP && last.CaptivePortal.EqualBool(true)
        // 	}
        // 	if doFull {
        // 		last = nil // causes makeProbePlan below to do a full (initial) plan
        // 		c.nextFull = false
        // 		c.lastFull = now
        // 		metricNumGetReportFull.Add(1)
        // 	}

        // 	rs.incremental = last != nil
        // 	c.mu.Unlock()

        // 	defer func() {
        // 		c.mu.Lock()
        // 		defer c.mu.Unlock()
        // 		c.curState = nil
        // 	}()

        // 	if runtime.GOOS == "js" {
        // 		if err := c.runHTTPOnlyChecks(ctx, last, rs, dm); err != nil {
        // 			return nil, err
        // 		}
        // 		return c.finishAndStoreReport(rs, dm), nil
        // 	}

        // 	ifState, err := interfaces.GetState()
        // 	if err != nil {
        // 		c.logf("[v1] interfaces: %v", err)
        // 		return nil, err
        // 	}

        // 	// See if IPv6 works at all, or if it's been hard disabled at the
        // 	// OS level.
        // 	v6udp, err := nettype.MakePacketListenerWithNetIP(netns.Listener(c.logf)).ListenPacket(ctx, "udp6", "[::1]:0")
        // 	if err == nil {
        // 		rs.report.OSHasIPv6 = true
        // 		v6udp.Close()
        // 	}

        // 	// Create a UDP4 socket used for sending to our discovered IPv4 address.
        // 	rs.pc4Hair, err = nettype.MakePacketListenerWithNetIP(netns.Listener(c.logf)).ListenPacket(ctx, "udp4", ":0")
        // 	if err != nil {
        // 		c.logf("udp4: %v", err)
        // 		return nil, err
        // 	}
        // 	defer rs.pc4Hair.Close()

        // 	if !c.SkipExternalNetwork && c.PortMapper != nil {
        // 		rs.waitPortMap.Add(1)
        // 		go rs.probePortMapServices()
        // 	}

        // 	// At least the Apple Airport Extreme doesn't allow hairpin
        // 	// sends from a private socket until it's seen traffic from
        // 	// that src IP:port to something else out on the internet.
        // 	//
        // 	// See https://github.com/tailscale/tailscale/issues/188#issuecomment-600728643
        // 	//
        // 	// And it seems that even sending to a likely-filtered RFC 5737
        // 	// documentation-only IPv4 range is enough to set up the mapping.
        // 	// So do that for now. In the future we might want to classify networks
        // 	// that do and don't require this separately. But for now help it.
        // 	const documentationIP = "203.0.113.1"
        // 	rs.pc4Hair.WriteTo([]byte("tailscale netcheck; see https://github.com/tailscale/tailscale/issues/188"), &net.UDPAddr{IP: net.ParseIP(documentationIP), Port: 12345})

        // 	if f := c.GetSTUNConn4; f != nil {
        // 		rs.pc4 = f()
        // 	} else {
        // 		u4, err := nettype.MakePacketListenerWithNetIP(netns.Listener(c.logf)).ListenPacket(ctx, "udp4", c.udpBindAddr())
        // 		if err != nil {
        // 			c.logf("udp4: %v", err)
        // 			return nil, err
        // 		}
        // 		rs.pc4 = u4
        // 		go c.readPackets(ctx, u4)
        // 	}

        // 	if ifState.HaveV6 {
        // 		if f := c.GetSTUNConn6; f != nil {
        // 			rs.pc6 = f()
        // 		} else {
        // 			u6, err := nettype.MakePacketListenerWithNetIP(netns.Listener(c.logf)).ListenPacket(ctx, "udp6", c.udpBindAddr())
        // 			if err != nil {
        // 				c.logf("udp6: %v", err)
        // 			} else {
        // 				rs.pc6 = u6
        // 				go c.readPackets(ctx, u6)
        // 			}
        // 		}
        // 	}

        // 	plan := makeProbePlan(dm, ifState, last)

        // 	// If we're doing a full probe, also check for a captive portal. We
        // 	// delay by a bit to wait for UDP STUN to finish, to avoid the probe if
        // 	// it's unnecessary.
        // 	captivePortalDone := syncs.ClosedChan()
        // 	captivePortalStop := func() {}
        // 	if !rs.incremental {
        // 		// NOTE(andrew): we can't simply add this goroutine to the
        // 		// `NewWaitGroupChan` below, since we don't wait for that
        // 		// waitgroup to finish when exiting this function and thus get
        // 		// a data race.
        // 		ch := make(chan struct{})
        // 		captivePortalDone = ch

        // 		tmr := time.AfterFunc(c.captivePortalDelay(), func() {
        // 			defer close(ch)
        // 			found, err := c.checkCaptivePortal(ctx, dm, preferredDERP)
        // 			if err != nil {
        // 				c.logf("[v1] checkCaptivePortal: %v", err)
        // 				return
        // 			}
        // 			rs.report.CaptivePortal.Set(found)
        // 		})

        // 		captivePortalStop = func() {
        // 			// Don't cancel our captive portal check if we're
        // 			// explicitly doing a verbose netcheck.
        // 			if c.Verbose {
        // 				return
        // 			}

        // 			if tmr.Stop() {
        // 				// Stopped successfully; need to close the
        // 				// signal channel ourselves.
        // 				close(ch)
        // 				return
        // 			}

        // 			// Did not stop; do nothing and it'll finish by itself
        // 			// and close the signal channel.
        // 		}
        // 	}

        // 	wg := syncs.NewWaitGroupChan()
        // 	wg.Add(len(plan))
        // 	for _, probeSet := range plan {
        // 		setCtx, cancelSet := context.WithCancel(ctx)
        // 		go func(probeSet []probe) {
        // 			for _, probe := range probeSet {
        // 				go rs.runProbe(setCtx, dm, probe, cancelSet)
        // 			}
        // 			<-setCtx.Done()
        // 			wg.Decr()
        // 		}(probeSet)
        // 	}

        // 	stunTimer := time.NewTimer(stunProbeTimeout)
        // 	defer stunTimer.Stop()

        // 	select {
        // 	case <-stunTimer.C:
        // 	case <-ctx.Done():
        // 	case <-wg.DoneChan():
        // 		// All of our probes finished, so if we have >0 responses, we
        // 		// stop our captive portal check.
        // 		if rs.anyUDP() {
        // 			captivePortalStop()
        // 		}
        // 	case <-rs.stopProbeCh:
        // 		// Saw enough regions.
        // 		c.vlogf("saw enough regions; not waiting for rest")
        // 		// We can stop the captive portal check since we know that we
        // 		// got a bunch of STUN responses.
        // 		captivePortalStop()
        // 	}

        // 	rs.waitHairCheck(ctx)
        // 	c.vlogf("hairCheck done")
        // 	if !c.SkipExternalNetwork && c.PortMapper != nil {
        // 		rs.waitPortMap.Wait()
        // 		c.vlogf("portMap done")
        // 	}
        // 	rs.stopTimers()

        // 	// Try HTTPS and ICMP latency check if all STUN probes failed due to
        // 	// UDP presumably being blocked.
        // 	// TODO: this should be moved into the probePlan, using probeProto probeHTTPS.
        // 	if !rs.anyUDP() && ctx.Err() == nil {
        // 		var wg sync.WaitGroup
        // 		var need []*tailcfg.DERPRegion
        // 		for rid, reg := range dm.Regions {
        // 			if !rs.haveRegionLatency(rid) && regionHasDERPNode(reg) {
        // 				need = append(need, reg)
        // 			}
        // 		}
        // 		if len(need) > 0 {
        // 			// Kick off ICMP in parallel to HTTPS checks; we don't
        // 			// reuse the same WaitGroup for those probes because we
        // 			// need to close the underlying Pinger after a timeout
        // 			// or when all ICMP probes are done, regardless of
        // 			// whether the HTTPS probes have finished.
        // 			wg.Add(1)
        // 			go func() {
        // 				defer wg.Done()
        // 				if err := c.measureAllICMPLatency(ctx, rs, need); err != nil {
        // 					c.logf("[v1] measureAllICMPLatency: %v", err)
        // 				}
        // 			}()

        // 			wg.Add(len(need))
        // 			c.logf("netcheck: UDP is blocked, trying HTTPS")
        // 		}
        // 		for _, reg := range need {
        // 			go func(reg *tailcfg.DERPRegion) {
        // 				defer wg.Done()
        // 				if d, ip, err := c.measureHTTPSLatency(ctx, reg); err != nil {
        // 					c.logf("[v1] netcheck: measuring HTTPS latency of %v (%d): %v", reg.RegionCode, reg.RegionID, err)
        // 				} else {
        // 					rs.mu.Lock()
        // 					if l, ok := rs.report.RegionLatency[reg.RegionID]; !ok {
        // 						mak.Set(&rs.report.RegionLatency, reg.RegionID, d)
        // 					} else if l >= d {
        // 						rs.report.RegionLatency[reg.RegionID] = d
        // 					}
        // 					// We set these IPv4 and IPv6 but they're not really used
        // 					// and we don't necessarily set them both. If UDP is blocked
        // 					// and both IPv4 and IPv6 are available over TCP, it's basically
        // 					// random which fields end up getting set here.
        // 					// Since they're not needed, that's fine for now.
        // 					if ip.Is4() {
        // 						rs.report.IPv4 = true
        // 					}
        // 					if ip.Is6() {
        // 						rs.report.IPv6 = true
        // 					}
        // 					rs.mu.Unlock()
        // 				}
        // 			}(reg)
        // 		}
        // 		wg.Wait()
        // 	}

        // 	// Wait for captive portal check before finishing the report.
        // 	<-captivePortalDone

        // 	return c.finishAndStoreReport(rs, dm), nil
    }

    fn finish_and_store_report(&self, rs: &ReportState, dm: &DerpMap) -> Report {
        todo!()
        // 	rs.mu.Lock()
        // 	report := rs.report.Clone()
        // 	rs.mu.Unlock()

        // 	c.addReportHistoryAndSetPreferredDERP(report)
        // 	c.logConciseReport(report, dm)

        // 	return report
    }

    /// Reports whether or not we think the system is behind a
    /// captive portal, detected by making a request to a URL that we know should
    /// return a "204 No Content" response and checking if that's what we get.
    ///
    /// The boolean return is whether we think we have a captive portal.
    fn check_captive_portal(
        &self,
        /*ctx context.Context,*/ dm: &DerpMap,
        preferred_derp: usize,
    ) -> Result<bool, ()> {
        todo!()
        // 	defer noRedirectClient.CloseIdleConnections()

        // 	// If we have a preferred DERP region with more than one node, try
        // 	// that; otherwise, pick a random one not marked as "Avoid".
        // 	if preferredDERP == 0 || dm.Regions[preferredDERP] == nil ||
        // 		(preferredDERP != 0 && len(dm.Regions[preferredDERP].Nodes) == 0) {
        // 		rids := make([]int, 0, len(dm.Regions))
        // 		for id, reg := range dm.Regions {
        // 			if reg == nil || reg.Avoid || len(reg.Nodes) == 0 {
        // 				continue
        // 			}
        // 			rids = append(rids, id)
        // 		}
        // 		if len(rids) == 0 {
        // 			return false, nil
        // 		}
        // 		preferredDERP = rids[rand.Intn(len(rids))]
        // 	}

        // 	node := dm.Regions[preferredDERP].Nodes[0]

        // 	if strings.HasSuffix(node.HostName, tailcfg.DotInvalid) {
        // 		// Don't try to connect to invalid hostnames. This occurred in tests:
        // 		// https://github.com/tailscale/tailscale/issues/6207
        // 		// TODO(bradfitz,andrew-d): how to actually handle this nicely?
        // 		return false, nil
        // 	}

        // 	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+node.HostName+"/generate_204", nil)
        // 	if err != nil {
        // 		return false, err
        // 	}

        // 	// Note: the set of valid characters in a challenge and the total
        // 	// length is limited; see isChallengeChar in cmd/derper for more
        // 	// details.
        // 	chal := "ts_" + node.HostName
        // 	req.Header.Set("X-Tailscale-Challenge", chal)
        // 	r, err := noRedirectClient.Do(req)
        // 	if err != nil {
        // 		return false, err
        // 	}
        // 	defer r.Body.Close()

        // 	expectedResponse := "response " + chal
        // 	validResponse := r.Header.Get("X-Tailscale-Response") == expectedResponse

        // 	c.logf("[v2] checkCaptivePortal url=%q status_code=%d valid_response=%v", req.URL.String(), r.StatusCode, validResponse)
        // 	return r.StatusCode != 204 || !validResponse, nil
    }

    fn measure_https_latency(
        &self,
        /*ctx context.Context,*/ reg: &DerpRegion,
    ) -> Result<(Duration, IpAddr), ()> {
        todo!()
        // 	metricHTTPSend.Add(1)
        // 	var result httpstat.Result
        // 	ctx, cancel := context.WithTimeout(httpstat.WithHTTPStat(ctx, &result), overallProbeTimeout)
        // 	defer cancel()

        // 	var ip netip.Addr

        // 	dc := derphttp.NewNetcheckClient(c.logf)
        // 	defer dc.Close()

        // 	tlsConn, tcpConn, node, err := dc.DialRegionTLS(ctx, reg)
        // 	if err != nil {
        // 		return 0, ip, err
        // 	}
        // 	defer tcpConn.Close()

        // 	if ta, ok := tlsConn.RemoteAddr().(*net.TCPAddr); ok {
        // 		ip, _ = netip.AddrFromSlice(ta.IP)
        // 		ip = ip.Unmap()
        // 	}
        // 	if ip == (netip.Addr{}) {
        // 		return 0, ip, fmt.Errorf("no unexpected RemoteAddr %#v", tlsConn.RemoteAddr())
        // 	}

        // 	connc := make(chan *tls.Conn, 1)
        // 	connc <- tlsConn

        // 	tr := &http.Transport{
        // 		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
        // 			return nil, errors.New("unexpected DialContext dial")
        // 		},
        // 		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
        // 			select {
        // 			case nc := <-connc:
        // 				return nc, nil
        // 			default:
        // 				return nil, errors.New("only one conn expected")
        // 			}
        // 		},
        // 	}
        // 	hc := &http.Client{Transport: tr}

        // 	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+node.HostName+"/derp/latency-check", nil)
        // 	if err != nil {
        // 		return 0, ip, err
        // 	}

        // 	resp, err := hc.Do(req)
        // 	if err != nil {
        // 		return 0, ip, err
        // 	}
        // 	defer resp.Body.Close()

        // 	// DERPs should give us a nominal status code, so anything else is probably
        // 	// an access denied by a MITM proxy (or at the very least a signal not to
        // 	// trust this latency check).
        // 	if resp.StatusCode > 299 {
        // 		return 0, ip, fmt.Errorf("unexpected status code: %d (%s)", resp.StatusCode, resp.Status)
        // 	}

        // 	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
        // 	if err != nil {
        // 		return 0, ip, err
        // 	}
        // 	result.End(c.timeNow())

        // 	// TODO: decide best timing heuristic here.
        // 	// Maybe the server should return the tcpinfo_rtt?
        // 	return result.ServerProcessing, ip, nil
    }

    fn measure_all_icmp_latency(
        &self,
        /*ctx context.Context,*/ rs: &ReportState,
        need: &[DerpRegion],
    ) -> Result<(), ()> {
        todo!()
        // 	if len(need) == 0 {
        // 		return nil
        // 	}
        // 	ctx, done := context.WithTimeout(ctx, icmpProbeTimeout)
        // 	defer done()

        // 	p, err := ping.New(ctx, c.logf)
        // 	if err != nil {
        // 		return err
        // 	}
        // 	defer p.Close()

        // 	c.logf("UDP is blocked, trying ICMP")

        // 	var wg sync.WaitGroup
        // 	wg.Add(len(need))
        // 	for _, reg := range need {
        // 		go func(reg *tailcfg.DERPRegion) {
        // 			defer wg.Done()
        // 			if d, err := c.measureICMPLatency(ctx, reg, p); err != nil {
        // 				c.logf("[v1] measuring ICMP latency of %v (%d): %v", reg.RegionCode, reg.RegionID, err)
        // 			} else {
        // 				c.logf("[v1] ICMP latency of %v (%d): %v", reg.RegionCode, reg.RegionID, d)
        // 				rs.mu.Lock()
        // 				if l, ok := rs.report.RegionLatency[reg.RegionID]; !ok {
        // 					mak.Set(&rs.report.RegionLatency, reg.RegionID, d)
        // 				} else if l >= d {
        // 					rs.report.RegionLatency[reg.RegionID] = d
        // 				}

        // 				// We only send IPv4 ICMP right now
        // 				rs.report.IPv4 = true
        // 				rs.report.ICMPv4 = true

        // 				rs.mu.Unlock()
        // 			}
        // 		}(reg)
        // 	}

        // 	wg.Wait()
        // 	return nil
    }

    fn measure_icmp_latency(
        &self,
        /*ctx context.Context,*/ reg: &DerpRegion,
        p: &Pinger,
    ) -> Result<Duration, ()> {
        todo!()
        // 	if len(reg.Nodes) == 0 {
        // 		return 0, fmt.Errorf("no nodes for region %d (%v)", reg.RegionID, reg.RegionCode)
        // 	}

        // 	// Try pinging the first node in the region
        // 	node := reg.Nodes[0]

        // 	// Get the IPAddr by asking for the UDP address that we would use for
        // 	// STUN and then using that IP.
        // 	//
        // 	// TODO(andrew-d): this is a bit ugly
        // 	nodeAddr := c.nodeAddr(ctx, node, probeIPv4)
        // 	if !nodeAddr.IsValid() {
        // 		return 0, fmt.Errorf("no address for node %v", node.Name)
        // 	}
        // 	addr := &net.IPAddr{
        // 		IP:   net.IP(nodeAddr.Addr().AsSlice()),
        // 		Zone: nodeAddr.Addr().Zone(),
        // 	}

        // 	// Use the unique node.Name field as the packet data to reduce the
        // 	// likelihood that we get a mismatched echo response.
        // 	return p.Send(ctx, addr, []byte(node.Name))
    }

    fn log_concise_report(&self, r: &Report, dm: &DerpMap) {
        todo!()
        // 	c.logf("[v1] report: %v", logger.ArgWriter(func(w *bufio.Writer) {
        // 		fmt.Fprintf(w, "udp=%v", r.UDP)
        // 		if !r.IPv4 {
        // 			fmt.Fprintf(w, " v4=%v", r.IPv4)
        // 		}
        // 		if !r.UDP {
        // 			fmt.Fprintf(w, " icmpv4=%v", r.ICMPv4)
        // 		}

        // 		fmt.Fprintf(w, " v6=%v", r.IPv6)
        // 		if !r.IPv6 {
        // 			fmt.Fprintf(w, " v6os=%v", r.OSHasIPv6)
        // 		}
        // 		fmt.Fprintf(w, " mapvarydest=%v", r.MappingVariesByDestIP)
        // 		fmt.Fprintf(w, " hair=%v", r.HairPinning)
        // 		if r.AnyPortMappingChecked() {
        // 			fmt.Fprintf(w, " portmap=%v%v%v", conciseOptBool(r.UPnP, "U"), conciseOptBool(r.PMP, "M"), conciseOptBool(r.PCP, "C"))
        // 		} else {
        // 			fmt.Fprintf(w, " portmap=?")
        // 		}
        // 		if r.GlobalV4 != "" {
        // 			fmt.Fprintf(w, " v4a=%v", r.GlobalV4)
        // 		}
        // 		if r.GlobalV6 != "" {
        // 			fmt.Fprintf(w, " v6a=%v", r.GlobalV6)
        // 		}
        // 		if r.CaptivePortal != "" {
        // 			fmt.Fprintf(w, " captiveportal=%v", r.CaptivePortal)
        // 		}
        // 		fmt.Fprintf(w, " derp=%v", r.PreferredDERP)
        // 		if r.PreferredDERP != 0 {
        // 			fmt.Fprintf(w, " derpdist=")
        // 			needComma := false
        // 			for _, rid := range dm.RegionIDs() {
        // 				if d := r.RegionV4Latency[rid]; d != 0 {
        // 					if needComma {
        // 						w.WriteByte(',')
        // 					}
        // 					fmt.Fprintf(w, "%dv4:%v", rid, d.Round(time.Millisecond))
        // 					needComma = true
        // 				}
        // 				if d := r.RegionV6Latency[rid]; d != 0 {
        // 					if needComma {
        // 						w.WriteByte(',')
        // 					}
        // 					fmt.Fprintf(w, "%dv6:%v", rid, d.Round(time.Millisecond))
        // 					needComma = true
        // 				}
        // 			}
        // 		}
        // 	}))
    }

    fn time_now(&self) -> SystemTime {
        SystemTime::now()
    }

    /// Adds `r` to the set of recent Reports and mutates r.PreferredDERP to contain the best recent one.
    fn add_report_history_and_set_preferred_derp(&self, r: &mut Report) {
        todo!()
        // 	c.mu.Lock()
        // 	defer c.mu.Unlock()

        // 	var prevDERP int
        // 	if c.last != nil {
        // 		prevDERP = c.last.PreferredDERP
        // 	}
        // 	if c.prev == nil {
        // 		c.prev = map[time.Time]*Report{}
        // 	}
        // 	now := c.timeNow()
        // 	c.prev[now] = r
        // 	c.last = r

        // 	const maxAge = 5 * time.Minute

        // 	// region ID => its best recent latency in last maxAge
        // 	bestRecent := map[int]time.Duration{}

        // 	for t, pr := range c.prev {
        // 		if now.Sub(t) > maxAge {
        // 			delete(c.prev, t)
        // 			continue
        // 		}
        // 		for regionID, d := range pr.RegionLatency {
        // 			if bd, ok := bestRecent[regionID]; !ok || d < bd {
        // 				bestRecent[regionID] = d
        // 			}
        // 		}
        // 	}

        // 	// Then, pick which currently-alive DERP server from the
        // 	// current report has the best latency over the past maxAge.
        // 	var bestAny time.Duration
        // 	var oldRegionCurLatency time.Duration
        // 	for regionID, d := range r.RegionLatency {
        // 		if regionID == prevDERP {
        // 			oldRegionCurLatency = d
        // 		}
        // 		best := bestRecent[regionID]
        // 		if r.PreferredDERP == 0 || best < bestAny {
        // 			bestAny = best
        // 			r.PreferredDERP = regionID
        // 		}
        // 	}

        // 	// If we're changing our preferred DERP but the old one's still
        // 	// accessible and the new one's not much better, just stick with
        // 	// where we are.
        // 	if prevDERP != 0 &&
        // 		r.PreferredDERP != prevDERP &&
        // 		oldRegionCurLatency != 0 &&
        // 		bestAny > oldRegionCurLatency/3*2 {
        // 		r.PreferredDERP = prevDERP
        // 	}
    }

    /// Proto is 4 or 6. If it returns nil, the node is skipped.
    fn node_addr(&self, /*ctx context.Context,*/ n: DerpNode, proto: ProbeProto) -> IpAddr {
        todo!()
        // 	port := n.STUNPort
        // 	if port == 0 {
        // 		port = 3478
        // 	}
        // 	if port < 0 || port > 1<<16-1 {
        // 		return
        // 	}
        // 	if n.STUNTestIP != "" {
        // 		ip, err := netip.ParseAddr(n.STUNTestIP)
        // 		if err != nil {
        // 			return
        // 		}
        // 		if proto == probeIPv4 && ip.Is6() {
        // 			return
        // 		}
        // 		if proto == probeIPv6 && ip.Is4() {
        // 			return
        // 		}
        // 		return netip.AddrPortFrom(ip, uint16(port))
        // 	}

        // 	switch proto {
        // 	case probeIPv4:
        // 		if n.IPv4 != "" {
        // 			ip, _ := netip.ParseAddr(n.IPv4)
        // 			if !ip.Is4() {
        // 				return
        // 			}
        // 			return netip.AddrPortFrom(ip, uint16(port))
        // 		}
        // 	case probeIPv6:
        // 		if n.IPv6 != "" {
        // 			ip, _ := netip.ParseAddr(n.IPv6)
        // 			if !ip.Is6() {
        // 				return
        // 			}
        // 			return netip.AddrPortFrom(ip, uint16(port))
        // 		}
        // 	default:
        // 		return
        // 	}

        // 	// TODO(bradfitz): add singleflight+dnscache here.
        // 	addrs, _ := net.DefaultResolver.LookupIPAddr(ctx, n.HostName)
        // 	for _, a := range addrs {
        // 		if (a.IP.To4() != nil) == (proto == probeIPv4) {
        // 			na, _ := netip.AddrFromSlice(a.IP.To4())
        // 			return netip.AddrPortFrom(na.Unmap(), uint16(port))
        // 		}
        // 	}
        // 	return
    }
}

/// The protocol used to time a node's latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ProbeProto {
    /// STUN IPv4
    IPv4,
    /// STUN IPv6
    IPv6,
    /// HTTPS
    HTTPS,
}

#[derive(Debug, Clone)]
struct Probe {
    /// When the probe is started, relative to the time that `get_report` is called.
    /// One probe in each `ProbePlan` should have a delay of 0. Non-zero values
    /// are for retries on UDP loss or timeout.
    delay: Duration,

    /// The name of the node name. DERP node names are globally
    /// unique so there's no region ID.
    node: String,

    /// How the node should be probed.
    proto: ProbeProto,

    /// Hhow long to wait until the probe is considered failed.
    /// 0 means to use a default value.
    wait: Duration,
}

/// Describes a set of node probes to run.
/// The map key is a descriptive name, only used for tests.
///
/// The values are logically an unordered set of tests to run concurrently.
/// In practice there's some order to them based on their delay fields,
/// but multiple probes can have the same delay time or be running concurrently
/// both within and between sets.
///
/// A set of probes is done once either one of the probes completes, or
/// the next probe to run wouldn't yield any new information not
/// already discovered by any previous probe in any set.
#[derive(Debug, Default, Clone)]
struct ProbePlan(HashMap<String, Vec<Probe>>);

/// Returns the regions of dm first sorted from fastest to slowest (based on the 'last' report),
/// end in regions that have no data.
fn sort_regions<'a>(dm: &'a DerpMap, last: &Report) -> Vec<&'a DerpRegion> {
    let mut prev = Vec::with_capacity(dm.regions.len());
    /*for _, reg := range dm.Regions {
    if reg.Avoid {
        continue
    }
    prev = append(prev, reg)
    }
    sort.Slice(prev, func(i, j int) bool {
    da, db := last.RegionLatency[prev[i].RegionID], last.RegionLatency[prev[j].RegionID]
        if db == 0 && da != 0 {
        // Non-zero sorts before zero.
        return true
        }
    if da == 0 {
        // Zero can't sort before anything else.
        return false
    }
    return da < db
    })*/
    prev
}

/// The number of fastest regions to periodically re-query during incremental netcheck
/// reports. (During a full report, all regions are scanned.)
const NUM_INCREMENTAL_REGIONS: usize = 3;

/// Generates the probe plan for a `DerpMap`, given the most recent report and
/// whether IPv6 is configured on an interface.
fn make_probe_plan(dm: &DerpMap, if_state: &interfaces::State, last: &Report) -> ProbePlan {
    if last.region_latency.is_empty() {
        return make_probe_plan_initial(dm, if_state);
    }
    let have6if = if_state.have_v6;
    let have4if = if_state.have_v4;
    let mut plan = ProbePlan::default();
    if !have4if && !have6if {
        return plan;
    }
    let had4 = !last.region_v4_latency.is_empty();
    let had6 = !last.region_v6_latency.is_empty();
    let hadBoth = have6if && had4 && had6;
    // for ri, reg := range sortRegions(dm, last) {
    //     if ri == numIncrementalRegions {
    //     	break
    //     }
    //     var p4, p6 []probe
    //         let do4 = have4if;
    //     let do6 = have6if;

    //     // By default, each node only gets one STUN packet sent,
    //     // except the fastest two from the previous round.
    //     let tries = 1;
    //     let isFastestTwo = ri < 2;

    //     if isFastestTwo {
    //     	tries = 2;
    //     } else if hadBoth {
    //     	// For dual stack machines, make the 3rd & slower nodes alternate
    //     	// between.
    //     	if ri%2 == 0 {
    //     		do4, do6 = true, false
    //     	} else {
    //     		do4, do6 = false, true
    //     	}
    //     }
    //     if !isFastestTwo && !had6 {
    //     	do6 = false;
    //     }

    //     if reg.RegionID == last.PreferredDERP {
    //     	// But if we already had a DERP home, try extra hard to
    //     	// make sure it's there so we don't flip flop around.
    //     	tries = 4;
    //     }

    //     for try := 0; try < tries; try++ {
    //     	if len(reg.Nodes) == 0 {
    //     		// Shouldn't be possible.
    //     		continue;
    //     	}
    //     	if try != 0 && !had6 {
    //     		do6 = false;
    //     	}
    //         let n = reg.Nodes[try%len(reg.Nodes)];
    //         let prevLatency = last.RegionLatency[reg.RegionID] * 120 / 100;
    //         if prevLatency == 0 {
    //     	prevLatency = defaultActiveRetransmitTime;
    //         }
    //         delay := time.Duration(try) * prevLatency;
    //         if try > 1 {
    //     	delay += time.Duration(try) * 50 * time.Millisecond;
    //         }
    //         if do4 {
    //     	p4 = append(p4, probe{delay: delay, node: n.Name, proto: probeIPv4});
    //         }
    //         if do6 {
    //     	p6 = append(p6, probe{delay: delay, node: n.Name, proto: probeIPv6});
    //         }
    //     }
    //     if len(p4) > 0 {
    //         plan[fmt.Sprintf("region-%d-v4", reg.RegionID)] = p4;
    //     }
    //     if len(p6) > 0 {
    //         plan[fmt.Sprintf("region-%d-v6", reg.RegionID)] = p6;
    //     }
    // }
    plan
}

fn make_probe_plan_initial(dm: &DerpMap, if_state: &interfaces::State) -> ProbePlan {
    todo!()
    // 	plan = make(probePlan)

    // 	for _, reg := range dm.Regions {
    // 		var p4 []probe
    // 		var p6 []probe
    // 		for try := 0; try < 3; try++ {
    // 			n := reg.Nodes[try%len(reg.Nodes)]
    // 			delay := time.Duration(try) * defaultInitialRetransmitTime
    // 			if ifState.HaveV4 && nodeMight4(n) {
    // 				p4 = append(p4, probe{delay: delay, node: n.Name, proto: probeIPv4})
    // 			}
    // 			if ifState.HaveV6 && nodeMight6(n) {
    // 				p6 = append(p6, probe{delay: delay, node: n.Name, proto: probeIPv6})
    // 			}
    // 		}
    // 		if len(p4) > 0 {
    // 			plan[fmt.Sprintf("region-%d-v4", reg.RegionID)] = p4
    // 		}
    // 		if len(p6) > 0 {
    // 			plan[fmt.Sprintf("region-%d-v6", reg.RegionID)] = p6
    // 		}
    // 	}
    // 	return plan
}

/// Reports whether n might reply to STUN over IPv6 based on
/// its config alone, without DNS lookups. It only returns false if
/// it's not explicitly disabled.
fn node_might6(n: &DerpNode) -> bool {
    todo!()
    // if n.ipv6 == "" {
    //     return true;
    // }
    // ip, _ := netip.ParseAddr(n.IPv6);
    // return ip.Is6()
}

/// Reports whether n might reply to STUN over IPv4 based on
/// its config alone, without DNS lookups. It only returns false if
/// it's not explicitly disabled.
fn node_might4(n: &DerpNode) -> bool {
    todo!()
    // 	if n.IPv4 == "" {
    // 		return true
    // 	}
    // 	ip, _ := netip.ParseAddr(n.IPv4)
    // 	return ip.Is4()
}

/// Holds the state for a single invocation of `Client::get_report`.
struct ReportState {
    hair_tx: stun_rs::TransactionId,
    got_hair_stun: mpsc::Receiver<IpAddr>,
    // hairTimeout chan struct{} // closed on timeout
    pc4: Box<dyn StunConn>,
    pc6: Box<dyn StunConn>,
    pc4_hair: Box<dyn PacketConn>,
    incremental: bool, // doing a lite, follow-up netcheck
    // stopProbeCh chan struct{}
    // waitPortMap: sync.WaitGroup
    state: Mutex<InnerReportState>,
}

struct InnerReportState {
    sent_hair_check: bool,
    // to be returned by GetReport
    report: Report,
    // called without c.mu held
    in_flight: HashMap<stun::TransactionId, Box<dyn Fn(SocketAddr)>>,
    got_ep4: String,
    timers: Vec<Timeout<()>>,
}

impl ReportState {
    fn any_udp(&self) -> bool {
        todo!()
        // 	rs.mu.Lock()
        // 	defer rs.mu.Unlock()
        // 	return rs.report.UDP
    }

    fn have_region_latency(&self, region_id: usize) -> bool {
        todo!()
        // 	rs.mu.Lock()
        // 	defer rs.mu.Unlock()
        // 	_, ok := rs.report.RegionLatency[regionID]
        // 	return ok
    }

    /// Reports whether executing the given probe would yield any new information.
    /// The given node is provided just because the sole caller already has it
    /// and it saves a lookup.
    fn probe_would_help(&self, probe: Probe, node: DerpNode) -> bool {
        todo!()
        // 	rs.mu.Lock()
        // 	defer rs.mu.Unlock()

        // 	// If the probe is for a region we don't yet know about, that
        // 	// would help.
        // 	if _, ok := rs.report.RegionLatency[node.RegionID]; !ok {
        // 		return true
        // 	}

        // 	// If the probe is for IPv6 and we don't yet have an IPv6
        // 	// report, that would help.
        // 	if probe.proto == probeIPv6 && len(rs.report.RegionV6Latency) == 0 {
        // 		return true
        //      }

        // 	// For IPv4, we need at least two IPv4 results overall to
        // 	// determine whether we're behind a NAT that shows us as
        // 	// different source IPs and/or ports depending on who we're
        // 	// talking to. If we don't yet have two results yet
        // 	// (MappingVariesByDestIP is blank), then another IPv4 probe
        // 	// would be good.
        // 	if probe.proto == probeIPv4 && rs.report.MappingVariesByDestIP == "" {
        // 		return true
        // 	}

        // 	// Otherwise not interesting.
        // 	return false
    }

    fn start_hair_check_locked(&self, inner: &mut InnerReportState, dst: IpAddr) {
        todo!()
        // 	if rs.sentHairCheck || rs.incremental {
        // 		return
        // 	}
        // 	rs.sentHairCheck = true
        // 	rs.pc4Hair.WriteToUDPAddrPort(stun.Request(rs.hairTX), dst)
        // 	rs.c.vlogf("sent haircheck to %v", dst)
        // 	time.AfterFunc(hairpinCheckTimeout, func() { close(rs.hairTimeout) })
    }

    fn wait_hair_check(&self /*ctx context.Context*/) {
        todo!()
        // 	rs.mu.Lock()
        // 	defer rs.mu.Unlock()
        // 	ret := rs.report
        // 	if rs.incremental {
        // 		if rs.c.last != nil {
        // 			ret.HairPinning = rs.c.last.HairPinning
        // 		}
        // 		return
        // 	}
        // 	if !rs.sentHairCheck {
        // 		return
        // 	}

        // 	select {
        // 	case <-rs.gotHairSTUN:
        // 		ret.HairPinning.Set(true)
        // 	case <-rs.hairTimeout:
        // 		rs.c.vlogf("hairCheck timeout")
        // 		ret.HairPinning.Set(false)
        // 	default:
        // 		select {
        // 		case <-rs.gotHairSTUN:
        // 			ret.HairPinning.Set(true)
        // 		case <-rs.hairTimeout:
        // 			ret.HairPinning.Set(false)
        // 		case <-ctx.Done():
        // 		}
        // 	}
    }

    fn stop_timers(&self) {
        todo!()
        // 	rs.mu.Lock()
        // 	defer rs.mu.Unlock()
        // 	for _, t := range rs.timers {
        // 		t.Stop()
        // 	}
    }

    /// Updates rs to note that node's latency is d. If ipp
    /// is non-zero (for all but HTTPS replies), it's recorded as our UDP IP:port.
    fn add_node_latency(&self, node: &DerpNode, ipp: IpAddr, d: Duration) {
        todo!()
        // 	var ipPortStr string
        // 	if ipp != (netip.AddrPort{}) {
        // 		ipPortStr = net.JoinHostPort(ipp.Addr().String(), fmt.Sprint(ipp.Port()))
        // 	}

        // 	rs.mu.Lock()
        // 	defer rs.mu.Unlock()
        // 	ret := rs.report

        // 	ret.UDP = true
        // 	updateLatency(ret.RegionLatency, node.RegionID, d)

        // 	// Once we've heard from enough regions (3), start a timer to
        // 	// give up on the other ones. The timer's duration is a
        // 	// function of whether this is our initial full probe or an
        // 	// incremental one. For incremental ones, wait for the
        // 	// duration of the slowest region. For initial ones, double
        // 	// that.
        // 	if len(ret.RegionLatency) == rs.c.enoughRegions() {
        // 		timeout := maxDurationValue(ret.RegionLatency)
        // 		if !rs.incremental {
        // 			timeout *= 2
        // 		}
        // 		rs.timers = append(rs.timers, time.AfterFunc(timeout, rs.stopProbes))
        // 	}

        // 	switch {
        // 	case ipp.Addr().Is6():
        // 		updateLatency(ret.RegionV6Latency, node.RegionID, d)
        // 		ret.IPv6 = true
        // 		ret.GlobalV6 = ipPortStr
        // 		// TODO: track MappingVariesByDestIP for IPv6
        // 		// too? Would be sad if so, but who knows.
        // 	case ipp.Addr().Is4():
        // 		updateLatency(ret.RegionV4Latency, node.RegionID, d)
        // 		ret.IPv4 = true
        // 		if rs.gotEP4 == "" {
        // 			rs.gotEP4 = ipPortStr
        // 			ret.GlobalV4 = ipPortStr
        // 			rs.startHairCheckLocked(ipp)
        // 		} else {
        // 			if rs.gotEP4 != ipPortStr {
        // 				ret.MappingVariesByDestIP.Set(true)
        // 			} else if ret.MappingVariesByDestIP == "" {
        // 				ret.MappingVariesByDestIP.Set(false)
        // 			}
        // 		}
        // 	}
    }

    fn stop_probes(&self) {
        todo!()
        // 	select {
        // 	case rs.stopProbeCh <- struct{}{}:
        // 	default:
        // 	}
    }

    fn set_opt_bool(&self, b: Option<bool>, v: bool) {
        // 	rs.mu.Lock()
        // 	defer rs.mu.Unlock()
        // 	b.Set(v)
    }

    /// Starts probes for UPnP, PMP and PCP.
    fn probe_port_map_services(&self) {
        todo!()
        // 	defer rs.waitPortMap.Done()

        // 	rs.setOptBool(&rs.report.UPnP, false)
        // 	rs.setOptBool(&rs.report.PMP, false)
        // 	rs.setOptBool(&rs.report.PCP, false)

        // 	res, err := rs.c.PortMapper.Probe(context.Background())
        // 	if err != nil {
        // 		if !errors.Is(err, portmapper.ErrGatewayRange) {
        // 			// "skipping portmap; gateway range likely lacks support"
        // 			// is not very useful, and too spammy on cloud systems.
        // 			// If there are other errors, we want to log those.
        // 			rs.c.logf("probePortMapServices: %v", err)
        // 		}
        // 		return
        // 	}

        // 	rs.setOptBool(&rs.report.UPnP, res.UPnP)
        // 	rs.setOptBool(&rs.report.PMP, res.PMP)
        // 	rs.setOptBool(&rs.report.PCP, res.PCP)
    }

    fn run_probe(
        &self,
        /*ctx context.Context,*/ dm: &DerpMap,
        probe: Probe,
        cancel_set: (), /* func()*/
    ) {
        todo!()
        // 	c := rs.c
        // 	node := namedNode(dm, probe.node)
        // 	if node == nil {
        // 		c.logf("netcheck.runProbe: named node %q not found", probe.node)
        // 		return
        // 	}

        // 	if probe.delay > 0 {
        // 		delayTimer := time.NewTimer(probe.delay)
        // 		select {
        // 		case <-delayTimer.C:
        // 		case <-ctx.Done():
        // 			delayTimer.Stop()
        // 			return
        // 		}
        // 	}

        // 	if !rs.probeWouldHelp(probe, node) {
        // 		cancelSet()
        // 		return
        // 	}

        // 	addr := c.nodeAddr(ctx, node, probe.proto)
        // 	if !addr.IsValid() {
        // 		return
        // 	}

        // 	txID := stun.NewTxID()
        // 	req := stun.Request(txID)

        // 	sent := time.Now() // after DNS lookup above

        // 	rs.mu.Lock()
        // 	rs.inFlight[txID] = func(ipp netip.AddrPort) {
        // 		rs.addNodeLatency(node, ipp, time.Since(sent))
        // 		cancelSet() // abort other nodes in this set
        // 	}
        // 	rs.mu.Unlock()

        // 	switch probe.proto {
        // 	case probeIPv4:
        // 		metricSTUNSend4.Add(1)
        // 		n, err := rs.pc4.WriteToUDPAddrPort(req, addr)
        // 		if n == len(req) && err == nil || neterror.TreatAsLostUDP(err) {
        // 			rs.mu.Lock()
        // 			rs.report.IPv4CanSend = true
        // 			rs.mu.Unlock()
        // 		}
        // 	case probeIPv6:
        // 		metricSTUNSend6.Add(1)
        // 		n, err := rs.pc6.WriteToUDPAddrPort(req, addr)
        // 		if n == len(req) && err == nil || neterror.TreatAsLostUDP(err) {
        // 			rs.mu.Lock()
        // 			rs.report.IPv6CanSend = true
        // 			rs.mu.Unlock()
        // 		}
        // 	default:
        // 		panic("bad probe proto " + fmt.Sprint(probe.proto))
        // 	}
        // 	c.vlogf("sent to %v", addr)
    }
}

// var noRedirectClient = &http.Client{
// 	// No redirects allowed
// 	CheckRedirect: func(req *http.Request, via []*http.Request) error {
// 		return http.ErrUseLastResponse
// 	},

// 	// Remaining fields are the same as the default client.
// 	Transport: http.DefaultClient.Transport,
// 	Jar:       http.DefaultClient.Jar,
// 	Timeout:   http.DefaultClient.Timeout,
// }

fn update_latency(m: &mut HashMap<usize, Duration>, region_id: usize, d: Duration) {
    let mut prev = m.entry(region_id).or_insert(d);
    if d < *prev {
        *prev = d;
    }
}

fn named_node<'a>(dm: &'a DerpMap, node_name: &str) -> Option<&'a DerpNode> {
    for r in &dm.regions {
        for n in &r.nodes {
            if n.name == node_name {
                return Some(n);
            }
        }
    }
    None
}

fn region_has_derp_node(r: &DerpRegion) -> bool {
    for n in &r.nodes {
        if !n.stun_only {
            return true;
        }
    }

    false
}

fn max_duration_value(m: &HashMap<usize, Duration>) -> Option<Duration> {
    m.values().max().cloned()
}

// TODO: Metrics
// var (
// 	metricNumGetReport      = clientmetric.NewCounter("netcheck_report")
// 	metricNumGetReportFull  = clientmetric.NewCounter("netcheck_report_full")
// 	metricNumGetReportError = clientmetric.NewCounter("netcheck_report_error")

// 	metricSTUNSend4 = clientmetric.NewCounter("netcheck_stun_send_ipv4")
// 	metricSTUNSend6 = clientmetric.NewCounter("netcheck_stun_send_ipv6")
// 	metricSTUNRecv4 = clientmetric.NewCounter("netcheck_stun_recv_ipv4")
// 	metricSTUNRecv6 = clientmetric.NewCounter("netcheck_stun_recv_ipv6")
// 	metricHTTPSend  = clientmetric.NewCounter("netcheck_https_measure")
// )
