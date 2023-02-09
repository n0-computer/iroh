//! Checks the network conditions from the current host.
//! Based on https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go

// The various default timeouts for things.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use anyhow::Error;
use rand::seq::IteratorRandom;
use tokio::{
    net,
    sync::{self, mpsc, oneshot, Mutex},
    task::JoinSet,
    time::{self, Timeout},
};
use tracing::{debug, info};

use crate::hp::stun::to_canonical;

use super::{
    derp::{DerpMap, DerpNode, DerpRegion},
    interfaces,
    ping::Pinger,
    stun,
};

/// Fake DNS TLD used in tests for an invalid hostname.
const DOT_INVALID: &str = ".invalid";

// TODO: better type
pub trait PacketConn: Sync + Send {}

// The interface required by the netcheck Client when reusing an existing UDP connection.
pub trait StunConn: Sync + Send {
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
#[derive(Clone)]
pub struct Client {
    /// Enables verbose logging.
    pub verbose: bool,

    /// Controls whether the client should not try
    /// to reach things other than localhost. This is set to true
    /// in tests to avoid probing the local LAN's router, etc.
    pub skip_external_network: bool,

    /// If set, is the address to listen on for UDP.
    /// It defaults to ":0".
    pub udp_bind_addr: SocketAddr,

    // Used for portmap queries.
    // If `None`, portmap discovery is not done.
    pub port_mapper: Option<()>, // TODO*portmapper.Client // lazily initialized on first use

    reports: Arc<Mutex<Reports>>,
}

struct Reports {
    /// Do a full region scan, even if last is `Some`.
    next_full: bool,
    /// Some previous reports.
    prev: HashMap<SystemTime, Report>,
    /// Most recent report.
    last: Option<Report>,
    /// Time of last full (non-incremental) report.
    last_full: Instant,
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
    async fn read_packets(&self, pc: Arc<net::UdpSocket>) {
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

    fn udp_bind_addr_v6(&self) -> SocketAddr {
        if self.udp_bind_addr.is_ipv6() {
            return self.udp_bind_addr;
        }

        "[::1]:0".parse().unwrap()
    }

    fn udp_bind_addr_v4(&self) -> SocketAddr {
        if self.udp_bind_addr.is_ipv4() {
            return self.udp_bind_addr;
        }

        "0.0.0.0:0".parse().unwrap()
    }

    /// Gets a report.
    ///
    /// It may not be called concurrently with itself.
    pub async fn get_report(&mut self, dm: &DerpMap) -> Result<Report, Error> {
        // TODO
        // metricNumGetReport.Add(1)

        // Wrap in timeout
        let this = self.clone();
        let rs =
            time::timeout(OVERALL_PROBE_TIMEOUT, async move {
                let mut reports = this.reports.lock().await;
                if reports.cur_state.is_some() {
                    anyhow::bail!("invalid concurrent call to get_report");
                }

                // Create a UDP4 socket used for sending to our discovered IPv4 address.
                let pc4_hair = match net::UdpSocket::bind("0.0.0.0:0").await {
                    Ok(val) => val,
                    Err(_) => {
                        info!("udp4: failed to bind");
                        return Err(anyhow::anyhow!("failed to bind UDP v4"));
                    }
                };

                let mut rs = ReportState {
                    incremental: false,
                    pc4: None,
                    pc6: None,
                    pc4_hair: Arc::new(pc4_hair),
                    stop_probe: Arc::new(sync::Notify::new()),
                    wait_port_map: wg::AsyncWaitGroup::new(),
                    state: Arc::new(Mutex::new(InnerReportState {
                        sent_hair_check: false,
                        report: Report::default(),
                        in_flight: Default::default(),
                        got_ep4: None,
                        timers: Default::default(),
                    })),
                    hair_tx: stun::TransactionId::default(), // random payload
                    got_hair_stun: Arc::new(mpsc::channel(1)),
                };

                let mut last = reports.last.clone();

                // Even if we're doing a non-incremental update, we may want to try our
                // preferred DERP region for captive portal detection. Save that, if we have it.
                let preferred_derp = last.as_ref().map(|l| l.preferred_derp);
                let now = Instant::now();

                let mut do_full = false;
                if reports.next_full
                    || now.duration_since(reports.last_full) > Duration::from_secs(5 * 60)
                {
                    do_full = true;
                }

                // If the last report had a captive portal and reported no UDP access,
                // it's possible that we didn't get a useful netcheck due to the
                // captive portal blocking us. If so, make this report a full
                // (non-incremental) one.
                if !do_full {
                    if let Some(ref last) = last {
                        do_full = !last.udp && last.captive_portal.unwrap_or_default();
                    }
                }
                if do_full {
                    last = None; // causes makeProbePlan below to do a full (initial) plan
                    reports.next_full = false;
                    reports.last_full = now;

                    // TODO
                    // metricNumGetReportFull.Add(1);
                }

                rs.incremental = last.is_some();
                reports.cur_state = Some(rs.clone());
                drop(reports);

                // TODO: always clear `cur_state`
                // defer func() { c.curState = nil }()

                let if_state = interfaces::State::new();

                // See if IPv6 works at all, or if it's been hard disabled at the OS level.
                {
                    let v6udp = net::UdpSocket::bind("[::1]:0").await;
                    if v6udp.is_ok() {
                        let mut inner_report = rs.state.lock().await;

                        inner_report.report.os_has_ipv6 = true;
                    }
                }

                if !this.skip_external_network && this.port_mapper.is_some() {
                    let worker = rs.wait_port_map.add(1);
                    let rs = rs.clone();
                    tokio::task::spawn(async move {
                        rs.probe_port_map_services().await;
                        worker.done();
                    });
                }

                // At least the Apple Airport Extreme doesn't allow hairpin
                // sends from a private socket until it's seen traffic from
                // that src IP:port to something else out on the internet.
                //
                // See https://github.com/tailscale/tailscale/issues/188#issuecomment-600728643
                //
                // And it seems that even sending to a likely-filtered RFC 5737
                // documentation-only IPv4 range is enough to set up the mapping.
                // So do that for now. In the future we might want to classify networks
                // that do and don't require this separately. But for now help it.
                let documentation_ip: SocketAddr = "203.0.113.1:12345".parse().unwrap();

                rs.pc4_hair.send_to(
                    b"tailscale netcheck; see https://github.com/tailscale/tailscale/issues/188",
                    documentation_ip,
                ).await?;

                match net::UdpSocket::bind(this.udp_bind_addr_v4()).await {
                    Ok(u4) => {
                        let u4 = Arc::new(u4);
                        rs.pc4 = Some(u4.clone());
                        // TODO: track task
                        let this = this.clone();
                        tokio::task::spawn(async move { this.read_packets(u4).await });
                    }
                    Err(err) => {
                        info!("udp4: failed to bind");
                        return Err(anyhow::anyhow!("failed to bind UDP 4"));
                    }
                }

                if if_state.have_v6 {
                    match net::UdpSocket::bind(this.udp_bind_addr_v6()).await {
                        Ok(u6) => {
                            let u6 = Arc::new(u6);
                            rs.pc6 = Some(u6.clone());
                            // TODO: track task
                            let this = this.clone();
                            tokio::task::spawn(async move { this.read_packets(u6).await });
                        }
                        Err(err) => {
                            info!("udp6: failed to bind");
                            return Err(anyhow::anyhow!("failed to bind UDP 6"));
                        }
                    }
                }

                let plan = make_probe_plan(dm, &if_state, last.as_ref());

                // If we're doing a full probe, also check for a captive portal. We
                // delay by a bit to wait for UDP STUN to finish, to avoid the probe if
                // it's unnecessary.
                let (done_send, captive_portal_done) = oneshot::channel();
                let mut captive_task = None;
                if !rs.incremental {
                    // TODO: track task
                    let rs = rs.clone();
                    let delay = this.captive_portal_delay();
                    let dm = dm.clone(); // TODO: avoid or make cheap
                    captive_task = Some(tokio::task::spawn(async move {
                        // wait
                        time::sleep(delay).await;
                        match check_captive_portal(&dm, preferred_derp).await {
                            Ok(found) => {
                                rs.state.lock().await.report.captive_portal = Some(found);
                            }
                            Err(err) => {
                                info!("[v1] checkCaptivePortal: {:?}", err);
                            }
                        }
                        let _ = done_send.send(());
                    }));
                }

                let mut task_set = JoinSet::new();

                for probe_set in plan.values() {
                    for probe in probe_set {
                        let probe = probe.clone();
                        let rs = rs.clone();
                        let dm = dm.clone(); // TODO: avoid or make cheap
                        task_set.spawn(async move {
                            rs.run_probe(&dm, probe).await;
                        });
                    }
                }

                let stun_timer = time::sleep(STUN_PROBE_TIMEOUT);
                let probes_done = async move {
                    while let Some(t) = task_set.join_next().await {
                        t?;
                    }
                    Ok::<_, Error>(())
                };

                let probes_aborted = rs.stop_probe.clone();

                tokio::select! {
                    _ = stun_timer => {},
                    _ = probes_done => {
                        // All of our probes finished, so if we have >0 responses, we
                        // stop our captive portal check.
                        if rs.any_udp().await {
                            if let Some(task) = captive_task {
                                task.abort();
                            }
                        }
                    }
                    _ = probes_aborted.notified() => {
                        // Saw enough regions.
                        debug!("saw enough regions; not waiting for rest");
                        // We can stop the captive portal check since we know that we
                        // got a bunch of STUN responses.
                        if let Some(task) = captive_task {
                            task.abort();
                        }
                    }
                }

                rs.wait_hair_check().await;
                debug!("hair_check done");

                if !this.skip_external_network && this.port_mapper.is_some() {
                    rs.wait_port_map.wait().await;
                    debug!("port_map done");
                }

                rs.stop_timers().await;

                // Try HTTPS and ICMP latency check if all STUN probes failed due to
                // UDP presumably being blocked.
                // TODO: this should be moved into the probePlan, using probeProto probeHTTPS.
                if !rs.any_udp().await {
                    let mut task_set = JoinSet::new();
                    let mut need = Vec::new();

                    for (rid, reg) in dm.regions.iter().enumerate() {
                        if !rs.have_region_latency(rid).await && region_has_derp_node(reg) {
                            need.push(reg.clone()); // TODO: avoid clone
                        }
                    }
                    if !need.is_empty() {
                        // Kick off ICMP in parallel to HTTPS checks; we don't
                        // reuse the same WaitGroup for those probes because we
                        // need to close the underlying Pinger after a timeout
                        // or when all ICMP probes are done, regardless of
                        // whether the HTTPS probes have finished.
                        let rs = rs.clone();
                        let need = need.clone();
                        task_set.spawn(async move {
                            if let Err(err) = measure_all_icmp_latency(&rs, &need).await {
                                debug!("[v1] measureAllICMPLatency: {:?}", err);
                            }
                        });
                        debug!("netcheck: UDP is blocked, trying HTTPS");
                    }
                    for reg in need.into_iter() {
                        task_set.spawn(async move {
                            match measure_https_latency(&reg).await {
                                Ok((d, ip)) => {
                                    // rs.mu.Lock()
                                    //  if l, ok := rs.report.RegionLatency[reg.RegionID]; !ok {
                                    // 			mak.Set(&rs.report.RegionLatency, reg.RegionID, d)
                                    // 		} else if l >= d {
                                    // 			rs.report.RegionLatency[reg.RegionID] = d
                                    // 		}
                                    // 		// We set these IPv4 and IPv6 but they're not really used
                                    // 		// and we don't necessarily set them both. If UDP is blocked
                                    // 		// and both IPv4 and IPv6 are available over TCP, it's basically
                                    // 		// random which fields end up getting set here.
                                    // 		// Since they're not needed, that's fine for now.
                                    // 		if ip.Is4() {
                                    // 			rs.report.IPv4 = true
                                    // 		}
                                    // 		if ip.Is6() {
                                    // 			rs.report.IPv6 = true
                                    // 		}
                                    // 		rs.mu.Unlock()
                                    // 	}
                                }
                                Err(err) => {
                                    debug!(
                                        "[v1] netcheck: measuring HTTPS latency of {} ({}): {:?}",
                                        reg.region_code, reg.region_id, err
                                    );
                                }
                            }
                        });
                    }
                    while let Some(t) = task_set.join_next().await {
                        t?;
                    }
                }
                // Wait for captive portal check before finishing the report.
                captive_portal_done.await?;

                Ok(rs)
            })
            .await??;
        let report = self.finish_and_store_report(&rs, dm).await;
        Ok(report)
    }

    async fn finish_and_store_report(&self, rs: &ReportState, dm: &DerpMap) -> Report {
        let mut report = rs.state.lock().await.report.clone();
        self.add_report_history_and_set_preferred_derp(&mut report);
        self.log_concise_report(&report, dm);

        report
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
}

async fn measure_https_latency(
    /*ctx context.Context,*/ reg: &DerpRegion,
) -> Result<(Duration, IpAddr), ()> {
    todo!()
    // TODO:
    // - needs derphttp::Client
    // - measurement hooks to measure server processing time

    // metricHTTPSend.Add(1)
    // let ctx, cancel := context.WithTimeout(httpstat.WithHTTPStat(ctx, &result), overallProbeTimeout);
    // let dc := derphttp.NewNetcheckClient(c.logf);
    // let tlsConn, tcpConn, node := dc.DialRegionTLS(ctx, reg)?;
    // if ta, ok := tlsConn.RemoteAddr().(*net.TCPAddr);
    // req, err := http.NewRequestWithContext(ctx, "GET", "https://"+node.HostName+"/derp/latency-check", nil);
    // resp, err := hc.Do(req);

    // // DERPs should give us a nominal status code, so anything else is probably
    // // an access denied by a MITM proxy (or at the very least a signal not to
    // // trust this latency check).
    // if resp.StatusCode > 299 {
    //     return 0, ip, fmt.Errorf("unexpected status code: %d (%s)", resp.StatusCode, resp.Status)
    // }
    // _, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10));
    // result.End(c.timeNow())

    // // TODO: decide best timing heuristic here.
    // // Maybe the server should return the tcpinfo_rtt?
    // return result.ServerProcessing, ip, nil
}

async fn measure_all_icmp_latency(rs: &ReportState, need: &[DerpRegion]) -> Result<(), Error> {
    if need.is_empty() {
        return Ok(());
    }
    info!("UDP is blocked, trying ICMP");

    time::timeout(ICMP_PROBE_TIMEOUT, async move {
        let p = Pinger::new()?;

        let mut tasks = JoinSet::new();
        for reg in need {
            let p = p.clone();
            let reg = reg.clone(); // TODO: avoid
            let rs = rs.clone(); // TODO: avoid
            tasks.spawn(async move {
                match measure_icmp_latency(&reg, &p).await {
                    Err(err) => {
                        info!(
                            "[v1] measuring ICMP latency of {} ({}): {:?}",
                            reg.region_code, reg.region_id, err
                        )
                    }
                    Ok(d) => {
                        info!(
                            "[v1] ICMP latency of {} ({}): {:?}",
                            reg.region_code, reg.region_id, d
                        );
                        let mut rsl = rs.state.lock().await;
                        let l = rsl.report.region_latency.entry(reg.region_id).or_insert(d);
                        if *l >= d {
                            *l = d;
                        }
                        // We only send IPv4 ICMP right now
                        rsl.report.ipv4 = true;
                        rsl.report.icmpv4 = true;
                    }
                }
            });
        }

        while let Some(t) = tasks.join_next().await {
            t?;
        }
        Ok::<_, Error>(())
    })
    .await??;

    Ok(())
}

/// Reports whether or not we think the system is behind a
/// captive portal, detected by making a request to a URL that we know should
/// return a "204 No Content" response and checking if that's what we get.
///
/// The boolean return is whether we think we have a captive portal.
async fn check_captive_portal(dm: &DerpMap, preferred_derp: Option<usize>) -> Result<bool, Error> {
    // If we have a preferred DERP region with more than one node, try
    // that; otherwise, pick a random one not marked as "Avoid".
    let preferred_derp = if preferred_derp.is_none()
        || dm.regions.get(preferred_derp.unwrap()).is_none()
        || (preferred_derp.is_some() && dm.regions[preferred_derp.unwrap()].nodes.is_empty())
    {
        let mut rids = Vec::with_capacity(dm.regions.len());
        for (id, reg) in dm.regions.iter().enumerate() {
            if reg.avoid || reg.nodes.is_empty() {
                continue;
            }
            rids.push(id);
        }

        if rids.is_empty() {
            return Ok(false);
        }
        (0..rids.len())
            .into_iter()
            .choose(&mut rand::thread_rng())
            .unwrap_or_default()
    } else {
        preferred_derp.unwrap()
    };

    // Has a node, as we filtered out regions without nodes above.
    let node = &dm.regions[preferred_derp].nodes[0];

    if node.host_name.ends_with(&DOT_INVALID) {
        // Don't try to connect to invalid hostnames. This occurred in tests:
        // https://github.com/tailscale/tailscale/issues/6207
        // TODO(bradfitz,andrew-d): how to actually handle this nicely?
        return Ok(false);
    }

    let client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // Note: the set of valid characters in a challenge and the total
    // length is limited; see isChallengeChar in cmd/derper for more
    // details.
    let chal = format!("ts_{}", node.host_name);

    let res = client
        .request(
            reqwest::Method::GET,
            format!("http://{}/generate_204", node.host_name),
        )
        .header("X-Tailscale-Challenge", &chal)
        .send()
        .await?;

    let expected_response = format!("response {chal}");
    let is_valid_response = res
        .headers()
        .get("X-Tailscale-Response")
        .map(|s| s.to_str().unwrap_or_default())
        == Some(&expected_response);

    info!(
        "[v2] checkCaptivePortal url={} status_code={} valid_response={}",
        res.url(),
        res.status(),
        is_valid_response,
    );
    let has_captive = res.status() != 204 || !is_valid_response;

    Ok(has_captive)
}
async fn measure_icmp_latency(reg: &DerpRegion, p: &Pinger) -> Result<Duration, Error> {
    if reg.nodes.is_empty() {
        anyhow::bail!(
            "no nodes for region {} ({})",
            reg.region_id,
            reg.region_code
        );
    }

    // Try pinging the first node in the region
    let node = &reg.nodes[0];

    // Get the IPAddr by asking for the UDP address that we would use for
    // STUN and then using that IP.
    let node_addr = get_node_addr(/*ctx,*/ node, ProbeProto::IPv4)
        .await
        .ok_or_else(|| anyhow::anyhow!("no address for node {}", node.name))?;

    // Use the unique node.name field as the packet data to reduce the
    // likelihood that we get a mismatched echo response.
    p.send(node_addr, node.name.as_bytes()).await
}

/// Proto must V4 or V6. If it returns `None`, the node is skipped.
async fn get_node_addr(n: &DerpNode, proto: ProbeProto) -> Option<SocketAddr> {
    let mut port = n.stun_port;
    if port == 0 {
        port = 3478;
    }
    if let Some(ip) = n.stun_test_ip {
        if proto == ProbeProto::IPv4 && ip.is_ipv6() {
            return None;
        }
        if proto == ProbeProto::IPv6 && ip.is_ipv4() {
            return None;
        }
        return Some(SocketAddr::new(ip, port));
    }

    match proto {
        ProbeProto::IPv4 => {
            if let Some(ip) = n.ipv4 {
                return Some(SocketAddr::new(IpAddr::V4(ip), port));
            }
        }
        ProbeProto::IPv6 => {
            if let Some(ip) = n.ipv6 {
                return Some(SocketAddr::new(IpAddr::V6(ip), port));
            }
        }
        _ => {
            return None;
        }
    }

    // TODO: add singleflight+dnscache here.
    if let Ok(addrs) = dns_lookup(&n.host_name).await {
        for addr in addrs {
            if addr.is_ipv4() && proto == ProbeProto::IPv4 {
                let addr = to_canonical(addr);
                return Some(SocketAddr::new(addr, port));
            }
        }
    }

    None
}

async fn dns_lookup(host: &str) -> Result<trust_dns_resolver::lookup_ip::LookupIp, Error> {
    // TODO: dnscache

    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let response = resolver.lookup_ip(host).await?;

    Ok(response)
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

impl Deref for ProbePlan {
    type Target = HashMap<String, Vec<Probe>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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
fn make_probe_plan(dm: &DerpMap, if_state: &interfaces::State, last: Option<&Report>) -> ProbePlan {
    if last.is_none() || last.unwrap().region_latency.is_empty() {
        return make_probe_plan_initial(dm, if_state);
    }
    let last = last.unwrap();
    let have6if = if_state.have_v6;
    let have4if = if_state.have_v4;
    let mut plan = ProbePlan::default();
    if !have4if && !have6if {
        return plan;
    }
    let had4 = !last.region_v4_latency.is_empty();
    let had6 = !last.region_v6_latency.is_empty();
    let had_both = have6if && had4 && had6;
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
#[derive(Clone)]
struct ReportState {
    hair_tx: stun_rs::TransactionId,
    got_hair_stun: Arc<(mpsc::Sender<IpAddr>, mpsc::Receiver<IpAddr>)>,
    // hairTimeout chan struct{} // closed on timeout
    pc4: Option<Arc<net::UdpSocket>>,
    pc6: Option<Arc<net::UdpSocket>>,
    pc4_hair: Arc<net::UdpSocket>,
    incremental: bool, // doing a lite, follow-up netcheck
    stop_probe: Arc<sync::Notify>,
    wait_port_map: wg::AsyncWaitGroup,
    state: Arc<Mutex<InnerReportState>>,
}

struct InnerReportState {
    sent_hair_check: bool,
    // to be returned by GetReport
    report: Report,
    // called without c.mu held
    in_flight: HashMap<stun::TransactionId, Box<dyn Fn(SocketAddr) + Sync + Send>>,
    got_ep4: Option<String>,
    timers: Vec<Timeout<()>>,
}

impl ReportState {
    async fn any_udp(&self) -> bool {
        self.state.lock().await.report.udp
    }

    async fn have_region_latency(&self, region_id: usize) -> bool {
        self.state
            .lock()
            .await
            .report
            .region_latency
            .contains_key(&region_id)
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

    async fn wait_hair_check(&self /*ctx context.Context*/) {
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

    async fn stop_timers(&self) {
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
    async fn probe_port_map_services(&self) {
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

    async fn run_probe(&self, /*ctx context.Context,*/ dm: &DerpMap, probe: Probe) {
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
