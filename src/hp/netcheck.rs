//! Checks the network conditions from the current host.
//! Based on https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go

use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    sync::Arc,
};

use anyhow::{ensure, Context, Error};
use async_time_mock_tokio::Instant;
use futures::{future::BoxFuture, FutureExt};
use rand::seq::IteratorRandom;
use tokio::{
    net,
    sync::{self, mpsc, oneshot, Mutex, RwLock},
    task::JoinSet,
    time::Duration,
};
use tracing::{debug, info};

use crate::hp::stun::to_canonical;

use super::{
    clock::Clock,
    derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6},
    interfaces,
    ping::Pinger,
    portmapper::PortMapper,
    stun,
};

/// Fake DNS TLD used in tests for an invalid hostname.
const DOT_INVALID: &str = ".invalid";

// The various default timeouts for things.

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

#[derive(Default, Debug, Clone)]
pub struct Report(Arc<RwLock<InnerReport>>);

#[derive(Default, Debug, PartialEq, Eq)]
struct InnerReport {
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
    pub region_v6_latency: HashMap<usize, Duration>,

    /// ip:port of global IPv4
    pub global_v4: Option<SocketAddr>,
    /// [ip]:port of global IPv6
    pub global_v6: Option<SocketAddr>,

    /// CaptivePortal is set when we think there's a captive portal that is
    /// intercepting HTTP traffic.
    pub captive_portal: Option<bool>,
}

impl InnerReport {
    /// Reports whether any of UPnP, PMP, or PCP are non-empty.
    pub fn any_port_mapping_checked(&self) -> bool {
        self.upnp.is_some() || self.pmp.is_some() || self.pcp.is_some()
    }
}

/// Generates a netcheck [`Report`].
#[derive(Clone, Debug)]
pub struct Client {
    /// Controls whether the client should not try
    /// to reach things other than localhost. This is set to true
    /// in tests to avoid probing the local LAN's router, etc.
    pub skip_external_network: bool,

    /// If set, is the address to listen on for UDP.
    /// It defaults to ":0".
    pub udp_bind_addr: SocketAddr,

    // Used for portmap queries.
    // If `None`, portmap discovery is not done.
    pub port_mapper: Option<PortMapper>,

    clock: Clock,

    reports: Arc<Mutex<Reports>>,
}

#[derive(Debug)]
struct Reports {
    /// Do a full region scan, even if last is `Some`.
    next_full: bool,
    /// Some previous reports.
    prev: HashMap<Instant, Report>,
    /// Most recent report.
    last: Option<Report>,
    /// Time of last full (non-incremental) report.
    last_full: Instant,
    /// `Some` if we're in a call to `get_report`.
    cur_state: Option<ReportState>,
}

const ENOUGH_REGIONS: usize = 3;
// Chosen semi-arbitrarily
const CAPTIVE_PORTAL_DELAY: Duration = Duration::from_millis(200);

impl Default for Client {
    fn default() -> Self {
        let clock = Clock::default();
        let last_full = clock.now();

        Client {
            skip_external_network: false,
            udp_bind_addr: "0.0.0.0:0".parse().unwrap(),
            port_mapper: None,
            clock,
            reports: Arc::new(Mutex::new(Reports {
                next_full: false,
                prev: Default::default(),
                last: None,
                last_full,
                cur_state: None,
            })),
        }
    }
}

impl Client {
    /// Reports whether `pkt` (from `src`) was our magic hairpin probe packet that we sent to ourselves.
    async fn handle_hair_stun_locked(
        &self,
        pkt: &[u8],
        src: SocketAddr,
        hs_s: mpsc::Sender<SocketAddr>,
    ) -> bool {
        let reports = &*self.reports.lock().await;
        if let Some(ref rs) = reports.cur_state {
            if let Ok(tx) = stun::parse_binding_request(pkt) {
                if tx == rs.hair_tx {
                    hs_s.send(src).await.ok();
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

    async fn receive_stun_packet(
        &self,
        pkt: &[u8],
        src: SocketAddr,
        hs_s: mpsc::Sender<SocketAddr>,
    ) {
        debug!("received STUN packet from {}", src);

        if src.is_ipv4() {
            // TODO:
            // metricSTUNRecv4.Add(1)
        } else if src.is_ipv6() {
            // TODO:
            // metricSTUNRecv6.Add(1)
        }

        if self.handle_hair_stun_locked(pkt, src, hs_s).await {
            return;
        }
        if self.reports.lock().await.cur_state.is_none() {
            return;
        }

        let res = stun::parse_response(pkt);
        if let Err(err) = res {
            if stun::parse_binding_request(pkt).is_ok() {
                // This was probably our own netcheck hairpin
                // check probe coming in late. Ignore.
                return;
            }
            info!(
                "received unexpected STUN message response from {}: {:?}",
                src, err
            );
            return;
        };
        let (tx, addr_port) = res.unwrap();

        let mut reports = self.reports.lock().await;
        if let Some(ref mut rs) = reports.cur_state {
            // TODO: avoid lock
            let mut rs_state = rs.state.lock().await;
            if let Some(on_done) = rs_state.in_flight.remove(&tx) {
                drop(rs_state);
                drop(reports);
                on_done(addr_port).await;
            }
        }
    }

    /// Reads STUN packets from pc until there's an error. In either case, it closes `pc`.
    async fn read_packets(&self, pc: Arc<net::UdpSocket>, hs_s: mpsc::Sender<SocketAddr>) {
        let mut buf = vec![0u8; 64 << 10];
        loop {
            match pc.recv_from(&mut buf).await {
                Err(err) => {
                    info!("ReadFrom: {:?}", err);
                    break;
                }
                Ok((n, mut addr)) => {
                    let pkt = &buf[..n];
                    if !stun::is(pkt) {
                        // ignore non stun packets
                        continue;
                    }
                    addr.set_ip(to_canonical(addr.ip()));
                    self.receive_stun_packet(pkt, addr, hs_s.clone()).await;
                }
            }
        }
        // TODO: close pc
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
        let report = self
            .clock
            .timeout(OVERALL_PROBE_TIMEOUT, self.clone().get_report_inner(dm))
            .await??;
        let report = self.finish_and_store_report(&report, dm).await;
        Ok(report)
    }

    async fn get_report_inner(&mut self, dm: &DerpMap) -> Result<ReportState, Error> {
        let mut reports = self.reports.lock().await;
        ensure!(
            reports.cur_state.is_none(),
            "invalid concurrent call to get_report"
        );

        // Create a UDP4 socket used for sending to our discovered IPv4 address.
        let pc4_hair = net::UdpSocket::bind("0.0.0.0:0")
            .await
            .context("udp4: failed to bind")?;

        let (got_hair_stun_s, got_hair_stun_r) = mpsc::channel(1);
        let mut rs = ReportState {
            incremental: false,
            pc4: None,
            pc6: None,
            pc4_hair: Arc::new(pc4_hair),
            hair_timeout: Arc::new(sync::Notify::new()),
            stop_probe: Arc::new(sync::Notify::new()),
            wait_port_map: wg::AsyncWaitGroup::new(),
            report: Report::default(),
            state: Arc::new(Mutex::new(InnerReportState {
                sent_hair_check: false,
                in_flight: Default::default(),
                got_ep4: None,
                timers: Default::default(),
            })),
            clock: self.clock.clone(),
            hair_tx: stun::TransactionId::default(), // random payload
            got_hair_stun: Arc::new(Mutex::new(got_hair_stun_r)),
        };

        let mut last = reports.last.clone();

        // Even if we're doing a non-incremental update, we may want to try our
        // preferred DERP region for captive portal detection. Save that, if we have it.
        let preferred_derp = if let Some(ref last) = last {
            Some(last.0.read().await.preferred_derp)
        } else {
            None
        };
        let now = self.clock.now();

        let mut do_full = false;
        if reports.next_full || now.duration_since(reports.last_full) > Duration::from_secs(5 * 60)
        {
            do_full = true;
        }

        // If the last report had a captive portal and reported no UDP access,
        // it's possible that we didn't get a useful netcheck due to the
        // captive portal blocking us. If so, make this report a full
        // (non-incremental) one.
        if !do_full {
            if let Some(ref last) = last {
                let last = last.0.read().await;
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
                rs.report.0.write().await.os_has_ipv6 = true;
            }
        }

        if !self.skip_external_network {
            if let Some(ref port_mapper) = self.port_mapper {
                let worker = rs.wait_port_map.add(1);
                let rs = rs.clone();
                let port_mapper = port_mapper.clone();
                tokio::task::spawn(async move {
                    rs.probe_port_map_services(port_mapper).await;
                    worker.done();
                });
            }
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

        rs.pc4_hair
            .send_to(
                b"tailscale netcheck; see https://github.com/tailscale/tailscale/issues/188",
                documentation_ip,
            )
            .await?;

        {
            let u4 = net::UdpSocket::bind(self.udp_bind_addr_v4())
                .await
                .context("udp4: failed to bind")?;
            let u4 = Arc::new(u4);
            rs.pc4 = Some(u4.clone());
            // TODO: track task
            let this = self.clone();
            let got_hair_stun_s = got_hair_stun_s.clone();
            tokio::task::spawn(async move { this.read_packets(u4, got_hair_stun_s).await });
        }

        if if_state.have_v6 {
            let u6 = net::UdpSocket::bind(self.udp_bind_addr_v6())
                .await
                .context("udp6: failed to bind")?;
            let u6 = Arc::new(u6);
            rs.pc6 = Some(u6.clone());
            // TODO: track task
            let this = self.clone();
            let got_hair_stun_s = got_hair_stun_s.clone();
            tokio::task::spawn(async move { this.read_packets(u6, got_hair_stun_s).await });
        }

        let plan = make_probe_plan(dm, &if_state, last.as_ref()).await;

        // If we're doing a full probe, also check for a captive portal. We
        // delay by a bit to wait for UDP STUN to finish, to avoid the probe if
        // it's unnecessary.
        let (done_send, captive_portal_done) = oneshot::channel();
        let mut captive_task = None;
        if !rs.incremental {
            // TODO: track task
            let rs = rs.clone();
            let delay = CAPTIVE_PORTAL_DELAY;
            let dm = dm.clone(); // TODO: avoid or make cheap
            let clock = self.clock.clone();
            captive_task = Some(tokio::task::spawn(async move {
                // wait
                clock.sleep(delay).await;
                match check_captive_portal(&dm, preferred_derp).await {
                    Ok(found) => {
                        rs.report.0.write().await.captive_portal = Some(found);
                    }
                    Err(err) => {
                        info!("check_captive_portal error: {:?}", err);
                    }
                }
                let _ = done_send.send(());
            }));
        }

        let mut task_set = JoinSet::new();
        let probe_done = Arc::new(sync::Notify::new());
        for probe_set in plan.values() {
            for probe in probe_set {
                let probe = probe.clone();
                let rs = rs.clone();
                let dm = dm.clone(); // TODO: avoid or make cheap
                let probe_done = probe_done.clone();
                task_set.spawn(async move {
                    let notified = probe_done.notified();
                    rs.run_probe(&dm, probe, probe_done.clone()).await;
                    // wait for the probe to actually finish
                    notified.await;
                });
            }
        }

        let stun_timer = self.clock.sleep(STUN_PROBE_TIMEOUT);
        let probes_done = async move {
            while let Some(t) = task_set.join_next().await {
                t?;
            }
            Ok::<_, Error>(())
        };

        let probes_aborted = rs.stop_probe.clone();

        tokio::select! {
            _ = stun_timer => {
                debug!("STUN timer expired");
            },
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

        {
            let reports = self.reports.lock().await;
            rs.wait_hair_check(reports.last.as_ref()).await;
            debug!("hair_check done");
        }

        if !self.skip_external_network && self.port_mapper.is_some() {
            rs.wait_port_map.wait().await;
            debug!("port_map done");
        }

        rs.stop_timers().await;

        // Try HTTPS and ICMP latency check if all STUN probes failed due to
        // UDP presumably being blocked.
        // TODO: this should be moved into the probePlan, using probeProto probeHTTPS.
        if !rs.any_udp().await {
            debug!("UDP is likely blocked, probing HTTPS & ICMP");
            let mut task_set = JoinSet::new();
            let mut need = Vec::new();

            for (rid, reg) in dm.regions.iter() {
                if !rs.have_region_latency(*rid).await && region_has_derp_node(reg) {
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
                let clock = self.clock.clone();
                task_set.spawn(async move {
                    if let Err(err) = measure_all_icmp_latency(&rs, &need, &clock).await {
                        debug!("measure_all_icmp_latency: {:?}", err);
                    }
                });
                debug!("UDP is blocked, trying HTTPS");
            }
            for reg in need.into_iter() {
                let rs = rs.clone();
                task_set.spawn(async move {
                    match measure_https_latency(&reg).await {
                        Ok((d, ip)) => {
                            let mut report = rs.report.0.write().await;
                            let l = report.region_latency.entry(reg.region_id).or_insert(d);
                            if *l >= d {
                                *l = d;
                            }
                            // We set these IPv4 and IPv6 but they're not really used
                            // and we don't necessarily set them both. If UDP is blocked
                            // and both IPv4 and IPv6 are available over TCP, it's basically
                            // random which fields end up getting set here.
                            // Since they're not needed, that's fine for now.
                            if ip.is_ipv4() {
                                report.ipv4 = true
                            }
                            if ip.is_ipv6() {
                                report.ipv6 = true
                            }
                        }
                        Err(err) => {
                            debug!(
                                "measuring HTTPS latency of {} ({}): {:?}",
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
        // If the task is aborted, this will error, so ignore potential task joining errors.
        captive_portal_done.await.ok();

        Ok(rs)
    }

    async fn finish_and_store_report(&self, rs: &ReportState, dm: &DerpMap) -> Report {
        let mut report = rs.report.clone();
        self.add_report_history_and_set_preferred_derp(&mut report)
            .await;
        self.log_concise_report(&report, dm).await;

        report
    }

    async fn log_concise_report(&self, r: &Report, dm: &DerpMap) {
        let r = &*r.0.read().await;
        let mut log = "report: ".to_string();
        log += &format!("udp={}", r.udp);
        if !r.ipv4 {
            log += &format!(" v4={}", r.ipv4)
        }
        if !r.udp {
            log += &format!(" icmpv4={}", r.icmpv4)
        }

        log += &format!(" v6={}", r.ipv6);
        if !r.ipv6 {
            log += &format!(" v6os={}", r.os_has_ipv6);
        }
        log += &format!(" mapvarydest={:?}", r.mapping_varies_by_dest_ip);
        log += &format!(" hair={:?}", r.hair_pinning);
        if r.any_port_mapping_checked() {
            log += &format!(
                " portmap={{ UPnP: {:?}, PMP: {:?}, PCP: {:?} }}",
                r.upnp, r.pmp, r.pcp
            );
        } else {
            log += " portmap=?";
        }
        if let Some(ipp) = r.global_v4 {
            log += &format!(" v4a={}", ipp);
        }
        if let Some(ipp) = r.global_v6 {
            log += &format!(" v6a={}", ipp);
        }
        if let Some(c) = r.captive_portal {
            log += &format!(" captiveportal={}", c);
        }
        log += &format!(" derp={}", r.preferred_derp);
        if r.preferred_derp != 0 {
            log += " derpdist=";
            let mut need_comma = false;
            for rid in &dm.region_ids() {
                if let Some(d) = r.region_v4_latency.get(rid) {
                    if need_comma {
                        log += ",";
                    }
                    log += &format!("{}v4:{}", rid, d.as_millis());
                    need_comma = true;
                }
                if let Some(d) = r.region_v6_latency.get(rid) {
                    if need_comma {
                        log += ",";
                    }
                    log += &format!("{}v6:{}", rid, d.as_millis());
                    need_comma = true;
                }
            }
        }

        info!("{}", log);
    }

    /// Adds `r` to the set of recent Reports and mutates `r.preferred_derp` to contain the best recent one.
    async fn add_report_history_and_set_preferred_derp(&self, r: &mut Report) {
        let mut reports = self.reports.lock().await;
        let mut prev_derp = 0;
        if let Some(ref last) = reports.last {
            prev_derp = last.0.read().await.preferred_derp;
        }
        let now = self.clock.now();

        reports.prev.insert(now, r.clone());
        reports.last = Some(r.clone());

        const MAX_AGE: Duration = Duration::from_secs(5 * 60);

        // region ID => its best recent latency in last MAX_AGE
        let mut best_recent = HashMap::new();

        let mut to_remove = Vec::new();
        for (t, pr) in &reports.prev {
            if dbg!(now.duration_since(*t)) > MAX_AGE {
                to_remove.push(dbg!(*t));
                continue;
            }
            let pr = pr.0.read().await;
            for (region_id, d) in &pr.region_latency {
                let bd = best_recent.entry(*region_id).or_insert(*d);
                if d < bd {
                    *bd = *d;
                }
            }
        }

        for t in to_remove {
            reports.prev.remove(&t);
        }

        // Then, pick which currently-alive DERP server from the
        // current report has the best latency over the past MAX_AGE.
        let mut best_any = Duration::default();
        let mut old_region_cur_latency = Duration::default();
        {
            let r = &mut *r.0.write().await;
            for (region_id, d) in &r.region_latency {
                if *region_id == prev_derp {
                    old_region_cur_latency = *d;
                }
                let best = *best_recent.get(region_id).unwrap();
                if r.preferred_derp == 0 || best < best_any {
                    best_any = best;
                    r.preferred_derp = *region_id;
                }
            }

            // If we're changing our preferred DERP but the old one's still
            // accessible and the new one's not much better, just stick with
            // where we are.
            if prev_derp != 0
                && r.preferred_derp != prev_derp
                && !old_region_cur_latency.is_zero()
                && best_any > old_region_cur_latency / 3 * 2
            {
                r.preferred_derp = prev_derp;
            }
        }
    }
}

async fn measure_https_latency(_reg: &DerpRegion) -> Result<(Duration, IpAddr), ()> {
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

async fn measure_all_icmp_latency(
    rs: &ReportState,
    need: &[DerpRegion],
    clock: &Clock,
) -> Result<(), Error> {
    if need.is_empty() {
        return Ok(());
    }
    info!("UDP is blocked, trying ICMP");

    clock
        .timeout(ICMP_PROBE_TIMEOUT, async move {
            let p = Pinger::new().await?;

            let mut tasks = JoinSet::new();
            for reg in need {
                let p = p.clone();
                let reg = reg.clone(); // TODO: avoid
                let rs = rs.clone(); // TODO: avoid
                tasks.spawn(async move {
                    match measure_icmp_latency(&reg, &p).await {
                        Err(err) => {
                            info!(
                                "measuring ICMP latency of {} ({}): {:?}",
                                reg.region_code, reg.region_id, err
                            )
                        }
                        Ok(d) => {
                            info!(
                                "ICMP latency of {} ({}): {:?}",
                                reg.region_code, reg.region_id, d
                            );
                            let mut report = rs.report.0.write().await;
                            let l = report.region_latency.entry(reg.region_id).or_insert(d);
                            if *l >= d {
                                *l = d;
                            }
                            // We only send IPv4 ICMP right now
                            report.ipv4 = true;
                            report.icmpv4 = true;
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
        || dm.regions.get(&preferred_derp.unwrap()).is_none()
        || (preferred_derp.is_some()
            && dm
                .regions
                .get(&preferred_derp.unwrap())
                .unwrap()
                .nodes
                .is_empty())
    {
        let mut rids = Vec::with_capacity(dm.regions.len());
        for (id, reg) in dm.regions.iter() {
            if reg.avoid || reg.nodes.is_empty() {
                continue;
            }
            rids.push(id);
        }

        if rids.is_empty() {
            return Ok(false);
        }

        let i = (0..rids.len())
            .into_iter()
            .choose(&mut rand::thread_rng())
            .unwrap_or_default();
        *rids[i]
    } else {
        preferred_derp.unwrap()
    };

    // Has a node, as we filtered out regions without nodes above.
    let node = &dm.regions.get(&preferred_derp).unwrap().nodes[0];

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
    let node_addr = get_node_addr(node, ProbeProto::IPv4)
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
            if let UseIpv4::Some(ip) = n.ipv4 {
                return Some(SocketAddr::new(IpAddr::V4(ip), port));
            }
        }
        ProbeProto::IPv6 => {
            if let UseIpv6::Some(ip) = n.ipv6 {
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

    /// How long to wait until the probe is considered failed.
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
fn sort_regions<'a>(dm: &'a DerpMap, last: &InnerReport) -> Vec<&'a DerpRegion> {
    let mut prev: Vec<_> = dm.regions.values().filter(|r| !r.avoid).collect();
    prev.sort_by(|a, b| {
        let da = last.region_latency.get(&a.region_id);
        let db = last.region_latency.get(&b.region_id);
        if db.is_none() && da.is_some() {
            // Non-zero sorts before zero.
            return Ordering::Greater;
        }
        if da.is_none() {
            // Zero can't sort before anything else.
            return Ordering::Less;
        }
        da.cmp(&db)
    });

    prev
}

/// The number of fastest regions to periodically re-query during incremental netcheck
/// reports. (During a full report, all regions are scanned.)
const NUM_INCREMENTAL_REGIONS: usize = 3;

/// Generates the probe plan for a `DerpMap`, given the most recent report and
/// whether IPv6 is configured on an interface.
async fn make_probe_plan(
    dm: &DerpMap,
    if_state: &interfaces::State,
    last: Option<&Report>,
) -> ProbePlan {
    if last.is_none() || last.unwrap().0.read().await.region_latency.is_empty() {
        return make_probe_plan_initial(dm, if_state);
    }
    let last = last.unwrap().0.read().await;
    let have6if = if_state.have_v6;
    let have4if = if_state.have_v4;
    let mut plan = ProbePlan::default();
    if !have4if && !have6if {
        return plan;
    }
    let had4 = !last.region_v4_latency.is_empty();
    let had6 = !last.region_v6_latency.is_empty();
    let had_both = have6if && had4 && had6;
    for (ri, reg) in sort_regions(dm, &last).into_iter().enumerate() {
        if ri == NUM_INCREMENTAL_REGIONS {
            break;
        }
        let mut do4 = have4if;
        let mut do6 = have6if;

        // By default, each node only gets one STUN packet sent,
        // except the fastest two from the previous round.
        let mut tries = 1;
        let is_fastest_two = ri < 2;

        if is_fastest_two {
            tries = 2;
        } else if had_both {
            // For dual stack machines, make the 3rd & slower nodes alternate between.
            if ri % 2 == 0 {
                (do4, do6) = (true, false);
            } else {
                (do4, do6) = (false, true);
            }
        }
        if !is_fastest_two && !had6 {
            do6 = false;
        }

        if reg.region_id == last.preferred_derp {
            // But if we already had a DERP home, try extra hard to
            // make sure it's there so we don't flip flop around.
            tries = 4;
        }

        let mut p4 = Vec::new();
        let mut p6 = Vec::new();

        for tr in 0..tries {
            if reg.nodes.is_empty() {
                // Shouldn't be possible.
                continue;
            }
            if tr != 0 && !had6 {
                do6 = false;
            }
            let n = &reg.nodes[tr % reg.nodes.len()];
            let mut prev_latency = last.region_latency[&reg.region_id] * 120 / 100;
            if prev_latency.is_zero() {
                prev_latency = DEFAULT_ACTIVE_RETRANSMIT_TIME;
            }
            let mut delay = prev_latency * tr as u32;
            if tr > 1 {
                delay += Duration::from_millis(50) * tr as u32;
            }
            if do4 {
                p4.push(Probe {
                    delay,
                    node: n.name.clone(),
                    proto: ProbeProto::IPv4,
                    wait: Duration::default(),
                });
            }
            if do6 {
                p6.push(Probe {
                    delay,
                    node: n.name.clone(),
                    proto: ProbeProto::IPv6,
                    wait: Duration::default(),
                });
            }
        }
        if !p4.is_empty() {
            plan.0.insert(format!("region-{}-v4", reg.region_id), p4);
        }
        if !p6.is_empty() {
            plan.0.insert(format!("region-{}-v6", reg.region_id), p6);
        }
    }
    plan
}

fn make_probe_plan_initial(dm: &DerpMap, if_state: &interfaces::State) -> ProbePlan {
    let mut plan = ProbePlan::default();

    for (_, reg) in &dm.regions {
        let mut p4 = Vec::new();
        let mut p6 = Vec::new();

        for tr in 0..3 {
            let n = &reg.nodes[tr % reg.nodes.len()];
            let delay = DEFAULT_INITIAL_RETRANSMIT * tr as u32;
            if if_state.have_v4 && node_might4(n) {
                p4.push(Probe {
                    delay,
                    node: n.name.clone(),
                    proto: ProbeProto::IPv4,
                    wait: Duration::default(),
                });
            }
            if if_state.have_v6 && node_might6(n) {
                p6.push(Probe {
                    delay,
                    node: n.name.clone(),
                    proto: ProbeProto::IPv6,
                    wait: Duration::default(),
                })
            }
        }
        if !p4.is_empty() {
            plan.0.insert(format!("region-{}-v4", reg.region_id), p4);
        }
        if !p6.is_empty() {
            plan.0.insert(format!("region-{}-v6", reg.region_id), p6);
        }
    }
    plan
}

/// Reports whether n might reply to STUN over IPv6 based on
/// its config alone, without DNS lookups. It only returns false if
/// it's not explicitly disabled.
fn node_might6(n: &DerpNode) -> bool {
    match n.ipv6 {
        UseIpv6::None => true,
        UseIpv6::Disabled => false,
        UseIpv6::Some(_) => true,
    }
}

/// Reports whether n might reply to STUN over IPv4 based on
/// its config alone, without DNS lookups. It only returns false if
/// it's not explicitly disabled.
fn node_might4(n: &DerpNode) -> bool {
    match n.ipv4 {
        UseIpv4::None => true,
        UseIpv4::Disabled => false,
        UseIpv4::Some(_) => true,
    }
}

/// Holds the state for a single invocation of `Client::get_report`.
#[derive(Clone, Debug)]
struct ReportState {
    hair_tx: stun::TransactionId,
    got_hair_stun: Arc<Mutex<mpsc::Receiver<SocketAddr>>>,
    // notified on hair pin timeout
    hair_timeout: Arc<sync::Notify>,
    pc4: Option<Arc<net::UdpSocket>>,
    pc6: Option<Arc<net::UdpSocket>>,
    pc4_hair: Arc<net::UdpSocket>,
    incremental: bool, // doing a lite, follow-up netcheck
    stop_probe: Arc<sync::Notify>,
    wait_port_map: wg::AsyncWaitGroup,
    // to be returned by GetReport
    report: Report,
    clock: Clock,
    state: Arc<Mutex<InnerReportState>>,
}

#[derive(Default)]
struct InnerReportState {
    sent_hair_check: bool,
    // TODO: called without lock held
    in_flight: HashMap<
        stun::TransactionId,
        Box<dyn Fn(SocketAddr) -> BoxFuture<'static, ()> + Sync + Send>,
    >,
    got_ep4: Option<SocketAddr>,
    timers: JoinSet<()>,
}

impl Debug for InnerReportState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerReportState")
            .field("sent_hair_check", &self.sent_hair_check)
            .field("in_flight", &self.in_flight.keys().collect::<Vec<_>>())
            .field("got_ep4", &self.got_ep4)
            .field("timers", &self.timers)
            .finish()
    }
}

impl ReportState {
    #[cfg(test)]
    pub fn new(
        got_hair_stun: Arc<Mutex<mpsc::Receiver<SocketAddr>>>,
        pc4_hair: Arc<net::UdpSocket>,
        clock: Clock,
    ) -> Self {
        Self {
            clock,
            hair_tx: stun::TransactionId::default(),
            got_hair_stun,
            hair_timeout: Default::default(),
            pc4: None,
            pc6: None,
            pc4_hair,
            incremental: false,
            stop_probe: Default::default(),
            wait_port_map: wg::AsyncWaitGroup::default(),
            report: Default::default(),
            state: Default::default(),
        }
    }

    async fn any_udp(&self) -> bool {
        self.report.0.read().await.udp
    }

    async fn have_region_latency(&self, region_id: usize) -> bool {
        self.report
            .0
            .read()
            .await
            .region_latency
            .contains_key(&region_id)
    }

    /// Reports whether executing the given probe would yield any new information.
    /// The given node is provided just because the sole caller already has it
    /// and it saves a lookup.
    async fn probe_would_help(&self, probe: &Probe, node: &DerpNode) -> bool {
        let report = self.report.0.read().await;
        // If the probe is for a region we don't yet know about, that would help.

        if report.region_latency.contains_key(&node.region_id) {
            return true;
        }

        // If the probe is for IPv6 and we don't yet have an IPv6 report, that would help.
        if probe.proto == ProbeProto::IPv6 && report.region_v6_latency.is_empty() {
            return true;
        }

        // For IPv4, we need at least two IPv4 results overall to
        // determine whether we're behind a NAT that shows us as
        // different source IPs and/or ports depending on who we're
        // talking to. If we don't yet have two results yet
        // (`mapping_varies_by_dest_ip` is blank), then another IPv4 probe
        // would be good.
        if probe.proto == ProbeProto::IPv4 && report.mapping_varies_by_dest_ip.is_none() {
            return true;
        }

        // Otherwise not interesting.
        false
    }

    async fn start_hair_check_locked(&self, inner: &mut InnerReportState, dst: SocketAddr) {
        if inner.sent_hair_check || self.incremental {
            return;
        }
        inner.sent_hair_check = true;
        if let Err(err) = self
            .pc4_hair
            .send_to(&stun::request(self.hair_tx), dst)
            .await
        {
            debug!("failed to send haircheck to {}: {:?}", dst, err);
        }

        debug!("sent haircheck to {}", dst);

        let timeout = self.hair_timeout.clone();
        let clock = self.clock.clone();
        tokio::task::spawn(async move {
            clock.sleep(HAIRPIN_CHECK_TIMEOUT).await;
            timeout.notify_waiters();
        });
    }

    async fn wait_hair_check(&self, last: Option<&Report>) {
        let rs = &mut *self.state.lock().await;
        if self.incremental {
            if let Some(ref last) = last {
                let last_val = last.0.read().await.hair_pinning;
                self.report.0.write().await.hair_pinning = last_val;
            }
            return;
        }
        if !rs.sent_hair_check {
            return;
        }

        let mut got_hair_stun = self.got_hair_stun.lock().await;
        tokio::select! {
            _ = got_hair_stun.recv() => {
                self.report.0.write().await.hair_pinning = Some(true);
            }
            _ = self.hair_timeout.notified() => {
                debug!("hair_check timeout");
                self.report.0.write().await.hair_pinning = Some(false);
            }
        }
    }

    async fn stop_timers(&self) {
        self.state.lock().await.timers.abort_all();
    }

    /// Updates `self` to note that node's latency is `d`. If `ipp`
    /// is non-zero (for all but HTTPS replies), it's recorded as our UDP IP:port.
    async fn add_node_latency(&self, node: &DerpNode, ipp: Option<SocketAddr>, d: Duration) {
        debug!("add node latency: {} - {}ms", node.name, d.as_millis());
        let mut rs = self.state.lock().await;
        let mut report = self.report.0.write().await;
        report.udp = true;
        update_latency(&mut report.region_latency, node.region_id, d);

        // Once we've heard from enough regions (3), start a timer to
        // give up on the other ones. The timer's duration is a
        // function of whether this is our initial full probe or an
        // incremental one. For incremental ones, wait for the
        // duration of the slowest region. For initial ones, double that.
        if report.region_latency.len() == ENOUGH_REGIONS {
            let mut timeout = max_duration_value(&report.region_latency);
            if !self.incremental {
                timeout *= 2;
            }

            let stop_probe = self.stop_probe.clone();
            let clock = self.clock.clone();
            rs.timers.spawn(async move {
                clock.sleep(timeout).await;
                stop_probe.notify_waiters();
            });
        }

        if let Some(ipp) = ipp {
            if ipp.is_ipv6() {
                update_latency(&mut report.region_v6_latency, node.region_id, d);
                report.ipv6 = true;
                report.global_v6 = Some(ipp);
            // TODO: track MappingVariesByDestIP for IPv6
            // too? Would be sad if so, but who knows.
            } else if ipp.is_ipv4() {
                update_latency(&mut report.region_v4_latency, node.region_id, d);
                report.ipv4 = true;
                if rs.got_ep4.is_none() {
                    rs.got_ep4 = Some(ipp);
                    report.global_v4 = Some(ipp);
                    self.start_hair_check_locked(&mut rs, ipp).await;
                } else if rs.got_ep4 != Some(ipp) {
                    report.mapping_varies_by_dest_ip = Some(true);
                } else if report.mapping_varies_by_dest_ip.is_none() {
                    report.mapping_varies_by_dest_ip = Some(false);
                }
            }
        }
    }

    /// Starts probes for UPnP, PMP and PCP.
    async fn probe_port_map_services(&self, port_mapper: PortMapper) {
        struct Guard(wg::AsyncWaitGroup);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.done();
            }
        }
        let _guard = Guard(self.wait_port_map.clone());

        {
            let mut report = self.report.0.write().await;
            report.upnp = Some(false);
            report.pmp = Some(false);
            report.pcp = Some(false);
        }

        match port_mapper.probe().await {
            Err(_err) => {
                // if !errors.Is(err, portmapper.ErrGatewayRange) {
                // "skipping portmap; gateway range likely lacks support"
                // is not very useful, and too spammy on cloud systems.
                // If there are other errors, we want to log those.
                // rs.c.logf("probePortMapServices: %v", err)
                // }
            }
            Ok(res) => {
                let mut report = self.report.0.write().await;
                report.upnp = Some(res.upnp);
                report.pmp = Some(res.pmp);
                report.pcp = Some(res.pcp);
            }
        }
    }

    async fn run_probe(&self, dm: &DerpMap, probe: Probe, done: Arc<sync::Notify>) {
        debug!("run_probe: {:?}", probe);
        let node = named_node(dm, &probe.node);
        if node.is_none() {
            info!("netcheck.runProbe: named node {} not found", probe.node);
            return;
        }
        let node = node.unwrap();

        if !probe.delay.is_zero() {
            debug!("delaying probe by {}ms", probe.delay.as_millis());
            tokio::select! {
                _ = done.notified() => {
                    debug!("aborting probe early");
                    return;
                }
                _ = self.clock.sleep(probe.delay) => {}
            }
        }

        if !self.probe_would_help(&probe, node).await {
            done.notify_waiters();
            return;
        }

        let addr = get_node_addr(node, probe.proto).await;
        if addr.is_none() {
            return;
        }
        let addr = addr.unwrap();

        let txid = stun::TransactionId::default();
        let req = stun::request(txid);
        let sent = self.clock.now(); // after DNS lookup above

        {
            let mut state = self.state.lock().await;
            // TODO: reduce cloning below
            let this = self.clone();
            let node = node.clone();
            let done = done.clone();

            state.in_flight.insert(
                txid,
                Box::new(move |ipp| {
                    let node = node.clone();
                    let this = this.clone();
                    let done = done.clone();

                    async move {
                        let elapsed = this.clock.now().duration_since(sent);
                        this.add_node_latency(&node, Some(ipp), elapsed).await;
                        done.notify_waiters();
                    }
                    .boxed()
                }),
            );
        }

        match probe.proto {
            ProbeProto::IPv4 => {
                // TODO:
                // metricSTUNSend4.Add(1)
                if let Some(ref pc4) = self.pc4 {
                    let n = pc4.send_to(&req, addr).await;
                    debug!("sending probe IPV4: {:?}", n);
                    // TODO:  || neterror.TreatAsLostUDP(err)
                    if n.is_ok() && n.unwrap() == req.len() {
                        self.report.0.write().await.ipv4_can_send = true;
                    }
                }
            }
            ProbeProto::IPv6 => {
                if let Some(ref pc6) = self.pc6 {
                    // TODO:
                    // metricSTUNSend6.Add(1)
                    debug!("sending probe IPV6");
                    let n = pc6.send_to(&req, addr).await;
                    // TODO:  || neterror.TreatAsLostUDP(err)
                    if n.is_ok() && n.unwrap() == req.len() {
                        self.report.0.write().await.ipv6_can_send = true;
                    }
                }
            }
            _ => {
                panic!("bad probe proto: {:?}", probe.proto);
            }
        }
        debug!("sent to {}", addr);
    }
}

fn update_latency(m: &mut HashMap<usize, Duration>, region_id: usize, d: Duration) {
    let prev = m.entry(region_id).or_insert(d);
    if d < *prev {
        *prev = d;
    }
}

fn named_node<'a>(dm: &'a DerpMap, node_name: &str) -> Option<&'a DerpNode> {
    for (_, r) in &dm.regions {
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

fn max_duration_value(m: &HashMap<usize, Duration>) -> Duration {
    m.values().max().cloned().unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::{prelude::*, EnvFilter};

    #[tokio::test]
    async fn test_hairpin_stun() {
        let client = Client::default();
        let pc4_hair = Arc::new(net::UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let (hs_s, hs_r) = mpsc::channel(1);
        let hs_r = Arc::new(Mutex::new(hs_r));
        let s = ReportState::new(hs_r.clone(), pc4_hair, client.clock.clone());
        let tx = s.hair_tx;
        client.reports.lock().await.cur_state = Some(s);

        let req = stun::request(tx);
        assert!(stun::is(&req));
        let src = "127.0.0.1:0".parse().unwrap();

        let res = client.handle_hair_stun_locked(&req, src, hs_s).await;
        assert!(res, "expected hair to be true");
        assert_eq!(hs_r.lock().await.recv().await.unwrap(), src);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_basic() -> Result<(), Error> {
        let (stun_addr, stun_stats, done) = stun::test::serve().await?;

        let mut client = Client::default();
        client.udp_bind_addr = "0.0.0.0:0".parse().unwrap();

        let dm = stun::test::derp_map_of([stun_addr].into_iter());
        let r = client.get_report(&dm).await?;
        let r = &*r.0.read().await;

        assert!(r.udp, "want UDP");
        assert_eq!(
            r.region_latency.len(),
            1,
            "expected 1 key in DERPLatency; got {}",
            r.region_latency.len()
        );
        assert!(
            r.region_latency.get(&1).is_some(),
            "expected key 1 in DERPLatency; got {:?}",
            r.region_latency
        );
        assert!(r.global_v4.is_some(), "expected globalV4 set");
        assert_eq!(
            r.preferred_derp, 1,
            "preferred_derp = {}; want 1",
            r.preferred_derp
        );

        done.send(()).unwrap();
        assert_eq!(stun_stats.total().await, 1, "expected 1 stun");

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_udp_tokio() -> Result<(), Error> {
        let local_addr = "127.0.0.1";
        let bind_addr = "0.0.0.0";

        let server = net::UdpSocket::bind(format!("{bind_addr}:0")).await?;
        let addr = server.local_addr()?;

        let server_task = tokio::task::spawn(async move {
            let mut buf = vec![0u8; 32];
            println!("server recv");
            let (n, addr) = server.recv_from(&mut buf).await.unwrap();
            println!("server send");
            server.send_to(&buf[..n], addr).await.unwrap();
        });

        let client = net::UdpSocket::bind(format!("{bind_addr}:0")).await?;
        let data = b"foobar";
        println!("client: send");
        let server_addr = format!("{local_addr}:{}", addr.port());
        client.send_to(data, server_addr).await?;
        let mut buf = vec![0u8; 32];
        println!("client recv");
        let (n, addr_r) = client.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], data);
        assert_eq!(addr_r.port(), addr.port());

        server_task.await?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_udp_blocked() -> Result<(), Error> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .init();

        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let stun_addr = blackhole.local_addr()?;
        let mut dm = stun::test::derp_map_of([stun_addr].into_iter());
        dm.regions.get_mut(&1).unwrap().nodes[0].stun_only = true;

        let mut client = Client::default();

        let r = client.get_report(&dm).await?;
        let r = &mut *r.0.write().await;
        r.upnp = None;
        r.pmp = None;
        r.pcp = None;

        let want_source = Report::default();
        let want = &mut *want_source.0.write().await;

        // The ip_v4_can_send flag gets set differently across platforms.
        // On Windows this test detects false, while on Linux detects true.
        // That's not relevant to this test, so just accept what we're given.
        want.ipv4_can_send = r.ipv4_can_send;
        // OS IPv6 test is irrelevant here, accept whatever the current machine has.
        want.os_has_ipv6 = r.os_has_ipv6;
        // Captive portal test is irrelevant; accept what the current report has.
        want.captive_portal = r.captive_portal;

        assert_eq!(r, want);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_add_reporrt_history_set_preferred_derp() -> Result<(), Error> {
        let clock = Clock::mock();

        // report returns a *Report from (DERP host, Duration)+ pairs.
        fn report(a: impl IntoIterator<Item = (&'static str, u64)>) -> Report {
            let report = Report::default();
            {
                let r = &mut *report.0.try_write().unwrap();
                for (s, d) in a {
                    assert!(s.starts_with("d"), "invalid derp server key");
                    let region_id: usize = s[1..].parse().unwrap();
                    r.region_latency.insert(region_id, Duration::from_secs(d));
                }
            }
            report
        }
        struct Step {
            /// Delay in seconds
            after: u64,
            r: Report,
        }
        struct Test {
            name: &'static str,
            steps: Vec<Step>,
            /// want PreferredDERP on final step
            want_derp: usize,
            // wanted len(c.prev)
            want_prev_len: usize,
        }

        let tests = [
            Test {
                name: "first_reading",
                steps: vec![Step {
                    after: 0,
                    r: report([("d1", 2), ("d2", 3)]),
                }],
                want_prev_len: 1,
                want_derp: 1,
            },
            Test {
                name: "with_two",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                ],
                want_prev_len: 2,
                want_derp: 1, // t0's d1 of 2 is still best
            },
            Test {
                name: "but_now_d1_gone",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d2", 3)]),
                    },
                ],
                want_prev_len: 3,
                want_derp: 2, // only option
            },
            Test {
                name: "d1_is_back",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d2", 3)]),
                    },
                    Step {
                        after: 3,
                        r: report([("d1", 4), ("d2", 3)]),
                    }, // same as 2 seconds ago
                ],
                want_prev_len: 4,
                want_derp: 1, // t0's d1 of 2 is still best
            },
            Test {
                name: "things_clean_up",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 3,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 10 * 60,
                        r: report([("d3", 3)]),
                    },
                ],
                want_prev_len: 1, // t=[0123]s all gone. (too old, older than 10 min)
                want_derp: 3,     // only option
            },
            Test {
                name: "preferred_derp_hysteresis_no_switch",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 4), ("d2", 5)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                ],
                want_prev_len: 2,
                want_derp: 1, // 2 didn't get fast enough
            },
            Test {
                name: "preferred_derp_hysteresis_do_switch",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 4), ("d2", 5)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 1)]),
                    },
                ],
                want_prev_len: 2,
                want_derp: 2, // 2 got fast enough
            },
        ];
        for mut tt in tests {
            println!("test: {}", tt.name);
            let mut client = Client::default();
            client.clock = clock.clone();

            for s in &mut tt.steps {
                let c = clock.clone();
                tokio::task::spawn(async move { c.sleep(Duration::from_millis(10)).await }); // trigger the timer
                clock
                    .controller
                    .as_ref()
                    .unwrap()
                    .advance_time(Duration::from_secs(s.after))
                    .await;
                client
                    .add_report_history_and_set_preferred_derp(&mut s.r)
                    .await;
            }
            let last_report = tt.steps[tt.steps.len() - 1].r.clone();
            let got = client.reports.lock().await.prev.len();
            let want = tt.want_prev_len;
            assert_eq!(got, want, "prev length");
            let got = last_report.0.read().await.preferred_derp;
            let want = tt.want_derp;
            assert_eq!(got, want, "preferred_derp");
        }

        Ok(())
    }
}
