//! Checks the network conditions from the current host.
//! Based on <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>

use std::{
    collections::HashMap,
    fmt::{self, Debug},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use bytes::Bytes;
use futures::{
    stream::{FuturesUnordered, StreamExt},
    Future, FutureExt,
};
use rand::seq::IteratorRandom;
use tokio::{
    net::UdpSocket,
    sync::{self, broadcast, mpsc, RwLock},
    task::JoinSet,
    time::{self, Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, info, instrument, trace, warn, Instrument};
use trust_dns_resolver::TokioAsyncResolver;

use crate::net::{interfaces, ip::to_canonical};

use self::probe::{Probe, ProbePlan, ProbeProto};

use super::{
    derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6},
    ping::Pinger,
    portmapper, stun,
};

mod probe;

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

const FULL_REPORT_INTERVAL: Duration = Duration::from_secs(5 * 60);

const ENOUGH_REGIONS: usize = 3;

// Chosen semi-arbitrarily
const CAPTIVE_PORTAL_DELAY: Duration = Duration::from_millis(200);

/// Timeout for captive portal checks, must be lower than OVERALL_PROBE_TIMEOUT
const CAPTIVE_PORTAL_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default, Debug, PartialEq, Eq, Clone)]
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
    /// Whether STUN results depend which STUN server you're talking to (on IPv4).
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
    /// `[ip]:port` of global IPv6
    pub global_v6: Option<SocketAddr>,
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

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// Generates a netcheck [`Report`].
/// Client to generate netcheck [`Report`]s.
///
/// This has an actor inside, but it only runs when [`Client::get_report`] is being called.
/// While running it expects to be passed received stun packets using
/// [`Client::get_msg_sender`], the [`crate::hp::magicsock::Conn`] using this client needs to be wired up to
/// do so.
#[derive(Debug)]
pub(crate) struct Client {
    msg_sender: mpsc::Sender<ActorMessage>,
    actor: Actor,
}

#[derive(Debug)]
struct Reports {
    /// Do a full region scan, even if last is `Some`.
    next_full: bool,
    /// Some previous reports.
    prev: HashMap<Instant, Arc<Report>>,
    /// Most recent report.
    last: Option<Arc<Report>>,
    /// Time of last full (non-incremental) report.
    last_full: Instant,
    /// Current hair pinning tx
    current_hair_tx: Option<stun::TransactionId>,
}

impl Client {
    pub(crate) async fn new(port_mapper: Option<portmapper::Client>) -> Result<Self> {
        let last_full = Instant::now();
        let (got_hair_stun, _) = broadcast::channel(1);

        let (msg_sender, msg_receiver) = mpsc::channel(32);

        let dns_resolver = TokioAsyncResolver::tokio_from_system_conf()?;

        let actor = Actor {
            receiver: msg_receiver,
            reports: Reports {
                next_full: false,
                prev: Default::default(),
                last: None,
                last_full,
                current_hair_tx: None,
            },
            skip_external_network: false,
            port_mapper,
            got_hair_stun,
            dns_resolver,
        };

        Ok(Client { msg_sender, actor })
    }

    /// Returns the sender which can send messages to the actor.
    ///
    /// Used by [`crate::hp::magicsock::Conn`] to pass received stun packets to the running
    /// netcheck actor.
    pub(crate) fn get_msg_sender(&self) -> mpsc::Sender<ActorMessage> {
        self.msg_sender.clone()
    }

    /// Runs a netcheck, returning the report.
    ///
    /// It may not be called concurrently with itself, `&mut self` takes care of that.
    ///
    /// The *stun_conn4* and *stun_conn6* endpoints are bound UDP sockets to use to send out
    /// STUN packets.  This function **will not read from the sockets**, as they may be
    /// receiving other traffic as well, normally they are the sockets carrying the real
    /// traffic.  Thus all stun packets received on those sockets should be passed to
    /// [`Client::get_msg_sender`] in order for this function to receive the stun
    /// responses and function correctly.
    ///
    /// If these are not passed in this will bind sockets for STUN itself, though results
    /// may not be as reliable.
    pub(crate) async fn get_report(
        &mut self,
        dm: DerpMap,
        stun_conn4: Option<Arc<UdpSocket>>,
        stun_conn6: Option<Arc<UdpSocket>>,
    ) -> Result<Arc<Report>> {
        // If not given  UdpSockets to send stun packets, create them.
        // TODO: Is failure really fatal?
        let cancel_token = CancellationToken::new();
        let stun_conn4 = match stun_conn4 {
            Some(stun_conn4) => stun_conn4,
            None => {
                let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
                let sock = UdpSocket::bind(addr)
                    .await
                    .context("netcheck: failed to bind udp 0.0.0.0:0")?;
                let sock = Arc::new(sock);
                Self::spawn_udp_listener(
                    sock.clone(),
                    self.msg_sender.clone(),
                    cancel_token.clone(),
                );
                sock
            }
        };
        let stun_conn6 = match stun_conn6 {
            Some(stun_conn6) => stun_conn6,
            None => {
                let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
                let sock = UdpSocket::bind(addr)
                    .await
                    .context("netcheck: failed to bind udp6 [::]:0")?;
                let sock = Arc::new(sock);
                Self::spawn_udp_listener(
                    sock.clone(),
                    self.msg_sender.clone(),
                    cancel_token.clone(),
                );
                sock
            }
        };
        let _cancel_on_drop = cancel_token.drop_guard();

        // TODO: consider if DerpMap should be made to easily clone?  It seems expensive
        // right now.
        self.actor.run(dm.clone(), stun_conn4, stun_conn6).await
    }

    /// Spawns a tokio task reading stun packets from the UDP socket.
    ///
    /// This is a sync function and does not wait until the task is running.  However this
    /// is fine since the socket is already bound so packets will not be lost.
    fn spawn_udp_listener(
        sock: Arc<UdpSocket>,
        sender: mpsc::Sender<ActorMessage>,
        cancel_token: CancellationToken,
    ) {
        let span = debug_span!(
            "stun.listener.udp",
            local_addr = sock
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or(String::from("-")),
        );
        tokio::spawn(
            async move {
                debug!("udp stun socket listener started");
                // TODO: Can we do better for buffers here?  Probably doesn't matter
                // much.
                let mut buf = vec![0u8; 64 << 10];
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel_token.cancelled() => break,
                        res = Self::recv_stun_once(&sock, &mut buf, &sender) => {
                            if let Err(err) = res {
                                warn!(%err, "stun recv failed");
                                break;
                            }
                        }
                    }
                }
                debug!("udp stun socket listener stopped");
            }
            .instrument(span),
        );
    }

    /// Receive STUN response from a UDP socket, pass it to the actor.
    async fn recv_stun_once(
        sock: &UdpSocket,
        buf: &mut [u8],
        sender: &mpsc::Sender<ActorMessage>,
    ) -> Result<()> {
        let (count, mut from_addr) = sock
            .recv_from(buf)
            .await
            .context("Error reading from stun socket")?;
        let payload = &buf[..count];
        from_addr.set_ip(to_canonical(from_addr.ip()));
        let msg = ActorMessage::StunPacket(Bytes::from(payload.to_vec()), from_addr);
        sender.send(msg).await.context("actor stopped")
    }
}

async fn measure_https_latency(_reg: &DerpRegion) -> Result<(Duration, IpAddr)> {
    anyhow::bail!("not implemented");
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

/// Reports whether or not we think the system is behind a
/// captive portal, detected by making a request to a URL that we know should
/// return a "204 No Content" response and checking if that's what we get.
///
/// The boolean return is whether we think we have a captive portal.
async fn check_captive_portal(dm: &DerpMap, preferred_derp: Option<usize>) -> Result<bool> {
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
    // length is limited; see is_challenge_char in bin/derper for more
    // details.
    let challenge = format!("ts_{}", node.host_name);

    let res = client
        .request(
            reqwest::Method::GET,
            format!("http://{}/generate_204", node.host_name),
        )
        .header("X-Tailscale-Challenge", &challenge)
        .send()
        .await?;

    let expected_response = format!("response {challenge}");
    let is_valid_response = res
        .headers()
        .get("X-Tailscale-Response")
        .map(|s| s.to_str().unwrap_or_default())
        == Some(&expected_response);

    info!(
        "check_captive_portal url={} status_code={} valid_response={}",
        res.url(),
        res.status(),
        is_valid_response,
    );
    let has_captive = res.status() != 204 || !is_valid_response;

    Ok(has_captive)
}

async fn measure_icmp_latency(
    resolver: &TokioAsyncResolver,
    reg: &DerpRegion,
    p: &Pinger,
) -> Result<Duration> {
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
    let node_addr = get_node_addr(resolver, node, ProbeProto::Ipv4)
        .await
        .ok_or_else(|| anyhow::anyhow!("no address for node {}", node.name))?;

    debug!(
        "ICMP ping start to {} with payload len {} - derp {} {}",
        node_addr,
        node.name.as_bytes().len(),
        node.name,
        reg.region_id
    );
    // Use the unique node.name field as the packet data to reduce the
    // likelihood that we get a mismatched echo response.
    let d = p.send(node_addr.ip(), node.name.as_bytes()).await?;
    debug!(
        "ICMP ping done {} with latency {}ms - derp {} {}",
        node_addr,
        d.as_millis(),
        node.name,
        reg.region_id
    );
    Ok(d)
}

async fn get_node_addr(
    resolver: &TokioAsyncResolver,
    n: &DerpNode,
    proto: ProbeProto,
) -> Option<SocketAddr> {
    let mut port = n.stun_port;
    if port == 0 {
        port = 3478;
    }
    if let Some(ip) = n.stun_test_ip {
        if proto == ProbeProto::Ipv4 && ip.is_ipv6() {
            return None;
        }
        if proto == ProbeProto::Ipv6 && ip.is_ipv4() {
            return None;
        }
        return Some(SocketAddr::new(ip, port));
    }

    match proto {
        ProbeProto::Ipv4 => {
            if let UseIpv4::Some(ip) = n.ipv4 {
                return Some(SocketAddr::new(IpAddr::V4(ip), port));
            }
        }
        ProbeProto::Ipv6 => {
            if let UseIpv6::Some(ip) = n.ipv6 {
                return Some(SocketAddr::new(IpAddr::V6(ip), port));
            }
        }
        _ => {}
    }

    // TODO: add singleflight+dnscache here.
    if let Ok(addrs) = dns_lookup(resolver, &n.host_name).await {
        for addr in addrs {
            if addr.is_ipv4() && proto == ProbeProto::Ipv4 {
                let addr = to_canonical(addr);
                return Some(SocketAddr::new(addr, port));
            }
            if addr.is_ipv6() && proto == ProbeProto::Ipv6 {
                return Some(SocketAddr::new(addr, port));
            }
            if proto == ProbeProto::Https {
                // For now just return the first one
                return Some(SocketAddr::new(addr, port));
            }
        }
    }

    None
}

async fn dns_lookup(
    resolver: &TokioAsyncResolver,
    host: &str,
) -> Result<trust_dns_resolver::lookup_ip::LookupIp> {
    let response = resolver.lookup_ip(host).await?;

    Ok(response)
}

/// Holds the state for a single invocation of `Client::get_report`.
#[derive(Debug)]
struct ReportState {
    hair_tx: stun::TransactionId,
    got_hair_stun: broadcast::Receiver<SocketAddr>,
    // notified on hair pin timeout
    hair_timeout: Arc<sync::Notify>,
    pc4: Arc<UdpSocket>,
    pc6: Arc<UdpSocket>,
    pc4_hair: Arc<UdpSocket>,
    /// Doing a lite, follow-up netcheck
    incremental: bool,
    stop_probe: Arc<sync::Notify>,
    wait_port_map: wg::AsyncWaitGroup,
    /// The report which will be returned.
    report: Arc<RwLock<Report>>,
    sent_hair_check: bool,
    got_ep4: Option<SocketAddr>,
    timers: JoinSet<()>,
    plan: ProbePlan,
    last: Option<Arc<Report>>,
}

#[derive(Debug)]
struct Inflight {
    tx: stun::TransactionId,
    start: Instant,
    s: sync::oneshot::Sender<(Duration, SocketAddr)>,
}

impl ReportState {
    #[instrument(name = "report_state", skip_all)]
    async fn run(
        mut self,
        in_flight: sync::mpsc::Sender<Inflight>,
        dm: DerpMap,
        port_mapper: Option<portmapper::Client>,
        skip_external_network: bool,
        resolver: &TokioAsyncResolver,
    ) -> Result<(Report, DerpMap)> {
        debug!(port_mapper = %port_mapper.is_some(), %skip_external_network, "running report");
        self.report.write().await.os_has_ipv6 = os_has_ipv6().await;

        let mut port_mapping = MaybeFuture::default();
        if !skip_external_network {
            if let Some(ref port_mapper) = port_mapper {
                let port_mapper = port_mapper.clone();
                port_mapping.inner = Some(Box::pin(async move {
                    match port_mapper.probe().await {
                        Ok(res) => Some((res.upnp, res.pmp, res.pcp)),
                        Err(err) => {
                            warn!("skipping port mapping: {:?}", err);
                            None
                        }
                    }
                }));
            }
        }

        self.prepare_hairpin().await;

        // Even if we're doing a non-incremental update, we may want to try our
        // preferred DERP region for captive portal detection. Save that, if we have it.
        let preferred_derp = self.last.as_ref().map(|l| l.preferred_derp);

        // If we're doing a full probe, also check for a captive portal. We
        // delay by a bit to wait for UDP STUN to finish, to avoid the probe if
        // it's unnecessary.
        let mut captive_task = if !self.incremental {
            let dm = dm.clone();
            MaybeFuture {
                inner: Some(Box::pin(async move {
                    // wait
                    time::sleep(CAPTIVE_PORTAL_DELAY).await;
                    let captive_portal_check = tokio::time::timeout(
                        CAPTIVE_PORTAL_TIMEOUT,
                        check_captive_portal(&dm, preferred_derp),
                    );
                    match captive_portal_check.await {
                        Ok(Ok(found)) => Some(found),
                        Ok(Err(err)) => {
                            info!("check_captive_portal error: {:?}", err);
                            None
                        }
                        Err(_) => {
                            info!("check_captive_portal timed out");
                            None
                        }
                    }
                })),
            }
        } else {
            MaybeFuture::default()
        };

        let pinger = if self.plan.has_https_probes() {
            Some(Pinger::new().await.context("failed to create pinger")?)
        } else {
            None
        };

        let mut probes = FuturesUnordered::default();
        for probe_set in self.plan.values() {
            let mut set = FuturesUnordered::default();
            for probe in probe_set {
                let probe = probe.clone();
                let node = named_node(&dm, probe.node());
                ensure!(node.is_some(), "missing named node {}", probe.node());
                let node = node.unwrap().clone();
                let in_flight = in_flight.clone();
                let pc4 = self.pc4.clone();
                let pc6 = self.pc6.clone();
                let report = self.report.clone();
                let pinger = pinger.clone();

                set.push(Box::pin(async move {
                    run_probe(report, resolver, pc4, pc6, node, probe, in_flight, pinger).await
                }));
            }

            probes.push(Box::pin(async move {
                while let Some(res) = set.next().await {
                    match res {
                        Ok(res) => {
                            trace!(probe = ?res.probe, "probe successfull");
                            return Ok(res);
                        }
                        Err(ProbeError::Transient(err, probe)) => {
                            warn!(?probe, "probe failed: {:?}", err);
                            continue;
                        }
                        Err(ProbeError::Fatal(err, probe)) => {
                            warn!(?probe, "probe error fatal: {:?}", err);
                            return Err(err);
                        }
                    }
                }
                bail!("no successfull probes");
            }));
        }

        let stun_timer = time::sleep(STUN_PROBE_TIMEOUT);
        tokio::pin!(stun_timer);
        let probes_aborted = self.stop_probe.clone();

        loop {
            tokio::select! {
                _ = &mut stun_timer => {
                    debug!("STUN timer expired");
                    break;
                },
                pm = &mut port_mapping => {
                    let mut report = self.report.write().await;
                    match pm {
                        Some((upnp, pmp, pcp)) => {
                            report.upnp = Some(upnp);
                            report.pmp = Some(pmp);
                            report.pcp = Some(pcp);
                        }
                        None => {
                            report.upnp = None;
                            report.pmp = None;
                            report.pcp = None;
                        }
                    }
                    port_mapping.inner = None;
                }
                probe_report = probes.next() => {
                    match probe_report {
                        Some(Ok(probe_report)) => {
                            debug!("finished probe: {:?}", probe_report);
                            match probe_report.probe {
                                Probe::Https { reg, .. } => {
                                    if let Some(delay) = probe_report.delay {
                                        let mut report = self.report.write().await;
                                        let l = report.region_latency.entry(reg.region_id).or_insert(delay);
                                        if *l >= delay {
                                            *l = delay;
                                        }
                                    }
                                }
                                Probe::Ipv4 { node, .. } | Probe::Ipv6 { node, .. } => {
                                    if let Some(delay) = probe_report.delay {
                                        let node = named_node(&dm, &node).expect("missing node");
                                        self.add_node_latency(node, probe_report.addr, delay).await;
                                    }
                                }
                            }
                            let mut report = self.report.write().await;
                            report.ipv4_can_send = probe_report.ipv4_can_send;
                            report.ipv6_can_send = probe_report.ipv6_can_send;
                            report.icmpv4 = probe_report.icmpv4;
                        }
                        Some(Err(err)) => {
                            warn!("probe error: {:?}", err);
                        }
                        None => {
                            // All of our probes finished, so if we have >0 responses, we
                            // stop our captive portal check.
                            if self.any_udp().await {
                                captive_task.inner = None;
                            }
                            break;
                        }
                    }
                }
                found = &mut captive_task => {
                    let mut report = self.report.write().await;
                    report.captive_portal = found;
                    captive_task.inner = None;
                }
                _ = probes_aborted.notified() => {
                    // Saw enough regions.
                    debug!("saw enough regions; not waiting for rest");
                    // We can stop the captive portal check since we know that we
                    // got a bunch of STUN responses.
                    captive_task.inner = None;
                    break;
                }
            }
        }

        // abort the rest of the probes
        debug!("aborting {} probes, already done", probes.len());
        drop(probes);

        self.wait_hair_check().await;
        debug!("hair_check done");

        if !skip_external_network && port_mapper.is_some() {
            self.wait_port_map.wait().await;
            debug!("port_map done");
        }

        self.stop_timers();

        // Wait for captive portal check before finishing the report.
        if captive_task.inner.is_some() {
            let mut report = self.report.write().await;
            report.captive_portal = captive_task.await;
        }

        let ReportState { report, .. } = self;
        let report = RwLock::into_inner(Arc::try_unwrap(report).expect("should be the last one"));

        Ok((report, dm))
    }

    async fn prepare_hairpin(&self) {
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

        if let Err(err) = self
            .pc4_hair
            .send_to(
                b"tailscale netcheck; see https://github.com/tailscale/tailscale/issues/188",
                documentation_ip,
            )
            .await
        {
            warn!("unable to send hairpin prep: {:?}", err);
        }
    }

    async fn any_udp(&self) -> bool {
        self.report.read().await.udp
    }

    /// Reports whether executing the given probe would yield any new information.
    /// The given node is provided just because the sole caller already has it
    /// and it saves a lookup.
    async fn start_hair_check(&mut self, dst: SocketAddr) {
        if self.sent_hair_check || self.incremental {
            return;
        }
        self.sent_hair_check = true;
        if let Err(err) = self
            .pc4_hair
            .send_to(&stun::request(self.hair_tx), dst)
            .await
        {
            debug!("failed to send haircheck to {}: {:?}", dst, err);
        }

        debug!("sent haircheck to {}", dst);

        let timeout = self.hair_timeout.clone();
        tokio::task::spawn(async move {
            time::sleep(HAIRPIN_CHECK_TIMEOUT).await;
            timeout.notify_waiters();
        });
    }

    async fn wait_hair_check(&mut self) {
        let last = self.last.as_deref();
        if self.incremental {
            if let Some(last) = last {
                let last_val = last.hair_pinning;
                self.report.write().await.hair_pinning = last_val;
            }
            return;
        }
        if !self.sent_hair_check {
            return;
        }

        tokio::select! {
            _ = self.got_hair_stun.recv() => {
                self.report.write().await.hair_pinning = Some(true);
            }
            _ = self.hair_timeout.notified() => {
                debug!("hair_check timeout");
                self.report.write().await.hair_pinning = Some(false);
            }
        }
    }

    fn stop_timers(&mut self) {
        self.timers.abort_all();
    }

    /// Updates `self` to note that node's latency is `d`. If `ipp`
    /// is non-zero (for all but HTTPS replies), it's recorded as our UDP IP:port.
    async fn add_node_latency(&mut self, node: &DerpNode, ipp: Option<SocketAddr>, d: Duration) {
        debug!(node = %node.name, latency = ?d, "add node latency");
        let mut report = self.report.write().await;
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
            self.timers.spawn(async move {
                time::sleep(timeout).await;
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
                if self.got_ep4.is_none() {
                    self.got_ep4 = Some(ipp);
                    report.global_v4 = Some(ipp);
                    drop(report);
                    self.start_hair_check(ipp).await;
                } else if self.got_ep4 != Some(ipp) {
                    report.mapping_varies_by_dest_ip = Some(true);
                } else if report.mapping_varies_by_dest_ip.is_none() {
                    report.mapping_varies_by_dest_ip = Some(false);
                }
            }
        }
    }
}

#[derive(Debug)]
enum ProbeError {
    /// Abort the current set.
    Fatal(anyhow::Error, Probe),
    /// Continue the other probes.
    Transient(anyhow::Error, Probe),
}

#[allow(clippy::too_many_arguments)]
#[instrument(level = "debug", skip_all, fields(probe = ?probe))]
async fn run_probe(
    report: Arc<RwLock<Report>>,
    resolver: &TokioAsyncResolver,
    pc4: Arc<UdpSocket>,
    pc6: Arc<UdpSocket>,
    node: DerpNode,
    probe: Probe,
    in_flight: sync::mpsc::Sender<Inflight>,
    pinger: Option<Pinger>,
) -> Result<ProbeReport, ProbeError> {
    if !probe.delay().is_zero() {
        debug!("delaying probe");
        time::sleep(*probe.delay()).await;
    }

    if !probe_would_help(&*report.read().await, &probe, &node) {
        return Err(ProbeError::Fatal(anyhow!("probe would not help"), probe));
    }

    let addr = get_node_addr(resolver, &node, probe.proto()).await;
    if addr.is_none() {
        return Err(ProbeError::Transient(anyhow!("no node addr"), probe));
    }
    let addr = addr.unwrap();
    let txid = stun::TransactionId::default();
    let req = stun::request(txid);
    let sent = Instant::now(); // after DNS lookup above

    let (s, r) = sync::oneshot::channel();
    in_flight
        .send(Inflight {
            tx: txid,
            start: sent,
            s,
        })
        .await
        .map_err(|e| ProbeError::Transient(e.into(), probe.clone()))?;
    let mut result = ProbeReport::new(probe.clone());

    match probe {
        Probe::Ipv4 { .. } => {
            // TODO:
            // metricSTUNSend4.Add(1)
            let n = pc4.send_to(&req, addr).await;
            debug!(%addr, send_res=?n, "sending probe IPV4");
            // TODO:  || neterror.TreatAsLostUDP(err)
            if n.is_ok() && n.unwrap() == req.len() {
                result.ipv4_can_send = true;

                let (delay, addr) = r
                    .await
                    .map_err(|e| ProbeError::Transient(e.into(), probe))?;
                result.delay = Some(delay);
                result.addr = Some(addr);
            }
        }
        Probe::Ipv6 { .. } => {
            // TODO:
            // metricSTUNSend6.Add(1)
            let n = pc6.send_to(&req, addr).await;
            debug!(%addr, snd_res=?n, "sending probe IPV6");
            // TODO:  || neterror.TreatAsLostUDP(err)
            if n.is_ok() && n.unwrap() == req.len() {
                result.ipv6_can_send = true;

                let (delay, addr) = r
                    .await
                    .map_err(|e| ProbeError::Transient(e.into(), probe))?;
                result.delay = Some(delay);
                result.addr = Some(addr);
            }
        }
        Probe::Https { reg, .. } => {
            debug!("sending probe HTTPS (icmp: {})", pinger.is_some());

            let res = if let Some(ref pinger) = pinger {
                tokio::join!(
                    time::timeout(
                        ICMP_PROBE_TIMEOUT,
                        measure_icmp_latency(resolver, &reg, pinger).map(Some)
                    ),
                    measure_https_latency(&reg)
                )
            } else {
                (Ok(None), measure_https_latency(&reg).await)
            };
            if let Ok(Some(icmp_res)) = res.0 {
                match icmp_res {
                    Ok(d) => {
                        result.delay = Some(d);
                        result.ipv4_can_send = true;
                        result.icmpv4 = true;
                    }
                    Err(err) => {
                        warn!("icmp latency measurement failed: {:?}", err);
                    }
                }
            }
            match res.1 {
                Ok((d, ip)) => {
                    result.delay = Some(d);
                    // We set these IPv4 and IPv6 but they're not really used
                    // and we don't necessarily set them both. If UDP is blocked
                    // and both IPv4 and IPv6 are available over TCP, it's basically
                    // random which fields end up getting set here.
                    // Since they're not needed, that's fine for now.
                    if ip.is_ipv4() {
                        result.ipv4_can_send = true
                    }
                    if ip.is_ipv6() {
                        result.ipv6_can_send = true
                    }
                }
                Err(err) => {
                    warn!("https latency measurement failed: {:?}", err);
                }
            }
        }
    }

    Ok(result)
}

fn probe_would_help(report: &Report, probe: &Probe, node: &DerpNode) -> bool {
    // If the probe is for a region we don't yet know about, that would help.
    if !report.region_latency.contains_key(&node.region_id) {
        return true;
    }

    // If the probe is for IPv6 and we don't yet have an IPv6 report, that would help.
    if probe.proto() == ProbeProto::Ipv6 && report.region_v6_latency.is_empty() {
        return true;
    }

    // For IPv4, we need at least two IPv4 results overall to
    // determine whether we're behind a NAT that shows us as
    // different source IPs and/or ports depending on who we're
    // talking to. If we don't yet have two results yet
    // (`mapping_varies_by_dest_ip` is blank), then another IPv4 probe
    // would be good.
    if probe.proto() == ProbeProto::Ipv4 && report.mapping_varies_by_dest_ip.is_none() {
        return true;
    }

    // Otherwise not interesting.
    false
}

fn update_latency(m: &mut HashMap<usize, Duration>, region_id: usize, d: Duration) {
    let prev = m.entry(region_id).or_insert(d);
    if d < *prev {
        *prev = d;
    }
}

fn named_node<'a>(dm: &'a DerpMap, node_name: &str) -> Option<&'a DerpNode> {
    for r in dm.regions.values() {
        for n in &r.nodes {
            if n.name == node_name {
                return Some(n);
            }
        }
    }
    None
}

fn max_duration_value(m: &HashMap<usize, Duration>) -> Duration {
    m.values().max().cloned().unwrap_or_default()
}

#[derive(Debug)]
struct ProbeReport {
    ipv4_can_send: bool,
    ipv6_can_send: bool,
    icmpv4: bool,
    delay: Option<Duration>,
    probe: Probe,
    addr: Option<SocketAddr>,
}
impl ProbeReport {
    fn new(probe: Probe) -> Self {
        ProbeReport {
            probe,
            ipv4_can_send: false,
            ipv6_can_send: false,
            icmpv4: false,
            delay: None,
            addr: None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum ActorMessage {
    StunPacket(Bytes, SocketAddr),
}

#[derive(Debug)]
struct Actor {
    /// Actor messages channel.
    receiver: mpsc::Receiver<ActorMessage>,
    reports: Reports,
    /// Whether the client should try to reach things other than localhost.
    ///
    /// This is set to true in tests to avoid probing the local LAN's router, etc.
    skip_external_network: bool,
    /// Whether to run port mapping queries.
    port_mapper: Option<portmapper::Client>,
    got_hair_stun: broadcast::Sender<SocketAddr>,
    dns_resolver: TokioAsyncResolver,
}

impl Actor {
    /// Performs a single netcheck run.
    ///
    /// See [`Client::get_report`] for the arguments.
    #[instrument(name = "get_report", skip_all)]
    async fn run(
        &mut self,
        dm: DerpMap,
        stun_sock_v4: Arc<UdpSocket>,
        stun_sock_v6: Arc<UdpSocket>,
    ) -> Result<Arc<Report>> {
        let report_state = self
            .create_report_state(&dm, stun_sock_v4.clone(), stun_sock_v6.clone())
            .await
            .context("failed to create ReportState")?;
        let (in_flight_s, mut in_flight_r) = sync::mpsc::channel(8);
        let mut running = {
            let port_mapper = self.port_mapper.clone();
            let skip_external = self.skip_external_network;
            let resolver = self.dns_resolver.clone(); // not a cheap clone
            Box::pin(time::timeout(OVERALL_PROBE_TIMEOUT, async move {
                report_state
                    .run(in_flight_s, dm, port_mapper, skip_external, &resolver)
                    .await
            }))
        };
        let mut in_flight = HashMap::new();

        loop {
            tokio::select! {
                Some(inf) = in_flight_r.recv() => {
                    in_flight.insert(inf.tx, inf);
                }
                msg = self.receiver.recv() => {
                    debug!("incoming stun packet: {:?}", msg);
                    match msg {
                        None => bail!("client dropped, abort"),
                        Some(ActorMessage::StunPacket(pkt, source)) =>
                            self.receive_stun_packet(&mut in_flight, &pkt, source),
                    }
                }
                res = &mut running => {
                    match res {
                        Ok(Ok((report, dm))) => {
                            let report = self.finish_and_store_report(report, &dm);
                            return Ok(report)
                        }
                        Err(err) => {
                            warn!("generate report timed out: {:?}", err);
                            return Err(err.into());
                        }
                        Ok(Err(err)) => {
                            warn!("failed to generate report: {:?}", err);
                            return Err(err);
                        }
                    }
                }
            }
        }
    }

    async fn create_report_state(
        &mut self,
        dm: &DerpMap,
        pc4: Arc<UdpSocket>,
        pc6: Arc<UdpSocket>,
    ) -> Result<ReportState> {
        let now = Instant::now();

        // Create a UDP4 socket used for sending to our discovered IPv4 address.
        let pc4_hair = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("udp4: failed to bind")?;

        // random payload
        let hair_tx = stun::TransactionId::default();
        // Store the last hair_tx to make sure we can check against hair pins.
        self.reports.current_hair_tx = Some(hair_tx);

        let got_hair_stun_r = self.got_hair_stun.subscribe();
        let if_state = interfaces::State::new().await;
        let mut do_full = self.reports.next_full
            || now.duration_since(self.reports.last_full) > FULL_REPORT_INTERVAL;

        // If the last report had a captive portal and reported no UDP access,
        // it's possible that we didn't get a useful netcheck due to the
        // captive portal blocking us. If so, make this report a full (non-incremental) one.
        if !do_full {
            if let Some(ref last) = self.reports.last {
                do_full = !last.udp && last.captive_portal.unwrap_or_default();
            }
        }
        if do_full {
            self.reports.last = None; // causes ProbePlan::new below to do a full (initial) plan
            self.reports.next_full = false;
            self.reports.last_full = now;

            // TODO
            // metricNumGetReportFull.Add(1);
        }

        let last = self.reports.last.clone();
        let plan = ProbePlan::new(dm, &if_state, last.as_deref()).await;

        Ok(ReportState {
            incremental: last.is_some(),
            pc4,
            pc6,
            pc4_hair: Arc::new(pc4_hair),
            hair_timeout: Arc::new(sync::Notify::new()),
            stop_probe: Arc::new(sync::Notify::new()),
            wait_port_map: wg::AsyncWaitGroup::new(),
            report: Default::default(),
            sent_hair_check: false,
            got_ep4: None,
            timers: Default::default(),
            hair_tx,
            got_hair_stun: got_hair_stun_r,
            plan,
            last,
        })
    }

    fn receive_stun_packet(
        &self,
        in_flight: &mut HashMap<stun::TransactionId, Inflight>,
        pkt: &[u8],
        src: SocketAddr,
    ) {
        trace!(%src, "received STUN packet");

        // if src.is_ipv4() {
        // TODO:
        // metricSTUNRecv4.Add(1)
        // } else if src.is_ipv6() {
        // TODO:
        // metricSTUNRecv6.Add(1)
        // }

        if self.handle_hair_stun(pkt, src) {
            return;
        }

        match stun::parse_response(pkt) {
            Ok((tx, addr_port)) => {
                if let Some(inf) = in_flight.remove(&tx) {
                    let elapsed = inf.start.elapsed();
                    let _ = inf.s.send((elapsed, addr_port));
                }
            }
            Err(err) => {
                if stun::parse_binding_request(pkt).is_ok() {
                    // This was probably our own netcheck hairpin
                    // check probe coming in late. Ignore.
                    return;
                }
                info!(
                    "received unexpected STUN message response from {}: {:?}",
                    src, err
                );
            }
        }
    }

    fn finish_and_store_report(&mut self, report: Report, dm: &DerpMap) -> Arc<Report> {
        let report = self.add_report_history_and_set_preferred_derp(report);
        self.log_concise_report(&report, dm);

        report
    }

    fn log_concise_report(&self, r: &Report, dm: &DerpMap) {
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
    /// `r` is stored ref counted and a reference is returned.
    fn add_report_history_and_set_preferred_derp(&mut self, mut r: Report) -> Arc<Report> {
        let mut prev_derp = 0;
        if let Some(ref last) = self.reports.last {
            prev_derp = last.preferred_derp;
        }
        let now = Instant::now();
        const MAX_AGE: Duration = Duration::from_secs(5 * 60);

        // region ID => its best recent latency in last MAX_AGE
        let mut best_recent = HashMap::new();

        // chain the current report as we are still mutating it
        let prevs_iter = self
            .reports
            .prev
            .iter()
            .map(|(a, b)| -> (&Instant, &Report) { (a, b) })
            .chain(std::iter::once((&now, &r)));

        let mut to_remove = Vec::new();
        for (t, pr) in prevs_iter {
            if now.duration_since(*t) > MAX_AGE {
                to_remove.push(*t);
                continue;
            }
            for (region_id, d) in &pr.region_latency {
                let bd = best_recent.entry(*region_id).or_insert(*d);
                if d < bd {
                    *bd = *d;
                }
            }
        }

        for t in to_remove {
            self.reports.prev.remove(&t);
        }

        // Then, pick which currently-alive DERP server from the
        // current report has the best latency over the past MAX_AGE.
        let mut best_any = Duration::default();
        let mut old_region_cur_latency = Duration::default();
        {
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

        let r = Arc::new(r);
        self.reports.prev.insert(now, r.clone());
        self.reports.last = Some(r.clone());

        r
    }

    /// Reports whether `pkt` (from `src`) was our magic hairpin probe packet that we sent to ourselves.
    fn handle_hair_stun(&self, pkt: &[u8], src: SocketAddr) -> bool {
        if let Some(ref hair_tx) = self.reports.current_hair_tx {
            if let Ok(ref tx) = stun::parse_binding_request(pkt) {
                if tx == hair_tx {
                    self.got_hair_stun.send(src).ok();
                    return true;
                }
            }
        }
        false
    }
}

/// Test if IPv6 works at all, or if it's been hard disabled at the OS level.
async fn os_has_ipv6() -> bool {
    // TODO: use socket2 to specify binding to ipv6
    let udp = UdpSocket::bind("[::1]:0").await;
    udp.is_ok()
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

/// Resolves to pending if the inner is `None`.
#[derive(Debug)]
struct MaybeFuture<T> {
    inner: Option<T>,
}

impl<T> Default for MaybeFuture<T> {
    fn default() -> Self {
        MaybeFuture { inner: None }
    }
}

impl<T: Future + Unpin> Future for MaybeFuture<T> {
    type Output = T::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner {
            Some(ref mut t) => Pin::new(t).poll(cx),
            None => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::{prelude::*, EnvFilter};

    fn setup_logging() {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();
    }

    #[tokio::test]
    async fn test_basic() -> Result<()> {
        setup_logging();

        let (stun_addr, stun_stats, done) = stun::test::serve("0.0.0.0".parse().unwrap()).await?;

        let mut client = Client::new(None).await?;
        let dm = stun::test::derp_map_of([stun_addr].into_iter());
        dbg!(&dm);

        for i in 0..5 {
            println!("--round {}", i);
            let r = client.get_report(dm.clone(), None, None).await?;

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
        }

        done.send(()).unwrap();
        assert!(
            stun_stats.total().await >= 5,
            "expected at least 5 stun, got {}",
            stun_stats.total().await,
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_google_stun() -> Result<()> {
        setup_logging();

        let mut client = Client::new(None)
            .await
            .context("failed to create netcheck client")?;
        let stun_port = 19302;
        let host_name = "stun.l.google.com".into();
        let derp_port = 0;
        let mut dm = DerpMap::default_from_node(
            host_name,
            stun_port,
            derp_port,
            UseIpv4::None,
            UseIpv6::None,
        );
        dm.regions.get_mut(&1).unwrap().nodes[0].stun_only = true;
        dbg!(&dm);

        let r = client
            .get_report(dm, None, None)
            .await
            .context("failed to get netcheck report")?;
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

        Ok(())
    }

    #[tokio::test]
    async fn test_udp_tokio() -> Result<()> {
        setup_logging();
        let local_addr = "127.0.0.1";
        let bind_addr = "0.0.0.0";

        let server = UdpSocket::bind(format!("{bind_addr}:0")).await?;
        let addr = server.local_addr()?;

        let server_task = tokio::task::spawn(async move {
            let mut buf = vec![0u8; 32];
            println!("server recv");
            let (n, addr) = server.recv_from(&mut buf).await.unwrap();
            println!("server send");
            server.send_to(&buf[..n], addr).await.unwrap();
        });

        let client = UdpSocket::bind(format!("{bind_addr}:0")).await?;
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

    #[tokio::test]
    async fn test_udp_blocked() -> Result<()> {
        setup_logging();

        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let stun_addr = blackhole.local_addr()?;
        let mut dm = stun::test::derp_map_of([stun_addr].into_iter());
        dm.regions.get_mut(&1).unwrap().nodes[0].stun_only = true;

        let mut client = Client::new(None).await?;

        let r = client.get_report(dm, None, None).await?;
        let mut r: Report = (*r).clone();
        r.upnp = None;
        r.pmp = None;
        r.pcp = None;

        let want = Report {
            // The ip_v4_can_send flag gets set differently across platforms.
            // On Windows this test detects false, while on Linux detects true.
            // That's not relevant to this test, so just accept what we're given.
            ipv4_can_send: r.ipv4_can_send,
            // OS IPv6 test is irrelevant here, accept whatever the current machine has.
            os_has_ipv6: r.os_has_ipv6,
            // Captive portal test is irrelevant; accept what the current report has.
            captive_portal: r.captive_portal,
            ..Default::default()
        };

        assert_eq!(r, want);

        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_add_report_history_set_preferred_derp() -> Result<()> {
        // report returns a *Report from (DERP host, Duration)+ pairs.
        fn report(a: impl IntoIterator<Item = (&'static str, u64)>) -> Option<Arc<Report>> {
            let mut report = Report::default();
            for (s, d) in a {
                assert!(s.starts_with('d'), "invalid derp server key");
                let region_id: usize = s[1..].parse().unwrap();
                report
                    .region_latency
                    .insert(region_id, Duration::from_secs(d));
            }

            Some(Arc::new(report))
        }
        struct Step {
            /// Delay in seconds
            after: u64,
            r: Option<Arc<Report>>,
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
            let mut client = Client::new(None).await?;

            for s in &mut tt.steps {
                // trigger the timer
                time::advance(Duration::from_secs(s.after)).await;
                let r = Arc::try_unwrap(s.r.take().unwrap()).unwrap();
                s.r = Some(client.actor.add_report_history_and_set_preferred_derp(r));
            }
            let last_report = tt.steps[tt.steps.len() - 1].r.clone().unwrap();
            let got = client.actor.reports.prev.len();
            let want = tt.want_prev_len;
            assert_eq!(got, want, "prev length");
            let got = last_report.preferred_derp;
            let want = tt.want_derp;
            assert_eq!(got, want, "preferred_derp");
        }

        Ok(())
    }
}
