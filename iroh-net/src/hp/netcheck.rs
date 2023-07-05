//! Checks the network conditions from the current host.
//!
//! Based on <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>

use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, Context as _, Result};
use bytes::Bytes;
use futures::Future;
use iroh_metrics::{inc, netcheck::NetcheckMetrics};
use rand::seq::IteratorRandom;
use tokio::net::UdpSocket;
use tokio::sync::{self, mpsc, oneshot};
use tokio::task::AbortHandle;
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, error, info, instrument, trace, warn, Instrument};

use crate::{
    net::{interfaces, ip::to_canonical},
    util::MaybeFuture,
};

use self::probe::{Probe, ProbePlan, ProbeProto};

use super::derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};
use super::dns::DNS_RESOLVER;
use super::ping::Pinger;
use super::portmapper;
use super::stun;

mod probe;
mod reportstate;

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
    /// Probe indicating the presence of port mapping protocols on the LAN.
    pub portmap_probe: Option<portmapper::ProbeOutput>,
    /// or 0 for unknown
    pub preferred_derp: u16,
    /// keyed by DERP Region ID
    pub region_latency: HashMap<u16, Duration>,
    /// keyed by DERP Region ID
    pub region_v4_latency: HashMap<u16, Duration>,
    /// keyed by DERP Region ID
    pub region_v6_latency: HashMap<u16, Duration>,
    /// ip:port of global IPv4
    pub global_v4: Option<SocketAddr>,
    /// `[ip]:port` of global IPv6
    pub global_v6: Option<SocketAddr>,
    /// CaptivePortal is set when we think there's a captive portal that is
    /// intercepting HTTP traffic.
    pub captive_portal: Option<bool>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// Client to run netchecks.
///
/// Creating this creates a netcheck actor which runs in the background.  Most of the time
/// it is idle unless [`Client::get_report`] is called, which is the main interface.
///
/// The [`Client`] struct can be cloned and results multiple handles to the running actor.
/// If all [`Client`]s are dropped the actor stops running.
///
/// While running the netcheck actor expects to be passed all received stun packets using
/// [`Client::receive_stun_packet`], the [`crate::hp::magicsock::Conn`] using this
/// client needs to be wired up to do so.
#[derive(Debug, Clone)]
pub struct Client {
    /// Channel to send message to the [`Actor`].
    ///
    /// If all senders are dropped, in other words all clones of this struct are dropped,
    /// the actor will terminate.
    addr: ActorAddr,
    /// Ensures the actor is terminated when the client is dropped.
    _drop_guard: Arc<ClientDropGuard>,
}

#[derive(Debug)]
struct ClientDropGuard {
    task: AbortHandle,
}

impl Drop for ClientDropGuard {
    fn drop(&mut self) {
        debug!("netcheck actor finished");
        self.task.abort();
    }
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
}

impl Default for Reports {
    fn default() -> Self {
        Self {
            next_full: Default::default(),
            prev: Default::default(),
            last: Default::default(),
            last_full: Instant::now(),
        }
    }
}

impl Client {
    /// Creates a new netcheck client.
    ///
    /// This starts a connected actor in the background.  Once the client is dropped it will
    /// stop running.
    pub async fn new(port_mapper: Option<portmapper::Client>) -> Result<Self> {
        let mut actor = Actor::new(port_mapper)?;
        let addr = actor.addr();
        let task = tokio::spawn(async move { actor.run().await });
        let drop_guard = ClientDropGuard {
            task: task.abort_handle(),
        };
        Ok(Client {
            addr,
            _drop_guard: Arc::new(drop_guard),
        })
    }

    /// Pass a received STUN packet to the netchecker.
    ///
    /// Normally the UDP sockets to send STUN messages from are passed in so that STUN
    /// packets are sent from the sockets that carry the real traffic.  However because
    /// these sockets carry real traffic they will also receive non-STUN traffic, thus the
    /// netcheck actor does not read from the sockets directly.  If you receive a STUN
    /// packet on the socket you should pass it to this method.
    ///
    /// It is safe to call this even when the netcheck actor does not currently have any
    /// in-flight STUN probes.  The actor will simply ignore any stray STUN packets.
    ///
    /// There is an implicit queue here which may drop packets if the actor does not keep up
    /// consuming them.
    pub fn receive_stun_packet(&self, payload: Bytes, src: SocketAddr) {
        if let Err(mpsc::error::TrySendError::Full(_)) =
            self.addr.try_send(ActorMessage::StunPacket {
                payload,
                from_addr: src,
            })
        {
            inc!(NetcheckMetrics::StunPacketsDropped);
            warn!("dropping stun packet from {}", src);
        }
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
    pub async fn get_report(
        &mut self,
        dm: DerpMap,
        stun_conn4: Option<Arc<UdpSocket>>,
        stun_conn6: Option<Arc<UdpSocket>>,
    ) -> Result<Arc<Report>> {
        // TODO: consider if DerpMap should be made to easily clone?  It seems expensive
        // right now.
        let (tx, rx) = oneshot::channel();
        self.addr
            .send(ActorMessage::RunCheck {
                derp_map: dm.clone(),
                stun_sock_v4: stun_conn4,
                stun_sock_v6: stun_conn6,
                response_tx: tx,
            })
            .await?;
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(anyhow!("channel closed, actor awol")),
        }
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
async fn check_captive_portal(dm: &DerpMap, preferred_derp: Option<u16>) -> Result<bool> {
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

    if node
        .host_name
        .host_str()
        .map(|s| s.ends_with(&DOT_INVALID))
        .unwrap_or_default()
    {
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

    let host_name = node.host_name.host_str().unwrap_or_default();
    let challenge = format!("ts_{}", host_name);
    let portal_url = format!("http://{}/generate_204", host_name);
    let res = client
        .request(reqwest::Method::GET, portal_url)
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

async fn measure_icmp_latency(reg: &DerpRegion, p: &Pinger) -> Result<Duration> {
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
    let node_addr = get_node_addr(node, ProbeProto::Ipv4)
        .await
        .with_context(|| format!("no address for node {}", node.name))?;

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

/// Returns the IP address to use to communicate to this derp node.
///
/// *proto* specifies the protocol we want to use to talk to the node.
async fn get_node_addr(n: &DerpNode, proto: ProbeProto) -> Result<SocketAddr> {
    let mut port = n.stun_port;
    if port == 0 {
        port = 3478;
    }
    if let Some(ip) = n.stun_test_ip {
        if proto == ProbeProto::Ipv4 && ip.is_ipv6() {
            bail!("STUN test IP set has mismatching protocol");
        }
        if proto == ProbeProto::Ipv6 && ip.is_ipv4() {
            bail!("STUN test IP set has mismatching protocol");
        }
        return Ok(SocketAddr::new(ip, port));
    }

    match proto {
        ProbeProto::Ipv4 => {
            if let UseIpv4::Some(ip) = n.ipv4 {
                return Ok(SocketAddr::new(IpAddr::V4(ip), port));
            }
        }
        ProbeProto::Ipv6 => {
            if let UseIpv6::Some(ip) = n.ipv6 {
                return Ok(SocketAddr::new(IpAddr::V6(ip), port));
            }
        }
        _ => {
            // TODO: original code returns None here, but that seems wrong?
        }
    }

    match n.host_name.host() {
        Some(url::Host::Domain(hostname)) => {
            async move {
                debug!(?proto, %hostname, "Performing DNS lookup for derp addr");

                if let Ok(addrs) = DNS_RESOLVER.lookup_ip(hostname).await {
                    for addr in addrs {
                        if addr.is_ipv4() && proto == ProbeProto::Ipv4 {
                            let addr = to_canonical(addr);
                            return Ok(SocketAddr::new(addr, port));
                        }
                        if addr.is_ipv6() && proto == ProbeProto::Ipv6 {
                            return Ok(SocketAddr::new(addr, port));
                        }
                        if proto == ProbeProto::Https {
                            // For now just return the first one
                            return Ok(SocketAddr::new(addr, port));
                        }
                    }
                }
                Err(anyhow!("no suitable addr found for derp config"))
            }
            .instrument(debug_span!("dns"))
            .await
        }
        Some(url::Host::Ipv4(ip)) => Ok(SocketAddr::new(IpAddr::V4(ip), port)),
        Some(url::Host::Ipv6(ip)) => Ok(SocketAddr::new(IpAddr::V6(ip), port)),
        None => Err(anyhow!("no valid hostname available")),
    }
}

#[derive(Debug)]
pub(crate) struct Inflight {
    /// The STUN transaction ID.
    txn: stun::TransactionId,
    /// The time the STUN probe was sent.
    start: Instant,
    /// Response to send STUN results: latency of STUN response and the discovered address.
    s: sync::oneshot::Sender<(Duration, SocketAddr)>,
}

/// Errors for [`run_probe`].
///
/// The main purpose is to signal whether other probes in this probe set should still be
/// run.  Recall that a probe set is normally a set of identical probes with delays,
/// effectively creating retries, and the first successful probe of a probe set will cancel
/// the others in the set.  So this allows an unsuccessful probe to cancel the remainder of
/// the set or not.
#[derive(Debug)]
enum ProbeError {
    /// Abort the current set.
    AbortSet(anyhow::Error, Probe),
    /// Continue the other probes in the set.
    Error(anyhow::Error, Probe),
}

// /// Executes a particular [`Probe`], including using a delayed start if needed.
// ///
// /// If *pc4* and *pc6* are `None` the STUN probes are disabled.
// #[allow(clippy::too_many_arguments)]
// #[instrument(level = "debug", skip_all, fields(probe = ?probe))]
// async fn run_probe(
//     report: Arc<RwLock<Report>>,
//     pc4: Option<Arc<UdpSocket>>,
//     pc6: Option<Arc<UdpSocket>>,
//     node: DerpNode,
//     probe: Probe,
//     actor_addr: ActorAddr,
//     pinger: Option<Pinger>,
// ) -> Result<ProbeReport, ProbeError> {
//     if !probe.delay().is_zero() {
//         debug!("delaying probe");
//         time::sleep(probe.delay()).await;
//     }

//     if !probe_would_help(&*report.read().await, &probe, &node) {
//         return Err(ProbeError::AbortSet(anyhow!("probe would not help"), probe));
//     }

//     let addr = get_node_addr(&node, probe.proto())
//         .await
//         .context("no derp node addr")
//         .map_err(|e| ProbeError::Error(e, probe.clone()))?;
//     let txid = stun::TransactionId::default();
//     let req = stun::request(txid);
//     let sent = Instant::now(); // after DNS lookup above

//     let (stun_tx, stun_rx) = oneshot::channel();
//     let (msg_response_tx, msg_response_rx) = oneshot::channel();
//     actor_addr
//         .send(ActorMessage::InFlightStun(
//             Inflight {
//                 txn: txid,
//                 start: sent,
//                 s: stun_tx,
//             },
//             msg_response_tx,
//         ))
//         .await
//         .map_err(|e| ProbeError::Error(e.into(), probe.clone()))?;
//     msg_response_rx
//         .await
//         .map_err(|e| ProbeError::Error(e.into(), probe.clone()))?;
//     let mut result = ProbeReport::new(probe.clone());

//     match probe {
//         Probe::Ipv4 { .. } => {
//             if let Some(ref pc4) = pc4 {
//                 let n = pc4.send_to(&req, addr).await;
//                 inc!(NetcheckMetrics::StunPacketsSentIpv4);
//                 debug!(%addr, send_res=?n, %txid, "sending probe IPV4");
//                 // TODO:  || neterror.TreatAsLostUDP(err)
//                 if n.is_ok() && n.unwrap() == req.len() {
//                     result.ipv4_can_send = true;

//                     let (delay, addr) = stun_rx
//                         .await
//                         .map_err(|e| ProbeError::Error(e.into(), probe))?;
//                     result.delay = Some(delay);
//                     result.addr = Some(addr);
//                 }
//             }
//         }
//         Probe::Ipv6 { .. } => {
//             if let Some(ref pc6) = pc6 {
//                 let n = pc6.send_to(&req, addr).await;
//                 inc!(NetcheckMetrics::StunPacketsSentIpv6);
//                 debug!(%addr, snd_res=?n, %txid, "sending probe IPV6");
//                 // TODO:  || neterror.TreatAsLostUDP(err)
//                 if n.is_ok() && n.unwrap() == req.len() {
//                     result.ipv6_can_send = true;

//                     let (delay, addr) = stun_rx
//                         .await
//                         .map_err(|e| ProbeError::Error(e.into(), probe))?;
//                     result.delay = Some(delay);
//                     result.addr = Some(addr);
//                 }
//             }
//         }
//         Probe::Https { region, .. } => {
//             debug!(icmp=%pinger.is_some(), "sending probe HTTPS");

//             let res = if let Some(ref pinger) = pinger {
//                 tokio::join!(
//                     time::timeout(
//                         ICMP_PROBE_TIMEOUT,
//                         measure_icmp_latency(&region, pinger).map(Some)
//                     ),
//                     measure_https_latency(&region)
//                 )
//             } else {
//                 (Ok(None), measure_https_latency(&region).await)
//             };
//             if let Ok(Some(icmp_res)) = res.0 {
//                 match icmp_res {
//                     Ok(d) => {
//                         result.delay = Some(d);
//                         result.ipv4_can_send = true;
//                         result.icmpv4 = true;
//                     }
//                     Err(err) => {
//                         warn!("icmp latency measurement failed: {:?}", err);
//                     }
//                 }
//             }
//             match res.1 {
//                 Ok((d, ip)) => {
//                     result.delay = Some(d);
//                     // We set these IPv4 and IPv6 but they're not really used
//                     // and we don't necessarily set them both. If UDP is blocked
//                     // and both IPv4 and IPv6 are available over TCP, it's basically
//                     // random which fields end up getting set here.
//                     // Since they're not needed, that's fine for now.
//                     if ip.is_ipv4() {
//                         result.ipv4_can_send = true
//                     }
//                     if ip.is_ipv6() {
//                         result.ipv6_can_send = true
//                     }
//                 }
//                 Err(err) => {
//                     warn!("https latency measurement failed: {:?}", err);
//                 }
//             }
//         }
//     }

//     Ok(result)
// }

// fn probe_would_help(report: &Report, probe: &Probe, node: &DerpNode) -> bool {
//     // If the probe is for a region we don't yet know about, that would help.
//     if !report.region_latency.contains_key(&node.region_id) {
//         return true;
//     }

//     // If the probe is for IPv6 and we don't yet have an IPv6 report, that would help.
//     if probe.proto() == ProbeProto::Ipv6 && report.region_v6_latency.is_empty() {
//         return true;
//     }

//     // For IPv4, we need at least two IPv4 results overall to
//     // determine whether we're behind a NAT that shows us as
//     // different source IPs and/or ports depending on who we're
//     // talking to. If we don't yet have two results yet
//     // (`mapping_varies_by_dest_ip` is blank), then another IPv4 probe
//     // would be good.
//     if probe.proto() == ProbeProto::Ipv4 && report.mapping_varies_by_dest_ip.is_none() {
//         return true;
//     }

//     // Otherwise not interesting.
//     false
// }

fn update_latency(m: &mut HashMap<u16, Duration>, region_id: u16, d: Duration) {
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

fn max_duration_value(m: &HashMap<u16, Duration>) -> Duration {
    m.values().max().cloned().unwrap_or_default()
}

// TODO: move to reportcheck.rs probably
#[derive(Debug)]
struct ProbeReport {
    /// Whether we can send IPv4 UDP packets.
    ipv4_can_send: bool,
    /// Whether we can send IPv6 UDP packets.
    ipv6_can_send: bool,
    /// Whether we can send ICMP packets.
    icmpv4: bool,
    /// The latency to the derp node.
    delay: Option<Duration>,
    /// The probe that generated this report.
    probe: Probe,
    /// The discovered public address.
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

/// Messages to send to the [`Actor`].
#[derive(Debug)]
pub(crate) enum ActorMessage {
    /// Run a netcheck.
    ///
    /// Only one netcheck can be run at a time, trying to run multiple concurrently will
    /// fail.
    RunCheck {
        /// The derp configuration.
        derp_map: DerpMap,
        /// Socket to send IPv4 STUN probes from.
        ///
        /// Responses are never read from this socket, they must be passed in via the
        /// [`ActorMessage::StunPacket`] message since the socket is also used to receive
        /// other packets from in the magicsocket (`Conn`).
        ///
        /// If not provided this will attempt to bind a suitable socket itself.
        stun_sock_v4: Option<Arc<UdpSocket>>,
        /// Socket to send IPv6 STUN probes from.
        ///
        /// Like `stun_sock_v4` but for IPv6.
        stun_sock_v6: Option<Arc<UdpSocket>>,
        /// Channel to receive the response.
        response_tx: oneshot::Sender<Result<Arc<Report>>>,
    },
    /// A report produced by [`ReportState`].
    ReportReady {
        report: Box<Report>,
        derp_map: DerpMap,
    },
    /// [`ReportState`] failed to produce a report.
    ReportAborted,
    /// An incoming STUN packet to parse.
    StunPacket {
        /// The raw UDP payload.
        payload: Bytes,
        /// The address this was claimed to be received from.
        from_addr: SocketAddr,
    },
    /// A probe wants to register an in-flight STUN request.
    ///
    /// The sender is signalled once the STUN packet is registered with the actor and will
    /// correctly accept the STUN response.
    InFlightStun(Inflight, oneshot::Sender<()>),
}

/// Sender to the [`Actor`].
///
/// Unlike [`Client`] this is the raw channel to send messages over.  Keeping this alive
/// will not keep the actor alive, which makes this handy to pass to internal tasks.
#[derive(Debug, Clone)]
struct ActorAddr {
    sender: mpsc::Sender<ActorMessage>,
}

impl ActorAddr {
    async fn send(&self, msg: ActorMessage) -> Result<(), mpsc::error::SendError<ActorMessage>> {
        self.sender.send(msg).await.map_err(|err| {
            error!("netcheck actor lost");
            err
        })
    }

    fn try_send(&self, msg: ActorMessage) -> Result<(), mpsc::error::TrySendError<ActorMessage>> {
        self.sender.try_send(msg).map_err(|err| {
            match &err {
                mpsc::error::TrySendError::Full(_) => {
                    // TODO: metrics, though the only place that uses this already does its
                    // own metrics.
                    warn!("netcheck actor inbox full");
                }
                mpsc::error::TrySendError::Closed(_) => error!("netcheck actor lost"),
            }
            err
        })
    }
}

/// The netcheck actor.
///
/// This actor runs for the entire duration there's a [`Client`] connected.
#[derive(Debug)]
struct Actor {
    // Actor plumbing.
    /// Actor messages channel.
    ///
    /// If there are no more senders the actor stops.
    receiver: mpsc::Receiver<ActorMessage>,
    /// The sender side of the messages channel.
    ///
    /// This allows creating new [`ActorAddr`]s from the actor.
    sender: mpsc::Sender<ActorMessage>,
    /// A collection of previously generated reports.
    ///
    /// Sometimes it is useful to look at past reports to decide what to do.
    reports: Reports,

    // Actor configuration.
    /// Whether the client should try to reach things other than localhost.
    ///
    /// This is set to true in tests to avoid probing the local LAN's router, etc.
    skip_external_network: bool,
    /// The port mapper client, if those are requested.
    ///
    /// The port mapper is responsible for talking to routers via UPnP and the like to try
    /// and open ports.
    port_mapper: Option<portmapper::Client>,

    // Actor state.
    /// Information about the currently in-flight STUN requests.
    ///
    /// This is used to complete the STUN probe when receiving STUN packets.
    in_flight_stun_requests: HashMap<stun::TransactionId, Inflight>,
    // /// The response channel if there is a check running.
    // ///
    // /// There can only ever be one check running at a time.  If it is running the response
    // /// channel is stored here.
    // current_check_run: Option<oneshot::Sender<Result<Arc<Report>>>>,
    /// The ReportState actor currently generating a report.
    ///
    /// The [`tokio_util::sync::DropGuard`] is to ensure the local STUN listener is shut
    /// down if it was started.  The finished report is sent on the channel.
    current_report_run: Option<(
        reportstate::ReportState,
        tokio_util::sync::DropGuard,
        oneshot::Sender<Result<Arc<Report>>>,
    )>,
}

impl Actor {
    /// Creates a new actor.
    ///
    /// This does not start the actor, see [`Actor::main`] for this.  You should not
    /// normally create this directly but rather create a [`Client`].
    fn new(port_mapper: Option<portmapper::Client>) -> Result<Self> {
        // TODO: consider an instrumented flume channel so we have metrics.
        let (sender, receiver) = mpsc::channel(32);
        Ok(Self {
            receiver,
            sender,
            reports: Default::default(),
            skip_external_network: false,
            port_mapper,
            in_flight_stun_requests: Default::default(),
            current_report_run: None,
        })
    }

    /// Returns the channel to send messages to the actor.
    fn addr(&self) -> ActorAddr {
        ActorAddr {
            sender: self.sender.clone(),
        }
    }

    /// Run the actor.
    ///
    /// It will now run and handle messages.  Once the connected [`Client`] (including all
    /// its clones) is dropped this will terminate.
    #[instrument(name = "netcheck.actor", skip_all)]
    async fn run(&mut self) {
        debug!("netcheck actor starting");
        while let Some(msg) = self.receiver.recv().await {
            trace!(?msg, "handling message");
            match msg {
                ActorMessage::RunCheck {
                    derp_map,
                    stun_sock_v4,
                    stun_sock_v6,
                    response_tx,
                } => {
                    self.handle_run_check(derp_map, stun_sock_v4, stun_sock_v6, response_tx)
                        .await;
                }
                ActorMessage::ReportReady { report, derp_map } => {
                    self.handle_report_ready(report, derp_map);
                }
                ActorMessage::ReportAborted => {
                    self.handle_report_aborted();
                }
                ActorMessage::StunPacket { payload, from_addr } => {
                    self.handle_stun_packet(&payload, from_addr);
                }
                ActorMessage::InFlightStun(inflight, response_tx) => {
                    self.handle_in_flight_stun(inflight, response_tx);
                }
            }
        }
    }

    /// Starts a check run as requested by the [`ActorMessage::RunCheck`] message.
    ///
    /// If *stun_sock_v4* or *stun_sock_v6* are not provided this will bind the sockets
    /// itself.  This is not ideal since really you want to send STUN probes from the
    /// sockets you will be using.
    async fn handle_run_check(
        &mut self,
        derp_map: DerpMap,
        stun_sock_v4: Option<Arc<UdpSocket>>,
        stun_sock_v6: Option<Arc<UdpSocket>>,
        response_tx: oneshot::Sender<Result<Arc<Report>>>,
    ) {
        if self.current_report_run.is_some() {
            warn!("ignoring RunCheck request; ReportState actor already running");
            return;
        }

        let now = Instant::now();

        let cancel_token = CancellationToken::new();
        let stun_sock_v4 = match stun_sock_v4 {
            Some(sock) => Some(sock),
            None => {
                bind_local_stun_socket(
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                    self.addr(),
                    cancel_token.clone(),
                )
                .await
            }
        };
        let stun_sock_v6 = match stun_sock_v6 {
            Some(sock) => Some(sock),
            None => {
                bind_local_stun_socket(
                    SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
                    self.addr(),
                    cancel_token.clone(),
                )
                .await
            }
        };
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
            inc!(NetcheckMetrics::ReportsFull);
        }
        inc!(NetcheckMetrics::Reports);

        // TODO: not sure we're allowed to await in this function...  We can make the
        // probeplan inside the ReportState actor though.
        let if_state = interfaces::State::new().await;
        let last = self.reports.last.clone();
        let plan = ProbePlan::new(&derp_map, &if_state, last.as_deref());

        let actor = reportstate::ReportState::new(
            self.addr(),
            last.clone(),
            plan,
            self.port_mapper.clone(),
            self.skip_external_network,
            last.is_some(), // TODO: doesn't need to be passed
            derp_map,
            stun_sock_v4,
            stun_sock_v6,
        );

        self.current_report_run = Some((actor, cancel_token.drop_guard(), response_tx));
    }

    fn handle_report_ready(&mut self, report: Box<Report>, derp_map: DerpMap) {
        let report = self.finish_and_store_report(*report, &derp_map);
        self.in_flight_stun_requests.clear();
        if let Some((_actor, _guard, report_tx)) = self.current_report_run.take() {
            report_tx.send(Ok(report)).ok();
        }
    }

    fn handle_report_aborted(&mut self) {
        self.in_flight_stun_requests.clear();
        if let Some((_actor, _guard, report_tx)) = self.current_report_run.take() {
            report_tx.send(Err(anyhow!("report aborted"))).ok();
        }
    }

    /// Handles [`ActorMesage::StunPacket`].
    ///
    /// If there are currently no in-flight stun requests registerd this is dropped,
    /// otherwise forwarded to the probe.
    fn handle_stun_packet(&mut self, pkt: &[u8], src: SocketAddr) {
        trace!(%src, "received STUN packet");
        if self.in_flight_stun_requests.is_empty() {
            return;
        }

        match &src {
            SocketAddr::V4(_) => inc!(NetcheckMetrics::StunPacketsRecvIpv4),
            SocketAddr::V6(_) => inc!(NetcheckMetrics::StunPacketsRecvIpv6),
        }

        match stun::parse_response(pkt) {
            Ok((txn, addr_port)) => match self.in_flight_stun_requests.remove(&txn) {
                Some(inf) => {
                    debug!(%src, %txn, "received known STUN packet");
                    let elapsed = inf.start.elapsed();
                    inf.s.send((elapsed, addr_port)).ok();
                }
                None => {
                    debug!(%src, %txn, "received unexpected STUN message response");
                }
            },
            Err(err) => {
                match stun::parse_binding_request(pkt) {
                    Ok(txn) => {
                        // Is this our hairpin request?
                        match self.in_flight_stun_requests.remove(&txn) {
                            Some(inf) => {
                                debug!(%src, %txn, "received our hairpin STUN request");
                                let elapsed = inf.start.elapsed();
                                inf.s.send((elapsed, src)).ok();
                            }
                            None => {
                                debug!(%src, %txn, "unknown STUN request");
                            }
                        }
                    }
                    Err(_) => {
                        debug!(%src, "received invalid STUN response: {err:#}");
                    }
                }
            }
        }
    }

    /// Handles [`ActorMessage::InFlightStun`].
    ///
    /// The in-flight request is added to [`Actor::in_flight_stun_requests`] so that
    /// [`Actor::handle_stun_packet`] can forward packets correctly.
    ///
    /// *response_tx* is to signal the actor message has been handled.
    fn handle_in_flight_stun(&mut self, inflight: Inflight, response_tx: oneshot::Sender<()>) {
        self.in_flight_stun_requests.insert(inflight.txn, inflight);
        response_tx.send(()).ok();
    }

    fn finish_and_store_report(&mut self, report: Report, dm: &DerpMap) -> Arc<Report> {
        let report = self.add_report_history_and_set_preferred_derp(report);
        self.log_concise_report(&report, dm);

        report
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
        if let Some(probe) = &r.portmap_probe {
            log += &format!(" {}", probe);
        } else {
            log += " portmap=?";
        }
        if let Some(ipp) = r.global_v4 {
            log += &format!(" v4a={ipp}");
        }
        if let Some(ipp) = r.global_v6 {
            log += &format!(" v6a={ipp}");
        }
        if let Some(c) = r.captive_portal {
            log += &format!(" captiveportal={c}");
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
}

/// Attempts to bind a local socket to send STUN packets from.
///
/// If successfull this returns the bound socket and will forward STUN responses to the
/// provided *actor_addr*.  The *cancel_token* serves to stop the packet forwarding when the
/// socket is no longer needed.
async fn bind_local_stun_socket(
    addr: SocketAddr,
    actor_addr: ActorAddr,
    cancel_token: CancellationToken,
) -> Option<Arc<UdpSocket>> {
    let sock = match UdpSocket::bind(addr).await {
        Ok(sock) => Arc::new(sock),
        Err(err) => {
            debug!("failed to bind STUN socket at 0.0.0.0:0: {}", err);
            return None;
        }
    };
    let span = debug_span!(
        "stun_udp_listener",
        local_addr = sock
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or(String::from("-")),
    );
    {
        let sock = sock.clone();
        tokio::spawn(
            async move {
                debug!("udp stun socket listener started");
                // TODO: Can we do better for buffers here?  Probably doesn't matter much.
                let mut buf = vec![0u8; 64 << 10];
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel_token.cancelled() => break,
                        res = recv_stun_once(&sock, &mut buf, &actor_addr) => {
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
    Some(sock)
}

/// Receive STUN response from a UDP socket, pass it to the actor.
async fn recv_stun_once(sock: &UdpSocket, buf: &mut [u8], actor_addr: &ActorAddr) -> Result<()> {
    let (count, mut from_addr) = sock
        .recv_from(buf)
        .await
        .context("Error reading from stun socket")?;
    let payload = &buf[..count];
    from_addr.set_ip(to_canonical(from_addr.ip()));
    let msg = ActorMessage::StunPacket {
        payload: Bytes::from(payload.to_vec()),
        from_addr,
    };
    actor_addr.send(msg).await.context("actor stopped")
}

/// Test if IPv6 works at all, or if it's been hard disabled at the OS level.
pub(crate) async fn os_has_ipv6() -> bool {
    // TODO: use socket2 to specify binding to ipv6
    let udp = UdpSocket::bind("[::1]:0").await;
    udp.is_ok()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::BytesMut;
    use tokio::time;

    use crate::test_utils::setup_logging;

    use super::*;

    #[tokio::test]
    async fn test_basic() -> Result<()> {
        let _guard = setup_logging();
        let (stun_addr, stun_stats, done) = stun::test::serve("0.0.0.0".parse().unwrap()).await?;

        let mut client = Client::new(None).await?;
        let dm = stun::test::derp_map_of([stun_addr].into_iter());
        dbg!(&dm);

        // Note that the ProbePlan will change with each iteration.
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
    async fn test_iroh_computer_stun() -> Result<()> {
        let _guard = setup_logging();

        let mut client = Client::new(None)
            .await
            .context("failed to create netcheck client")?;

        let stun_servers = vec![("https://derp.iroh.network.", 3478, 0)];

        let mut dm = DerpMap::default();
        dm.regions.insert(
            1,
            DerpRegion {
                region_id: 1,
                nodes: stun_servers
                    .into_iter()
                    .enumerate()
                    .map(|(i, (host_name, stun_port, derp_port))| DerpNode {
                        name: format!("default-{}", i),
                        region_id: 1,
                        host_name: host_name.parse().unwrap(),
                        stun_only: true,
                        stun_port,
                        ipv4: UseIpv4::None,
                        ipv6: UseIpv6::None,
                        derp_port,
                        stun_test_ip: None,
                    })
                    .collect(),
                avoid: false,
                region_code: "default".into(),
            },
        );
        dbg!(&dm);

        let r = client
            .get_report(dm, None, None)
            .await
            .context("failed to get netcheck report")?;

        dbg!(&r);
        if r.udp {
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
        } else {
            eprintln!("missing UDP, probe not returned by network");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_udp_tokio() -> Result<()> {
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
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let stun_addr = blackhole.local_addr()?;
        let mut dm = stun::test::derp_map_of([stun_addr].into_iter());
        dm.regions.get_mut(&1).unwrap().nodes[0].stun_only = true;

        let mut client = Client::new(None).await?;

        let r = client.get_report(dm, None, None).await?;
        let mut r: Report = (*r).clone();
        r.portmap_probe = None;

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
                let region_id: u16 = s[1..].parse().unwrap();
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
            want_derp: u16,
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
            let mut actor = Actor::new(None).unwrap();
            for s in &mut tt.steps {
                // trigger the timer
                time::advance(Duration::from_secs(s.after)).await;
                let r = Arc::try_unwrap(s.r.take().unwrap()).unwrap();
                s.r = Some(actor.add_report_history_and_set_preferred_derp(r));
            }
            let last_report = tt.steps.last().unwrap().r.clone().unwrap();
            let got = actor.reports.prev.len();
            let want = tt.want_prev_len;
            assert_eq!(got, want, "prev length");
            let got = last_report.preferred_derp;
            let want = tt.want_derp;
            assert_eq!(got, want, "preferred_derp");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_hairpin() -> Result<()> {
        // Hairpinning is initiated after we discover our own IPv4 socket address (IP +
        // port) via STUN, so the test needs to have a STUN server and perform STUN over
        // IPv4 first.  Hairpinning detection works by sending a STUN *request* to **our own
        // public socket address** (IP + port).  If the router supports hairpinning the STUN
        // request is returned back to us and received on our public address.  This doesn't
        // need to be a STUN request, but STUN already has a unique transaction ID which we
        // can easily use to identify the packet.

        // Setup STUN server and create derpmap.
        let (stun_addr, _stun_stats, _done) = stun::test::serve_v4().await?;
        let dm = stun::test::derp_map_of([stun_addr].into_iter());
        dbg!(&dm);

        let mut client = Client::new(None).await?;

        // Set up an external socket to send STUN requests from, this will be discovered as
        // our public socket address by STUN.  We send back any packets received on this
        // socket to the netcheck client using Client::receive_stun_packet.  Once we sent
        // the hairpin STUN request (from a different randomly bound socket) we are sending
        // it to this socket, which is forwarnding it back to our netcheck client, because
        // this dumb implementation just forwards anything even if it would be garbage.
        // Thus hairpinning detection will declare hairpinning to work.
        let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let sock = Arc::new(sock);
        info!(addr=?sock.local_addr().unwrap(), "Using local addr");
        let task = {
            let sock = sock.clone();
            let client = client.clone();
            tokio::spawn(async move {
                let mut buf = BytesMut::zeroed(64 << 10);
                loop {
                    let (count, src) = sock.recv_from(&mut buf).await.unwrap();
                    info!(
                        addr=?sock.local_addr().unwrap(),
                        %count,
                        "Forwarding payload to netcheck client",
                    );
                    let payload = buf.split_to(count).freeze();
                    client.receive_stun_packet(payload, src);
                }
            })
        };

        let r = client.get_report(dm, Some(sock), None).await?;
        dbg!(&r);
        assert_eq!(r.hair_pinning, Some(true));

        task.abort();
        Ok(())
    }

    // TODO: test captive task
}
