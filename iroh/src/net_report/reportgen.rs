//! The reportgen actor is responsible for generating a single net_report report.
//!
//! It is implemented as an actor with [`Client`] as handle.
//!
//! The actor starts generating the report as soon as it is created, it does not receive any
//! messages from the client.  It follows roughly these steps:
//!
//! - Determines host IPv6 support.
//! - Creates portmapper future.
//! - Creates captive portal detection future.
//! - Creates Probe Set futures.
//!   - These send messages to the reportgen actor.
//! - Loops driving the futures and handling actor messages:
//!   - Disables futures as they are completed or aborted.
//!   - Stop if there are no outstanding tasks/futures, or on timeout.
//! - Sends the completed report to the net_report actor.

#[cfg(not(wasm_browser))]
use std::net::{SocketAddrV4, SocketAddrV6};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use http::StatusCode;
use iroh_base::RelayUrl;
use iroh_relay::{defaults::DEFAULT_RELAY_QUIC_PORT, http::RELAY_PROBE_PATH, RelayMap, RelayNode};
#[cfg(not(wasm_browser))]
use iroh_relay::{
    dns::{DnsError, DnsResolver, StaggeredError},
    quic::QuicClient,
};
#[cfg(wasm_browser)]
use n0_future::future::Pending;
use n0_future::{
    task::{self, AbortOnDropHandle, JoinSet},
    time::{self, Duration, Instant},
    StreamExt as _,
};
use rand::seq::IteratorRandom;
use snafu::{IntoError, OptionExt, ResultExt, Snafu};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, error, info_span, trace, warn, Instrument};
use url::Host;

#[cfg(wasm_browser)]
use super::portmapper; // We stub the library
#[cfg(not(wasm_browser))]
use super::{defaults::timeouts::DNS_TIMEOUT, ip_mapped_addrs::IpMappedAddresses};
use super::{
    probes::{Probe, ProbePlan},
    Report,
};
#[cfg(not(wasm_browser))]
use crate::discovery::dns::DNS_STAGGERING_MS;
use crate::net_report::defaults::timeouts::{
    CAPTIVE_PORTAL_DELAY, CAPTIVE_PORTAL_TIMEOUT, OVERALL_REPORT_TIMEOUT, PROBES_TIMEOUT,
};

/// Holds the state for a single report generation.
///
/// Dropping this will cancel the actor and stop the report generation.
#[derive(Debug)]
pub(super) struct Client {
    _drop_guard: AbortOnDropHandle<()>,
}

/// Some details required from the interface state of the device.
#[derive(Debug, Clone, Default)]
pub(crate) struct IfStateDetails {
    /// Do we have IPv4 capbilities
    pub have_v4: bool,
    /// Do we have IPv6 capbilities
    pub have_v6: bool,
}

impl IfStateDetails {
    #[cfg(test)]
    pub(super) fn fake() -> Self {
        IfStateDetails {
            have_v4: true,
            have_v6: true,
        }
    }
}

impl From<netwatch::netmon::State> for IfStateDetails {
    fn from(value: netwatch::netmon::State) -> Self {
        IfStateDetails {
            have_v4: value.have_v4,
            have_v6: value.have_v6,
        }
    }
}

/// Any state that depends on sockets being available in the current environment.
///
/// Factored out so it can be disabled easily in browsers.
#[cfg(not(wasm_browser))]
#[derive(Debug, Clone)]
pub(crate) struct SocketState {
    /// QUIC client to do QUIC address Discovery
    pub(crate) quic_client: Option<QuicClient>,
    /// The DNS resolver to use for probes that need to resolve DNS records.
    pub(crate) dns_resolver: DnsResolver,
    /// Optional [`IpMappedAddresses`] used to enable QAD in iroh
    pub(crate) ip_mapped_addrs: Option<IpMappedAddresses>,
}

impl Client {
    /// Creates a new actor generating a single report.
    ///
    /// The actor starts running immediately and only generates a single report, after which
    /// it shuts down.  Dropping this handle will abort the actor.
    pub(super) fn new(
        last_report: Option<Report>,
        relay_map: RelayMap,
        protocols: BTreeSet<Probe>,
        if_state: IfStateDetails,
        #[cfg(not(wasm_browser))] socket_state: SocketState,
        #[cfg(any(test, feature = "test-utils"))] insecure_skip_relay_cert_verify: bool,
    ) -> (Self, mpsc::Receiver<ProbeFinished>) {
        let (msg_tx, msg_rx) = mpsc::channel(32);
        let actor = Actor {
            msg_tx,
            last_report,
            relay_map,
            protocols,
            #[cfg(not(wasm_browser))]
            socket_state,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
            if_state,
        };
        let task = task::spawn(actor.run().instrument(info_span!("reportgen.actor")));
        (
            Self {
                _drop_guard: AbortOnDropHandle::new(task),
            },
            msg_rx,
        )
    }
}

/// The reportstate actor.
///
/// This actor starts, generates a single report and exits.
#[derive(Debug)]
struct Actor {
    msg_tx: mpsc::Sender<ProbeFinished>,

    // Provided state
    /// The previous report, if it exists.
    last_report: Option<Report>,
    /// The relay configuration.
    relay_map: RelayMap,

    // Internal state.
    /// Protocols we should attempt to create probes for, if we have the correct
    /// configuration for that protocol.
    protocols: BTreeSet<Probe>,

    /// Any socket-related state that doesn't exist/work in browsers
    #[cfg(not(wasm_browser))]
    socket_state: SocketState,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
    if_state: IfStateDetails,
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(module)]
pub(super) enum ProbesError {
    #[snafu(display("Probe failed"))]
    ProbeFailure { source: ProbeError },
    #[snafu(display("All probes failed"))]
    AllProbesFailed,
    #[snafu(display("Probe cancelled"))]
    Cancelled,
    #[snafu(display("Probe timed out"))]
    Timeout,
}

#[derive(Debug)]
pub(super) enum ProbeFinished {
    Regular(Result<ProbeReport, ProbesError>),
    #[cfg(not(wasm_browser))]
    CaptivePortal(Option<bool>),
}

impl Actor {
    async fn run(self) {
        match time::timeout(OVERALL_REPORT_TIMEOUT, self.run_inner()).await {
            Ok(()) => debug!("reportgen actor finished"),
            Err(time::Elapsed { .. }) => {
                warn!("reportgen timed out");
            }
        }
    }

    /// Runs the main reportgen actor logic.
    ///
    /// This actor runs by:
    ///
    /// - Creates a captive portal future.
    /// - Creates ProbeSet futures in a group of futures.
    /// - Runs a main loop:
    ///   - Drives all the above futures.
    ///   - Receives actor messages (sent by those futures).
    ///   - Updates the report, cancels unneeded futures.
    /// - Sends the report to the net_report actor.
    async fn run_inner(self) {
        debug!("reportstate actor starting");

        let mut probes = JoinSet::default();

        let _probes_token = self.spawn_probes_task(self.if_state.clone(), &mut probes);
        let mut num_probes = probes.len();

        let captive_token = self.prepare_captive_portal_task(&mut probes);

        // any reports of working UDP/QUIC?
        let mut have_udp = false;

        // Check for probes finishing.
        while let Some(probe_result) = probes.join_next().await {
            trace!(?probe_result, num_probes, "processing finished probe");
            match probe_result {
                Ok(report) => {
                    #[cfg_attr(wasm_browser, allow(irrefutable_let_patterns))]
                    if let ProbeFinished::Regular(report) = &report {
                        have_udp |= report.as_ref().map(|r| r.is_udp()).unwrap_or_default();
                        num_probes -= 1;

                        // If all probes are done & we have_udp cancel captive
                        if num_probes == 0 {
                            debug!("all regular probes done");
                            debug_assert!(probes.len() <= 1, "{} probes", probes.len());

                            if have_udp {
                                captive_token.cancel();
                            }
                        }
                    }
                    self.msg_tx.send(report).await.ok();
                }
                Err(e) => {
                    if e.is_panic() {
                        error!("Task panicked {:?}", e);
                        break;
                    }
                    warn!("probes task join error: {:?}", e);
                }
            }
        }
    }

    /// Creates the future which will perform the captive portal check.
    fn prepare_captive_portal_task(&self, tasks: &mut JoinSet<ProbeFinished>) -> CancellationToken {
        let token = CancellationToken::new();

        // If we're doing a full probe, also check for a captive portal. We
        // delay by a bit to wait for UDP QAD to finish, to avoid the probe if
        // it's unnecessary.
        #[cfg(not(wasm_browser))]
        if self.last_report.is_none() {
            // Even if we're doing a non-incremental update, we may want to try our
            // preferred relay for captive portal detection.
            let preferred_relay = self
                .last_report
                .as_ref()
                .and_then(|l| l.preferred_relay.clone());

            let dns_resolver = self.socket_state.dns_resolver.clone();
            let dm = self.relay_map.clone();
            let token = token.clone();
            tasks.spawn(
                async move {
                    let res = token
                        .run_until_cancelled_owned(async move {
                            time::sleep(CAPTIVE_PORTAL_DELAY).await;
                            trace!("check started after {CAPTIVE_PORTAL_DELAY:?}");
                            time::timeout(
                                CAPTIVE_PORTAL_TIMEOUT,
                                check_captive_portal(&dns_resolver, &dm, preferred_relay),
                            )
                            .await
                        })
                        .await;
                    let res = match res {
                        Some(Ok(Ok(found))) => Some(found),
                        Some(Ok(Err(err))) => {
                            match err {
                                CaptivePortalError::CreateReqwestClient { source }
                                | CaptivePortalError::HttpRequest { source }
                                    if source.is_connect() =>
                                {
                                    debug!("check_captive_portal failed: {source:#}");
                                }
                                err => warn!("check_captive_portal error: {err:#}"),
                            }
                            None
                        }
                        Some(Err(time::Elapsed { .. })) => {
                            warn!("probe timed out");
                            None
                        }
                        None => {
                            trace!("probe cancelled");
                            None
                        }
                    };
                    ProbeFinished::CaptivePortal(res)
                }
                .instrument(debug_span!("captive-portal")),
            );
        }
        token
    }

    /// Prepares the future which will run all the probes as per generated ProbePlan.
    ///
    /// Probes operate like the following:
    ///
    /// - A future is created for each probe in all probe sets.
    /// - All probes in a set are grouped in [`JoinSet`].
    /// - All those probe sets are grouped in one overall [`JoinSet`].
    ///   - This future is polled by the main actor loop to make progress.
    /// - Once a probe future is polled:
    ///   - Many probes start with a delay, they sleep during this time.
    ///   - When a probe starts it first asks the reportgen [`Actor`] if it is still useful
    ///     to run.  If not it aborts the entire probe set.
    ///   - When a probe finishes, its [`ProbeReport`] is yielded to the reportgen actor.
    /// - Probes get aborted in several ways:
    ///   - A running it can fail and abort the entire probe set if it deems the
    ///     failure permanent.  Probes in a probe set are essentially retries.
    ///   - Once there are [`ProbeReport`]s from enough nodes, all remaining probes are
    ///     aborted.  That is, the main actor loop stops polling them.
    fn spawn_probes_task(
        &self,
        if_state: IfStateDetails,
        probes: &mut JoinSet<ProbeFinished>,
    ) -> CancellationToken {
        debug!(?if_state, "local interface details");
        let plan = match self.last_report {
            Some(ref report) => {
                ProbePlan::with_last_report(&self.relay_map, report, &self.protocols)
            }
            None => ProbePlan::initial(&self.relay_map, &self.protocols),
        };
        trace!(%plan, "probe plan");

        let token = CancellationToken::new();

        for probe_set in plan.iter() {
            let set_token = token.child_token();
            let proto = probe_set.proto();
            for (delay, relay_node) in probe_set.params() {
                let probe_token = set_token.child_token();

                let fut = probe_token.run_until_cancelled_owned(time::timeout(
                    PROBES_TIMEOUT,
                    proto.run(
                        *delay,
                        relay_node.clone(),
                        #[cfg(not(wasm_browser))]
                        self.socket_state.clone(),
                        #[cfg(any(test, feature = "test-utils"))]
                        self.insecure_skip_relay_cert_verify,
                    ),
                ));
                probes.spawn(
                    async move {
                        let res = fut.await;
                        let res = match res {
                            Some(Ok(Ok(report))) => Ok(report),
                            Some(Ok(Err(err))) => {
                                warn!("probe failed: {:#}", err);
                                Err(probes_error::ProbeFailureSnafu {}.into_error(err))
                            }
                            Some(Err(time::Elapsed { .. })) => {
                                Err(probes_error::TimeoutSnafu.build())
                            }
                            None => Err(probes_error::CancelledSnafu.build()),
                        };
                        ProbeFinished::Regular(res)
                    }
                    .instrument(debug_span!(
                        "run-probe",
                        ?proto,
                        ?delay,
                        ?relay_node
                    )),
                );
            }
        }

        token
    }
}

/// The result of running a probe.
#[derive(Debug, Clone)]
pub(super) enum ProbeReport {
    #[cfg(not(wasm_browser))]
    QadIpv4(QadProbeReport),
    #[cfg(not(wasm_browser))]
    QadIpv6(QadProbeReport),
    Https(HttpsProbeReport),
}

impl ProbeReport {
    #[cfg(not(wasm_browser))]
    pub(super) fn is_udp(&self) -> bool {
        matches!(self, Self::QadIpv4(_) | Self::QadIpv6(_))
    }

    #[cfg(wasm_browser)]
    pub(super) fn is_udp(&self) -> bool {
        false
    }
}

#[cfg(not(wasm_browser))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct QadProbeReport {
    /// The relay node that was probed
    pub(super) node: RelayUrl,
    /// The latency to the relay node.
    pub(super) latency: Duration,
    /// The discovered public address.
    pub(super) addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub(super) struct HttpsProbeReport {
    /// The relay node that was probed
    pub(super) node: RelayUrl,
    /// The latency to the relay node.
    pub(super) latency: Duration,
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub(super) enum ProbeError {
    #[snafu(display("Client is gone"))]
    ClientGone,
    #[snafu(display("Probe is no longer useful"))]
    NotUseful,
    #[snafu(display("Failed to run HTTPS probe"))]
    Https { source: MeasureHttpsLatencyError },
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub(super) enum QuicError {
    #[snafu(display("No QUIC endpoint available"))]
    NoEndpoint,
    #[snafu(display("URL must have 'host' to use QUIC address discovery probes"))]
    InvalidUrl,
}

/// Pieces needed to do QUIC address discovery.
#[derive(derive_more::Debug, Clone)]
pub struct QuicConfig {
    /// A QUIC Endpoint
    #[debug("quinn::Endpoint")]
    pub ep: quinn::Endpoint,
    /// A client config.
    pub client_config: rustls::ClientConfig,
    /// Enable ipv4 QUIC address discovery probes
    pub ipv4: bool,
    /// Enable ipv6 QUIC address discovery probes
    pub ipv6: bool,
}

impl Probe {
    /// Executes this particular [`Probe`], including using a delayed start if needed.
    async fn run(
        self,
        delay: Duration,
        relay_node: Arc<RelayNode>,
        #[cfg(not(wasm_browser))] socket_state: SocketState,
        #[cfg(any(test, feature = "test-utils"))] insecure_skip_relay_cert_verify: bool,
    ) -> Result<ProbeReport, ProbeError> {
        if !delay.is_zero() {
            trace!("delaying probe");
            time::sleep(delay).await;
        }
        debug!("starting probe");

        match self {
            Probe::Https => {
                match run_https_probe(
                    #[cfg(not(wasm_browser))]
                    &socket_state.dns_resolver,
                    relay_node.url.clone(),
                    #[cfg(any(test, feature = "test-utils"))]
                    insecure_skip_relay_cert_verify,
                )
                .await
                {
                    Ok(report) => Ok(ProbeReport::Https(report)),
                    Err(err) => Err(probe_error::HttpsSnafu.into_error(err)),
                }
            }
            #[cfg(not(wasm_browser))]
            Probe::QadIpv4 | Probe::QadIpv6 => unreachable!("must not be used"),
        }
    }
}

#[cfg(not(wasm_browser))]
pub(super) fn maybe_to_mapped_addr(
    ip_mapped_addrs: Option<&IpMappedAddresses>,
    addr: SocketAddr,
) -> SocketAddr {
    if let Some(ip_mapped_addrs) = ip_mapped_addrs {
        return ip_mapped_addrs.get_or_register(addr).private_socket_addr();
    }
    addr
}

#[cfg(not(wasm_browser))]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
enum CaptivePortalError {
    #[snafu(transparent)]
    DnsLookup { source: StaggeredError<DnsError> },
    #[snafu(display("Creating HTTP client failed"))]
    CreateReqwestClient { source: reqwest::Error },
    #[snafu(display("HTTP request failed"))]
    HttpRequest { source: reqwest::Error },
}

/// Reports whether or not we think the system is behind a
/// captive portal, detected by making a request to a URL that we know should
/// return a "204 No Content" response and checking if that's what we get.
///
/// The boolean return is whether we think we have a captive portal.
#[cfg(not(wasm_browser))]
async fn check_captive_portal(
    dns_resolver: &DnsResolver,
    dm: &RelayMap,
    preferred_relay: Option<RelayUrl>,
) -> Result<bool, CaptivePortalError> {
    // If we have a preferred relay node and we can use it for non-QAD requests, try that;
    // otherwise, pick a random one suitable for non-STUN requests.

    let preferred_relay = preferred_relay.and_then(|url| dm.get_node(&url).map(|_| url));

    let url = match preferred_relay {
        Some(url) => url,
        None => {
            let urls: Vec<_> = dm.nodes().map(|n| n.url.clone()).collect();
            if urls.is_empty() {
                debug!("No suitable relay node for captive portal check");
                return Ok(false);
            }

            let i = (0..urls.len())
                .choose(&mut rand::thread_rng())
                .unwrap_or_default();
            urls[i].clone()
        }
    };

    let mut builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());

    if let Some(Host::Domain(domain)) = url.host() {
        // Use our own resolver rather than getaddrinfo
        //
        // Be careful, a non-zero port will override the port in the URI.
        //
        // Ideally we would try to resolve **both** IPv4 and IPv6 rather than purely race
        // them.  But our resolver doesn't support that yet.
        let addrs: Vec<_> = dns_resolver
            .lookup_ipv4_ipv6_staggered(domain, DNS_TIMEOUT, DNS_STAGGERING_MS)
            .await?
            .map(|ipaddr| SocketAddr::new(ipaddr, 0))
            .collect();
        builder = builder.resolve_to_addrs(domain, &addrs);
    }
    let client = builder
        .build()
        .context(captive_portal_error::CreateReqwestClientSnafu)?;

    // Note: the set of valid characters in a challenge and the total
    // length is limited; see is_challenge_char in bin/iroh-relay for more
    // details.

    let host_name = url.host_str().unwrap_or_default();
    let challenge = format!("ts_{host_name}");
    let portal_url = format!("http://{host_name}/generate_204");
    let res = client
        .request(reqwest::Method::GET, portal_url)
        .header("X-Tailscale-Challenge", &challenge)
        .send()
        .await
        .context(captive_portal_error::HttpRequestSnafu)?;

    let expected_response = format!("response {challenge}");
    let is_valid_response = res
        .headers()
        .get("X-Tailscale-Response")
        .map(|s| s.to_str().unwrap_or_default())
        == Some(&expected_response);

    debug!(
        "check_captive_portal url={} status_code={} valid_response={}",
        res.url(),
        res.status(),
        is_valid_response,
    );
    let has_captive = res.status() != 204 || !is_valid_response;

    Ok(has_captive)
}

/// Returns the proper port based on the protocol of the probe.
#[cfg(not(wasm_browser))]
fn get_quic_port(relay_node: &RelayNode) -> Option<u16> {
    if let Some(ref quic) = relay_node.quic {
        if quic.port == 0 {
            Some(DEFAULT_RELAY_QUIC_PORT)
        } else {
            Some(quic.port)
        }
    } else {
        None
    }
}

#[cfg(not(wasm_browser))]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum GetRelayAddrError {
    #[snafu(display("No valid hostname in the relay URL"))]
    InvalidHostname,
    #[snafu(display("No suitable relay address found"))]
    NoAddrFound,
    #[snafu(display("DNS lookup failed"))]
    DnsLookup { source: StaggeredError<DnsError> },
    #[snafu(display("Relay node is not suitable for non-STUN probes"))]
    UnsupportedRelayNode,
    #[snafu(display("HTTPS probes are not implemented"))]
    UnsupportedHttps,
    #[snafu(display("No port available for this protocol"))]
    MissingPort,
}

/// Returns the IP address to use to communicate to this relay node for quic.
#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr_ipv4(
    dns_resolver: &DnsResolver,
    relay_node: &RelayNode,
) -> Result<SocketAddrV4, GetRelayAddrError> {
    let port = get_quic_port(relay_node).context(get_relay_addr_error::MissingPortSnafu)?;
    relay_lookup_ipv4_staggered(dns_resolver, relay_node, port).await
}

#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr_ipv6(
    dns_resolver: &DnsResolver,
    relay_node: &RelayNode,
) -> Result<SocketAddrV6, GetRelayAddrError> {
    let port = get_quic_port(relay_node).context(get_relay_addr_error::MissingPortSnafu)?;
    relay_lookup_ipv6_staggered(dns_resolver, relay_node, port).await
}

/// Do a staggared ipv4 DNS lookup based on [`RelayNode`]
///
/// `port` is combined with the resolved [`std::net::Ipv4Addr`] to return a [`SocketAddr`]
#[cfg(not(wasm_browser))]
async fn relay_lookup_ipv4_staggered(
    dns_resolver: &DnsResolver,
    relay: &RelayNode,
    port: u16,
) -> Result<SocketAddrV4, GetRelayAddrError> {
    match relay.url.host() {
        Some(url::Host::Domain(hostname)) => {
            trace!(%hostname, "Performing DNS A lookup for relay addr");
            match dns_resolver
                .lookup_ipv4_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                .await
            {
                Ok(mut addrs) => addrs
                    .next()
                    .map(|ip| ip.to_canonical())
                    .map(|addr| match addr {
                        IpAddr::V4(ip) => SocketAddrV4::new(ip, port),
                        IpAddr::V6(_) => unreachable!("bad DNS lookup: {:?}", addr),
                    })
                    .ok_or(get_relay_addr_error::NoAddrFoundSnafu.build()),
                Err(err) => Err(get_relay_addr_error::DnsLookupSnafu.into_error(err)),
            }
        }
        Some(url::Host::Ipv4(addr)) => Ok(SocketAddrV4::new(addr, port)),
        Some(url::Host::Ipv6(_addr)) => Err(get_relay_addr_error::NoAddrFoundSnafu.build()),
        None => Err(get_relay_addr_error::InvalidHostnameSnafu.build()),
    }
}

/// Do a staggared ipv6 DNS lookup based on [`RelayNode`]
///
/// `port` is combined with the resolved [`std::net::Ipv6Addr`] to return a [`SocketAddr`]
#[cfg(not(wasm_browser))]
async fn relay_lookup_ipv6_staggered(
    dns_resolver: &DnsResolver,
    relay: &RelayNode,
    port: u16,
) -> Result<SocketAddrV6, GetRelayAddrError> {
    match relay.url.host() {
        Some(url::Host::Domain(hostname)) => {
            trace!(%hostname, "Performing DNS AAAA lookup for relay addr");
            match dns_resolver
                .lookup_ipv6_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                .await
            {
                Ok(mut addrs) => addrs
                    .next()
                    .map(|addr| match addr {
                        IpAddr::V4(_) => unreachable!("bad DNS lookup: {:?}", addr),
                        IpAddr::V6(ip) => SocketAddrV6::new(ip, port, 0, 0),
                    })
                    .ok_or(get_relay_addr_error::NoAddrFoundSnafu.build()),
                Err(err) => Err(get_relay_addr_error::DnsLookupSnafu.into_error(err)),
            }
        }
        Some(url::Host::Ipv4(_addr)) => Err(get_relay_addr_error::NoAddrFoundSnafu.build()),
        Some(url::Host::Ipv6(addr)) => Ok(SocketAddrV6::new(addr, port, 0, 0)),
        None => Err(get_relay_addr_error::InvalidHostnameSnafu.build()),
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum MeasureHttpsLatencyError {
    #[snafu(transparent)]
    InvalidUrl { source: url::ParseError },
    #[cfg(not(wasm_browser))]
    #[snafu(transparent)]
    DnsLookup { source: StaggeredError<DnsError> },
    #[snafu(display("Creating HTTP client failed"))]
    CreateReqwestClient { source: reqwest::Error },
    #[snafu(display("HTTP request failed"))]
    HttpRequest { source: reqwest::Error },
    #[snafu(display("Error response from server {status}: {:?}", status.canonical_reason()))]
    InvalidResponse { status: StatusCode },
}

/// Executes an HTTPS probe.
///
/// If `certs` is provided they will be added to the trusted root certificates, allowing the
/// use of self-signed certificates for servers.  Currently this is used for testing.
#[allow(clippy::unused_async)]
async fn run_https_probe(
    #[cfg(not(wasm_browser))] dns_resolver: &DnsResolver,
    relay_node: RelayUrl,
    #[cfg(any(test, feature = "test-utils"))] insecure_skip_relay_cert_verify: bool,
) -> Result<HttpsProbeReport, MeasureHttpsLatencyError> {
    trace!("HTTPS probe start");
    let url = relay_node.join(RELAY_PROBE_PATH)?;

    // This should also use same connection establishment as relay client itself, which
    // needs to be more configurable so users can do more crazy things:
    // https://github.com/n0-computer/iroh/issues/2901
    let mut builder = reqwest::ClientBuilder::new();

    #[cfg(not(wasm_browser))]
    {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    #[cfg(not(wasm_browser))]
    if let Some(Host::Domain(domain)) = url.host() {
        // Use our own resolver rather than getaddrinfo
        //
        // Be careful, a non-zero port will override the port in the URI.
        //
        // The relay Client uses `.lookup_ipv4_ipv6` to connect, so use the same function
        // but staggered for reliability.  Ideally this tries to resolve **both** IPv4 and
        // IPv6 though.  But our resolver does not have a function for that yet.
        let addrs: Vec<_> = dns_resolver
            .lookup_ipv4_ipv6_staggered(domain, DNS_TIMEOUT, DNS_STAGGERING_MS)
            .await?
            .map(|ipaddr| SocketAddr::new(ipaddr, 0))
            .collect();
        trace!(?addrs, "resolved addrs");
        builder = builder.resolve_to_addrs(domain, &addrs);
    }

    #[cfg(all(not(wasm_browser), any(test, feature = "test-utils")))]
    let builder = builder.danger_accept_invalid_certs(insecure_skip_relay_cert_verify);

    let client = builder
        .build()
        .context(measure_https_latency_error::CreateReqwestClientSnafu)?;

    let start = Instant::now();
    let response = client
        .request(reqwest::Method::GET, url)
        .send()
        .await
        .context(measure_https_latency_error::HttpRequestSnafu)?;
    let latency = start.elapsed();
    if response.status().is_success() {
        // Drain the response body to be nice to the server, up to a limit.
        const MAX_BODY_SIZE: usize = 8 << 10; // 8 KiB
        let mut body_size = 0;
        let mut stream = response.bytes_stream();
        // ignore failing frames
        while let Some(Ok(chunk)) = stream.next().await {
            body_size += chunk.len();
            if body_size >= MAX_BODY_SIZE {
                break;
            }
        }

        Ok(HttpsProbeReport {
            node: relay_node,
            latency,
        })
    } else {
        Err(measure_https_latency_error::InvalidResponseSnafu {
            status: response.status(),
        }
        .build())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use iroh_relay::dns::DnsResolver;
    use n0_snafu::{Result, ResultExt};
    use tracing_test::traced_test;

    use super::{super::test_utils, *};

    #[tokio::test]
    async fn test_measure_https_latency() -> Result {
        let (_server, relay) = test_utils::relay().await;
        let dns_resolver = DnsResolver::new();
        tracing::info!(relay_url = ?relay.url , "RELAY_URL");
        let report = run_https_probe(&dns_resolver, relay.url, true).await?;

        assert!(report.latency > Duration::ZERO);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_qad_probe_v4() -> Result {
        let (server, relay) = test_utils::relay().await;
        let relay = Arc::new(relay);
        let client_config = iroh_relay::client::make_dangerous_client_config();
        let ep = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).e()?;
        let client_addr = ep.local_addr().e()?;

        let quic_client = iroh_relay::quic::QuicClient::new(ep.clone(), client_config);
        let dns_resolver = DnsResolver::default();

        let (report, conn) = super::super::run_probe_v4(None, relay, quic_client, dns_resolver)
            .await
            .unwrap();

        assert_eq!(report.addr, client_addr);
        drop(conn);
        ep.wait_idle().await;
        server.shutdown().await?;
        Ok(())
    }
}
