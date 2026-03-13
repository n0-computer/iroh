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
use iroh_relay::{
    RelayConfig, RelayMap, defaults::DEFAULT_RELAY_QUIC_PORT, http::RELAY_PROBE_PATH,
};
#[cfg(not(wasm_browser))]
use iroh_relay::{
    dns::{DnsError, DnsResolver, StaggeredError},
    quic::QuicClient,
};
use n0_error::{e, stack_error};
#[cfg(wasm_browser)]
use n0_future::future::Pending;
#[cfg(wasm_browser)]
use n0_future::StreamExt as _;
use n0_future::{
    task::{self, AbortOnDropHandle, JoinSet},
    time::{self, Duration, Instant},
};
use rand::seq::IteratorRandom;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, trace, warn, warn_span};
use url::Host;

#[cfg(not(wasm_browser))]
use super::defaults::timeouts::DNS_TIMEOUT;
use super::{
    Report,
    probes::{Probe, ProbePlan},
};
#[cfg(not(wasm_browser))]
use crate::address_lookup::DNS_STAGGERING_MS;
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
    pub(crate) have_v4: bool,
    /// Do we have IPv6 capbilities
    pub(crate) have_v6: bool,
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
pub(super) struct SocketState {
    /// QUIC client to do QUIC address Discovery
    pub(super) quic_client: Option<QuicClient>,
    /// The DNS resolver to use for probes that need to resolve DNS records.
    pub(super) dns_resolver: DnsResolver,
}

impl Client {
    /// Creates a new actor generating a single report.
    ///
    /// The actor starts running immediately and only generates a single report, after which
    /// it shuts down.  Dropping this handle will abort the actor.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        last_report: Option<Report>,
        relay_map: RelayMap,
        protocols: BTreeSet<Probe>,
        captive_portal_check: bool,
        if_state: IfStateDetails,
        shutdown_token: CancellationToken,
        #[cfg(not(wasm_browser))] socket_state: SocketState,
        #[cfg(not(wasm_browser))] tls_config: rustls::ClientConfig,
    ) -> (Self, mpsc::Receiver<ProbeFinished>) {
        let (msg_tx, msg_rx) = mpsc::channel(32);
        let actor = Actor {
            msg_tx,
            last_report,
            relay_map,
            protocols,
            captive_portal_check,
            #[cfg(not(wasm_browser))]
            socket_state,
            #[cfg(not(wasm_browser))]
            tls_config,
            if_state,
        };
        let task = task::spawn(
            actor
                .run(shutdown_token)
                .instrument(warn_span!("reportgen-actor")),
        );
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

    /// Whether to check for captive portals.
    captive_portal_check: bool,

    /// Any socket-related state that doesn't exist/work in browsers
    #[cfg(not(wasm_browser))]
    socket_state: SocketState,
    #[cfg(not(wasm_browser))]
    tls_config: rustls::ClientConfig,
    if_state: IfStateDetails,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum ProbesError {
    #[error("Probe failed")]
    ProbeFailure { source: ProbeError },
    #[error("All probes failed")]
    AllProbesFailed,
    #[error("Probe cancelled")]
    Cancelled,
    #[error("Probe timed out")]
    Timeout,
}

#[derive(Debug)]
pub(super) enum ProbeFinished {
    Regular(Result<ProbeReport, ProbesError>),
    #[cfg(not(wasm_browser))]
    CaptivePortal(Option<bool>),
}

impl Actor {
    async fn run(self, shutdown_token: CancellationToken) {
        shutdown_token
            .run_until_cancelled_owned(async {
                match time::timeout(OVERALL_REPORT_TIMEOUT, self.run_inner()).await {
                    Ok(()) => trace!("reportgen actor finished"),
                    Err(time::Elapsed { .. }) => {
                        warn!("reportgen timed out");
                    }
                }
            })
            .await;
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
        trace!("reportgen actor starting");

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
                            trace!("all regular probes done");
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
        if self.captive_portal_check && self.last_report.is_none() {
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
                                check_captive_portal(
                                    &dns_resolver,
                                    &dm,
                                    preferred_relay,
                                ),
                            )
                            .await
                        })
                        .await;
                    let res = match res {
                        Some(Ok(Ok(found))) => Some(found),
                        Some(Ok(Err(err))) => {
                            warn!("check_captive_portal error: {err:#}");
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
                .instrument(warn_span!("captive-portal")),
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
    ///   - Once there are [`ProbeReport`]s from enough relays, all remaining probes are
    ///     aborted.  That is, the main actor loop stops polling them.
    fn spawn_probes_task(
        &self,
        if_state: IfStateDetails,
        probes: &mut JoinSet<ProbeFinished>,
    ) -> CancellationToken {
        trace!(?if_state, "local interface details");
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
            for (delay, relay) in probe_set.params() {
                let probe_token = set_token.child_token();

                let fut = probe_token.run_until_cancelled_owned(time::timeout(
                    PROBES_TIMEOUT,
                    proto.run(
                        *delay,
                        relay.clone(),
                        #[cfg(not(wasm_browser))]
                        self.socket_state.clone(),
                        #[cfg(not(wasm_browser))]
                        self.tls_config.clone(),
                    ),
                ));
                probes.spawn(
                    async move {
                        let res = fut.await;
                        let res = match res {
                            Some(Ok(Ok(report))) => Ok(report),
                            Some(Ok(Err(err))) => {
                                warn!("probe failed: {:#}", err);
                                Err(e!(ProbesError::ProbeFailure, err))
                            }
                            Some(Err(time::Elapsed { .. })) => Err(e!(ProbesError::Timeout)),
                            None => Err(e!(ProbesError::Cancelled)),
                        };
                        ProbeFinished::Regular(res)
                    }
                    .instrument(warn_span!(
                        "run-probe",
                        ?proto,
                        ?delay,
                        relay=%relay.url,
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
    /// The relay that was probed
    pub(super) relay: RelayUrl,
    /// The latency to the relay.
    pub(super) latency: Duration,
    /// The discovered public address.
    pub(super) addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub(super) struct HttpsProbeReport {
    /// The relay that was probed
    pub(super) relay: RelayUrl,
    /// The latency to the relay.
    pub(super) latency: Duration,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum ProbeError {
    #[error("Client is gone")]
    ClientGone,
    #[error("Probe is no longer useful")]
    NotUseful,
    #[error("Failed to run HTTPS probe")]
    Https { source: MeasureHttpsLatencyError },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum QuicError {
    #[error("No relay available")]
    NoRelay,
    #[error("URL must have 'host' to use QUIC address discovery probes")]
    InvalidUrl,
}

/// Pieces needed to do QUIC address discovery.
#[derive(derive_more::Debug, Clone)]
pub(crate) struct QuicConfig {
    /// A QUIC Endpoint
    #[debug("noq::Endpoint")]
    pub(crate) ep: noq::Endpoint,
    /// A client config.
    pub(crate) client_config: rustls::ClientConfig,
    /// Enable ipv4 QUIC address discovery probes
    pub(crate) ipv4: bool,
    /// Enable ipv6 QUIC address discovery probes
    pub(crate) ipv6: bool,
}

impl Probe {
    /// Executes this particular [`Probe`], including using a delayed start if needed.
    async fn run(
        self,
        delay: Duration,
        relay: Arc<RelayConfig>,
        #[cfg(not(wasm_browser))] socket_state: SocketState,
        #[cfg(not(wasm_browser))] tls_config: rustls::ClientConfig,
    ) -> Result<ProbeReport, ProbeError> {
        if !delay.is_zero() {
            trace!("delaying probe");
            time::sleep(delay).await;
        }
        trace!("starting probe");

        let report = match self {
            Probe::Https => {
                #[cfg(not(wasm_browser))]
                let res = run_https_probe(
                    &socket_state.dns_resolver,
                    relay.url.clone(),
                    tls_config,
                )
                .await;
                #[cfg(wasm_browser)]
                let res = run_https_probe(relay.url.clone()).await;
                match res {
                    Ok(report) => Ok(ProbeReport::Https(report)),
                    Err(err) => Err(e!(ProbeError::Https, err)),
                }
            }
            #[cfg(not(wasm_browser))]
            Probe::QadIpv4 | Probe::QadIpv6 => unreachable!("must not be used"),
        };
        debug!(?report, "probe finished");
        report
    }
}

#[cfg(not(wasm_browser))]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
enum CaptivePortalError {
    #[error(transparent)]
    DnsLookup {
        #[error(from)]
        source: StaggeredError<DnsError>,
    },
    #[error("TCP connection failed")]
    Connect {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("HTTP request failed")]
    HttpRequest {
        #[error(std_err)]
        source: hyper::Error,
    },
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
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    // If we have a preferred relay and we can use it for non-QAD requests, try that;
    // otherwise, pick a random one suitable for non-STUN requests.
    let preferred_relay = preferred_relay.and_then(|url| dm.get(&url).map(|_| url));

    let url = match preferred_relay {
        Some(url) => url,
        None => {
            let urls: Vec<_> = dm.urls();
            if urls.is_empty() {
                trace!("No suitable relay for captive portal check");
                return Ok(false);
            }

            let i = (0..urls.len()).choose(&mut rand::rng()).unwrap_or_default();
            urls[i].clone()
        }
    };

    let host_name = url.host_str().unwrap_or_default();

    // Resolve the relay hostname using our own resolver.
    let addr = if let Some(Host::Domain(domain)) = url.host() {
        let addrs: Vec<_> = dns_resolver
            .lookup_ipv4_ipv6_staggered(domain, DNS_TIMEOUT, DNS_STAGGERING_MS)
            .await?
            .collect();
        if addrs.is_empty() {
            trace!("No addresses resolved for captive portal check");
            return Ok(false);
        }
        SocketAddr::new(addrs[0], 80)
    } else {
        trace!("No domain host for captive portal check");
        return Ok(false);
    };

    // Plain HTTP — captive portals intercept unencrypted requests.
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|err| e!(CaptivePortalError::Connect, err))?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|err| e!(CaptivePortalError::HttpRequest, err))?;

    // Drive the connection in the background.
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            debug!("captive portal connection error: {err:#}");
        }
    });

    let challenge = format!("ts_{host_name}");
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("/generate_204")
        .header(hyper::header::HOST, host_name)
        .header("X-Iroh-Challenge", &challenge)
        .body(Empty::<Bytes>::new())
        .expect("valid request");

    let res = sender
        .send_request(req)
        .await
        .map_err(|err| e!(CaptivePortalError::HttpRequest, err))?;

    let expected_response = format!("response {challenge}");
    let is_valid_response = res
        .headers()
        .get("X-Iroh-Response")
        .and_then(|s| s.to_str().ok())
        == Some(&expected_response);

    trace!(
        "check_captive_portal host={host_name} status={} valid={is_valid_response}",
        res.status(),
    );
    let has_captive = res.status() != StatusCode::NO_CONTENT || !is_valid_response;

    Ok(has_captive)
}

/// Returns the proper port based on the protocol of the probe.
#[cfg(not(wasm_browser))]
fn get_quic_port(relay: &RelayConfig) -> Option<u16> {
    if let Some(ref quic) = relay.quic {
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
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum GetRelayAddrError {
    #[error("No valid hostname in the relay URL")]
    InvalidHostname,
    #[error("No suitable relay address found for {url} ({addr_type})")]
    NoAddrFound {
        url: RelayUrl,
        addr_type: &'static str,
    },
    #[error("DNS lookup failed")]
    DnsLookup { source: StaggeredError<DnsError> },
    #[error("Relay is not suitable")]
    UnsupportedRelay,
    #[error("HTTPS probes are not implemented")]
    UnsupportedHttps,
    #[error("No port available for this protocol")]
    MissingPort,
}

/// Returns the IP address to use to communicate to this relay for quic.
#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr_ipv4(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
) -> Result<SocketAddrV4, GetRelayAddrError> {
    let port = get_quic_port(relay).ok_or_else(|| e!(GetRelayAddrError::MissingPort))?;
    relay_lookup_ipv4_staggered(dns_resolver, relay, port).await
}

#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr_ipv6(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
) -> Result<SocketAddrV6, GetRelayAddrError> {
    let port = get_quic_port(relay).ok_or_else(|| e!(GetRelayAddrError::MissingPort))?;
    relay_lookup_ipv6_staggered(dns_resolver, relay, port).await
}

/// Do a staggared ipv4 DNS lookup based on [`RelayConfig`]
///
/// `port` is combined with the resolved [`std::net::Ipv4Addr`] to return a [`SocketAddr`]
#[cfg(not(wasm_browser))]
async fn relay_lookup_ipv4_staggered(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
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
                    .ok_or_else(|| {
                        e!(GetRelayAddrError::NoAddrFound {
                            url: relay.url.clone(),
                            addr_type: "A",
                        })
                    }),
                Err(err) => Err(e!(GetRelayAddrError::DnsLookup, err)),
            }
        }
        Some(url::Host::Ipv4(addr)) => Ok(SocketAddrV4::new(addr, port)),
        Some(url::Host::Ipv6(_addr)) => Err(e!(GetRelayAddrError::NoAddrFound {
            url: relay.url.clone(),
            addr_type: "A",
        })),
        None => Err(e!(GetRelayAddrError::InvalidHostname)),
    }
}

/// Do a staggared ipv6 DNS lookup based on [`RelayConfig`]
///
/// `port` is combined with the resolved [`std::net::Ipv6Addr`] to return a [`SocketAddr`]
#[cfg(not(wasm_browser))]
async fn relay_lookup_ipv6_staggered(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
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
                    .ok_or_else(|| {
                        e!(GetRelayAddrError::NoAddrFound {
                            url: relay.url.clone(),
                            addr_type: "AAAA",
                        })
                    }),
                Err(err) => Err(e!(GetRelayAddrError::DnsLookup, err)),
            }
        }
        Some(url::Host::Ipv4(_addr)) => Err(e!(GetRelayAddrError::NoAddrFound {
            url: relay.url.clone(),
            addr_type: "AAAA",
        })),
        Some(url::Host::Ipv6(addr)) => Ok(SocketAddrV6::new(addr, port, 0, 0)),
        None => Err(e!(GetRelayAddrError::InvalidHostname)),
    }
}

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum MeasureHttpsLatencyError {
    #[error(transparent)]
    InvalidUrl {
        #[error(std_err, from)]
        source: url::ParseError,
    },
    #[cfg(not(wasm_browser))]
    #[error(transparent)]
    DnsLookup {
        #[error(from)]
        source: StaggeredError<DnsError>,
    },
    #[cfg(not(wasm_browser))]
    #[error("TCP/TLS connection failed")]
    Connect {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[cfg(not(wasm_browser))]
    #[error("HTTP request failed")]
    HttpRequest {
        #[error(std_err)]
        source: hyper::Error,
    },
    #[cfg(wasm_browser)]
    #[error("Creating HTTP client failed")]
    CreateReqwestClient {
        #[error(std_err)]
        source: reqwest::Error,
    },
    #[cfg(wasm_browser)]
    #[error("HTTP request failed")]
    HttpRequest {
        #[error(std_err)]
        source: reqwest::Error,
    },
    #[error("Error response from server {status}: {:?}", status.canonical_reason())]
    InvalidResponse { status: StatusCode },
}

/// Executes an HTTPS probe.
///
/// Measures relay latency by making an HTTPS GET to the relay's probe endpoint.
#[cfg(not(wasm_browser))]
async fn run_https_probe(
    dns_resolver: &DnsResolver,
    relay: RelayUrl,
    tls_config: rustls::ClientConfig,
) -> Result<HttpsProbeReport, MeasureHttpsLatencyError> {
    use http_body_util::BodyExt;
    use hyper_util::rt::TokioIo;

    trace!("HTTPS probe start");
    let url = relay.join(RELAY_PROBE_PATH)?;
    let host_name = url.host_str().unwrap_or_default();
    let port = url.port().unwrap_or(443);

    // Resolve the address — use our own DNS resolver for domains, direct for IPs.
    let addr = match url.host() {
        Some(Host::Domain(domain)) => {
            let addrs: Vec<_> = dns_resolver
                .lookup_ipv4_ipv6_staggered(domain, DNS_TIMEOUT, DNS_STAGGERING_MS)
                .await?
                .collect();
            trace!(?addrs, "resolved addrs");
            if addrs.is_empty() {
                return Err(e!(MeasureHttpsLatencyError::Connect,
                    std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved")));
            }
            SocketAddr::new(addrs[0], port)
        }
        Some(Host::Ipv4(ip)) => SocketAddr::new(ip.into(), port),
        Some(Host::Ipv6(ip)) => SocketAddr::new(ip.into(), port),
        None => {
            return Err(e!(MeasureHttpsLatencyError::Connect,
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "no host in relay URL")));
        }
    };

    // TCP + TLS connection.
    let tcp_stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|err| e!(MeasureHttpsLatencyError::Connect, err))?;

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(host_name.to_owned())
        .map_err(|e| e!(MeasureHttpsLatencyError::Connect,
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|err| e!(MeasureHttpsLatencyError::Connect, err))?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
        .await
        .map_err(|err| e!(MeasureHttpsLatencyError::HttpRequest, err))?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            debug!("HTTPS probe connection error: {err:#}");
        }
    });

    let start = Instant::now();
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(url.path())
        .header(hyper::header::HOST, host_name)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("valid request");

    let response = sender
        .send_request(req)
        .await
        .map_err(|err| e!(MeasureHttpsLatencyError::HttpRequest, err))?;
    let latency = start.elapsed();

    if response.status().is_success() {
        // Drain the response body to be nice to the server, up to a limit.
        const MAX_BODY_SIZE: usize = 8 << 10; // 8 KiB
        let mut body = response.into_body();
        let mut body_size = 0;
        while let Some(frame) = body.frame().await {
            if let Ok(frame) = frame && let Some(data) = frame.data_ref() {
                body_size += data.len();
                if body_size >= MAX_BODY_SIZE {
                    break;
                }
            }
        }
        Ok(HttpsProbeReport { relay, latency })
    } else {
        Err(e!(MeasureHttpsLatencyError::InvalidResponse {
            status: response.status()
        }))
    }
}

/// Executes an HTTPS probe.
///
/// If `certs` is provided they will be added to the trusted root certificates, allowing the
/// use of self-signed certificates for servers.  Currently this is used for testing.
#[cfg(wasm_browser)]
#[allow(clippy::unused_async)]
async fn run_https_probe(
    relay: RelayUrl,
) -> Result<HttpsProbeReport, MeasureHttpsLatencyError> {
    use crate::util::reqwest_client_builder;

    trace!("HTTPS probe start");
    let url = relay.join(RELAY_PROBE_PATH)?;

    let builder = reqwest_client_builder(None);

    let client = builder
        .build()
        .map_err(|err| e!(MeasureHttpsLatencyError::CreateReqwestClient, err))?;

    let start = Instant::now();
    let response = client
        .request(reqwest::Method::GET, url)
        .send()
        .await
        .map_err(|err| e!(MeasureHttpsLatencyError::HttpRequest, err))?;
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

        Ok(HttpsProbeReport { relay, latency })
    } else {
        Err(e!(MeasureHttpsLatencyError::InvalidResponse {
            status: response.status()
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use iroh_relay::{
        dns::DnsResolver,
        tls::{CaRootsConfig, default_provider},
    };
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;

    use super::{super::test_utils, *};

    #[tokio::test]
    #[cfg(feature = "ring")]
    async fn test_measure_https_latency() -> Result {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (_server, relay) = test_utils::relay().await;
        let dns_resolver = DnsResolver::new();
        tracing::info!(relay_url = ?relay.url , "RELAY_URL");
        let report = run_https_probe(
            &dns_resolver,
            relay.url,
            CaRootsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
        )
        .await?;

        assert!(report.latency > Duration::ZERO);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_qad_probe_v4() -> Result {
        let (server, relay) = test_utils::relay().await;
        let relay = Arc::new(relay);
        let client_config = iroh_relay::client::make_dangerous_client_config();
        let ep = noq::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).anyerr()?;
        let client_addr = ep.local_addr().anyerr()?;

        let quic_client = iroh_relay::quic::QuicClient::new(ep.clone(), client_config);
        let dns_resolver = DnsResolver::default();

        let (report, conn) =
            super::super::run_probe_v4(relay, quic_client, dns_resolver, CancellationToken::new())
                .await
                .unwrap();

        assert_eq!(report.addr, client_addr);
        drop(conn);
        ep.wait_idle().await;
        server.shutdown().await?;
        Ok(())
    }
}
