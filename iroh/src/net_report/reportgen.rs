//! Probe types and execution functions for net report generation.
//!
//! The actual orchestration is done by [`super::actor::NetReportActor`].
//! This module provides the probe report types, individual probe execution
//! functions (HTTPS, captive portal), and supporting types.

#[cfg(not(wasm_browser))]
use std::net::{SocketAddrV4, SocketAddrV6};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use http::StatusCode;
use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_dns::dns::{DnsError, DnsResolver, StaggeredError};
#[cfg(not(wasm_browser))]
use iroh_relay::quic::QuicClient;
use iroh_relay::{
    RelayConfig, RelayMap, defaults::DEFAULT_RELAY_QUIC_PORT, http::RELAY_PROBE_PATH,
};
use n0_error::{e, stack_error};
#[cfg(wasm_browser)]
use n0_future::future::Pending;
use n0_future::{
    StreamExt as _,
    time::{self, Duration, Instant},
};
use rand::seq::IteratorRandom;
use tracing::{debug, trace};
use url::Host;

#[cfg(not(wasm_browser))]
use super::defaults::timeouts::DNS_TIMEOUT;
use super::probes::Probe;
#[cfg(not(wasm_browser))]
use crate::address_lookup::DNS_STAGGERING_MS;
use crate::util::reqwest_client_builder;

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
    #[allow(dead_code)] // may be useful for future probe logic
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
    pub(super) async fn run(
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
                match run_https_probe(
                    #[cfg(not(wasm_browser))]
                    &socket_state.dns_resolver,
                    relay.url.clone(),
                    #[cfg(not(wasm_browser))]
                    tls_config,
                )
                .await
                {
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
pub(super) enum CaptivePortalError {
    #[error(transparent)]
    DnsLookup {
        #[error(from)]
        source: StaggeredError<DnsError>,
    },
    #[error("Creating HTTP client failed")]
    CreateReqwestClient {
        #[error(std_err)]
        source: reqwest::Error,
    },
    #[error("HTTP request failed")]
    HttpRequest {
        #[error(std_err)]
        source: reqwest::Error,
    },
}

/// Reports whether or not we think the system is behind a
/// captive portal, detected by making a request to a URL that we know should
/// return a "204 No Content" response and checking if that's what we get.
///
/// The boolean return is whether we think we have a captive portal.
#[cfg(not(wasm_browser))]
pub(super) async fn check_captive_portal(
    dns_resolver: &DnsResolver,
    dm: &RelayMap,
    preferred_relay: Option<RelayUrl>,
    tls_config: rustls::ClientConfig,
) -> Result<bool, CaptivePortalError> {
    // If we have a preferred relay and we can use it for non-QAD requests, try that;
    // otherwise, pick a random one suitable for non-STUN requests.

    use crate::util::reqwest_client_builder;

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

    let mut builder = reqwest_client_builder(tls_config, dns_resolver.clone())
        .redirect(reqwest::redirect::Policy::none());

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
        .map_err(|err| e!(CaptivePortalError::CreateReqwestClient, err))?;

    // Note: the set of valid characters in a challenge and the total
    // length is limited; see is_challenge_char in bin/iroh-relay for more
    // details.

    let host_name = url.host_str().unwrap_or_default();
    let challenge = format!("ts_{host_name}");
    let portal_url = format!("http://{host_name}/generate_204");
    let res = client
        .request(reqwest::Method::GET, portal_url)
        .header("X-Iroh-Challenge", &challenge)
        .send()
        .await
        .map_err(|err| e!(CaptivePortalError::HttpRequest, err))?;

    let expected_response = format!("response {challenge}");
    let is_valid_response = res
        .headers()
        .get("X-Iroh-Response")
        .map(|s| s.to_str().unwrap_or_default())
        == Some(&expected_response);

    trace!(
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
    #[error("Creating HTTP client failed")]
    CreateReqwestClient {
        #[error(std_err)]
        source: reqwest::Error,
    },
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
/// If `certs` is provided they will be added to the trusted root certificates, allowing the
/// use of self-signed certificates for servers.  Currently this is used for testing.
#[allow(clippy::unused_async)]
async fn run_https_probe(
    #[cfg(not(wasm_browser))] dns_resolver: &DnsResolver,
    relay: RelayUrl,
    #[cfg(not(wasm_browser))] tls_config: rustls::ClientConfig,
) -> Result<HttpsProbeReport, MeasureHttpsLatencyError> {
    trace!("HTTPS probe start");
    let url = relay.join(RELAY_PROBE_PATH)?;

    // This should also use same connection establishment as relay client itself, which
    // needs to be more configurable so users can do more crazy things:
    // https://github.com/n0-computer/iroh/issues/2901
    #[cfg(not(wasm_browser))]
    let mut builder = reqwest_client_builder(tls_config, dns_resolver.clone());
    #[cfg(wasm_browser)]
    let mut builder = reqwest_client_builder();

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

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use iroh_dns::dns::DnsResolver;
    use iroh_relay::tls::{CaRootsConfig, default_provider};
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;
    use tokio_util::sync::CancellationToken;

    use super::{super::test_utils, *};

    #[tokio::test]
    async fn test_measure_https_latency() -> Result {
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
        let client_config = iroh_relay::tls::make_dangerous_client_config();
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
