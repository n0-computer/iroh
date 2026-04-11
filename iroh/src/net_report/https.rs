//! HTTPS latency probe execution.

use std::net::SocketAddr;

use http::StatusCode;
use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_dns::dns::{DnsError, DnsResolver, StaggeredError};
use iroh_relay::http::RELAY_PROBE_PATH;
use n0_error::{e, stack_error};
use n0_future::{
    StreamExt as _,
    time::{Duration, Instant},
};
use tracing::trace;
use url::Host;

#[cfg(not(wasm_browser))]
use super::defaults::timeouts::DNS_TIMEOUT;
#[cfg(not(wasm_browser))]
use crate::address_lookup::DNS_STAGGERING_MS;
use crate::util::reqwest_client_builder;

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum ProbesError {
    #[error("HTTPS probe failed")]
    ProbeFailure { source: MeasureHttpsLatencyError },
    #[error("Probe cancelled")]
    Cancelled,
    #[error("Probe timed out")]
    Timeout,
}

#[derive(Debug, Clone)]
pub(super) struct HttpsProbeReport {
    /// The relay that was probed
    pub(super) relay: RelayUrl,
    /// The latency to the relay.
    pub(super) latency: Duration,
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
/// Sends a GET request to the relay's probe endpoint and measures the
/// round-trip time. DNS resolution goes through our own resolver (on
/// native targets) so it follows the same path as relay client connections.
#[allow(clippy::unused_async)]
pub(super) async fn run_https_probe(
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
    let mut builder = reqwest_client_builder(tls_config, dns_resolver.clone())
        .redirect(reqwest::redirect::Policy::none());
    #[cfg(wasm_browser)]
    let mut builder = reqwest_client_builder();

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
    use iroh_dns::dns::DnsResolver;
    use iroh_relay::tls::{CaRootsConfig, default_provider};
    use n0_error::Result;

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
}
