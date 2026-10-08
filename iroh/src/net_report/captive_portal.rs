//! Captive portal detection.

use iroh_base::RelayUrl;
use iroh_dns::dns::DnsResolver;
use iroh_relay::RelayMap;
use n0_error::{Result, StdResultExt};
use rand::seq::IndexedRandom;
use tracing::trace;
use url::Url;

use super::https::http_client;

/// Checks whether the host is behind a captive portal.
///
/// Returns `true` if we appear to be behind one. The check requests a
/// relay's `/generate_204` endpoint: a portal intercepting HTTP answers with
/// something other than the expected empty 204.
pub(super) async fn check(
    dns_resolver: DnsResolver,
    relay_map: RelayMap,
    preferred_relay: Option<RelayUrl>,
    tls_config: rustls::ClientConfig,
    proxy_url: Option<Url>,
) -> Result<bool> {
    trace!("captive portal check starting");
    // Use the preferred relay if it is still in the map, otherwise a random one.
    let url = match preferred_relay.filter(|url| relay_map.contains(url)) {
        Some(url) => url,
        None => {
            let urls: Vec<_> = relay_map.urls();
            let Some(url) = urls.choose(&mut rand::rng()) else {
                trace!("No suitable relay for captive portal check");
                return Ok(false);
            };
            url.clone()
        }
    };

    let client = http_client(dns_resolver, tls_config, proxy_url)?;

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
        .std_context("Captive portal HTTP request failed")?;

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
