//! Captive portal detection for net_report.

use iroh_base::RelayUrl;
use iroh_dns::dns::{DnsError, DnsResolver, StaggeredError};
use iroh_relay::RelayMap;
use n0_error::{e, stack_error};
use rand::seq::IteratorRandom;
use tracing::trace;
use url::Url;

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
    proxy_url: Option<&Url>,
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
    if let Some(proxy_url) = proxy_url {
        let proxy = reqwest::Proxy::all(proxy_url.clone())
            .map_err(|err| e!(CaptivePortalError::CreateReqwestClient, err))?;
        builder = builder.proxy(proxy);
    } else {
        // Like the relay connection, ignore any proxy the environment names.
        builder = builder.no_proxy();
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
