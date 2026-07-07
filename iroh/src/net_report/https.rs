//! HTTPS latency probes for net_report.

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
#[cfg(not(wasm_browser))]
use url::Url;

use crate::util::reqwest_client_builder;

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
/// If `certs` is provided they will be added to the trusted root certificates, allowing the
/// use of self-signed certificates for servers.  Currently this is used for testing.
#[allow(clippy::unused_async)]
pub(super) async fn run_https_probe(
    #[cfg(not(wasm_browser))] dns_resolver: &DnsResolver,
    relay: RelayUrl,
    #[cfg(not(wasm_browser))] tls_config: rustls::ClientConfig,
    #[cfg(not(wasm_browser))] proxy_url: Option<&Url>,
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
    let builder = reqwest_client_builder();

    #[cfg(not(wasm_browser))]
    if let Some(proxy_url) = proxy_url {
        let proxy = reqwest::Proxy::all(proxy_url.clone())
            .map_err(|err| e!(MeasureHttpsLatencyError::CreateReqwestClient, err))?;
        builder = builder.proxy(proxy);
    } else {
        // Like the relay connection, ignore any proxy the environment names.
        builder = builder.no_proxy();
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
    use std::net::Ipv4Addr;

    use iroh_dns::dns::DnsResolver;
    use iroh_relay::tls::{CaTlsConfig, default_provider};
    use n0_error::{Result, StdResultExt};
    use n0_future::{task, time};
    use n0_tracing_test::traced_test;
    use tokio::{io::AsyncReadExt, sync::oneshot};

    use super::{super::test_utils, *};

    #[tokio::test]
    async fn test_measure_https_latency() -> Result {
        let (_server, relay) = test_utils::relay().await;
        let dns_resolver = DnsResolver::new();
        tracing::info!(relay_url = ?relay.url , "RELAY_URL");
        let report = run_https_probe(
            &dns_resolver,
            relay.url,
            CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
            None,
        )
        .await?;

        assert!(report.latency > Duration::ZERO);

        Ok(())
    }

    /// Spawns a fake HTTP proxy which captures the request line of the first connection
    /// it receives and then hangs up.
    ///
    /// Returns the URL to configure as proxy and a receiver for the captured request line.
    async fn capturing_proxy() -> Result<(Url, oneshot::Receiver<String>)> {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .anyerr()?;
        let url: Url = format!("http://{}", listener.local_addr().anyerr()?)
            .parse()
            .anyerr()?;
        let (tx, rx) = oneshot::channel();
        task::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while let Ok(1) = stream.read(&mut byte).await {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            tx.send(String::from_utf8_lossy(&line).trim().to_string())
                .ok();
        });
        Ok((url, rx))
    }

    #[tokio::test]
    #[traced_test]
    async fn test_measure_https_latency_via_proxy() -> Result {
        let (_server, relay) = test_utils::relay().await;
        let dns_resolver = DnsResolver::new();
        let (proxy_url, request_line) = capturing_proxy().await?;
        let target = format!(
            "{}:{}",
            relay.url.host_str().expect("relay url has a host"),
            relay.url.port().expect("relay url has a port")
        );

        // The probe cannot succeed: the fake proxy never completes the CONNECT tunnel.
        // What matters is that the probe was attempted via the proxy rather than
        // connecting to the relay directly.
        let res = run_https_probe(
            &dns_resolver,
            relay.url,
            CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
            Some(&proxy_url),
        )
        .await;
        assert!(
            res.is_err(),
            "probe must not succeed through a proxy that refuses to tunnel, got {res:?}"
        );

        let request_line = time::timeout(Duration::from_secs(10), request_line)
            .await
            .expect("proxy did not receive a request, the probe bypassed it")
            .anyerr()?;
        assert!(
            request_line.starts_with(&format!("CONNECT {target} ")),
            "expected the probe to tunnel to {target}, proxy received: {request_line}"
        );

        Ok(())
    }
    /// Tests that without a configured proxy the probes ignore the proxy variables in the
    /// environment, like the relay connection does.
    ///
    /// The environment is shared by the whole process, so the probes run in a child
    /// process of this test binary that starts with the variables set.
    #[tokio::test]
    #[traced_test]
    async fn test_probes_ignore_env_proxy() -> Result {
        const CHILD_VAR: &str = "IROH_TEST_PROBES_IGNORE_ENV_PROXY";
        if std::env::var_os(CHILD_VAR).is_some() {
            let (_server, relay) = test_utils::relay().await;
            let relay_map = iroh_relay::RelayMap::from_iter([relay.clone()]);
            let dns_resolver = DnsResolver::new();
            let tls_config = CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible");
            // Nothing serves the captive portal check here, only where it connects matters.
            time::timeout(
                Duration::from_secs(5),
                super::super::captive_portal::check_captive_portal(
                    &dns_resolver,
                    &relay_map,
                    None,
                    tls_config.clone(),
                    None,
                ),
            )
            .await
            .ok();
            time::timeout(
                Duration::from_secs(5),
                run_https_probe(&dns_resolver, relay.url, tls_config, None),
            )
            .await
            .anyerr()??;
            return Ok(());
        }

        // The proxy never accepts, so a connection to it stays queued for the check below.
        let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).anyerr()?;
        let proxy_url = format!("http://{}", proxy.local_addr().anyerr()?);
        // The test harness names tests by their path without the crate.
        let (_crate, module) = module_path!().split_once("::").expect("in a crate");
        let test_name = format!("{module}::test_probes_ignore_env_proxy");
        let mut child = std::process::Command::new(std::env::current_exe().anyerr()?);
        child
            .args(["--exact", &test_name])
            .env(CHILD_VAR, "1")
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            // Any of these would keep reqwest from using the variables and hide a regression.
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("REQUEST_METHOD");
        let output = tokio::task::spawn_blocking(move || child.output())
            .await
            .anyerr()?
            .anyerr()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // A filter that matches no test also exits successfully.
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "the probes failed in the child process:\n{stdout}\n{stderr}"
        );

        proxy.set_nonblocking(true).anyerr()?;
        let accepted = proxy.accept();
        assert!(
            matches!(&accepted, Err(err) if err.kind() == std::io::ErrorKind::WouldBlock),
            "a probe connected to the proxy from the environment: {accepted:?}"
        );

        Ok(())
    }
}
