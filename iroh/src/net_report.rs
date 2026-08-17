//! Checks the network conditions from the current host.
//!
//! NetReport is responsible for finding out the network conditions of the current host, like
//! whether it is connected to the internet via IPv4 and/or IPv6, what the NAT situation is
//! etc and reachability to the configured relays.
// Based on <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>

#![cfg_attr(wasm_browser, allow(unused))]

use std::{sync::Arc, time::Duration};

#[cfg(not(wasm_browser))]
use iroh_dns::dns::DnsResolver;
use iroh_relay::RelayMap;
use n0_future::task::AbortOnDropHandle;
use n0_watcher::Watchable;
use tokio_util::sync::CancellationToken;

mod actor;
mod captive_portal;
mod defaults;
mod https;
mod metrics;
mod options;
mod probes;
mod qad;
mod report;

/// The interface state the actor uses to pick address families to probe.
#[derive(Debug, Clone, Default)]
pub(crate) struct IfState {
    /// Whether IPv4 is available on some interface.
    pub(crate) have_v4: bool,
    /// Whether IPv6 is available on some interface.
    pub(crate) have_v6: bool,
}

impl IfState {
    /// Returns an [`IfState`] with both families available, for tests.
    #[cfg(all(test, with_crypto_provider))]
    pub(super) fn fake() -> Self {
        IfState {
            have_v4: true,
            have_v6: true,
        }
    }
}

impl From<netwatch::netmon::State> for IfState {
    fn from(value: netwatch::netmon::State) -> Self {
        IfState {
            have_v4: value.have_v4,
            have_v6: value.have_v6,
        }
    }
}

/// Configuration for the net report component.
///
/// Controls which probes and checks are performed when generating network
/// reports, and how they are paced.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NetReportConfig {
    /// Whether to run HTTPS latency probes against relay servers.
    ///
    /// HTTPS latency probes perform an empty HTTPS GET request to each configured
    /// relay server and measure latency.
    ///
    /// They are performed in addition to the QUIC address discovery (QAD) probes.
    /// In networks that do not allow QUIC traffic, they are the only way to detect
    /// relay latencies and thus the preferred relay.
    ///
    /// Disabling them is harmless on networks that do allow QUIC traffic, but will
    /// completely prevent finding the home relay on networks that do block QUIC.
    pub https_probes: bool,

    /// Whether to check for captive portals when generating the first report.
    ///
    /// This is done by accessing a well-known URL that is available on each relay
    /// server, `/generate_204`. If a GET request to this URL returns anything else
    /// but a 204 No Content response, we assume we are behind a captive portal.
    ///
    /// When we have detected that we are behind a captive portal, we try to contact
    /// the relay servers more frequently in case the captive portal status changes.
    pub captive_portal_check: bool,

    /// Delay inserted between successive QAD probes within a report cycle.
    ///
    /// A cycle runs QUIC address discovery against several relays. By default
    /// those probes all start at once, a brief burst of QUIC handshakes. On
    /// resource-constrained devices (an ESP32, say) that burst is disruptive,
    /// so a non-zero value spreads the probes out: the first still starts
    /// immediately, and each following one is delayed by a further multiple
    /// of this duration. Setting it does not delay the first result.
    ///
    /// Defaults to [`Duration::ZERO`], which keeps the all-at-once behavior.
    pub qad_stagger: Duration,
}

impl NetReportConfig {
    /// Creates a minimal configuration that disables all optional probes and checks.
    pub fn minimal() -> Self {
        Self {
            https_probes: false,
            captive_portal_check: false,
            qad_stagger: Duration::ZERO,
        }
    }
}

impl Default for NetReportConfig {
    fn default() -> Self {
        Self {
            https_probes: true,
            captive_portal_check: true,
            qad_stagger: Duration::ZERO,
        }
    }
}

use self::actor::{NetReportActor, RequestSlot};
pub(crate) use self::{actor::ProbeScope, options::Options, qad::QuicConfig};
#[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
pub use self::{
    // exported primarily for use in documentation
    defaults::timeouts::FIRST_REPORT_TIMEOUT_SECS,
    metrics::Metrics,
    report::Report,
};
// Re-exported only for the `unstable-net-report` public API. Internally,
// these are reached via their own module paths (`probes::Probe`,
// `report::RelayLatencies`).
#[cfg(feature = "unstable-net-report")]
pub use self::{probes::Probe, report::RelayLatencies};

/// Handle to the net report actor.
///
/// The handle only triggers probe cycles; it does not carry the results.
/// The [`NetReportActor`] runs in the background and writes each [`Report`]
/// into the `report_out` [`Watchable`] that the caller passes to
/// [`Client::new`] and watches directly.
#[derive(Debug)]
pub(crate) struct Client {
    /// Shared slot the client writes probe triggers into.
    probe_requests: Arc<RequestSlot>,
    /// Aborts the background actor when the client is dropped.
    _actor_handle: AbortOnDropHandle<()>,
}

impl Client {
    /// Creates a new net report client, spawning the background actor.
    ///
    /// The actor writes reports into `report_out` as probe results arrive.
    /// It is owned by the caller (the socket) so it can be read via the
    /// public `Endpoint::net_report` accessor; the client only drives
    /// probes into it.
    pub(crate) fn new(
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
        relay_map: RelayMap,
        opts: Options,
        metrics: Arc<Metrics>,
        shutdown: CancellationToken,
        report_out: Watchable<Option<Report>>,
    ) -> Self {
        let probe_requests = Arc::new(RequestSlot::new());

        let actor = NetReportActor::new(
            Arc::clone(&probe_requests),
            report_out,
            relay_map,
            opts,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            shutdown,
            metrics,
        );

        let handle = n0_future::task::spawn(actor.run());

        Self {
            probe_requests,
            _actor_handle: AbortOnDropHandle::new(handle),
        }
    }

    /// Triggers a probe cycle.
    ///
    /// Non-blocking; returns immediately. Calls that arrive close together
    /// coalesce into a single request, keeping the most urgent scope.
    pub(crate) fn run_probes(&self, if_state: IfState, scope: ProbeScope) {
        self.probe_requests.request(if_state, scope);
    }
}

#[cfg(test)]
mod test_utils {
    //! Creates a relay server against which to perform tests

    use iroh_relay::{RelayConfig, RelayQuicConfig, server};

    pub(crate) async fn relay() -> (server::Server, RelayConfig) {
        let server = server::Server::spawn(server::testing::server_config())
            .await
            .expect("should serve relay");
        let quic = Some(RelayQuicConfig::new(
            server.quic_addr().expect("server should run quic").port(),
        ));
        let endpoint_desc =
            RelayConfig::new(server.https_url().expect("should work as relay"), quic);

        (server, endpoint_desc)
    }

    /// Create a [`crate::RelayMap`] of the given size.
    pub(crate) async fn relay_map(relays: usize) -> (Vec<server::Server>, crate::RelayMap) {
        let mut servers = Vec::with_capacity(relays);
        let mut endpoints = Vec::with_capacity(relays);
        for _ in 0..relays {
            let (relay_server, endpoint) = relay().await;
            servers.push(relay_server);
            endpoints.push(endpoint);
        }
        (servers, crate::RelayMap::from_iter(endpoints))
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use iroh_dns::dns::DnsResolver;
    use iroh_relay::tls::{CaTlsConfig, default_provider};
    use n0_error::{Result, StdResultExt};
    use n0_future::time::Duration;
    use n0_tracing_test::traced_test;
    use n0_watcher::Watcher;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_basic() -> Result<()> {
        let (server, relay) = test_utils::relay().await;
        let client_config = iroh_relay::tls::make_dangerous_client_config();
        let ep = noq::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).anyerr()?;
        let quic_addr_disc = QuicConfig {
            ep: ep.clone(),
            client_config,
            ipv4: true,
            ipv6: true,
        };
        let relay_map = RelayMap::from(relay);

        let resolver = DnsResolver::new();
        let tls_config = CaTlsConfig::insecure_skip_verify()
            .client_config(default_provider())
            .expect("infallible");
        let opts = Options::new(tls_config).quic_config(Some(quic_addr_disc));
        let cancel = CancellationToken::new();
        let report_out = Watchable::new(None);
        let client = Client::new(
            resolver,
            relay_map,
            opts,
            Default::default(),
            cancel.child_token(),
            report_out.clone(),
        );
        let if_state = IfState::fake();

        // Trigger a probe cycle.
        client.run_probes(if_state, ProbeScope::Full);

        // Wait for the report to have QAD data.
        let mut watcher = report_out.watch();
        let report = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let r = watcher.updated().await.expect("watcher closed");
                if let Some(ref r) = r
                    && r.global_v4.is_some()
                    && r.preferred_relay.is_some()
                {
                    return r.clone();
                }
            }
        })
        .await
        .expect("timed out waiting for report");

        assert!(report.has_udp(), "want UDP");
        assert!(
            !report.relay_latency.is_empty(),
            "expected at least 1 key in RelayLatency; got none",
        );
        assert!(report.global_v4.is_some(), "expected globalV4 set");
        assert!(report.preferred_relay.is_some());

        cancel.cancel();
        drop(client);
        ep.wait_idle().await;
        server.shutdown().await?;

        Ok(())
    }
}
