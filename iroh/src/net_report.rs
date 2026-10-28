//! Learns our public addresses and the best relay, and keeps both current.
//!
//! Net report probes the configured relays. QUIC address discovery (QAD) tells
//! us the public address the relays see us coming from, and the round trips
//! tell us which relay is closest. The net report re-assesses both when the
//! network changes and periodically.
//!
//! It runs on its own: it watches the network interfaces itself and needs no
//! requests. What it learns it publishes as [`Outputs`], small watchable values
//! the rest of iroh subscribes to. The socket watches the public addresses, and
//! the relay transport watches the home relay. The full report is only a
//! debug view, exposed through `Endpoint::net_report`.
// Based on <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>

#![cfg_attr(wasm_browser, allow(unused))]

use std::{net::SocketAddr, sync::Arc, time::Duration};

#[cfg(not(wasm_browser))]
use iroh_dns::dns::DnsResolver;
use iroh_relay::RelayMap;
#[cfg(not(wasm_browser))]
use iroh_relay::quic::QuicClient;
use n0_future::task::{self, AbortOnDropHandle};
#[cfg(test)]
use n0_watcher::Watchable;
use n0_watcher::{Direct, Watcher};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Span, info_span};
#[cfg(not(wasm_browser))]
use url::Url;

#[cfg(test)]
pub(crate) use self::outputs::PublicAddr;
pub(crate) use self::outputs::{Outputs, PublicAddrs, Update};
#[cfg(any(test, feature = "unstable-net-report"))]
#[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
pub use self::report::Report;
#[cfg(feature = "unstable-net-report")]
pub use self::report::{Probe, RelayLatencies};
use self::{
    actor::NetReportActor,
    interfaces::{Changes, Interfaces, NetworkState},
    timing::Timing,
};
#[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
pub use self::{
    metrics::Metrics,
    // exported primarily for use in documentation
    timing::FIRST_REPORT_TIMEOUT_SECS,
};
use crate::endpoint::RelayStatus;

mod actor;
#[cfg(not(wasm_browser))]
mod captive_portal;
mod https;
mod interfaces;
mod metrics;
mod outputs;
mod qad;
mod report;
mod timing;

/// Configuration for the net report component.
///
/// Controls which probes and checks the net report performs.
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

    /// Whether to check for captive portals.
    ///
    /// This is done by accessing a well-known URL that is available on each relay
    /// server, `/generate_204`. If a GET request to this URL returns anything else
    /// but a 204 No Content response, we assume we are behind a captive portal.
    ///
    /// The check runs on every full probe cycle: at startup, after a major
    /// network change, and periodically. When we have detected that we are
    /// behind a captive portal and UDP does not work, every cycle is a full
    /// one, in case the captive portal status changes.
    pub captive_portal_check: bool,

    /// Delay inserted between successive QAD probes within a probe cycle.
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

/// Configuration and dependencies for the net report actor.
#[derive(Debug, Clone)]
pub(crate) struct Options {
    /// Which optional probes run.
    pub(crate) config: NetReportConfig,
    /// Timeouts and pacing.
    pub(crate) timing: Timing,
    /// The relays to probe.
    pub(crate) relay_map: RelayMap,
    /// The relay transport's connection to the home relay.
    pub(crate) relay_status: Direct<Option<RelayStatus>>,
    /// The QUIC client for QAD probes, or `None` to skip QAD.
    ///
    /// QAD needs IP transports: the probes go out from the endpoint's own
    /// sockets.
    #[cfg(not(wasm_browser))]
    pub(crate) quic_client: Option<QuicClient>,
    /// Whether QAD probes IPv6, which needs an IPv6 socket.
    #[cfg(not(wasm_browser))]
    pub(crate) qad_ipv6: bool,
    /// Resolves relay hostnames.
    #[cfg(not(wasm_browser))]
    pub(crate) dns_resolver: DnsResolver,
    /// TLS config for the HTTPS and captive portal requests.
    #[cfg(not(wasm_browser))]
    pub(crate) tls_config: rustls::ClientConfig,
    /// Proxy for the HTTPS and captive portal requests, if any.
    #[cfg(not(wasm_browser))]
    pub(crate) proxy_url: Option<Url>,
}

/// Prepares subscriptions before the endpoint needed for QAD exists.
///
/// Consumed by [`Self::spawn`] once the endpoint has been constructed.
#[derive(Debug, Default)]
pub(crate) struct Builder {
    outputs: Outputs,
}

impl Builder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Read-only access for the relay transport and the report API.
    pub(crate) fn outputs(&self) -> Outputs {
        self.outputs.clone()
    }

    /// Starts interface monitoring and probing, returning the owning client.
    pub(crate) async fn spawn(
        self,
        opts: Options,
        metrics: Arc<Metrics>,
        shutdown: CancellationToken,
    ) -> Result<Client, netwatch::netmon::Error> {
        let interfaces = Interfaces::new().await?;
        Ok(self.spawn_with_interfaces(opts, interfaces, metrics, shutdown))
    }

    fn spawn_with_interfaces(
        self,
        opts: Options,
        interfaces: Interfaces,
        metrics: Arc<Metrics>,
        shutdown: CancellationToken,
    ) -> Client {
        let network = self.outputs.network_state.watch();
        let public_addrs = self.outputs.public_addrs.watch();
        let (messages, receiver) = mpsc::unbounded_channel();
        let actor =
            NetReportActor::new(opts, interfaces, receiver, self.outputs, metrics, shutdown);
        let handle = task::spawn(
            actor
                .run()
                .instrument(info_span!(parent: Span::current(), "net_report")),
        );
        Client {
            messages,
            network,
            public_addrs,
            changes: Changes::default(),
            ready: Changes::default(),
            _actor_handle: AbortOnDropHandle::new(handle),
        }
    }
}

/// Owns the net report task, its commands, and the socket's output subscription.
///
/// Dropping the client stops the actor and its probes. Cloning the outputs
/// does not extend the task's lifetime.
#[derive(Debug)]
pub(crate) struct Client {
    /// Changes the actor cannot observe itself.
    messages: mpsc::UnboundedSender<Message>,
    /// The addresses and network changes consumed by the socket.
    network: Direct<NetworkState>,
    public_addrs: Direct<PublicAddrs>,
    /// Last consumed network changes, including any coalesced major changes.
    changes: Changes,
    ready: Changes,
    /// Aborts the background actor when the client is dropped.
    _actor_handle: AbortOnDropHandle<()>,
}

#[derive(Debug)]
enum Message {
    RelaysChanged,
    NetworkChange,
    #[cfg(all(test, with_crypto_provider))]
    ForceNetworkChange(bool),
}

impl Client {
    /// Waits for the next address or network change.
    pub(crate) async fn updated(&mut self) -> Update {
        loop {
            let network = self.network.get();
            if let Some(is_major) = network.changes.since(self.changes) {
                self.changes = network.changes;
                return Update::NetworkChanged { is_major };
            }
            if let Some(ready) = network.ready
                && let Some(is_major) = ready.since(self.ready)
            {
                self.ready = ready;
                return Update::NetworkReady {
                    is_major,
                    hint: network.hint(),
                };
            }
            tokio::select! {
                Ok(_) = self.network.updated() => {},
                Ok(_) = self.public_addrs.updated() => return Update::AddressesChanged,
                else => std::future::pending().await,
            }
        }
    }

    /// The current public addresses, without consuming update notifications.
    #[cfg(not(wasm_browser))]
    pub(crate) fn public_addrs(&self) -> PublicAddrs {
        self.public_addrs.clone().get()
    }

    /// Expands bound sockets into usable local addresses.
    #[cfg(not(wasm_browser))]
    pub(crate) fn local_addresses(
        &self,
        bound_local: &[(SocketAddr, SocketAddr)],
        include_loopback: bool,
    ) -> Vec<SocketAddr> {
        self.network
            .clone()
            .get()
            .local_addresses(bound_local, include_loopback)
    }

    /// Asks the interface monitor to check for a network change.
    pub(crate) fn network_change(&self) {
        self.messages.send(Message::NetworkChange).ok();
    }

    #[cfg(all(test, with_crypto_provider))]
    pub(crate) fn force_network_change(&self, is_major: bool) {
        self.messages
            .send(Message::ForceNetworkChange(is_major))
            .ok();
    }

    /// Tells the net report that the relay map changed, starting a full cycle.
    pub(crate) fn relays_changed(&self) {
        self.messages.send(Message::RelaysChanged).ok();
    }
}

#[cfg(test)]
mod test_utils {
    //! Creates a relay server against which to perform tests

    use iroh_relay::{RelayConfig, RelayQuicConfig, server};

    pub(super) async fn relay() -> (server::Server, RelayConfig) {
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
    pub(super) async fn relay_map(relays: usize) -> (Vec<server::Server>, crate::RelayMap) {
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

    use futures_util::FutureExt;
    use iroh_dns::dns::DnsResolver;
    use iroh_relay::tls::{CaTlsConfig, default_provider};
    use n0_error::{Result, StdResultExt};
    use n0_future::time::{self, Duration};
    use n0_tracing_test::traced_test;
    use n0_watcher::Watcher;
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// How long a test waits for an output or a cycle.
    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// A net report probing from a local QUIC endpoint.
    struct TestClient {
        client: Client,
        outputs: Outputs,
        interfaces: Watchable<netwatch::netmon::State>,
        metrics: Arc<Metrics>,
        ep: noq::Endpoint,
        cancel: CancellationToken,
    }

    impl TestClient {
        /// Spawns a net report with the default timing.
        fn new(relay_map: RelayMap) -> Result<Self> {
            Self::with_timing(relay_map, timing::Timing::default())
        }

        /// Spawns a net report with `timing`.
        fn with_timing(relay_map: RelayMap, timing: timing::Timing) -> Result<Self> {
            let ep =
                noq::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).anyerr()?;
            let relay_status = Watchable::new(None);
            let opts = Options {
                config: NetReportConfig::default(),
                timing,
                relay_map,
                relay_status: relay_status.watch(),
                quic_client: Some(QuicClient::new(
                    ep.clone(),
                    iroh_relay::tls::make_dangerous_client_config(),
                )),
                qad_ipv6: true,
                dns_resolver: DnsResolver::new(),
                tls_config: CaTlsConfig::insecure_skip_verify()
                    .client_config(default_provider())
                    .expect("infallible"),
                proxy_url: None,
            };
            let interfaces = Watchable::new(netwatch::netmon::State::fake());
            let builder = Builder::new();
            let outputs = builder.outputs();
            let metrics = Arc::new(Metrics::default());
            let cancel = CancellationToken::new();
            let client = builder.spawn_with_interfaces(
                opts,
                Interfaces::from_watcher(interfaces.watch()),
                metrics.clone(),
                cancel.child_token(),
            );
            Ok(Self {
                client,
                outputs,
                interfaces,
                metrics,
                ep,
                cancel,
            })
        }

        /// Waits until `watcher` holds a value that satisfies `f`, and returns it.
        async fn wait<W: Watcher>(
            &self,
            mut watcher: W,
            f: impl Fn(&W::Value) -> bool,
        ) -> W::Value {
            time::timeout(TEST_TIMEOUT, async {
                loop {
                    let value = watcher.get();
                    if f(&value) {
                        return value;
                    }
                    watcher.updated().await.expect("watcher closed");
                }
            })
            .await
            .expect("timed out waiting for output")
        }

        /// Waits for the actor to process an interface change without consuming client updates.
        async fn set_interfaces(&self, state: netwatch::netmon::State) {
            let previous = self.outputs.network_state.get().changes;
            self.interfaces.set(state).unwrap();
            self.wait(self.outputs.network_state.watch(), |network| {
                network.changes != previous
            })
            .await;
        }

        /// Waits until `n` cycles have started.
        async fn wait_cycles(&self, n: u64) {
            time::timeout(TEST_TIMEOUT, async {
                while self.metrics.reports.get() < n {
                    time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("timed out waiting for cycles");
        }

        /// Stops the net report and waits for its endpoint to close.
        async fn shutdown(self) {
            self.cancel.cancel();
            drop(self.client);
            self.ep.wait_idle().await;
        }
    }

    /// Returns whether `report` has an IPv4 address and a preferred relay.
    fn has_v4_and_relay(report: &Option<Report>) -> bool {
        report
            .as_ref()
            .is_some_and(|r| r.global_v4.is_some() && r.preferred_relay.is_some())
    }

    /// Readiness for an older usable network must not bypass a newer route wait.
    #[tokio::test(start_paused = true)]
    async fn test_network_readiness_ignores_superseded_ready_state() -> Result<()> {
        let mut client = TestClient::new(RelayMap::empty())?;
        assert!(client.client.updated().now_or_never().is_none());

        let mut state = client.interfaces.get();
        state.is_expensive = true;
        client.set_interfaces(state.clone()).await;
        state.default_route_interface = None;
        client.set_interfaces(state).await;

        assert!(matches!(
            client.client.updated().await,
            Update::NetworkChanged { is_major: true }
        ));
        assert!(client.client.updated().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(client.client.updated().now_or_never().is_none());
        // A minor change must neither restart the deadline nor forget the major one.
        let previous = client.outputs.network_state.get().changes;
        client.client.force_network_change(false);
        client
            .wait(client.outputs.network_state.watch(), |network| {
                network.changes != previous
            })
            .await;
        assert!(matches!(
            client.client.updated().await,
            Update::NetworkChanged { is_major: false }
        ));
        assert!(client.client.updated().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            client.client.updated().await,
            Update::NetworkReady { is_major: true, .. }
        ));
        assert!(client.client.updated().now_or_never().is_none());
        client.shutdown().await;
        Ok(())
    }

    /// A restored route releases the pending change before the fallback timeout.
    #[tokio::test(start_paused = true)]
    async fn test_network_readiness_recovers_without_waiting_for_timeout() -> Result<()> {
        let mut client = TestClient::new(RelayMap::empty())?;
        assert!(client.client.updated().now_or_never().is_none());
        let state = client.interfaces.get();
        let mut offline = state.clone();
        offline.default_route_interface = None;
        client.set_interfaces(offline).await;
        assert!(matches!(
            client.client.updated().await,
            Update::NetworkChanged { is_major: true }
        ));
        assert!(client.client.updated().now_or_never().is_none());

        tokio::time::advance(Duration::from_secs(1)).await;
        client.set_interfaces(state).await;
        assert!(matches!(
            client.client.updated().await,
            Update::NetworkChanged { is_major: true }
        ));
        assert!(matches!(
            client.client.updated().await,
            Update::NetworkReady { is_major: true, .. }
        ));
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(client.client.updated().now_or_never().is_none());
        client.shutdown().await;
        Ok(())
    }

    /// The net report starts on its own and fills every output.
    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_basic() -> Result<()> {
        let (server, relay) = test_utils::relay().await;
        let relay_url = relay.url.clone();
        let client = TestClient::new(RelayMap::from(relay))?;

        let addrs = client
            .wait(client.outputs.public_addrs(), |a| a.v4.is_some())
            .await;
        assert!(!addrs.v4.unwrap().varies_by_dest);
        let home_relay = client
            .wait(client.outputs.home_relay(), Option::is_some)
            .await;
        assert_eq!(home_relay, Some(relay_url));
        let report = client
            .wait(client.outputs.report(), has_v4_and_relay)
            .await
            .unwrap();
        assert!(report.has_udp(), "want UDP");
        assert_eq!(report.global_v4, addrs.v4.map(|a| a.addr));

        client.shutdown().await;
        server.shutdown().await?;
        Ok(())
    }

    /// A periodic refresh reuses the kept connections.
    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_refresh_after_full() -> Result<()> {
        let (servers, relay_map) = test_utils::relay_map(2).await;
        let timing = timing::Timing {
            refresh_interval: Duration::from_millis(300),
            ..Default::default()
        };
        let client = TestClient::with_timing(relay_map, timing)?;
        let first = client
            .wait(client.outputs.report(), has_v4_and_relay)
            .await
            .unwrap();
        assert_eq!(
            first
                .relay_latency
                .iter()
                .map(|(_, url, _)| url)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2,
        );

        client.wait_cycles(2).await;
        assert_eq!(client.metrics.reports_full.get(), 1);
        // The kept connection still provides the address.
        let addrs = client.outputs.public_addrs().get();
        assert_eq!(addrs.v4.map(|a| a.addr), first.global_v4);
        assert!(client.outputs.home_relay().get().is_some());

        client.shutdown().await;
        for server in servers {
            server.shutdown().await?;
        }
        Ok(())
    }

    /// A closed QAD connection makes the actor start a cycle by itself.
    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_closed_qad_conn_refreshes() -> Result<()> {
        let (server, relay) = test_utils::relay().await;
        let client = TestClient::new(RelayMap::from(relay))?;
        client.wait(client.outputs.report(), has_v4_and_relay).await;
        let cycles = client.metrics.reports.get();

        // Only a connection that lived for a while triggers a refresh.
        time::sleep(actor::MIN_QAD_CONN_AGE).await;
        server.shutdown().await?;
        client.wait_cycles(cycles + 1).await;

        client.shutdown().await;
        Ok(())
    }

    /// An empty relay map clears the outputs.
    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_empty_relay_map_clears_outputs() -> Result<()> {
        let (server, relay) = test_utils::relay().await;
        let relay_url = relay.url.clone();
        let relay_map = RelayMap::from(relay);
        let client = TestClient::new(relay_map.clone())?;
        client.wait(client.outputs.report(), has_v4_and_relay).await;

        relay_map.remove(&relay_url);
        client.client.relays_changed();
        client.wait(client.outputs.report(), Option::is_none).await;
        assert_eq!(client.outputs.public_addrs().get(), PublicAddrs::default());

        client.shutdown().await;
        server.shutdown().await?;
        Ok(())
    }
}
