//! Checks the network conditions from the current host.
//!
//! NetReport is responsible for finding out the network conditions of the current host, like
//! whether it is connected to the internet via IPv4 and/or IPv6, what the NAT situation is
//! etc and reachability to the configured relays.
// Based on <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>

#![cfg_attr(iroh_docsrs, feature(doc_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(wasm_browser, allow(unused))]

use std::{net::SocketAddr, sync::Arc};

// exported primarily for use in documentation
pub use defaults::timeouts::TIMEOUT;
use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_dns::dns::DnsResolver;
#[cfg(not(wasm_browser))]
use iroh_relay::RelayConfig;
#[cfg(not(wasm_browser))]
use iroh_relay::quic::QuicClient;
use iroh_relay::{
    RelayMap,
    quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON},
};
use n0_error::e;
#[cfg(not(wasm_browser))]
use n0_error::stack_error;
#[cfg(not(wasm_browser))]
use n0_future::task;
use n0_future::{StreamExt, task::AbortOnDropHandle};
use n0_watcher::{Watchable, Watcher};
use tokio_util::sync::CancellationToken;
use tracing::trace;

#[cfg(not(wasm_browser))]
use self::reportgen::QadProbeReport;

mod actor;
mod defaults;
mod metrics;
mod probes;
mod report;
mod reportgen;

mod options;

pub(crate) use self::reportgen::IfStateDetails;
#[cfg(not(wasm_browser))]
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
enum QadProbeError {
    #[error("Failed to resolve relay address")]
    GetRelayAddr {
        source: self::reportgen::GetRelayAddrError,
    },
    #[error("Missing host in relay URL")]
    MissingHost,
    #[error("QUIC connection failed")]
    Quic { source: iroh_relay::quic::Error },
    #[error("Receiver dropped")]
    ReceiverDropped,
}

use self::actor::{NetReportActor, ProbeRequestSlot};
#[cfg(wasm_browser)]
pub use self::probes::Probe;
#[cfg(not(wasm_browser))]
use self::reportgen::SocketState;
pub use self::{metrics::Metrics, report::Report};
pub(crate) use self::{options::Options, reportgen::QuicConfig};

// QAD connection types, used by the actor.

#[cfg(not(wasm_browser))]
#[derive(Debug, Default)]
struct QadConns {
    v4: Option<(RelayUrl, QadConn)>,
    v6: Option<(RelayUrl, QadConn)>,
}

#[cfg(not(wasm_browser))]
impl QadConns {
    fn clear(&mut self) {
        if let Some((_, conn)) = self.v4.take() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
        if let Some((_, conn)) = self.v6.take() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
    }

    fn current_v4(&self) -> Option<QadProbeReport> {
        if let Some((_, ref conn)) = self.v4
            && let Some(mut r) = conn.observer.get()
        {
            use noq_proto::PathId;
            if let Some(latency) = conn.conn.rtt(PathId::ZERO) {
                r.latency = latency;
            }
            return Some(r);
        }
        None
    }

    fn current_v6(&self) -> Option<QadProbeReport> {
        if let Some((_, ref conn)) = self.v6
            && let Some(mut r) = conn.observer.get()
        {
            use noq_proto::PathId;
            if let Some(latency) = conn.conn.rtt(PathId::ZERO) {
                r.latency = latency;
            }
            return Some(r);
        }
        None
    }

    /// Returns a watcher over both QAD connections' observed addresses.
    ///
    /// The watcher yields `(v4, v6)` tuples. When either connection
    /// observes a new address the watcher fires. Connections that do not
    /// exist contribute a stable `None`.
    fn watch(
        &self,
    ) -> impl Watcher<Value = (Option<QadProbeReport>, Option<QadProbeReport>)> + use<> {
        let v4 = match self.v4.as_ref() {
            Some((_, conn)) => conn.observer.watch(),
            None => Watchable::new(None).watch(),
        };
        let v6 = match self.v6.as_ref() {
            Some((_, conn)) => conn.observer.watch(),
            None => Watchable::new(None).watch(),
        };
        v4.or(v6)
    }
}

#[cfg(not(wasm_browser))]
#[derive(Debug)]
struct QadConn {
    conn: noq::Connection,
    observer: Watchable<Option<QadProbeReport>>,
    _handle: AbortOnDropHandle<Option<()>>,
}

/// Handle to the net report subsystem.
///
/// Provides a non-blocking API to trigger probe cycles and watch for
/// report updates. Backed by a long-lived [`NetReportActor`] task.
#[derive(Debug)]
pub(crate) struct Client {
    probe_requests: Arc<ProbeRequestSlot>,
    report_watcher: n0_watcher::Direct<Option<Report>>,
    _actor_handle: AbortOnDropHandle<()>,
}

impl Client {
    /// Creates a new net report client, spawning the background actor.
    ///
    /// The `report_out` Watchable is written to by the actor as probe results arrive.
    pub(crate) fn new(
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
        relay_map: RelayMap,
        opts: Options,
        metrics: Arc<Metrics>,
        shutdown: CancellationToken,
        report_out: Watchable<Option<Report>>,
    ) -> Self {
        let protocols = opts.as_protocols();

        #[cfg(not(wasm_browser))]
        let quic_client = opts
            .quic_config
            .map(|c| iroh_relay::quic::QuicClient::new(c.ep, c.client_config));

        #[cfg(not(wasm_browser))]
        let socket_state = SocketState {
            quic_client,
            dns_resolver,
        };

        let report_watcher = report_out.watch();

        let probe_requests = Arc::new(ProbeRequestSlot::new());

        let actor = NetReportActor::new(
            Arc::clone(&probe_requests),
            report_out,
            relay_map,
            #[cfg(not(wasm_browser))]
            socket_state,
            #[cfg(not(wasm_browser))]
            opts.tls_config,
            protocols,
            shutdown,
            metrics,
        );

        let handle = n0_future::task::spawn(actor.run());

        Self {
            probe_requests,
            report_watcher,
            _actor_handle: AbortOnDropHandle::new(handle),
        }
    }

    /// Trigger a probe cycle. Non-blocking, returns immediately.
    ///
    /// Multiple calls between actor ticks coalesce into a single request.
    /// The `is_major` flag is sticky: if any call in a batch is major, the
    /// resulting cycle will be major.
    pub(crate) fn run_probes(&self, if_state: IfStateDetails, is_major: bool) {
        self.probe_requests.request(if_state, is_major);
    }

    /// Watch the report for updates.
    ///
    /// The watcher emits intermediate reports as probes complete.
    /// `None` until the first probe cycle produces data.
    pub(crate) fn watch(&self) -> impl Watcher<Value = Option<Report>> + use<> {
        self.report_watcher.clone()
    }
}

// QAD probe functions, used by the actor.

#[cfg(not(wasm_browser))]
async fn run_probe_v4(
    relay: Arc<RelayConfig>,
    quic_client: QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
) -> n0_error::Result<(QadProbeReport, QadConn), QadProbeError> {
    use noq_proto::PathId;

    let relay_addr = reportgen::get_relay_addr_ipv4(&dns_resolver, &relay)
        .await
        .map_err(|source| e!(QadProbeError::GetRelayAddr { source }))?;

    trace!(?relay_addr, "resolved relay server address");
    let host = relay
        .url
        .host_str()
        .ok_or_else(|| e!(QadProbeError::MissingHost))?;
    let conn = quic_client
        .create_conn(relay_addr.into(), host)
        .await
        .map_err(|source| e!(QadProbeError::Quic { source }))?;

    let mut watcher = conn.observed_external_addr();

    // wait for an addr
    let addr = watcher
        .next()
        .await
        .ok_or_else(|| e!(QadProbeError::ReceiverDropped))?;
    let report = QadProbeReport {
        relay: relay.url.clone(),
        addr: SocketAddr::new(addr.ip().to_canonical(), addr.port()),
        latency: conn.rtt(PathId::ZERO).unwrap_or_default(),
    };

    let observer = Watchable::new(None);
    let endpoint = relay.url.clone();
    let handle = task::spawn(shutdown_token.run_until_cancelled_owned({
        let conn = conn.clone();
        let observer = observer.clone();
        async move {
            while let Some(val) = watcher.next().await {
                let val = SocketAddr::new(val.ip().to_canonical(), val.port());
                let latency = conn.rtt(PathId::ZERO).unwrap_or_default();
                observer
                    .set(Some(QadProbeReport {
                        relay: endpoint.clone(),
                        addr: val,
                        latency,
                    }))
                    .ok();
            }
        }
    }));
    let handle = AbortOnDropHandle::new(handle);

    Ok((
        report,
        QadConn {
            conn,
            observer,
            _handle: handle,
        },
    ))
}

#[cfg(not(wasm_browser))]
async fn run_probe_v6(
    relay: Arc<RelayConfig>,
    quic_client: QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
) -> n0_error::Result<(QadProbeReport, QadConn), QadProbeError> {
    use noq_proto::PathId;

    let relay_addr = reportgen::get_relay_addr_ipv6(&dns_resolver, &relay)
        .await
        .map_err(|source| e!(QadProbeError::GetRelayAddr { source }))?;

    trace!(?relay_addr, "resolved relay server address");
    let host = relay
        .url
        .host_str()
        .ok_or_else(|| e!(QadProbeError::MissingHost))?;
    let conn = quic_client
        .create_conn(relay_addr.into(), host)
        .await
        .map_err(|source| e!(QadProbeError::Quic { source }))?;

    let mut watcher = conn.observed_external_addr();

    // wait for an addr
    let addr = watcher
        .next()
        .await
        .ok_or_else(|| e!(QadProbeError::ReceiverDropped))?;
    let report = QadProbeReport {
        relay: relay.url.clone(),
        addr: SocketAddr::new(addr.ip().to_canonical(), addr.port()),
        latency: conn.rtt(PathId::ZERO).unwrap_or_default(),
    };

    let observer = Watchable::new(None);
    let endpoint = relay.url.clone();
    let handle = task::spawn(shutdown_token.run_until_cancelled_owned({
        let observer = observer.clone();
        let conn = conn.clone();
        async move {
            while let Some(val) = watcher.next().await {
                let val = SocketAddr::new(val.ip().to_canonical(), val.port());
                let latency = conn.rtt(PathId::ZERO).unwrap_or_default();
                observer
                    .set(Some(QadProbeReport {
                        relay: endpoint.clone(),
                        addr: val,
                        latency,
                    }))
                    .ok();
            }
        }
    }));
    let handle = AbortOnDropHandle::new(handle);

    Ok((
        report,
        QadConn {
            conn,
            observer,
            _handle: handle,
        },
    ))
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
    use iroh_relay::{
        RelayMap,
        tls::{CaRootsConfig, default_provider},
    };
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
        let tls_config = CaRootsConfig::insecure_skip_verify()
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
            report_out,
        );
        let if_state = IfStateDetails::fake();

        // Trigger a probe cycle.
        client.run_probes(if_state, true);

        // Wait for the report to have QAD data.
        let mut watcher = client.watch();
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
