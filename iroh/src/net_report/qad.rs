//! QAD (QUIC Address Discovery) probe types, execution, and connection
//! management.
//!
//! A QAD probe opens a QUIC connection to a relay and reads back the
//! public socket address that the relay observes. That address is the
//! starting point for direct connectivity between peers.

#[cfg(not(wasm_browser))]
use std::net::{SocketAddrV4, SocketAddrV6};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_dns::dns::{DnsError, DnsResolver, StaggeredError};
use iroh_relay::{
    RelayConfig,
    defaults::DEFAULT_RELAY_QUIC_PORT,
    quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON},
};
use n0_error::{e, stack_error};
#[cfg(not(wasm_browser))]
use n0_future::task;
use n0_future::{StreamExt, task::AbortOnDropHandle, time::Duration};
use n0_watcher::{Watchable, Watcher};
use tokio_util::sync::CancellationToken;
use tracing::trace;

#[cfg(not(wasm_browser))]
use super::defaults::timeouts::DNS_TIMEOUT;
#[cfg(not(wasm_browser))]
use crate::address_lookup::DNS_STAGGERING_MS;

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

#[cfg(not(wasm_browser))]
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum QadProbeError {
    #[error("Failed to resolve relay address")]
    GetRelayAddr { source: GetRelayAddrError },
    #[error("Missing host in relay URL")]
    MissingHost,
    #[error("QUIC connection failed")]
    Quic { source: iroh_relay::quic::Error },
    #[error("Receiver dropped")]
    ReceiverDropped,
}

#[cfg(not(wasm_browser))]
#[derive(Debug, Default)]
pub(super) struct QadConns {
    pub(super) v4: Option<(RelayUrl, QadConn)>,
    pub(super) v6: Option<(RelayUrl, QadConn)>,
}

#[cfg(not(wasm_browser))]
impl QadConns {
    pub(super) fn clear(&mut self) {
        if let Some((_, conn)) = self.v4.take() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
        if let Some((_, conn)) = self.v6.take() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
    }

    pub(super) fn current_v4(&self) -> Option<QadProbeReport> {
        self.v4.as_ref().and_then(current_report)
    }

    pub(super) fn current_v6(&self) -> Option<QadProbeReport> {
        self.v6.as_ref().and_then(current_report)
    }

    /// Watches both slots and yields `(v4, v6)` whenever either observes
    /// a new address. Empty slots contribute a stable `None`.
    pub(super) fn watch(
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

/// Returns the most recent QAD report from a connection, refreshing the
/// latency from the current RTT estimate.
#[cfg(not(wasm_browser))]
fn current_report((_, conn): &(RelayUrl, QadConn)) -> Option<QadProbeReport> {
    use noq_proto::PathId;
    let mut r = conn.observer.get()?;
    if let Some(latency) = conn.conn.rtt(PathId::ZERO) {
        r.latency = latency;
    }
    Some(r)
}

#[cfg(not(wasm_browser))]
#[derive(Debug)]
pub(super) struct QadConn {
    pub(super) conn: noq::Connection,
    pub(super) observer: Watchable<Option<QadProbeReport>>,
    pub(super) _handle: AbortOnDropHandle<Option<()>>,
}

/// Runs a QAD probe over IPv4 against `relay`.
///
/// Returns the first observed address plus a long-lived [`QadConn`]
/// that keeps watching for address updates in the background.
#[cfg(not(wasm_browser))]
pub(super) async fn run_probe_v4(
    relay: Arc<RelayConfig>,
    quic_client: iroh_relay::quic::QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
) -> n0_error::Result<(QadProbeReport, QadConn), QadProbeError> {
    use noq_proto::PathId;

    let relay_addr = get_relay_addr_ipv4(&dns_resolver, &relay)
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

/// Same as [`run_probe_v4`] but against the relay's IPv6 address.
#[cfg(not(wasm_browser))]
pub(super) async fn run_probe_v6(
    relay: Arc<RelayConfig>,
    quic_client: iroh_relay::quic::QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
) -> n0_error::Result<(QadProbeReport, QadConn), QadProbeError> {
    use noq_proto::PathId;

    let relay_addr = get_relay_addr_ipv6(&dns_resolver, &relay)
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
#[allow(missing_docs)]
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

/// Returns the IPv6 socket address of the relay's QUIC endpoint.
///
/// Resolves the relay URL's hostname via AAAA lookup, or returns the
/// literal address if the URL already contains an IPv6 address.
#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr_ipv6(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
) -> Result<SocketAddrV6, GetRelayAddrError> {
    let port = get_quic_port(relay).ok_or_else(|| e!(GetRelayAddrError::MissingPort))?;
    relay_lookup_ipv6_staggered(dns_resolver, relay, port).await
}

/// Performs a staggered IPv4 DNS lookup for a relay and returns a [`SocketAddrV4`].
///
/// Combines the first resolved A record with the given `port`.
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

/// Performs a staggered IPv6 DNS lookup for a relay and returns a [`SocketAddrV6`].
///
/// Combines the first resolved AAAA record with the given `port`.
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

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use iroh_dns::dns::DnsResolver;
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;
    use tokio_util::sync::CancellationToken;

    use super::super::test_utils;

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
            super::run_probe_v4(relay, quic_client, dns_resolver, CancellationToken::new())
                .await
                .unwrap();

        assert_eq!(report.addr, client_addr);
        drop(conn);
        ep.wait_idle().await;
        server.shutdown().await?;
        Ok(())
    }
}
