//! QAD (QUIC Address Discovery) probe types, execution, and connection
//! management.
//!
//! A QAD probe opens a QUIC connection to a relay and reads back the
//! public socket address that the relay observes. That address is the
//! starting point for direct connectivity between peers.

use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
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

/// IP address family (IPv4 or IPv6) for QAD probes.
#[cfg(not(wasm_browser))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddrFamily {
    V4,
    V6,
}

#[cfg(not(wasm_browser))]
impl AddrFamily {
    /// DNS record type queried for this family (`A` or `AAAA`).
    fn dns_record_type(self) -> &'static str {
        match self {
            Self::V4 => "A",
            Self::V6 => "AAAA",
        }
    }
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
    #[error("Probe timed out")]
    Timeout,
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

#[cfg(not(wasm_browser))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct QadProbeReport {
    /// The relay that was probed.
    pub(super) relay_url: RelayUrl,
    /// The latency to the relay.
    pub(super) latency: Duration,
    /// The discovered public address.
    pub(super) addr: SocketAddr,
}

/// A live QAD connection, its address observer, and the background task
/// that keeps the observer fresh.
#[cfg(not(wasm_browser))]
#[derive(Debug)]
pub(super) struct QadConn {
    pub(super) conn: noq::Connection,
    pub(super) observer: Watchable<Option<QadProbeReport>>,
    /// Aborts the observer task when dropped.
    _handle: AbortOnDropHandle<Option<()>>,
}

#[cfg(not(wasm_browser))]
impl QadConn {
    /// Returns the most recent observed address, refreshing the latency
    /// from the connection's current RTT estimate.
    pub(super) fn latest_report(&self) -> Option<QadProbeReport> {
        use noq_proto::PathId;
        let mut r = self.observer.get()?;
        if let Some(latency) = self.conn.rtt(PathId::ZERO) {
            r.latency = latency;
        }
        Some(r)
    }
}

/// Tracks the winning QAD connection per address family, together with
/// the cancellation tokens used to stop remaining probes for that family
/// as soon as a winner is found.
#[cfg(not(wasm_browser))]
#[derive(Debug, Default)]
pub(super) struct QadConns {
    pub(super) v4: Option<(RelayUrl, QadConn)>,
    pub(super) v6: Option<(RelayUrl, QadConn)>,
    cancel_v4: CancellationToken,
    cancel_v6: CancellationToken,
}

#[cfg(not(wasm_browser))]
impl QadConns {
    pub(super) fn clear(&mut self) {
        for (_, conn) in [self.v4.take(), self.v6.take()].into_iter().flatten() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
    }

    pub(super) fn slot(&self, family: AddrFamily) -> Option<&(RelayUrl, QadConn)> {
        match family {
            AddrFamily::V4 => self.v4.as_ref(),
            AddrFamily::V6 => self.v6.as_ref(),
        }
    }

    pub(super) fn slot_mut(&mut self, family: AddrFamily) -> &mut Option<(RelayUrl, QadConn)> {
        match family {
            AddrFamily::V4 => &mut self.v4,
            AddrFamily::V6 => &mut self.v6,
        }
    }

    pub(super) fn current(&self, family: AddrFamily) -> Option<QadProbeReport> {
        self.slot(family).and_then(|(_, c)| c.latest_report())
    }

    /// Returns the cancellation token for `family`. Cancel it once a
    /// winner is found to stop outstanding probes for the family.
    pub(super) fn cancel(&self, family: AddrFamily) -> &CancellationToken {
        match family {
            AddrFamily::V4 => &self.cancel_v4,
            AddrFamily::V6 => &self.cancel_v6,
        }
    }

    /// Replaces the per-family cancellation tokens with fresh ones for
    /// the next probe cycle.
    pub(super) fn reset_cancels(&mut self) {
        self.cancel_v4 = CancellationToken::new();
        self.cancel_v6 = CancellationToken::new();
    }

    /// Watches both slots and yields [`QadUpdate`] whenever either slot
    /// observes a new address. Empty slots contribute a stable `None`.
    pub(super) fn watch(&self) -> impl Watcher<Value = QadUpdate> + use<> {
        fn one(
            slot: Option<&(RelayUrl, QadConn)>,
        ) -> impl Watcher<Value = Option<QadProbeReport>> + use<> {
            match slot {
                Some((_, conn)) => conn.observer.watch(),
                None => Watchable::new(None).watch(),
            }
        }
        one(self.v4.as_ref())
            .or(one(self.v6.as_ref()))
            .map(|(v4, v6)| QadUpdate { v4, v6 })
    }
}

/// Latest observed addresses from [`QadConns::watch`].
#[cfg(not(wasm_browser))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct QadUpdate {
    pub(super) v4: Option<QadProbeReport>,
    pub(super) v6: Option<QadProbeReport>,
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

/// Runs a QAD probe for `family` against `relay`.
///
/// Returns the first observed address plus a long-lived [`QadConn`]
/// that keeps watching for address updates in the background.
#[cfg(not(wasm_browser))]
pub(super) async fn run_probe(
    family: AddrFamily,
    relay: Arc<RelayConfig>,
    quic_client: iroh_relay::quic::QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
) -> n0_error::Result<(QadProbeReport, QadConn), QadProbeError> {
    use noq_proto::PathId;

    trace!(?family, url = %relay.url, "QAD probe starting");

    let relay_addr = get_relay_addr(&dns_resolver, &relay, family)
        .await
        .map_err(|source| e!(QadProbeError::GetRelayAddr { source }))?;

    trace!(?relay_addr, "resolved relay server address");
    let host = relay
        .url
        .host_str()
        .ok_or_else(|| e!(QadProbeError::MissingHost))?;
    let conn = quic_client
        .create_conn(relay_addr, host)
        .await
        .map_err(|source| e!(QadProbeError::Quic { source }))?;

    let mut watcher = conn.observed_external_addr();

    let addr = watcher
        .next()
        .await
        .ok_or_else(|| e!(QadProbeError::ReceiverDropped))?;
    let report = QadProbeReport {
        relay_url: relay.url.clone(),
        addr: SocketAddr::new(addr.ip().to_canonical(), addr.port()),
        latency: conn.rtt(PathId::ZERO).unwrap_or_default(),
    };

    let observer = Watchable::new(None);
    let relay_url = relay.url.clone();
    let handle = task::spawn(shutdown_token.run_until_cancelled_owned({
        let conn = conn.clone();
        let observer = observer.clone();
        async move {
            while let Some(val) = watcher.next().await {
                let val = SocketAddr::new(val.ip().to_canonical(), val.port());
                let latency = conn.rtt(PathId::ZERO).unwrap_or_default();
                observer
                    .set(Some(QadProbeReport {
                        relay_url: relay_url.clone(),
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

/// Resolves the relay's QUIC socket address for the given address family.
#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
    family: AddrFamily,
) -> Result<SocketAddr, GetRelayAddrError> {
    let port = get_quic_port(relay).ok_or_else(|| e!(GetRelayAddrError::MissingPort))?;
    let no_addr = || {
        e!(GetRelayAddrError::NoAddrFound {
            url: relay.url.clone(),
            addr_type: family.dns_record_type(),
        })
    };

    match (relay.url.host(), family) {
        (Some(url::Host::Ipv4(ip)), AddrFamily::V4) => Ok(SocketAddrV4::new(ip, port).into()),
        (Some(url::Host::Ipv6(ip)), AddrFamily::V6) => Ok(SocketAddrV6::new(ip, port, 0, 0).into()),
        (Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)), _) => Err(no_addr()),
        (Some(url::Host::Domain(hostname)), _) => {
            trace!(%hostname, ?family, "Performing DNS lookup for relay addr");
            let first = match family {
                AddrFamily::V4 => dns_resolver
                    .lookup_ipv4_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                    .await
                    .map_err(|err| e!(GetRelayAddrError::DnsLookup, err))?
                    .next(),
                AddrFamily::V6 => dns_resolver
                    .lookup_ipv6_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                    .await
                    .map_err(|err| e!(GetRelayAddrError::DnsLookup, err))?
                    .next(),
            };
            match (first.map(|ip| ip.to_canonical()), family) {
                (Some(IpAddr::V4(ip)), AddrFamily::V4) => Ok(SocketAddrV4::new(ip, port).into()),
                (Some(IpAddr::V6(ip)), AddrFamily::V6) => {
                    Ok(SocketAddrV6::new(ip, port, 0, 0).into())
                }
                _ => Err(no_addr()),
            }
        }
        (None, _) => Err(e!(GetRelayAddrError::InvalidHostname)),
    }
}

#[cfg(not(wasm_browser))]
fn get_quic_port(relay: &RelayConfig) -> Option<u16> {
    relay.quic.as_ref().map(|q| {
        if q.port == 0 {
            DEFAULT_RELAY_QUIC_PORT
        } else {
            q.port
        }
    })
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

    use super::{super::test_utils, AddrFamily};

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

        let (report, conn) = super::run_probe(
            AddrFamily::V4,
            relay,
            quic_client,
            dns_resolver,
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(report.addr, client_addr);
        drop(conn);
        ep.wait_idle().await;
        server.shutdown().await?;
        Ok(())
    }
}
