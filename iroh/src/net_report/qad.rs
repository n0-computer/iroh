//! QUIC Address Discovery: the probe, its report, and its kept-open connection.
//!
//! A QAD probe opens a QUIC connection to a relay. The relay reports the
//! public socket address it sees us coming from, which is where other peers
//! can try to reach us directly, and the round trip gives us our latency to
//! that relay. The connection then stays open with a keep-alive. Because the
//! relay only sees our address from the packets we send, it reports a change
//! on the connection's next keep-alive rather than the instant our address
//! changes. Keeping the connection open avoids a fresh handshake each time we
//! need the current address.

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
#[cfg(not(wasm_browser))]
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::trace;

#[cfg(not(wasm_browser))]
use super::actor::QadObserved;
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
    /// Returns the DNS record type queried for this family (`A` or `AAAA`).
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

/// The address and latency a QAD probe learned from a relay.
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

/// An open QAD connection and the task that forwards its address observations.
#[cfg(not(wasm_browser))]
#[derive(Debug)]
pub(super) struct QadConn {
    /// The open QUIC connection to the relay.
    pub(super) conn: noq::Connection,
    /// The most recent report from the relay.
    ///
    /// Set to the first address, then updated by the actor as observations
    /// arrive. A later cycle reuses the connection instead of probing this
    /// family again.
    pub(super) probe_report: QadProbeReport,
    /// Aborts the observation-forwarding task when dropped.
    _handle: AbortOnDropHandle<Option<()>>,
}

#[cfg(not(wasm_browser))]
impl QadConn {
    /// The relay this connection is to.
    pub(super) fn relay_url(&self) -> &RelayUrl {
        &self.probe_report.relay_url
    }
}

/// The open QAD connection kept for each address family.
///
/// Each family also has a cancellation token that stops its other probes once
/// one of them has answered.
#[cfg(not(wasm_browser))]
#[derive(Debug, Default)]
pub(super) struct QadConns {
    /// The open IPv4 connection, if any.
    v4: Option<QadConn>,
    /// The open IPv6 connection, if any.
    v6: Option<QadConn>,
    /// Cancels the remaining IPv4 probes once one has answered.
    cancel_v4: CancellationToken,
    /// Cancels the remaining IPv6 probes once one has answered.
    cancel_v6: CancellationToken,
}

#[cfg(not(wasm_browser))]
impl QadConns {
    /// Closes and drops both families' connections.
    pub(super) fn clear(&mut self) {
        for conn in [self.v4.take(), self.v6.take()].into_iter().flatten() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
    }

    /// Returns the open connection for `family`, if any.
    pub(super) fn slot(&self, family: AddrFamily) -> Option<&QadConn> {
        match family {
            AddrFamily::V4 => self.v4.as_ref(),
            AddrFamily::V6 => self.v6.as_ref(),
        }
    }

    /// Returns the mutable slot for `family`'s open connection.
    pub(super) fn slot_mut(&mut self, family: AddrFamily) -> &mut Option<QadConn> {
        match family {
            AddrFamily::V4 => &mut self.v4,
            AddrFamily::V6 => &mut self.v6,
        }
    }

    /// Returns the most recent report from `family`'s open connection, if any.
    pub(super) fn current(&self, family: AddrFamily) -> Option<QadProbeReport> {
        self.slot(family).map(|c| c.probe_report.clone())
    }

    /// Returns the cancellation token for `family`.
    ///
    /// Cancel it once one probe has answered, to stop the family's remaining
    /// probes.
    pub(super) fn cancel(&self, family: AddrFamily) -> &CancellationToken {
        match family {
            AddrFamily::V4 => &self.cancel_v4,
            AddrFamily::V6 => &self.cancel_v6,
        }
    }

    /// Replaces the per-family cancellation tokens with fresh ones.
    pub(super) fn reset_cancels(&mut self) {
        self.cancel_v4 = CancellationToken::new();
        self.cancel_v6 = CancellationToken::new();
    }
}

/// Pieces needed to do QUIC address discovery.
#[derive(derive_more::Debug, Clone)]
pub(crate) struct QuicConfig {
    /// The QUIC endpoint to probe from.
    #[debug("noq::Endpoint")]
    pub(crate) ep: noq::Endpoint,
    /// The TLS client config.
    pub(crate) client_config: rustls::ClientConfig,
    /// Enables IPv4 QUIC address discovery probes.
    pub(crate) ipv4: bool,
    /// Enables IPv6 QUIC address discovery probes.
    pub(crate) ipv6: bool,
}

/// Runs a QAD probe for `family` against `relay`.
///
/// Returns the first address the relay reports, along with an open
/// [`QadConn`]. A background task on that connection keeps watching for
/// address changes and stores each one into `observed` for this family, so a
/// later change reaches the actor without starting another cycle. The watch
/// channel keeps only the newest report per family.
#[cfg(not(wasm_browser))]
pub(super) async fn run_probe(
    family: AddrFamily,
    relay: Arc<RelayConfig>,
    quic_client: iroh_relay::quic::QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
    observed: watch::Sender<QadObserved>,
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
    let probe_report = QadProbeReport {
        relay_url: relay.url.clone(),
        addr: SocketAddr::new(addr.ip().to_canonical(), addr.port()),
        latency: conn.rtt(PathId::ZERO).unwrap_or_default(),
    };

    let relay_url = relay.url.clone();
    let handle = task::spawn(shutdown_token.run_until_cancelled_owned({
        let conn = conn.clone();
        async move {
            // Hold the connection open and stream each address change to the
            // actor. noq's keep-alive prompts the relay to re-observe our
            // address within the keep-alive interval, so we learn of a change
            // without a fresh probe; the connection is reused across cycles
            // until a Full reset or a close drops it. The loop ends when the
            // watcher closes; the connection is closed by whoever drops the
            // [`QadConn`] (a Full reset, or the actor once a second result
            // makes it redundant).
            while let Some(val) = watcher.next().await {
                let val = SocketAddr::new(val.ip().to_canonical(), val.port());
                let latency = conn.rtt(PathId::ZERO).unwrap_or_default();
                let probe_report = QadProbeReport {
                    relay_url: relay_url.clone(),
                    addr: val,
                    latency,
                };
                observed.send_modify(|o| o.set(family, probe_report));
            }
        }
    }));
    let handle = AbortOnDropHandle::new(handle);

    Ok((
        probe_report.clone(),
        QadConn {
            conn,
            probe_report,
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

    use super::{super::test_utils, AddrFamily, QadObserved};

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

        let (observed_tx, _observed_rx) = tokio::sync::watch::channel(QadObserved::default());
        let (report, conn) = super::run_probe(
            AddrFamily::V4,
            relay,
            quic_client,
            dns_resolver,
            CancellationToken::new(),
            observed_tx,
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
