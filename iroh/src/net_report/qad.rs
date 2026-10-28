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
    ops::{Index, IndexMut},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_dns::dns::{DNS_TIMEOUT, DnsResolver};
use iroh_relay::{
    RelayConfig,
    defaults::DEFAULT_RELAY_QUIC_PORT,
    quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON, QuicClient},
};
#[cfg(not(wasm_browser))]
use n0_error::{Result, StackResultExt, anyerr};
use n0_future::{
    FutureExt, Stream, StreamExt,
    boxed::BoxFuture,
    time::{Duration, Instant},
};
use noq::ObservedExternalAddr;
use noq_proto::PathId;
use tracing::trace;

use super::report::Probe;
#[cfg(not(wasm_browser))]
use crate::address_lookup::DNS_STAGGERING_MS;

/// IP address family (IPv4 or IPv6) for QAD probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddrFamily {
    V4,
    V6,
}

impl AddrFamily {
    /// Both families, IPv4 first.
    pub(super) const ALL: [Self; 2] = [Self::V4, Self::V6];

    /// Returns the DNS record type queried for this family (`A` or `AAAA`).
    fn dns_record_type(self) -> &'static str {
        match self {
            Self::V4 => "A",
            Self::V6 => "AAAA",
        }
    }

    /// Returns the [`Probe`] that latencies from this family are filed under.
    pub(super) fn probe(self) -> Probe {
        match self {
            Self::V4 => Probe::QadIpv4,
            Self::V6 => Probe::QadIpv6,
        }
    }
}

/// One value per address family, indexed by [`AddrFamily`].
#[derive(Debug, Default)]
pub(super) struct PerFamily<T> {
    v4: T,
    v6: T,
}

impl<T> Index<AddrFamily> for PerFamily<T> {
    type Output = T;

    fn index(&self, family: AddrFamily) -> &T {
        match family {
            AddrFamily::V4 => &self.v4,
            AddrFamily::V6 => &self.v6,
        }
    }
}

impl<T> IndexMut<AddrFamily> for PerFamily<T> {
    fn index_mut(&mut self, family: AddrFamily) -> &mut T {
        match family {
            AddrFamily::V4 => &mut self.v4,
            AddrFamily::V6 => &mut self.v6,
        }
    }
}

/// The address and latency a QAD probe learned from a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct QadProbeReport {
    /// The relay that was probed.
    pub(super) relay_url: RelayUrl,
    /// The latency to the relay.
    pub(super) latency: Duration,
    /// The discovered public address.
    pub(super) addr: SocketAddr,
}

/// An open QAD connection, kept to learn about later address changes.
///
/// It is a stream of [`QadConnEvent`]s that the actor polls directly. Dropping
/// it drops the connection, and with it any update not yet polled.
#[derive(derive_more::Debug)]
pub(super) struct QadConn {
    /// The relay this connection is to.
    relay_url: RelayUrl,
    /// The open QUIC connection to the relay.
    conn: noq::Connection,
    /// The addresses the relay reports, starting after the first one.
    observed: ObservedExternalAddr,
    /// Completes when the connection closes.
    #[debug(skip)]
    closed: BoxFuture<()>,
    /// When the connection was opened.
    opened: Instant,
}

/// An update from an open [`QadConn`].
#[derive(Debug)]
pub(super) enum QadConnEvent {
    /// The relay reported a new address for us.
    Observed(QadProbeReport),
    /// The connection closed. The actor drops it.
    Closed,
}

impl QadConn {
    /// Wraps an open connection.
    ///
    /// The first address was already read from `observed`.
    fn new(relay_url: RelayUrl, conn: noq::Connection, observed: ObservedExternalAddr) -> Self {
        let closed = {
            let conn = conn.clone();
            Box::pin(async move {
                conn.closed().await;
            })
        };
        Self {
            relay_url,
            conn,
            observed,
            closed,
            opened: Instant::now(),
        }
    }

    /// Returns how long the connection has been open.
    pub(super) fn age(&self) -> Duration {
        self.opened.elapsed()
    }

    /// Returns `true` if the connection has closed.
    pub(super) fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    /// The relay this connection is to.
    pub(super) fn relay_url(&self) -> &RelayUrl {
        &self.relay_url
    }

    /// Returns the connection's latest observed address and current latency.
    ///
    /// Returns `None` before the relay has reported an address, which cannot
    /// happen for a connection that [`run_probe`] returned.
    pub(super) fn current_report(&self) -> Option<QadProbeReport> {
        let addr = self.observed.get()?;
        Some(self.report(addr))
    }

    /// Closes the connection with the QAD close code.
    pub(super) fn close(&self) {
        self.conn
            .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
    }

    /// Builds a report for `addr` with the connection's current latency.
    fn report(&self, addr: SocketAddr) -> QadProbeReport {
        QadProbeReport {
            relay_url: self.relay_url.clone(),
            // If we've sent to an IPv4 address, but received an observed
            // address that is IPv6, then the address is an [IPv4-Mapped IPv6
            // Address](https://doc.rust-lang.org/beta/std/net/struct.Ipv6Addr.html#ipv4-mapped-ipv6-addresses).
            addr: SocketAddr::new(addr.ip().to_canonical(), addr.port()),
            latency: self.conn.rtt(PathId::ZERO).unwrap_or_default(),
        }
    }
}

impl Stream for QadConn {
    type Item = QadConnEvent;

    /// Yields the next update.
    ///
    /// After [`QadConnEvent::Closed`] the actor drops the connection, so the
    /// stream never ends on its own.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<QadConnEvent>> {
        if self.closed.poll(cx).is_ready() {
            return Poll::Ready(Some(QadConnEvent::Closed));
        }
        match self.observed.poll_next(cx) {
            Poll::Ready(Some(addr)) => Poll::Ready(Some(QadConnEvent::Observed(self.report(addr)))),
            Poll::Ready(None) => Poll::Ready(Some(QadConnEvent::Closed)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Runs a QAD probe for `family` against `relay`.
///
/// Returns the first address the relay reports, along with the open
/// [`QadConn`] that yields later address changes.
#[cfg(not(wasm_browser))]
pub(super) async fn run_probe(
    family: AddrFamily,
    relay: Arc<RelayConfig>,
    quic_client: QuicClient,
    dns_resolver: DnsResolver,
) -> Result<(QadProbeReport, QadConn)> {
    trace!(?family, url = %relay.url, "QAD probe starting");

    let relay_addr = get_relay_addr(&dns_resolver, &relay, family)
        .await
        .context("Failed to resolve relay address")?;

    trace!(?relay_addr, "resolved relay server address");
    let host = relay_tls_server_name(&relay).ok_or_else(|| anyerr!("Missing host in relay URL"))?;
    let conn = quic_client
        .create_conn(relay_addr, &host)
        .await
        .context("QUIC connection failed")?;

    let mut observed = conn.observed_external_addr();
    let addr = observed
        .next()
        .await
        .ok_or_else(|| anyerr!("Connection closed before the relay reported an address"))?;
    let conn = QadConn::new(relay.url.clone(), conn, observed);
    Ok((conn.report(addr), conn))
}

/// Resolves the relay's QUIC socket address for the given address family.
#[cfg(not(wasm_browser))]
async fn get_relay_addr(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
    family: AddrFamily,
) -> Result<SocketAddr> {
    let port = get_quic_port(relay)
        .ok_or_else(|| anyerr!("No QUIC port configured for relay {}", relay.url))?;
    let no_addr = || {
        anyerr!(
            "No suitable relay address found for {} ({})",
            relay.url,
            family.dns_record_type()
        )
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
                    .context("DNS lookup failed")?
                    .next(),
                AddrFamily::V6 => dns_resolver
                    .lookup_ipv6_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                    .await
                    .context("DNS lookup failed")?
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
        (None, _) => Err(anyerr!("No valid hostname in the relay URL")),
    }
}

/// Returns the proper port based on the protocol of the probe.
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

/// Returns the TLS server name for the relay's host.
#[cfg(not(wasm_browser))]
fn relay_tls_server_name(relay: &RelayConfig) -> Option<std::borrow::Cow<'_, str>> {
    // host_str() includes brackets around IPv6 literals.
    match relay.url.host()? {
        url::Host::Domain(name) => Some(name.into()),
        url::Host::Ipv4(ip) => Some(ip.to_string().into()),
        url::Host::Ipv6(ip) => Some(ip.to_string().into()),
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use iroh_base::RelayUrl;
    use iroh_dns::dns::DnsResolver;
    use iroh_relay::{RelayConfig, quic::QuicClient, tls::default_provider};
    use n0_error::{Result, StdResultExt};
    use n0_future::{
        StreamExt,
        time::{self, Duration},
    };
    use n0_tracing_test::traced_test;

    use super::{super::test_utils, AddrFamily, QadConnEvent, relay_tls_server_name};

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

        let (report, mut conn) = super::run_probe(AddrFamily::V4, relay, quic_client, dns_resolver)
            .await
            .unwrap();

        assert_eq!(report.addr, client_addr);
        assert_eq!(conn.current_report().map(|r| r.addr), Some(client_addr));

        // Closing the connection ends its updates with a `Closed` event.
        conn.close();
        let event = time::timeout(Duration::from_secs(5), conn.next())
            .await
            .anyerr()?;
        assert!(
            matches!(event, Some(QadConnEvent::Closed)),
            "expected Closed, got {event:?}"
        );
        drop(conn);
        ep.wait_idle().await;
        server.shutdown().await?;
        Ok(())
    }

    #[test]
    fn relay_tls_server_names() {
        for (url, expected) in [
            ("https://relay.example.test", "relay.example.test"),
            ("https://192.0.2.10", "192.0.2.10"),
            ("https://[2001:db8::10]", "2001:db8::10"),
        ] {
            let relay = RelayConfig::from(url.parse::<RelayUrl>().unwrap());
            assert_eq!(relay_tls_server_name(&relay).as_deref(), Some(expected));
        }
    }

    #[tokio::test]
    async fn qad_probe_accepts_ipv6_literal_relay_url() {
        use std::net::Ipv6Addr;

        use iroh_relay::{RelayQuicConfig, server};

        match std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipping IPv6 QAD probe: IPv6 loopback is unavailable ({err})");
                return;
            }
            Err(err) => panic!("failed to bind IPv6 loopback: {err}"),
        }

        let (certs, server_crypto) = server::testing::self_signed_tls_certs_and_config();
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots.add(cert).unwrap();
        }
        let client_crypto = rustls::ClientConfig::builder_with_provider(default_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut config = server::testing::server_config();
        config.relay = None;
        let quic = config.quic.as_mut().unwrap();
        // Dual-stack sockets cannot bind to ::1 on Windows.
        quic.bind_addr = (Ipv6Addr::UNSPECIFIED, 0).into();
        quic.server_config = Some(server_crypto);
        let server = server::Server::spawn(config).await.unwrap();
        let server_addr =
            SocketAddr::from((Ipv6Addr::LOCALHOST, server.quic_addr().unwrap().port()));
        let ep = noq::Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into()).unwrap();
        let client_addr = SocketAddr::from((Ipv6Addr::LOCALHOST, ep.local_addr().unwrap().port()));
        let client = QuicClient::new(ep.clone(), client_crypto);
        let https_port = if server_addr.port() == 443 { 8443 } else { 443 };
        let relay = RelayConfig::new(
            format!("https://[::1]:{https_port}").parse().unwrap(),
            Some(RelayQuicConfig::new(server_addr.port())),
        );

        let result = time::timeout(Duration::from_secs(5), async {
            // Verify the same server accepts the bare IPv6 address.
            let control = client
                .create_conn(server_addr, "::1")
                .await
                .map_err(|err| format!("control connection failed: {err:#}"))?;
            let observed = control
                .observed_external_addr()
                .next()
                .await
                .ok_or_else(|| "control connection returned no address".to_owned())?;
            control.close(0u32.into(), b"control complete");

            let (report, conn) =
                super::run_probe(AddrFamily::V6, Arc::new(relay), client, DnsResolver::new())
                    .await
                    .map_err(|err| format!("IPv6 literal QAD probe failed: {err:#}"))?;
            Ok::<_, String>((observed, report, conn))
        })
        .await;

        ep.close(0u32.into(), b"test complete");
        let (_, server_result) = time::timeout(Duration::from_secs(5), async {
            tokio::join!(ep.wait_idle(), server.shutdown())
        })
        .await
        .expect("QAD test cleanup timed out");
        server_result.unwrap();

        let (observed, report, _conn) = result
            .expect("IPv6 QAD probe timed out")
            .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(observed, client_addr);
        assert_eq!(report.addr, client_addr);
    }
}
