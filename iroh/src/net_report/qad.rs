//! QUIC address discovery (QAD) probes for net_report.

#[cfg(not(wasm_browser))]
use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

#[cfg(not(wasm_browser))]
use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_dns::dns::{DnsError, DnsResolver, StaggeredError};
#[cfg(not(wasm_browser))]
use iroh_relay::{
    RelayConfig,
    defaults::DEFAULT_RELAY_QUIC_PORT,
    quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON, QuicClient},
};
#[cfg(not(wasm_browser))]
use n0_error::e;
use n0_error::stack_error;
#[cfg(not(wasm_browser))]
use n0_future::{
    StreamExt as _,
    task::{self, AbortOnDropHandle},
    time::Duration,
};
#[cfg(not(wasm_browser))]
use n0_watcher::{Watchable, Watcher};
#[cfg(not(wasm_browser))]
use tokio_util::sync::CancellationToken;
#[cfg(not(wasm_browser))]
use tracing::trace;

#[cfg(not(wasm_browser))]
use super::defaults::timeouts::DNS_TIMEOUT;
#[cfg(not(wasm_browser))]
use super::reportgen::ProbeReport;
#[cfg(not(wasm_browser))]
use crate::address_lookup::DNS_STAGGERING_MS;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct QadProbeReport {
    /// The relay that was probed
    pub(super) relay: RelayUrl,
    /// The latency to the relay.
    pub(super) latency: Duration,
    /// The discovered public address.
    pub(super) addr: SocketAddr,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum QuicError {
    #[error("No relay available")]
    NoRelay,
    #[error("URL must have 'host' to use QUIC address discovery probes")]
    InvalidUrl,
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

    pub(super) fn current_v4(&self) -> Option<ProbeReport> {
        if let Some((_, ref conn)) = self.v4
            && let Some(mut r) = conn.observer.get()
        {
            // grab latest rtt

            use noq_proto::PathId;
            if let Some(latency) = conn.conn.rtt(PathId::ZERO) {
                r.latency = latency;
            }
            return Some(ProbeReport::QadIpv4(r));
        }
        None
    }

    pub(super) fn current_v6(&self) -> Option<ProbeReport> {
        if let Some((_, ref conn)) = self.v6
            && let Some(mut r) = conn.observer.get()
        {
            // grab latest rtt

            use noq_proto::PathId;
            if let Some(latency) = conn.conn.rtt(PathId::ZERO) {
                r.latency = latency;
            }
            return Some(ProbeReport::QadIpv6(r));
        }
        None
    }

    pub(super) fn watch_v4(
        &self,
    ) -> impl n0_future::Stream<Item = Option<QadProbeReport>> + Unpin + use<> {
        let watcher = self.v4.as_ref().map(|(_url, conn)| conn.observer.watch());

        if let Some(watcher) = watcher {
            watcher.stream_updates_only().boxed()
        } else {
            n0_future::stream::empty().boxed()
        }
    }

    pub(super) fn watch_v6(
        &self,
    ) -> impl n0_future::Stream<Item = Option<QadProbeReport>> + Unpin + use<> {
        let watcher = self.v6.as_ref().map(|(_url, conn)| conn.observer.watch());
        if let Some(watcher) = watcher {
            watcher.stream_updates_only().boxed()
        } else {
            n0_future::stream::empty().boxed()
        }
    }
}

#[cfg(not(wasm_browser))]
#[derive(Debug)]
pub(super) struct QadConn {
    pub(super) conn: noq::Connection,
    observer: Watchable<Option<QadProbeReport>>,
    _handle: AbortOnDropHandle<Option<()>>,
}

/// Returns the proper port based on the protocol of the probe.
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

#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr_ipv6(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
) -> Result<SocketAddrV6, GetRelayAddrError> {
    let port = get_quic_port(relay).ok_or_else(|| e!(GetRelayAddrError::MissingPort))?;
    relay_lookup_ipv6_staggered(dns_resolver, relay, port).await
}

/// Do a staggared ipv4 DNS lookup based on [`RelayConfig`]
///
/// `port` is combined with the resolved [`std::net::Ipv4Addr`] to return a [`SocketAddr`]
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

/// Do a staggared ipv6 DNS lookup based on [`RelayConfig`]
///
/// `port` is combined with the resolved [`std::net::Ipv6Addr`] to return a [`SocketAddr`]
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

#[cfg(not(wasm_browser))]
pub(super) async fn run_probe_v4(
    relay: Arc<RelayConfig>,
    quic_client: QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
) -> n0_error::Result<(QadProbeReport, QadConn), QadProbeError> {
    use noq_proto::PathId;

    let relay_addr = get_relay_addr_ipv4(&dns_resolver, &relay)
        .await
        .map_err(|source| e!(QadProbeError::GetRelayAddr { source }))?;

    trace!(?relay_addr, "resolved relay server address");
    let host = relay_tls_server_name(&relay).ok_or_else(|| e!(QadProbeError::MissingHost))?;
    let conn = quic_client
        .create_conn(relay_addr.into(), &host)
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
                // if we've sent to an ipv4 address, but received an observed address
                // that is ivp6 then the address is an [IPv4-Mapped IPv6 Addresses](https://doc.rust-lang.org/beta/std/net/struct.Ipv6Addr.html#ipv4-mapped-ipv6-addresses)
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
pub(super) async fn run_probe_v6(
    relay: Arc<RelayConfig>,
    quic_client: QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
) -> n0_error::Result<(QadProbeReport, QadConn), QadProbeError> {
    use noq_proto::PathId;

    let relay_addr = get_relay_addr_ipv6(&dns_resolver, &relay)
        .await
        .map_err(|source| e!(QadProbeError::GetRelayAddr { source }))?;

    trace!(?relay_addr, "resolved relay server address");
    let host = relay_tls_server_name(&relay).ok_or_else(|| e!(QadProbeError::MissingHost))?;
    let conn = quic_client
        .create_conn(relay_addr.into(), &host)
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
                // if we've sent to an ipv4 address, but received an observed address
                // that is ivp6 then the address is an [IPv4-Mapped IPv6 Addresses](https://doc.rust-lang.org/beta/std/net/struct.Ipv6Addr.html#ipv4-mapped-ipv6-addresses)
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
    use std::net::Ipv4Addr;

    use iroh_dns::dns::DnsResolver;
    use iroh_relay::tls::default_provider;
    use n0_error::{Result, StdResultExt};
    use n0_future::time;
    use n0_tracing_test::traced_test;

    use super::{super::test_utils, *};

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
            run_probe_v4(relay, quic_client, dns_resolver, CancellationToken::new())
                .await
                .unwrap();

        assert_eq!(report.addr, client_addr);
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
        let shutdown = CancellationToken::new();
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

            let (report, conn) = run_probe_v6(
                Arc::new(relay),
                client,
                DnsResolver::new(),
                shutdown.clone(),
            )
            .await
            .map_err(|err| format!("IPv6 literal QAD probe failed: {err:#}"))?;
            Ok::<_, String>((observed, report, conn))
        })
        .await;

        shutdown.cancel();
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
