//! Functionality related to lower-level tls-based connection establishment.
//!
//! Primarily to support [`ClientBuilder::connect`].
//!
//! This doesn't work in the browser - thus separated into its own file.

// Based on tailscale/derp/derphttp/derphttp_client.go

use std::{collections::VecDeque, net::IpAddr};

use bytes::Bytes;
use data_encoding::BASE64URL;
use http_body_util::Empty;
use hyper::{Request, upgrade::Parts};
use hyper_util::rt::TokioIo;
use n0_error::e;
use n0_future::{
    FuturesUnordered, MaybeFuture, StreamExt, task,
    time::{self},
};
use rustls::client::Resumption;
use tokio::net::TcpStream;
use tracing::{Instrument, error, info_span};

use super::{
    streams::{MaybeTlsStream, ProxyStream},
    *,
};
use crate::defaults::timeouts::*;

#[derive(Debug, Clone)]
pub(super) struct MaybeTlsStreamBuilder {
    url: Url,
    dns_resolver: DnsResolver,
    proxy_url: Option<Url>,
    prefer_ipv6: bool,
    tls_config: rustls::ClientConfig,
}

impl MaybeTlsStreamBuilder {
    pub(super) fn new(
        url: Url,
        dns_resolver: DnsResolver,
        tls_config: rustls::ClientConfig,
    ) -> Self {
        Self {
            url,
            dns_resolver,
            proxy_url: None,
            prefer_ipv6: false,
            tls_config,
        }
    }

    pub(super) fn proxy_url(mut self, proxy_url: Option<Url>) -> Self {
        self.proxy_url = proxy_url;
        self
    }

    pub(super) fn prefer_ipv6(mut self, prefer: bool) -> Self {
        self.prefer_ipv6 = prefer;
        self
    }

    pub(super) async fn connect(self) -> Result<MaybeTlsStream<ProxyStream>, ConnectError> {
        let mut config = self.tls_config.clone();
        config.resumption = Resumption::default();
        let tls_connector: tokio_rustls::TlsConnector = Arc::new(config).into();

        let tcp_stream = self.dial_url(&tls_connector).await?;

        let local_addr = tcp_stream
            .local_addr()
            .map_err(|_| e!(ConnectError::NoLocalAddr))?;

        debug!(server_addr = ?tcp_stream.peer_addr(), %local_addr, "TCP stream connected");

        if self.use_tls() {
            debug!("Starting TLS handshake");
            let hostname = self
                .tls_servername()
                .ok_or_else(|| e!(ConnectError::InvalidTlsServername))?;

            let hostname = hostname.to_owned();
            let tls_stream = tls_connector
                .connect(hostname, tcp_stream)
                .await
                .map_err(|err| e!(ConnectError::Tls, err))?;
            debug!("tls_connector connect success");
            Ok(MaybeTlsStream::Tls(tls_stream))
        } else {
            debug!("Starting handshake");
            Ok(MaybeTlsStream::Raw(tcp_stream))
        }
    }

    fn use_tls(&self) -> bool {
        // only disable tls if we are explicitly dialing a http url
        #[allow(clippy::match_like_matches_macro)]
        match self.url.scheme() {
            "http" => false,
            "ws" => false,
            _ => true,
        }
    }

    fn tls_servername(&self) -> Option<rustls::pki_types::ServerName<'_>> {
        let host_str = self.url.host_str()?;
        let servername = rustls::pki_types::ServerName::try_from(host_str).ok()?;
        Some(servername)
    }

    async fn dial_url(
        &self,
        tls_connector: &tokio_rustls::TlsConnector,
    ) -> Result<ProxyStream, DialError> {
        if let Some(ref proxy) = self.proxy_url {
            let stream = self.dial_url_proxy(proxy.clone(), tls_connector).await?;
            Ok(ProxyStream::Proxied(stream))
        } else {
            let stream =
                dial_happy_eyeballs(&self.dns_resolver, &self.url, self.prefer_ipv6).await?;
            Ok(ProxyStream::Raw(stream))
        }
    }

    async fn dial_url_proxy(
        &self,
        proxy_url: Url,
        tls_connector: &tokio_rustls::TlsConnector,
    ) -> Result<util::Chain<std::io::Cursor<Bytes>, MaybeTlsStream<tokio::net::TcpStream>>, DialError>
    {
        debug!(%self.url, %proxy_url, "dial url via proxy");

        let tcp_stream = dial_happy_eyeballs(&self.dns_resolver, &proxy_url, self.prefer_ipv6)
            .await
            .map_err(|err| match err {
                DialError::InvalidTargetPort { meta } => DialError::ProxyInvalidTargetPort { meta },
                err => err,
            })?;

        // Setup TLS if necessary
        let io = if proxy_url.scheme() == "http" {
            MaybeTlsStream::Raw(tcp_stream)
        } else {
            let hostname = proxy_url.host_str().ok_or_else(|| {
                e!(DialError::ProxyInvalidUrl {
                    proxy_url: proxy_url.clone()
                })
            })?;
            let hostname =
                rustls::pki_types::ServerName::try_from(hostname.to_string()).map_err(|_| {
                    e!(DialError::ProxyInvalidTlsServername {
                        proxy_hostname: hostname.to_string()
                    })
                })?;
            let tls_stream = tls_connector.connect(hostname, tcp_stream).await?;
            MaybeTlsStream::Tls(tls_stream)
        };
        let io = TokioIo::new(io);

        let target_host = self.url.host_str().ok_or_else(|| {
            e!(DialError::InvalidUrl {
                url: self.url.clone()
            })
        })?;

        let port = url_port(&self.url).ok_or_else(|| e!(DialError::InvalidTargetPort))?;

        // Establish Proxy Tunnel
        let mut req_builder = Request::builder()
            .uri(format!("{target_host}:{port}"))
            .method("CONNECT")
            .header("Host", target_host)
            .header("Proxy-Connection", "Keep-Alive");
        if !proxy_url.username().is_empty() {
            // Passthrough authorization
            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization
            debug!(
                "setting proxy-authorization: username={}",
                proxy_url.username()
            );
            let to_encode = format!(
                "{}:{}",
                proxy_url.username(),
                proxy_url.password().unwrap_or_default()
            );
            let encoded = BASE64URL.encode(to_encode.as_bytes());
            req_builder = req_builder.header("Proxy-Authorization", format!("Basic {encoded}"));
        }
        let req = req_builder
            .body(Empty::<Bytes>::new())
            .expect("fixed config");

        debug!("Sending proxy request: {:?}", req);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|err| e!(DialError::ProxyConnect, err))?;
        task::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                error!("Proxy connection failed: {:?}", err);
            }
        });

        let res = sender
            .send_request(req)
            .await
            .map_err(|err| e!(DialError::ProxyConnect, err))?;
        if !res.status().is_success() {
            return Err(e!(DialError::ProxyConnectInvalidStatus {
                status: res.status()
            }));
        }

        let upgraded = hyper::upgrade::on(res)
            .await
            .map_err(|err| e!(DialError::ProxyConnect, err))?;
        let Parts { io, read_buf, .. } = upgraded
            .downcast::<TokioIo<MaybeTlsStream<tokio::net::TcpStream>>>()
            .expect("only this upgrade used");

        let res = util::chain(std::io::Cursor::new(read_buf), io.into_inner());

        Ok(res)
    }
}

/// Resolves `url` and races TCP connections across the resulting addresses,
/// Happy Eyeballs style (RFC 8305).
///
/// IPv4 and IPv6 addresses stream in as their lookups resolve and are appended
/// to a single queue. The loop dials them one at a time, [`pop_family`] taking
/// the next address interleaved by family, the preferred one (`prefer_ipv6`)
/// first:
///
/// - the first attempt waits a [`RESOLUTION_DELAY`] head start for the preferred
///   family while only the other family has resolved, and starts immediately
///   once the preferred family resolves;
/// - each later attempt starts [`CONNECTION_ATTEMPT_DELAY`] after the previous
///   one, or as soon as an attempt fails (fail fast), whichever comes first;
/// - every attempt is itself capped at [`DIAL_ENDPOINT_TIMEOUT`].
///
/// The first connection to succeed is returned; the rest are dropped, which
/// cancels them.
async fn dial_happy_eyeballs(
    dns_resolver: &DnsResolver,
    url: &Url,
    prefer_ipv6: bool,
) -> Result<TcpStream, DialError> {
    let port = url_port(url).ok_or_else(|| e!(DialError::InvalidTargetPort))?;

    // Stream of DNS results, or `None` once the resolver has finished
    let resolve_stream = dns_resolver.resolve_host_all(url, DNS_TIMEOUT);
    tokio::pin!(resolve_stream);
    let mut resolve_stream = Some(resolve_stream);

    // Addresses resolved but not yet tried, in arrival order.
    let mut queue: VecDeque<IpAddr> = VecDeque::new();
    // Family to dial next, toggled to interleave.
    let mut next_prefer_v6 = prefer_ipv6;
    // In-progress connection attempts.
    let mut dials = FuturesUnordered::new();
    // Whether the first attempt has been scheduled yet.
    let mut started = false;
    // Last error that occurred, returned if no connection attempt succeeded.
    let mut last_err: Option<DialError> = None;
    // Delay after which to start the next connection attempt, or `None` for immediately.
    let next_dial_delay = MaybeFuture::None;
    tokio::pin!(next_dial_delay);

    loop {
        if resolve_stream.is_none() && queue.is_empty() && dials.is_empty() {
            // Nothing left to resolve, attempt, or wait on.
            return Err(last_err.unwrap_or_else(|| e!(DnsError::NoResponse).into()));
        }

        let next_addr = match resolve_stream.as_mut() {
            Some(stream) => MaybeFuture::Some(stream.next()),
            None => MaybeFuture::None,
        };

        tokio::select! {
            biased;
            Some(res) = dials.next(), if !dials.is_empty() => match res {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    last_err = Some(err);
                    // Fail fast: start the next attempt now rather than waiting it out.
                    next_dial_delay.as_mut().set_none();
                }
            },
            () = &mut next_dial_delay => {},
            addr = next_addr => match addr {
                Some(Ok(ip)) => {
                    queue.push_back(ip);
                    if !started {
                        // If no connection attempt has been started, and a non-preferred
                        // address is resolved, delay the connect by `RESOLUTION_DELAY`.
                        // If a preferred address arrives later but before this delay expires,
                        // it will be dialed instead.
                        if prefer_ipv6 == ip.is_ipv6() {
                            next_dial_delay.as_mut().set_none()
                        } else if next_dial_delay.is_none() {
                            next_dial_delay.as_mut().set_future(time::sleep(RESOLUTION_DELAY));
                        }
                    }
                }
                Some(Err(err)) => last_err = Some(err.into()),
                None => {
                    resolve_stream = None;
                    if !started {
                        next_dial_delay.as_mut().set_none()
                    }
                }
            },
        }

        // The delay has elapsed and an address is waiting: dial the next one
        // (interleaved by family) and arm the Connection Attempt Delay before
        // the one after it.
        if next_dial_delay.as_mut().is_none()
            && let Some(ip) = pop_family(&mut queue, &mut next_prefer_v6)
        {
            let addr = SocketAddr::new(ip, port);
            dials.push(
                async move {
                    trace!("connecting TCP stream");
                    let stream = time::timeout(DIAL_ENDPOINT_TIMEOUT, TcpStream::connect(addr))
                        .await
                        .map_err(DialError::from)
                        .and_then(|res| res.map_err(DialError::from))
                        .inspect_err(|err| debug!("failed to connect: {err:#}"))?;
                    trace!("TCP stream connected");
                    stream.set_nodelay(true)?;
                    Ok(stream)
                }
                .instrument(info_span!("connect", %addr)),
            );
            started = true;
            next_dial_delay
                .as_mut()
                .set_future(time::sleep(CONNECTION_ATTEMPT_DELAY));
        }
    }
}

/// Removes the next address to attempt, preferring `*next_is_v6`'s family and
/// flipping it so families interleave; falls back to whatever is available.
fn pop_family(addrs: &mut VecDeque<IpAddr>, next_is_v6: &mut bool) -> Option<IpAddr> {
    let idx = addrs
        .iter()
        .position(|ip| ip.is_ipv6() == *next_is_v6)
        .unwrap_or(0);
    let addr = addrs.remove(idx)?;
    *next_is_v6 = !*next_is_v6;
    Some(addr)
}

fn url_port(url: &Url) -> Option<u16> {
    if let Some(port) = url.port() {
        return Some(port);
    }

    match url.scheme() {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use iroh_dns::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};
    use n0_future::boxed::BoxFuture;
    use tokio::net::TcpListener;

    use super::*;

    /// Resolver that hands out fixed IPv4 and IPv6 addresses for every host.
    #[derive(Debug, Clone)]
    struct StaticResolver {
        v4: Vec<Ipv4Addr>,
        v6: Vec<Ipv6Addr>,
    }

    impl Resolver for StaticResolver {
        fn lookup_ipv4(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
            let addrs: BoxIter<_> = Box::new(self.v4.clone().into_iter());
            Box::pin(std::future::ready(Ok(addrs)))
        }

        fn lookup_ipv6(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
            let addrs: BoxIter<_> = Box::new(self.v6.clone().into_iter());
            Box::pin(std::future::ready(Ok(addrs)))
        }

        fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
            let records: BoxIter<_> = Box::new(std::iter::empty());
            Box::pin(std::future::ready(Ok(records)))
        }

        fn clear_cache(&self) {}

        fn reset(&self) -> Box<dyn Resolver> {
            Box::new(self.clone())
        }
    }

    fn resolver(v4: Vec<Ipv4Addr>, v6: Vec<Ipv6Addr>) -> DnsResolver {
        DnsResolver::custom(StaticResolver { v4, v6 })
    }

    fn relay_url(port: u16) -> Url {
        format!("http://relay.test:{port}")
            .parse()
            .expect("valid url")
    }

    /// An unreachable IPv4 address (RFC 5737 TEST-NET-1): a connection attempt to
    /// it never succeeds, modelling a stale or dead record.
    fn dead_v4(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, n)
    }

    /// An unreachable IPv6 address (RFC 3849 documentation prefix).
    fn dead_v6(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)
    }

    /// Runs the dialer against `relay.test` on `port`. An attempt to an
    /// unreachable address is capped by [`DIAL_ENDPOINT_TIMEOUT`] internally, so
    /// the dialer always makes progress; the outer timeout only guards against a
    /// true hang.
    async fn dial(
        resolver: &DnsResolver,
        port: u16,
        prefer_ipv6: bool,
    ) -> Result<TcpStream, DialError> {
        time::timeout(
            time::Duration::from_secs(10),
            dial_happy_eyeballs(resolver, &relay_url(port), prefer_ipv6),
        )
        .await
        .expect("dialer finishes in time")
    }

    #[tokio::test]
    async fn connects_to_the_resolved_address() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let stream = dial(&resolver(vec![Ipv4Addr::LOCALHOST], vec![]), port, false)
            .await
            .expect("connects to the listener");
        assert_eq!(
            stream.peer_addr().unwrap(),
            (Ipv4Addr::LOCALHOST, port).into()
        );
    }

    #[tokio::test]
    async fn tries_addresses_until_one_connects() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Vary the number of unreachable addresses preceding the reachable one:
        // the dialer should skip the dead ones and still connect.
        for dead in [0u8, 1, 3] {
            let v4 = (1..=dead)
                .map(dead_v4)
                .chain([Ipv4Addr::LOCALHOST])
                .collect();
            let stream = dial(&resolver(v4, vec![]), port, false)
                .await
                .unwrap_or_else(|err| panic!("connects with {dead} dead addresses: {err:#}"));
            assert_eq!(stream.peer_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
        }
    }

    #[tokio::test]
    async fn falls_back_from_unreachable_preferred_family() {
        // IPv6 is preferred but every IPv6 address is unreachable; the dialer must
        // interleave across families and fall back to the reachable IPv4 address.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let resolver = resolver(vec![Ipv4Addr::LOCALHOST], vec![dead_v6(1), dead_v6(2)]);

        let stream = dial(&resolver, port, true)
            .await
            .expect("falls back to IPv4");
        assert!(stream.peer_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn errors_when_all_addresses_unreachable() {
        let resolver = resolver(vec![dead_v4(1), dead_v4(2)], vec![dead_v6(1)]);
        let err = dial(&resolver, 8080, true)
            .await
            .expect_err("nothing reachable");
        assert!(matches!(
            err,
            DialError::Io { .. } | DialError::Timeout { .. }
        ));
    }

    #[tokio::test]
    async fn errors_when_nothing_resolves() {
        let err = dial_happy_eyeballs(&resolver(vec![], vec![]), &relay_url(80), false)
            .await
            .expect_err("no addresses to dial");
        assert!(matches!(err, DialError::Dns { .. }));
    }
}
