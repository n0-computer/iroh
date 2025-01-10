//! Functionality related to `ClientBuilder::connect_relay`.
//!
//! This is (1) likely to be phased out over time in favor of websockets, and
//! (2) doesn't work in the browser - thus separated into its own file.
//!
//! `connect_relay` uses a custom HTTP upgrade header value (see [`HTTP_UPGRADE_PROTOCOL`]),
//! as opposed to [`WEBSOCKET_UPGRADE_PROTOCOL`].
//! However, this code path also contains support for HTTP(s) proxies, which is
//! why it still remains the default code path as of now.
//!
//! [`HTTP_UPGRADE_PROTOCOL`]: crate::http::HTTP_UPGRADE_PROTOCOL
//! [`WEBSOCKET_UPGRADE_PROTOCOL`]: crate::http::WEBSOCKET_UPGRADE_PROTOCOL

// Based on tailscale/derp/derphttp/derphttp_client.go

use super::streams::{downcast_upgrade, MaybeTlsStream, ProxyStream};
use crate::defaults::timeouts::*;
use anyhow::Context;
use bytes::Bytes;
use data_encoding::BASE64URL;
use http_body_util::Empty;
use hyper::{
    body::Incoming,
    header::{HOST, UPGRADE},
    upgrade::Parts,
    Request,
};
use rustls::client::Resumption;
use std::{future::Future, net::IpAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, info_span, Instrument};

use super::*;

impl ClientBuilder {
    /// Connects to configured relay using HTTP(S) with an upgrade header
    /// set to [`HTTP_UPGRADE_PROTOCOL`].
    ///
    /// [`HTTP_UPGRADE_PROTOCOL`]: crate::http::HTTP_UPGRADE_PROTOCOL
    pub(super) async fn connect_relay(&self) -> Result<(Conn, SocketAddr)> {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut config = rustls::client::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocols supported by ring")
        .with_root_certificates(roots)
        .with_no_client_auth();
        #[cfg(any(test, feature = "test-utils"))]
        if self.insecure_skip_cert_verify {
            warn!("Insecure config: SSL certificates from relay servers not verified");
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertVerifier));
        }
        config.resumption = Resumption::default();
        let tls_connector: tokio_rustls::TlsConnector = Arc::new(config).into();

        let url = self.url.clone();
        let tcp_stream = self.dial_url(&tls_connector).await?;

        let local_addr = tcp_stream
            .local_addr()
            .context("No local addr for TCP stream")?;

        debug!(server_addr = ?tcp_stream.peer_addr(), %local_addr, "TCP stream connected");

        let response = if self.use_tls() {
            debug!("Starting TLS handshake");
            let hostname = self
                .tls_servername()
                .ok_or_else(|| anyhow!("No tls servername"))?;
            let hostname = hostname.to_owned();
            let tls_stream = tls_connector.connect(hostname, tcp_stream).await?;
            debug!("tls_connector connect success");
            Self::start_upgrade(tls_stream, url).await?
        } else {
            debug!("Starting handshake");
            Self::start_upgrade(tcp_stream, url).await?
        };

        if response.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
            bail!(
                "Unexpected status code: expected {}, actual: {}",
                hyper::StatusCode::SWITCHING_PROTOCOLS,
                response.status(),
            );
        }

        debug!("starting upgrade");
        let upgraded = hyper::upgrade::on(response)
            .await
            .context("Upgrade failed")?;

        debug!("connection upgraded");
        let conn = downcast_upgrade(upgraded)?;

        let conn = Conn::new_relay(conn, self.key_cache.clone(), &self.secret_key).await?;

        Ok((conn, local_addr))
    }

    /// Sends the HTTP upgrade request to the relay server.
    async fn start_upgrade<T>(io: T, relay_url: RelayUrl) -> Result<hyper::Response<Incoming>>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        use hyper_util::rt::TokioIo;
        let host_header_value = host_header_value(relay_url)?;

        let io = TokioIo::new(io);
        let (mut request_sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(io)
            .await?;
        tokio::spawn(
            // This task drives the HTTP exchange, completes once connection is upgraded.
            async move {
                debug!("HTTP upgrade driver started");
                if let Err(err) = connection.with_upgrades().await {
                    error!("HTTP upgrade error: {err:#}");
                }
                debug!("HTTP upgrade driver finished");
            }
            .instrument(info_span!("http-driver")),
        );
        debug!("Sending upgrade request");
        let req = Request::builder()
            .uri(RELAY_PATH)
            .header(UPGRADE, Protocol::Relay.upgrade_header())
            // https://datatracker.ietf.org/doc/html/rfc2616#section-14.23
            // > A client MUST include a Host header field in all HTTP/1.1 request messages.
            // This header value helps reverse proxies identify how to forward requests.
            .header(HOST, host_header_value)
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
        request_sender.send_request(req).await.map_err(From::from)
    }

    fn tls_servername(&self) -> Option<rustls::pki_types::ServerName> {
        self.url
            .host_str()
            .and_then(|s| rustls::pki_types::ServerName::try_from(s).ok())
    }

    async fn dial_url(&self, tls_connector: &tokio_rustls::TlsConnector) -> Result<ProxyStream> {
        if let Some(ref proxy) = self.proxy_url {
            let stream = self.dial_url_proxy(proxy.clone(), tls_connector).await?;
            Ok(ProxyStream::Proxied(stream))
        } else {
            let stream = self.dial_url_direct().await?;
            Ok(ProxyStream::Raw(stream))
        }
    }

    async fn dial_url_direct(&self) -> Result<tokio::net::TcpStream> {
        use tokio::net::TcpStream;
        debug!(%self.url, "dial url");
        let prefer_ipv6 = self.prefer_ipv6();
        let dst_ip = self
            .dns_resolver
            .resolve_host(&self.url, prefer_ipv6)
            .await?;

        let port = url_port(&self.url).ok_or_else(|| anyhow!("Missing URL port"))?;
        let addr = SocketAddr::new(dst_ip, port);

        debug!("connecting to {}", addr);
        let tcp_stream =
            tokio::time::timeout(
                DIAL_NODE_TIMEOUT,
                async move { TcpStream::connect(addr).await },
            )
            .await
            .context("Timeout connecting")?
            .context("Failed connecting")?;
        tcp_stream.set_nodelay(true)?;

        Ok(tcp_stream)
    }

    async fn dial_url_proxy(
        &self,
        proxy_url: Url,
        tls_connector: &tokio_rustls::TlsConnector,
    ) -> Result<util::Chain<std::io::Cursor<Bytes>, MaybeTlsStream>> {
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpStream;
        debug!(%self.url, %proxy_url, "dial url via proxy");

        // Resolve proxy DNS
        let prefer_ipv6 = self.prefer_ipv6();
        let proxy_ip = self
            .dns_resolver
            .resolve_host(&proxy_url, prefer_ipv6)
            .await?;

        let proxy_port = url_port(&proxy_url).ok_or_else(|| anyhow!("Missing proxy url port"))?;
        let proxy_addr = SocketAddr::new(proxy_ip, proxy_port);

        debug!(%proxy_addr, "connecting to proxy");

        let tcp_stream = tokio::time::timeout(DIAL_NODE_TIMEOUT, async move {
            TcpStream::connect(proxy_addr).await
        })
        .await
        .context("Timeout connecting")?
        .context("Connecting")?;

        tcp_stream.set_nodelay(true)?;

        // Setup TLS if necessary
        let io = if proxy_url.scheme() == "http" {
            MaybeTlsStream::Raw(tcp_stream)
        } else {
            let hostname = proxy_url.host_str().context("No hostname in proxy URL")?;
            let hostname = rustls::pki_types::ServerName::try_from(hostname.to_string())?;
            let tls_stream = tls_connector.connect(hostname, tcp_stream).await?;
            MaybeTlsStream::Tls(tls_stream)
        };
        let io = TokioIo::new(io);

        let target_host = self
            .url
            .host_str()
            .ok_or_else(|| anyhow!("Missing proxy host"))?;

        let port = url_port(&self.url).ok_or_else(|| anyhow!("invalid target port"))?;

        // Establish Proxy Tunnel
        let mut req_builder = Request::builder()
            .uri(format!("{}:{}", target_host, port))
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
            req_builder = req_builder.header("Proxy-Authorization", format!("Basic {}", encoded));
        }
        let req = req_builder.body(Empty::<Bytes>::new())?;

        debug!("Sending proxy request: {:?}", req);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                error!("Proxy connection failed: {:?}", err);
            }
        });

        let res = sender.send_request(req).await?;
        if !res.status().is_success() {
            bail!("Failed to connect to proxy: {}", res.status());
        }

        let upgraded = hyper::upgrade::on(res).await?;
        let Ok(Parts { io, read_buf, .. }) = upgraded.downcast::<TokioIo<MaybeTlsStream>>() else {
            bail!("Invalid upgrade");
        };

        let res = util::chain(std::io::Cursor::new(read_buf), io.into_inner());

        Ok(res)
    }

    /// Reports whether IPv4 dials should be slightly
    /// delayed to give IPv6 a better chance of winning dial races.
    /// Implementations should only return true if IPv6 is expected
    /// to succeed. (otherwise delaying IPv4 will delay the connection
    /// overall)
    fn prefer_ipv6(&self) -> bool {
        match self.address_family_selector {
            Some(ref selector) => selector(),
            None => false,
        }
    }
}

fn host_header_value(relay_url: RelayUrl) -> Result<String> {
    // grab the host, turns e.g. https://example.com:8080/xyz -> example.com.
    let relay_url_host = relay_url.host_str().context("Invalid URL")?;
    // strip the trailing dot, if present: example.com. -> example.com
    let relay_url_host = relay_url_host.strip_suffix('.').unwrap_or(relay_url_host);
    // build the host header value (reserve up to 6 chars for the ":" and port digits):
    let mut host_header_value = String::with_capacity(relay_url_host.len() + 6);
    host_header_value += relay_url_host;
    if let Some(port) = relay_url.port() {
        host_header_value += ":";
        host_header_value += &port.to_string();
    }
    Ok(host_header_value)
}

fn url_port(url: &Url) -> Option<u16> {
    if let Some(port) = url.port() {
        return Some(port);
    }

    match url.scheme() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

trait DnsExt {
    fn lookup_ipv4<N: hickory_resolver::IntoName>(
        &self,
        host: N,
    ) -> impl Future<Output = Result<Option<IpAddr>>>;

    fn lookup_ipv6<N: hickory_resolver::IntoName>(
        &self,
        host: N,
    ) -> impl Future<Output = Result<Option<IpAddr>>>;

    fn resolve_host(&self, url: &Url, prefer_ipv6: bool) -> impl Future<Output = Result<IpAddr>>;
}

impl DnsExt for DnsResolver {
    async fn lookup_ipv4<N: hickory_resolver::IntoName>(&self, host: N) -> Result<Option<IpAddr>> {
        let addrs = tokio::time::timeout(DNS_TIMEOUT, self.ipv4_lookup(host)).await??;
        Ok(addrs.into_iter().next().map(|ip| IpAddr::V4(ip.0)))
    }

    async fn lookup_ipv6<N: hickory_resolver::IntoName>(&self, host: N) -> Result<Option<IpAddr>> {
        let addrs = tokio::time::timeout(DNS_TIMEOUT, self.ipv6_lookup(host)).await??;
        Ok(addrs.into_iter().next().map(|ip| IpAddr::V6(ip.0)))
    }

    async fn resolve_host(&self, url: &Url, prefer_ipv6: bool) -> Result<IpAddr> {
        let host = url.host().context("Invalid URL")?;
        match host {
            url::Host::Domain(domain) => {
                // Need to do a DNS lookup
                let lookup = tokio::join!(self.lookup_ipv4(domain), self.lookup_ipv6(domain));
                let (v4, v6) = match lookup {
                    (Err(ipv4_err), Err(ipv6_err)) => {
                        bail!("Ipv4: {ipv4_err:?}, Ipv6: {ipv6_err:?}");
                    }
                    (Err(_), Ok(v6)) => (None, v6),
                    (Ok(v4), Err(_)) => (v4, None),
                    (Ok(v4), Ok(v6)) => (v4, v6),
                };
                if prefer_ipv6 { v6.or(v4) } else { v4.or(v6) }.context("No response")
            }
            url::Host::Ipv4(ip) => Ok(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Ok(IpAddr::V6(ip)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::Result;

    use super::*;

    #[test]
    fn test_host_header_value() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let cases = [
            (
                "https://euw1-1.relay.iroh.network.",
                "euw1-1.relay.iroh.network",
            ),
            ("http://localhost:8080", "localhost:8080"),
        ];

        for (url, expected_host) in cases {
            let relay_url = RelayUrl::from_str(url)?;
            let host = host_header_value(relay_url)?;
            assert_eq!(host, expected_host);
        }

        Ok(())
    }
}
