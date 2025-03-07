//! Functionality related to lower-level tls-based connection establishment.
//!
//! Primarily to support [`ClientBuilder::connect_relay`].
//!
//! This doesn't work in the browser - thus separated into its own file.
//!
//! `connect_relay` uses a custom HTTP upgrade header value (see [`HTTP_UPGRADE_PROTOCOL`]),
//! as opposed to [`WEBSOCKET_UPGRADE_PROTOCOL`].
//!
//! `connect_ws` however reuses websockets for framing.
//!
//! [`HTTP_UPGRADE_PROTOCOL`]: crate::http::HTTP_UPGRADE_PROTOCOL
//! [`WEBSOCKET_UPGRADE_PROTOCOL`]: crate::http::WEBSOCKET_UPGRADE_PROTOCOL

// Based on tailscale/derp/derphttp/derphttp_client.go

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
use n0_future::{task, time};
use rustls::client::Resumption;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, info_span, Instrument};

use super::{
    streams::{downcast_upgrade, MaybeTlsStream, ProxyStream},
    *,
};
use crate::defaults::timeouts::*;

#[derive(Debug, Clone)]
pub struct MaybeTlsStreamBuilder {
    url: Url,
    dns_resolver: DnsResolver,
    proxy_url: Option<Url>,
    prefer_ipv6: bool,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_cert_verify: bool,
}

impl MaybeTlsStreamBuilder {
    pub fn new(url: Url, dns_resolver: DnsResolver) -> Self {
        Self {
            url,
            dns_resolver,
            proxy_url: None,
            prefer_ipv6: false,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_cert_verify: false,
        }
    }

    pub fn proxy_url(mut self, proxy_url: Option<Url>) -> Self {
        self.proxy_url = proxy_url;
        self
    }

    pub fn prefer_ipv6(mut self, prefer: bool) -> Self {
        self.prefer_ipv6 = prefer;
        self
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn insecure_skip_cert_verify(mut self, skip: bool) -> Self {
        self.insecure_skip_cert_verify = skip;
        self
    }

    pub async fn connect(self) -> Result<MaybeTlsStream<ProxyStream>> {
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

        let tcp_stream = self.dial_url(&tls_connector).await?;

        let local_addr = tcp_stream
            .local_addr()
            .context("No local addr for TCP stream")?;

        debug!(server_addr = ?tcp_stream.peer_addr(), %local_addr, "TCP stream connected");

        if self.use_tls() {
            debug!("Starting TLS handshake");
            let hostname = self
                .tls_servername()
                .ok_or_else(|| anyhow!("No tls servername"))?;
            let hostname = hostname.to_owned();
            let tls_stream = tls_connector.connect(hostname, tcp_stream).await?;
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
        let dst_ip = self
            .dns_resolver
            .resolve_host(&self.url, self.prefer_ipv6, DNS_TIMEOUT)
            .await?;

        let port = url_port(&self.url).ok_or_else(|| anyhow!("Missing URL port"))?;
        let addr = SocketAddr::new(dst_ip, port);

        debug!("connecting to {}", addr);
        let tcp_stream = time::timeout(
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
    ) -> Result<util::Chain<std::io::Cursor<Bytes>, MaybeTlsStream<tokio::net::TcpStream>>> {
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpStream;
        debug!(%self.url, %proxy_url, "dial url via proxy");

        // Resolve proxy DNS
        let proxy_ip = self
            .dns_resolver
            .resolve_host(&proxy_url, self.prefer_ipv6, DNS_TIMEOUT)
            .await?;

        let proxy_port = url_port(&proxy_url).ok_or_else(|| anyhow!("Missing proxy url port"))?;
        let proxy_addr = SocketAddr::new(proxy_ip, proxy_port);

        debug!(%proxy_addr, "connecting to proxy");

        let tcp_stream = time::timeout(DIAL_NODE_TIMEOUT, async move {
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
        task::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                error!("Proxy connection failed: {:?}", err);
            }
        });

        let res = sender.send_request(req).await?;
        if !res.status().is_success() {
            bail!("Failed to connect to proxy: {}", res.status());
        }

        let upgraded = hyper::upgrade::on(res).await?;
        let Ok(Parts { io, read_buf, .. }) =
            upgraded.downcast::<TokioIo<MaybeTlsStream<tokio::net::TcpStream>>>()
        else {
            bail!("Invalid upgrade");
        };

        let res = util::chain(std::io::Cursor::new(read_buf), io.into_inner());

        Ok(res)
    }
}

impl ClientBuilder {
    /// Connects to configured relay using HTTP(S) with an upgrade header
    /// set to [`HTTP_UPGRADE_PROTOCOL`].
    ///
    /// [`HTTP_UPGRADE_PROTOCOL`]: crate::http::HTTP_UPGRADE_PROTOCOL
    pub(super) async fn connect_relay(&self) -> Result<(Conn, SocketAddr)> {
        #[allow(unused_mut)]
        let mut builder =
            MaybeTlsStreamBuilder::new(self.url.clone().into(), self.dns_resolver.clone())
                .prefer_ipv6(self.prefer_ipv6())
                .proxy_url(self.proxy_url.clone());

        #[cfg(any(test, feature = "test-utils"))]
        if self.insecure_skip_cert_verify {
            builder = builder.insecure_skip_cert_verify(self.insecure_skip_cert_verify);
        }

        let stream = builder.connect().await?;
        let local_addr = stream.as_ref().local_addr()?;
        let response = self.http_upgrade_relay(stream).await?;

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

    pub(super) async fn connect_ws(&self) -> Result<(Conn, SocketAddr)> {
        let mut dial_url = (*self.url).clone();
        dial_url.set_path(RELAY_PATH);
        // The relay URL is exchanged with the http(s) scheme in tickets and similar.
        // We need to use the ws:// or wss:// schemes when connecting with websockets, though.
        dial_url
            .set_scheme(match self.url.scheme() {
                "http" => "ws",
                "ws" => "ws",
                _ => "wss",
            })
            .map_err(|()| anyhow!("Invalid URL"))?;

        debug!(%dial_url, "Dialing relay by websocket");

        #[allow(unused_mut)]
        let mut builder = MaybeTlsStreamBuilder::new(dial_url.clone(), self.dns_resolver.clone())
            .prefer_ipv6(self.prefer_ipv6())
            .proxy_url(self.proxy_url.clone());

        #[cfg(any(test, feature = "test-utils"))]
        if self.insecure_skip_cert_verify {
            builder = builder.insecure_skip_cert_verify(self.insecure_skip_cert_verify);
        }

        let stream = builder.connect().await?;
        let local_addr = stream.as_ref().local_addr()?;
        let (conn, response) = tokio_websockets::ClientBuilder::new()
            .uri(dial_url.as_str())?
            .connect_on(stream)
            .await?;

        if response.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
            bail!(
                "Unexpected status code: expected {}, actual: {}",
                hyper::StatusCode::SWITCHING_PROTOCOLS,
                response.status(),
            );
        }

        let conn = Conn::new_ws(conn, self.key_cache.clone(), &self.secret_key).await?;

        Ok((conn, local_addr))
    }

    /// Sends the HTTP upgrade request to the relay server.
    async fn http_upgrade_relay<T>(&self, io: T) -> Result<hyper::Response<Incoming>>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        use hyper_util::rt::TokioIo;
        let host_header_value = host_header_value(self.url.clone())?;

        let io = TokioIo::new(io);
        let (mut request_sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(io)
            .await?;
        task::spawn(
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
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::Result;
    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    fn test_host_header_value() -> Result<()> {
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
