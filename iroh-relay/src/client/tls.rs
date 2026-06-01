//! Functionality related to lower-level tls-based connection establishment.
//!
//! Primarily to support [`ClientBuilder::connect`].
//!
//! This doesn't work in the browser - thus separated into its own file.

// Based on tailscale/derp/derphttp/derphttp_client.go

use bytes::Bytes;
use data_encoding::BASE64URL;
use http_body_util::Empty;
use hyper::{Request, upgrade::Parts};
use hyper_util::rt::TokioIo;
use n0_error::e;
use n0_future::{IterExt, StreamExt, task, time};
use rustls::client::Resumption;
use tokio::net::TcpStream;
use tracing::error;

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
                err @ _ => err,
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

/// Resolves `url` and races a TCP connection across the resolved addresses.
///
/// The host is resolved to all of its addresses in preference order (IPv6 first
/// when `prefer_ipv6`, otherwise IPv4). Each successive dial is started
/// [`DIAL_STAGGER_DELAY`] after the previous one and capped at
/// [`DIAL_ENDPOINT_TIMEOUT`], so a slow or unreachable preferred address
/// does not hold back the rest for the full timeout. The first connection to succeed
/// is returned. The remaining attempts are cancelled.
async fn dial_happy_eyeballs(
    dns_resolver: &DnsResolver,
    url: &Url,
    prefer_ipv6: bool,
) -> Result<TcpStream, DialError> {
    let port = url_port(url).ok_or_else(|| e!(DialError::InvalidTargetPort))?;
    let addrs = dns_resolver
        .resolve_host_all(url, prefer_ipv6, DNS_TIMEOUT)
        .await?;
    let mut dials = addrs
        .into_iter()
        .enumerate()
        .map(|(i, ip)| {
            let addr = SocketAddr::new(ip, port);
            async move {
                time::sleep(DIAL_STAGGER_DELAY * i as u32).await;
                trace!("connecting to {}", addr);
                let tcp_stream = time::timeout(DIAL_ENDPOINT_TIMEOUT, TcpStream::connect(addr))
                    .await
                    .map_err(|err| e!(DialError::Timeout, err))
                    .and_then(|res| res.map_err(|err| e!(DialError::Io, err)))
                    .inspect_err(|err| {
                        debug!(%addr, "failed to connect to relay at {addr}: {err:#}");
                    })?;
                tcp_stream.set_nodelay(true)?;
                Ok(tcp_stream)
            }
        })
        .into_unordered_stream();

    let mut last_err = None;
    while let Some(res) = dials.next().await {
        match res {
            Ok(tcp_stream) => return Ok(tcp_stream),
            Err(err) => last_err = Some(err),
        }
    }

    // If we haven't returned yet, last_err is always set unless `addrs` was empty.
    Err(last_err.unwrap_or_else(|| e!(DnsError::NoResponse).into()))
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
