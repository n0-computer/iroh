//! A pluggable way to open the TCP connection to a relay server.
//!
//! By default the relay client resolves the relay hostname and connects with an
//! OS TCP socket, optionally through an HTTP CONNECT proxy. A [`RelayDialer`]
//! replaces that step: it gets the relay host and port, and returns any byte
//! stream. TLS and the WebSocket upgrade run on top as usual.
//!
//! This lets the relay connection run through a userspace network stack, such
//! as a VPN tunnel, without the process ever opening an OS socket to the relay.

use std::{fmt, io, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use n0_future::{boxed::BoxFuture, task, time::Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;
use url::Url;

/// A byte stream returned by a [`RelayDialer`].
pub trait DialedStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> DialedStream for T {}

type DialFn =
    dyn Fn(String, u16) -> BoxFuture<io::Result<Box<dyn DialedStream>>> + Send + Sync + 'static;

/// Opens the TCP connection to a relay server.
///
/// The dialer gets the relay's hostname (or IP literal) and port, unresolved.
/// Name resolution is up to the dialer, so a dialer that tunnels the
/// connection can also resolve through the tunnel.
#[derive(Clone)]
pub struct RelayDialer(Arc<DialFn>);

impl fmt::Debug for RelayDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelayDialer").finish_non_exhaustive()
    }
}

impl RelayDialer {
    /// Creates a dialer from an async function of `(host, port)`.
    pub fn new<F, Fut, S>(dial: F) -> Self
    where
        F: Fn(String, u16) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<S>> + Send + 'static,
        S: DialedStream,
    {
        Self(Arc::new(move |host, port| {
            let fut = dial(host, port);
            Box::pin(async move { Ok(Box::new(fut.await?) as Box<dyn DialedStream>) })
        }))
    }

    /// Opens a connection to `host:port`.
    pub async fn dial(&self, host: &str, port: u16) -> io::Result<Box<dyn DialedStream>> {
        (self.0)(host.to_string(), port).await
    }

    /// Dials the host of `url`, wrapping the stream in TLS for `https` URLs.
    pub(crate) async fn dial_url(
        &self,
        url: &Url,
        tls_config: rustls::ClientConfig,
    ) -> io::Result<Box<dyn DialedStream>> {
        let host = url
            .host_str()
            .ok_or_else(|| io::Error::other("url has no host"))?;
        // `Url::host_str` keeps the brackets of IPv6 literals.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = url
            .port_or_known_default()
            .ok_or_else(|| io::Error::other("url has no port"))?;
        let stream = self.dial(host, port).await?;
        match url.scheme() {
            "http" | "ws" => Ok(stream),
            _ => {
                let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(io::Error::other)?;
                let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
                let tls = connector.connect(server_name, stream).await?;
                Ok(Box::new(tls))
            }
        }
    }

    /// Measures the latency of an HTTP(S) `GET` to `url` over this dialer.
    ///
    /// The timer covers the request and response only, not the dial or the TLS
    /// handshake, matching what the reqwest-based relay probe measures on a
    /// warm connection pool as closely as a single request can.
    pub async fn probe_latency(
        &self,
        url: &Url,
        tls_config: rustls::ClientConfig,
    ) -> io::Result<Duration> {
        let stream = self.dial_url(url, tls_config).await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(io::Error::other)?;
        let conn = task::spawn(async move {
            if let Err(err) = conn.await {
                debug!("probe connection ended: {err:#}");
            }
        });
        let host = url.host_str().unwrap_or_default();
        let req = Request::get(url.path())
            .header(hyper::header::HOST, host)
            .body(Empty::<Bytes>::new())
            .map_err(io::Error::other)?;
        let start = Instant::now();
        let res = sender.send_request(req).await.map_err(io::Error::other)?;
        let latency = start.elapsed();
        let status = res.status();
        // Drain the (small) body to be nice to the server.
        let _ = res.into_body().collect().await;
        conn.abort();
        if status.is_success() {
            Ok(latency)
        } else {
            Err(io::Error::other(format!("probe returned {status}")))
        }
    }
}
