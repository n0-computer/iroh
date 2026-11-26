//! Implementation of a DNS name server for iroh endpoint announces

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use n0_error::{Result, StdResultExt};
use serde::{Deserialize, Serialize};
use simple_dns::RCODE;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, info, warn};

use self::{
    authority::Authority,
    message::{EDNS_UDP_PAYLOAD, PLAIN_UDP_PAYLOAD, Request, Response, parse_request},
};
use crate::{metrics::Metrics, store::ZoneStore};

mod authority;
pub(crate) mod message;

/// Time a TCP connection may stay idle, and the limit for reading or writing one message.
const TCP_TIMEOUT: Duration = Duration::from_millis(1000);
/// Maximum number of concurrently open TCP connections.
const MAX_TCP_CONNECTIONS: usize = 512;
/// Maximum number of UDP queries answered concurrently. Further queries are dropped.
const MAX_UDP_IN_FLIGHT: usize = 1024;
/// Receive buffer size for UDP queries. Larger datagrams are truncated and rejected.
const UDP_RECV_BUFFER: usize = 4096;

/// Configuration for the DNS listener.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DnsConfig {
    /// Port to bind the DNS listener to, for both UDP and TCP.
    pub port: u16,
    /// Address to bind the DNS listener to (defaults to `::`, i.e. IPv6 wildcard which also covers IPv4).
    pub bind_addr: Option<IpAddr>,
    /// SOA record data served for authoritative zones, in zone-file format.
    pub default_soa: String,
    /// Default time-to-live, in seconds, for returned DNS records.
    pub default_ttl: u32,
    /// Origins under which the server publishes pkarr-signed zones.
    ///
    /// For each origin, the server answers queries for any published
    /// `<endpointid>.<origin>` name.
    pub origins: Vec<String>,

    /// Optional `A` record to serve at each origin apex.
    pub rr_a: Option<Ipv4Addr>,
    /// Optional `AAAA` record to serve at each origin apex.
    pub rr_aaaa: Option<Ipv6Addr>,
    /// Optional `NS` record to serve at each origin apex.
    pub rr_ns: Option<String>,
}

impl DnsConfig {
    /// Creates a new [`DnsConfig`] with the given required fields.
    ///
    /// The optional `bind_addr` and apex resource records (`rr_a`, `rr_aaaa`, `rr_ns`)
    /// default to `None`. Assign them after construction to override.
    pub fn new(port: u16, default_soa: String, default_ttl: u32, origins: Vec<String>) -> Self {
        Self {
            port,
            bind_addr: None,
            default_soa,
            default_ttl,
            origins,
            rr_a: None,
            rr_aaaa: None,
            rr_ns: None,
        }
    }
}

/// The transport a DNS request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display)]
pub(crate) enum Protocol {
    #[display("udp")]
    Udp,
    #[display("tcp")]
    Tcp,
    #[display("https")]
    Https,
}

/// A DNS server that serves pkarr signed packets.
#[derive(Debug)]
pub(crate) struct DnsServer {
    local_addr: SocketAddr,
    cancel: CancellationToken,
    /// Per-query and per-connection tasks.
    tasks: TaskTracker,
    /// The UDP receive loop and the TCP accept loop.
    listeners: JoinSet<Result<()>>,
}

impl DnsServer {
    /// Spawn the server.
    pub(crate) async fn spawn(config: DnsConfig, dns_handler: DnsHandler) -> Result<Self> {
        let bind_addr = SocketAddr::new(
            config.bind_addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into()),
            config.port,
        );

        let socket = UdpSocket::bind(bind_addr).await.anyerr()?;
        let local_addr = socket.local_addr().anyerr()?;
        // Bind TCP to the port UDP got, which matters when binding to port 0.
        let tcp = TcpListener::bind(local_addr).await.anyerr()?;
        info!("DNS server listening on {}", local_addr);

        let cancel = CancellationToken::new();
        let tasks = TaskTracker::new();
        let mut listeners = JoinSet::new();
        listeners.spawn(run_udp(
            Arc::new(socket),
            dns_handler.clone(),
            tasks.clone(),
            cancel.clone(),
        ));
        listeners.spawn(run_tcp(tcp, dns_handler, tasks.clone(), cancel.clone()));

        Ok(Self {
            local_addr,
            cancel,
            tasks,
            listeners,
        })
    }

    /// Get the local address of the UDP/TCP socket.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shutdown the server an wait for all tasks to complete.
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        self.cancel.cancel();
        let res = self.join_listeners().await;
        self.tasks.close();
        self.tasks.wait().await;
        res
    }

    /// Wait for all tasks to complete.
    ///
    /// Runs forever unless tasks fail.
    pub(crate) async fn run_until_done(mut self) -> Result<()> {
        let res = self.join_listeners().await;
        self.cancel.cancel();
        self.tasks.close();
        self.tasks.wait().await;
        res
    }

    /// Waits for both listener loops, returning the first error.
    async fn join_listeners(&mut self) -> Result<()> {
        let mut res = Ok(());
        while let Some(joined) = self.listeners.join_next().await {
            let outcome = joined.anyerr().and_then(|r| r);
            if let Err(err) = outcome {
                self.cancel.cancel();
                if res.is_ok() {
                    res = Err(err);
                }
            }
        }
        res
    }
}

async fn run_udp(
    socket: Arc<UdpSocket>,
    handler: DnsHandler,
    tasks: TaskTracker,
    cancel: CancellationToken,
) -> Result<()> {
    let in_flight = Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT));
    let mut buf = vec![0u8; UDP_RECV_BUFFER];
    loop {
        let (len, peer) = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            res = socket.recv_from(&mut buf) => match res {
                Ok(res) => res,
                Err(err) => {
                    // Errors such as ICMP port unreachable are reported on some platforms.
                    debug!("UDP receive failed: {err:#}");
                    continue;
                }
            },
        };
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            debug!(%peer, "dropping UDP query: too many in flight");
            continue;
        };
        let query = buf[..len].to_vec();
        let socket = socket.clone();
        let handler = handler.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if let Some(response) = handler.answer_bytes(&query, Protocol::Udp).await
                && let Err(err) = socket.send_to(&response, peer).await
            {
                debug!(%peer, "UDP send failed: {err:#}");
            }
        });
    }
}

async fn run_tcp(
    listener: TcpListener,
    handler: DnsHandler,
    tasks: TaskTracker,
    cancel: CancellationToken,
) -> Result<()> {
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            res = listener.accept() => match res {
                Ok(res) => res,
                Err(err) => {
                    // Accept fails transiently, e.g. when out of file descriptors.
                    warn!("TCP accept failed: {err:#}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            debug!(%peer, "dropping TCP connection: too many open");
            continue;
        };
        let handler = handler.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = cancel.cancelled() => {}
                res = serve_tcp(stream, &handler) => {
                    if let Err(err) = res {
                        debug!(%peer, "TCP connection closed: {err:#}");
                    }
                }
            }
        });
    }
}

/// Serves length-prefixed DNS messages on a TCP connection (RFC 7766).
///
/// The connection is closed when idle for [`TCP_TIMEOUT`], or when reading or writing a
/// single message takes longer than that.
async fn serve_tcp(mut stream: TcpStream, handler: &DnsHandler) -> Result<()> {
    loop {
        let len = match tokio::time::timeout(TCP_TIMEOUT, stream.read_u16()).await {
            Err(_elapsed) => return Ok(()),
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(res) => res.anyerr()?,
        };
        let mut query = vec![0u8; len as usize];
        tokio::time::timeout(TCP_TIMEOUT, stream.read_exact(&mut query))
            .await
            .anyerr()?
            .anyerr()?;
        let Some(response) = handler.answer_bytes(&query, Protocol::Tcp).await else {
            continue;
        };
        let Ok(response_len) = u16::try_from(response.len()) else {
            warn!("dropping oversized TCP response");
            continue;
        };
        let mut framed = Vec::with_capacity(2 + response.len());
        framed.extend_from_slice(&response_len.to_be_bytes());
        framed.extend_from_slice(&response);
        tokio::time::timeout(TCP_TIMEOUT, stream.write_all(&framed))
            .await
            .anyerr()?
            .anyerr()?;
    }
}

/// State for serving DNS
#[derive(Clone, derive_more::Debug)]
pub(crate) struct DnsHandler {
    authority: Arc<Authority>,
    #[debug("metrics")]
    metrics: Arc<Metrics>,
}

impl DnsHandler {
    /// Create a DNS handler for the configured origins, answering from `zone_store`.
    pub(crate) fn new(
        zone_store: ZoneStore,
        config: &DnsConfig,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        Ok(Self {
            authority: Arc::new(Authority::new(zone_store, config)?),
            metrics,
        })
    }

    /// Answers a wire-format DNS message, returning the encoded response.
    ///
    /// Returns `None` for messages that must not be answered.
    pub(crate) async fn answer_bytes(&self, message: &[u8], protocol: Protocol) -> Option<Vec<u8>> {
        let (response, max_len) = self.answer(message, protocol).await?;
        Some(response.encode(max_len))
    }

    /// Answers a wire-format DNS message.
    ///
    /// Returns `None` for messages that must not be answered, and otherwise the response
    /// along with the maximum length it may be encoded to.
    pub(crate) async fn answer(
        &self,
        message: &[u8],
        protocol: Protocol,
    ) -> Option<(Response, usize)> {
        let query = match parse_request(message) {
            Request::Ignore => return None,
            Request::Reject(response) => {
                self.metrics.dns_requests.inc();
                self.metrics.dns_lookup_error.inc();
                return Some((response, PLAIN_UDP_PAYLOAD as usize));
            }
            Request::Query(query) => query,
        };
        self.metrics.dns_requests.inc();
        match protocol {
            Protocol::Udp => self.metrics.dns_requests_udp.inc(),
            Protocol::Https => self.metrics.dns_requests_https.inc(),
            Protocol::Tcp => 0,
        };
        debug!(%protocol, question=?query.question, "incoming DNS request");

        let max_len = match protocol {
            Protocol::Udp => query
                .edns
                .map(|edns| edns.udp_payload.clamp(PLAIN_UDP_PAYLOAD, EDNS_UDP_PAYLOAD))
                .unwrap_or(PLAIN_UDP_PAYLOAD) as usize,
            Protocol::Tcp | Protocol::Https => u16::MAX as usize,
        };

        let response = match query.edns {
            Some(edns) if edns.version != 0 => query.response(RCODE::BADVERS),
            _ => self.authority.answer(&query).await,
        };
        match response.rcode {
            RCODE::NoError if response.answers.is_empty() => self.metrics.dns_lookup_notfound.inc(),
            RCODE::NoError => self.metrics.dns_lookup_success.inc(),
            RCODE::NameError => self.metrics.dns_lookup_notfound.inc(),
            _ => self.metrics.dns_lookup_error.inc(),
        };
        Some((response, max_len))
    }
}
