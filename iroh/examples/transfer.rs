//! Transfer example: Transfer data between two endpoints and print stats.
//!
//! This example uses most of iroh's endpoint builder options and thus allows for flexible testing of connections
//! with different discovery and transport configuration. Once a connection is established, it uses a simple protocol
//! that transfers data between endpoints in both directions, measuring time and connection stats.
//!
//! The protocol is client-initiated and allows to set either a size or time limit on the transfers.

use std::{
    fmt,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
use data_encoding::HEXLOWER;
use indicatif::HumanBytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr,
    Watcher,
    discovery::{
        dns::DnsDiscovery,
        pkarr::{N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING, PkarrPublisher},
    },
    dns::{DnsResolver, N0_DNS_ENDPOINT_ORIGIN_PROD, N0_DNS_ENDPOINT_ORIGIN_STAGING},
    endpoint::{BindOpts, Connection, ConnectionError, PathInfoList, RecvStream, SendStream},
};
use n0_error::{Result, StackResultExt, StdResultExt, ensure_any};
use n0_future::{IterExt, stream::StreamExt, task::AbortOnDropHandle};
use netdev::ipnet::{Ipv4Net, Ipv6Net};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};
use url::Url;

/// ALPN of our transport protocol.
const TRANSFER_ALPN: &[u8] = b"n0/iroh/transfer/example/1";

const DEV_RELAY_URL: &str = "http://localhost:3340";
const DEV_PKARR_RELAY_URL: &str = "http://localhost:8080/pkarr";
const DEV_DNS_ORIGIN_DOMAIN: &str = "irohdns.example";
const DEV_DNS_SERVER: &str = "127.0.0.1:5300";

/// Transfer data between iroh endpoints.
///
/// This is a useful example to test connection establishment and transfer speed.
///
/// Note that some options are only available with optional features:
///
/// --relay-only needs the `test-utils` feature
///
/// --dev needs the `test-utils` feature
///
/// --mdns needs the `discovery-local-network` feature
///
/// To emit qlog files, enable the `qlog` feature and set the QLOGDIR
/// environment variable to the path where qlog files should be written to.
///
/// To enable all features, run the example with --all-features:
///
/// cargo run --release --example transfer --all-features -- ARGS
#[derive(Parser, Debug)]
#[command(name = "transfer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, clap::ValueEnum)]
enum Env {
    /// Use the production servers hosted by number0.
    Prod,
    /// Use the staging servers hosted by number0.
    #[default]
    Staging,
    /// Use localhost servers.
    ///
    /// To run the DNS server:
    ///     cargo run --bin iroh-dns-server
    /// To run the relay server:
    ///     cargo run --bin iroh-relay --features server -- --dev
    Dev,
}

impl Env {
    fn relay_mode(self) -> RelayMode {
        match self {
            Env::Prod => RelayMode::Default,
            Env::Staging => RelayMode::Staging,
            Env::Dev => RelayMode::Custom(RelayMap::from(
                RelayUrl::from_str(DEV_RELAY_URL).expect("valid url"),
            )),
        }
    }

    fn pkarr_relay_url(self) -> Url {
        match self {
            Env::Prod => N0_DNS_PKARR_RELAY_PROD.parse(),
            Env::Staging => N0_DNS_PKARR_RELAY_STAGING.parse(),
            Env::Dev => DEV_PKARR_RELAY_URL.parse(),
        }
        .expect("valid url")
    }

    fn dns_origin_domain(self) -> String {
        match self {
            Env::Prod => N0_DNS_ENDPOINT_ORIGIN_PROD.to_string(),
            Env::Staging => N0_DNS_ENDPOINT_ORIGIN_STAGING.to_string(),
            Env::Dev => DEV_DNS_ORIGIN_DOMAIN.to_string(),
        }
    }
}

#[derive(ValueEnum, Default, Debug, Clone)]
enum Mode {
    /// We send data to the remote, measuring our upload speed.
    Upload,
    /// We receive data from the remote, measuring our download speed.
    Download,
    /// We both sends and receives data.
    #[default]
    Bidi,
}

#[derive(Serialize, Deserialize, MaxSize, derive_more::Debug, Clone, Copy)]
enum Length {
    #[debug("Size({})", HumanBytes(*_0))]
    Size(u64),
    #[debug("Duration({_0:?})")]
    Duration(Duration),
}

#[derive(Debug)]
enum RequestKind {
    Upload,
    Download,
}

#[derive(Serialize, Deserialize, MaxSize, Debug, Clone)]
enum Request {
    Download(Length),
    Upload,
}

impl Request {
    async fn read(recv: &mut RecvStream) -> Result<Self> {
        let header_len = recv.read_u32().await.anyerr()? as usize;
        ensure_any!(
            header_len <= Self::POSTCARD_MAX_SIZE,
            "received invalid header length"
        );
        let mut buf = vec![0u8; header_len];
        recv.read_exact(&mut buf).await.anyerr()?;
        postcard::from_bytes(&buf).std_context("failed to decode request")
    }

    async fn write(&self, send: &mut SendStream) -> Result<()> {
        let buf = postcard::to_stdvec(&self).unwrap();
        send.write_u32(buf.len() as u32).await.anyerr()?;
        send.write_all(&buf).await.anyerr()?;
        Ok(())
    }
}

#[derive(Debug, clap::Parser)]
struct EndpointArgs {
    /// Set the environment for relay, pkarr, and DNS servers.
    ///
    /// If other options are set, those will override the environment defaults.
    #[clap(short, long, value_enum, default_value_t)]
    env: Env,
    /// Set one or more relay servers to use.
    #[clap(long)]
    relay_url: Vec<RelayUrl>,
    /// Disable relays completely.
    #[clap(long, conflicts_with = "relay_url")]
    no_relay: bool,
    /// Disable discovery completely.
    #[clap(long, conflicts_with_all = ["pkarr_relay_url", "no_pkarr_publish", "dns_origin_domain", "no_dns_resolve"])]
    no_discovery: bool,
    /// If set no direct connections will be established.
    #[clap(long)]
    relay_only: bool,
    /// Use a custom pkarr server.
    #[clap(long)]
    pkarr_relay_url: Option<Url>,
    /// Disable publishing endpoint info to pkarr.
    #[clap(long, conflicts_with = "pkarr_relay_url")]
    no_pkarr_publish: bool,
    /// Use a custom domain when resolving endpoint info via DNS.
    #[clap(long)]
    dns_origin_domain: Option<String>,
    /// Use a custom DNS server for resolving relay and endpoint info domains.
    #[clap(long)]
    dns_server: Option<String>,
    /// Do not resolve endpoint info via DNS.
    #[clap(long)]
    no_dns_resolve: bool,
    #[clap(long)]
    /// Enable mDNS discovery.
    mdns: bool,
    /// Set the default IPv4 bind address.
    #[clap(long)]
    bind_addr_v4: Option<SocketAddrV4>,
    /// Set additional IPv4 bind addresses.
    ///
    /// Syntax is "addr/mask:port", so e.g. "10.0.0.1/16:1234".
    /// The mask is used to define for which destinations this bind address is used.
    #[clap(long)]
    bind_addr_v4_additional: Vec<String>,
    /// Set the default IPv6 bind address.
    #[clap(long)]
    bind_addr_v6: Option<SocketAddrV6>,
    /// Set additional IPv6 bind addresses.
    ///
    /// Syntax is "addr/mask:port", so e.g. "2001:db8::1/16:1234".
    /// The mask is used to define for which destinations this bind address is used.
    #[clap(long)]
    bind_addr_v6_additional: Vec<String>,
    /// Disable all default bind addresses.
    #[clap(long)]
    no_default_bind: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Provide data.
    Provide {
        #[clap(flatten)]
        endpoint_args: EndpointArgs,
    },
    /// Fetch data.
    Fetch {
        /// Endpoint id of the remote to connect to.
        remote_id: EndpointId,
        /// Transfer mode.
        #[clap(long, value_enum, default_value_t)]
        mode: Mode,
        /// Limit the transferred data size.
        #[clap(long, value_parser = parse_byte_size, conflicts_with = "duration")]
        size: Option<u64>,
        /// Limit the duration of the transfer, in seconds.
        ///
        /// [default: 10]
        #[clap(long, conflicts_with = "size")]
        duration: Option<u64>,
        /// Optionally set a relay URL for the remote.
        #[clap(long)]
        remote_relay_url: Option<RelayUrl>,
        /// Optionally set direct addresses for the remote.
        #[clap(long)]
        remote_direct_address: Vec<SocketAddr>,
        #[clap(flatten)]
        endpoint_args: EndpointArgs,
    },
}

/// How long we maximally wait for a clean shutdown
const SHUTDOWN_TIME: Duration = Duration::from_secs(4);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Provide { endpoint_args } => {
            let endpoint = endpoint_args.bind_endpoint().await?;
            provide(endpoint).await?
        }
        Commands::Fetch {
            remote_id,
            remote_relay_url,
            remote_direct_address,
            endpoint_args,
            mode,
            size,
            duration,
        } => {
            let length = match (size, duration) {
                (Some(size), None) => Length::Size(size),
                (None, Some(duration)) => Length::Duration(Duration::from_secs(duration)),
                (None, None) => Length::Duration(Duration::from_secs(10)),
                (Some(_), Some(_)) => unreachable!("--size and --duration args are conflicting"),
            };
            let endpoint = endpoint_args.bind_endpoint().await?;
            let addrs = remote_relay_url
                .into_iter()
                .map(TransportAddr::Relay)
                .chain(remote_direct_address.into_iter().map(TransportAddr::Ip));
            let remote_addr = EndpointAddr::from_parts(remote_id, addrs);
            fetch(endpoint, remote_addr, length, mode).await?
        }
    }

    Ok(())
}

impl EndpointArgs {
    async fn bind_endpoint(self) -> Result<Endpoint> {
        let relay_mode = if self.no_relay {
            RelayMode::Disabled
        } else if !self.relay_url.is_empty() {
            RelayMode::Custom(RelayMap::from_iter(self.relay_url))
        } else {
            self.env.relay_mode()
        };
        let mut builder = Endpoint::empty_builder(relay_mode);

        let secret_key = match std::env::var("IROH_SECRET") {
            Ok(s) => SecretKey::from_str(&s)
                .context("Failed to parse IROH_SECRET environment variable as iroh secret key")?,
            Err(_) => {
                let s = SecretKey::generate(&mut rand::rng());
                println!("Generated a new endpoint secret. To reuse, set");
                println!("\tIROH_SECRET={}", HEXLOWER.encode(&s.to_bytes()));
                s
            }
        };
        builder = builder.secret_key(secret_key);

        if Env::Dev == self.env {
            #[cfg(feature = "test-utils")]
            {
                builder = builder.insecure_skip_relay_cert_verify(true);
            }
            #[cfg(not(feature = "test-utils"))]
            {
                n0_error::bail_any!(
                    "Must have the `test-utils` feature enabled when using the `--env=dev` flag"
                )
            }
        }

        if !self.no_discovery {
            if !self.no_pkarr_publish {
                let url = self
                    .pkarr_relay_url
                    .unwrap_or_else(|| self.env.pkarr_relay_url());
                builder = builder.discovery(PkarrPublisher::builder(url));
            }

            if !self.no_dns_resolve {
                let domain = self
                    .dns_origin_domain
                    .unwrap_or_else(|| self.env.dns_origin_domain());
                builder = builder.discovery(DnsDiscovery::builder(domain));
            }
        }

        if let Some(host) = self.dns_server {
            let addr = tokio::net::lookup_host(host)
                .await
                .std_context("Failed to resolve DNS server address")?
                .next()
                .std_context("Failed to resolve DNS server address")?;
            builder = builder.dns_resolver(DnsResolver::with_nameserver(addr));
        } else if self.env == Env::Dev {
            let addr = DEV_DNS_SERVER.parse().expect("valid addr");
            builder = builder.dns_resolver(DnsResolver::with_nameserver(addr));
        }

        if self.relay_only || self.no_default_bind {
            builder = builder.clear_ip_transports();
        }

        if let Some(addr) = self.bind_addr_v4 {
            builder = builder.bind_addr(addr)?;
        }
        for addr in self.bind_addr_v4_additional {
            let (addr, prefix_len) = parse_ipv4_net(&addr)
                .with_context(|_| format!("invalid bind-addr-v4-additional: {addr}"))?;
            builder = builder
                .bind_addr_with_opts(addr, BindOpts::default().set_prefix_len(prefix_len))?;
        }

        if let Some(addr) = self.bind_addr_v6 {
            builder = builder.bind_addr(addr)?;
        }
        for addr in self.bind_addr_v6_additional {
            let (addr, prefix_len) = parse_ipv6_net(&addr)
                .with_context(|_| format!("invalid bind-addr-v6-additional: {addr}"))?;
            builder = builder
                .bind_addr_with_opts(addr, BindOpts::default().set_prefix_len(prefix_len))?;
        }
        #[cfg(feature = "qlog")]
        {
            let cfg = iroh::endpoint::QuicTransportConfig::builder()
                .qlog_from_env("transfer")
                .build();
            builder = builder.transport_config(cfg)
        }

        let endpoint = builder.alpns(vec![TRANSFER_ALPN.to_vec()]).bind().await?;

        if self.mdns {
            #[cfg(feature = "discovery-local-network")]
            {
                use iroh::discovery::mdns::MdnsDiscovery;

                endpoint
                    .discovery()
                    .add(MdnsDiscovery::builder().build(endpoint.id())?);
            }
            #[cfg(not(feature = "discovery-local-network"))]
            {
                n0_error::bail_any!(
                    "Must have the `discovery-local-network` enabled when using the `--mdns` flag"
                );
            }
        }

        let endpoint_id = endpoint.id();
        println!("Our endpoint id:\n\t{endpoint_id}");

        if self.relay_only {
            endpoint.online().await;
        } else if !self.no_relay {
            tokio::time::timeout(Duration::from_secs(3), endpoint.online())
                .await
                .ok();
        }

        let endpoint_addr = endpoint.addr();

        println!("Our direct addresses:");
        for addr in endpoint_addr.ip_addrs() {
            println!("\t{addr}");
        }

        if let Some(url) = endpoint_addr.relay_urls().next() {
            println!("Our home relay server:\t{url}");
        } else {
            println!("No home relay server found");
        }

        println!();
        Ok(endpoint)
    }
}

async fn provide(endpoint: Endpoint) -> Result<()> {
    // Spawn a task that closes the endpoint upon Ctrl-C.
    // Closing the endpoint will also stop the accept loop and close all open connections,
    // thus terminating all other tasks we spawn.
    tokio::task::spawn({
        let endpoint = endpoint.clone();
        async move {
            tokio::signal::ctrl_c().await.ok();
            println!("Shutting down..");
            endpoint.close().await;
            println!("Endpoint closed");
        }
    });

    // Accept incoming connections and spawn a task fo reach.
    while let Some(incoming) = endpoint.accept().await {
        let accepting = match incoming.accept() {
            Ok(accepting) => accepting,
            Err(err) => {
                warn!("incoming connection failed: {err:#}");
                // we can carry on in these cases:
                // this can be caused by retransmitted datagrams
                continue;
            }
        };
        tokio::spawn(async move {
            match accepting.await {
                Ok(conn) => handle_connection(conn).await,
                Err(err) => warn!("incoming connection failed during handshake: {err:#}"),
            }
        });
    }
    println!("Accept loop finished");

    Ok(())
}

#[tracing::instrument("conn", skip_all, fields(remote=%conn.remote_id().fmt_short()))]
async fn handle_connection(conn: Connection) {
    let endpoint_id = conn.remote_id();
    info!(
        "new connection from {endpoint_id} with ALPN {}",
        String::from_utf8_lossy(TRANSFER_ALPN),
    );
    let remote = endpoint_id.fmt_short();
    println!("[{remote}] Accepted connection");
    let _guard = watch_conn_type(conn.remote_id(), conn.paths());

    // Accept incoming streams in a loop until the connection is closed by the remote.
    let close_reason = loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(err) => break err,
        };
        let conn = conn.clone();
        tokio::task::spawn(async move {
            if let Err(err) = handle_request(&conn, send, recv).await {
                warn!("[{remote}] Request failed: {err:#}");
            }
        });
    };

    if !is_graceful(&close_reason) {
        println!("[{remote}] Remote closed with error: {close_reason:#}");
    } else {
        println!("[{remote}] Disconnected");
    }

    println!("[{remote}] Path stats:");
    for path in conn.paths().get() {
        let stats = path.stats();
        println!(
            "  {:?}: RTT {:?}, tx={}, rx={}",
            path.remote_addr(),
            stats.rtt,
            stats.udp_tx.bytes,
            stats.udp_rx.bytes,
        );
    }
}

async fn handle_request(
    conn: &Connection,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let remote = conn.remote_id().fmt_short();
    let request = Request::read(&mut recv).await?;
    println!("[{remote}] Handling {request:?} request",);
    match request {
        Request::Download(length) => {
            let stats = send_data(&mut send, length).await?;
            println!("[{remote}] {stats}");
        }
        Request::Upload => {
            let stats = drain_stream(recv, None).await?;
            send.finish().anyerr()?;
            println!("[{remote}] {stats}");
        }
    }
    Ok(())
}

async fn fetch(
    endpoint: Endpoint,
    remote_addr: EndpointAddr,
    length: Length,
    mode: Mode,
) -> Result<()> {
    // Attempt to connect, over the given ALPN. Returns a connection.
    let start = Instant::now();
    let conn = endpoint.connect(remote_addr, TRANSFER_ALPN).await?;
    println!(
        "Connected to {} in {}ms",
        conn.remote_id(),
        start.elapsed().as_millis()
    );
    println!("Starting {mode:?} request for {length:?}");
    // Spawn a background task that prints connection type changes. Will be aborted on drop.
    let _guard = watch_conn_type(conn.remote_id(), conn.paths());

    // Perform requests depending on the request mode.
    match mode {
        Mode::Upload => perform_request(&conn, RequestKind::Upload, length, start).await?,
        Mode::Download => perform_request(&conn, RequestKind::Download, length, start).await?,
        Mode::Bidi => {
            [
                perform_request(&conn, RequestKind::Download, length, start),
                perform_request(&conn, RequestKind::Upload, length, start),
            ]
            .try_join_all()
            .await?;
        }
    };

    // We finished our requests. Close the connection.
    conn.close(1u32.into(), b"done");
    // Also close the endpoint, with a timeout.
    let shutdown_start = Instant::now();
    if let Err(_err) = tokio::time::timeout(SHUTDOWN_TIME, endpoint.close()).await {
        warn!(timeout = ?SHUTDOWN_TIME, "Endpoint closing timed out");
        println!("Shutdown timed out");
    } else {
        println!(
            "Shutdown took {:.4}s",
            shutdown_start.elapsed().as_secs_f32()
        );
    }

    println!("Path stats:");
    for path in conn.paths().get() {
        let stats = path.stats();
        println!(
            "  {:?}: RTT {:?}, tx={}, rx={}",
            path.remote_addr(),
            stats.rtt,
            stats.udp_tx.bytes,
            stats.udp_rx.bytes,
        );
    }

    Ok(())
}

async fn perform_request(
    conn: &Connection,
    request_kind: RequestKind,
    length: Length,
    conn_start: Instant,
) -> Result<()> {
    info!("Start request {request_kind:?} with {length:?}");
    let request = match request_kind {
        RequestKind::Upload => Request::Upload,
        RequestKind::Download => Request::Download(length),
    };
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    request.write(&mut send).await?;
    match request_kind {
        RequestKind::Download => {
            info!("downloading {length:?}");
            let stats = drain_stream(recv, Some(conn_start)).await?;
            println!("{stats}");
        }
        RequestKind::Upload => {
            info!("uploading {length:?}");
            let stats = send_data(&mut send, length).await?;
            recv.read_to_end(0).await.anyerr()?;
            println!("{stats}");
        }
    }
    Ok(())
}

async fn drain_stream(mut recv: RecvStream, conn_start: Option<Instant>) -> Result<DownloadStats> {
    let start = Instant::now();
    let mut read = 0;
    let mut num_chunks: u64 = 0;
    let mut time_to_first_byte = None;

    // These are 32 buffers, for reading approximately 32kB at once
    #[rustfmt::skip]
    let mut bufs = [
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
    ];

    while let Some(n) = recv.read_chunks(&mut bufs[..]).await.anyerr()? {
        if let Some(conn_start) = conn_start
            && time_to_first_byte.is_none()
        {
            time_to_first_byte = Some(conn_start.elapsed());
        }
        read += bufs.iter().take(n).map(|buf| buf.len()).sum::<usize>();
        num_chunks += 1;
    }

    Ok(DownloadStats {
        len: read as u64,
        time_to_first_byte,
        num_chunks,
        duration: start.elapsed(),
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DownloadStats {
    len: u64,
    time_to_first_byte: Option<Duration>,
    num_chunks: u64,
    duration: Duration,
}

impl fmt::Display for DownloadStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Downloaded: {:>10} in {:.2}s, {:>10}/s ({}{} chunks)",
            HumanBytes(self.len).to_string(),
            self.duration.as_secs_f64(),
            HumanBytes((self.len as f64 / self.duration.as_secs_f64()) as u64),
            self.time_to_first_byte
                .map(|t| format!("time to first byte {}ms, ", t.as_millis()))
                .unwrap_or_default(),
            self.num_chunks
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UploadStats {
    len: u64,
    duration: Duration,
}

impl fmt::Display for UploadStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Uploaded:   {:>10} in {:.2}s, {:>10}/s",
            HumanBytes(self.len).to_string(),
            self.duration.as_secs_f64(),
            HumanBytes((self.len as f64 / self.duration.as_secs_f64()) as u64)
        )
    }
}

async fn send_data(stream: &mut iroh::endpoint::SendStream, length: Length) -> Result<UploadStats> {
    const DATA: &[u8] = &[0xAB; 1024 * 64];
    let data = Bytes::from_static(DATA);

    let start = Instant::now();
    let mut total = 0;
    loop {
        // If a time limit was set, stop sending data once it is exceeded.
        if let Length::Duration(duration) = length
            && start.elapsed() > duration
        {
            break;
        }
        // If a size limit is set, stop sending once it is exceeded,
        // and make sure that the last block has the correct size.
        let data = match length {
            Length::Duration(_) => data.clone(),
            Length::Size(limit) => match limit.saturating_sub(total) as usize {
                0 => break,
                x if x >= data.len() => data.clone(),
                x => data.slice(0..x),
            },
        };
        let len = data.len();
        stream
            .write_chunk(data)
            .await
            .std_context("failed sending data")?;
        total += len as u64;
    }

    stream.finish().std_context("failed to finish stream")?;
    stream
        .stopped()
        .await
        .std_context("failed to wait for stream to be stopped")?;

    Ok(UploadStats {
        len: total,
        duration: start.elapsed(),
    })
}

fn is_graceful(err: &ConnectionError) -> bool {
    match err {
        ConnectionError::ApplicationClosed(frame) if frame.error_code == 1u32.into() => true,
        _ => false,
    }
}

fn parse_byte_size(s: &str) -> std::result::Result<u64, parse_size::Error> {
    let cfg = parse_size::Config::new().with_binary();
    cfg.parse_size(s)
}

fn watch_conn_type(
    endpoint_id: EndpointId,
    paths_watcher: impl Watcher<Value = PathInfoList> + Send + Unpin + 'static,
) -> AbortOnDropHandle<()> {
    let id = endpoint_id.fmt_short();
    let task = tokio::task::spawn(async move {
        let mut stream = paths_watcher.stream();
        let mut previous = None;
        while let Some(paths) = stream.next().await {
            if let Some(path) = paths.iter().find(|p| p.is_selected()) {
                // We can get path updates without the selected path changing. We don't want to log again in that case.
                if Some(path) == previous.as_ref() {
                    continue;
                }
                println!(
                    "[{id}] Connection type changed to: {:?} (RTT: {:?})",
                    path.remote_addr(),
                    path.rtt()
                );
                previous = Some(path.clone());
            } else if !paths.is_empty() {
                println!(
                    "[{id}] Connection type changed to: mixed ({} paths)",
                    paths.len()
                );
                previous = None;
            } else {
                println!("[{id}] Connection type changed to none (no active transmission paths)",);
                previous = None;
            }
        }
    });
    AbortOnDropHandle::new(task)
}

fn parse_ipv4_net(s: &str) -> Result<(SocketAddrV4, u8)> {
    let (net, port) = s.split_once(":").std_context("missing colon")?;
    let net: Ipv4Net = net.parse().std_context("invalid net")?;
    let port: u16 = port.parse().std_context("invalid port")?;

    Ok((SocketAddrV4::new(net.addr(), port), net.prefix_len()))
}

fn parse_ipv6_net(s: &str) -> Result<(SocketAddrV6, u8)> {
    let (net, port) = s.rsplit_once(":").std_context("missing colon")?;
    let net: Ipv6Net = net.parse().std_context("invalid net")?;
    let port: u16 = port.parse().std_context("invalid port")?;
    Ok((SocketAddrV6::new(net.addr(), port, 0, 0), net.prefix_len()))
}
