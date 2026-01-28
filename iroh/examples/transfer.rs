//! Transfer data between two endpoints and print various stats and metrics.
//!
//! This example implements a transfer protocol to upload or download data between two iroh endpoints
//! with a time or size limit. After the transfer finishes, statistics about the transfer and the used
//! network paths are printed.
//!
//! It is not the typical "simple" example, yet it may be interesting to read because it uses most of
//! iroh's endpoint builder options. We use it for manual testing before release, and it also runs as
//! part of our CI infrastructure.
//!
//! You can use this example to easily test iroh connectivity between devices. Usage is straightforward:
//!
//! ```sh
//! # Run in release mode and with all features and print available commands and options:
//! cargo run --example transfer --release --all-features -- help
//!
//! # Run a provider endpoint on a device
//! cargo run --example transfer --release --all-features -- provide
//!
//! # And connect to the provider endpoint from another device
//! cargo run --example transfer --release --all-features -- fetch PROVIDER_ENDPOINT_ID
//! ```

use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use chrono::Local;
use clap::{Parser, Subcommand, ValueEnum};
use console::Style;
use data_encoding::HEXLOWER;
use derive_more::{Display, From};
use indicatif::HumanBytes;
#[cfg(feature = "qlog")]
use iroh::endpoint::QuicTransportConfig;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr,
    Watcher,
    address_lookup::{
        dns::DnsAddressLookup,
        pkarr::{N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING, PkarrPublisher},
    },
    dns::{DnsResolver, N0_DNS_ENDPOINT_ORIGIN_PROD, N0_DNS_ENDPOINT_ORIGIN_STAGING},
    endpoint::{
        BindOpts, Connection, ConnectionError, PathId, PathInfoList, RecvStream, SendStream,
        VarInt, WriteError,
    },
};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr, ensure_any};
use n0_future::{stream::StreamExt, task::AbortOnDropHandle};
use netdev::ipnet::{Ipv4Net, Ipv6Net};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize, Serializer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tracing::{Instrument, Span, debug, info, info_span, instrument, warn};
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

/// ALPN of our transport protocol.
const TRANSFER_ALPN: &[u8] = b"n0/iroh/transfer/example/1";

const DEV_RELAY_URL: &str = "http://localhost:3340";
const DEV_PKARR_RELAY_URL: &str = "http://localhost:8080/pkarr";
const DEV_DNS_ORIGIN_DOMAIN: &str = "irohdns.example";
const DEV_DNS_SERVER: &str = "127.0.0.1:5300";

/// Connection error code for a gracefully closed connection.
const GRACEFUL_CLOSE: VarInt = VarInt::from_u32(1);

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
/// --mdns needs the `mdns` feature
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
    /// Output format.
    #[clap(global = true, long, value_enum, default_value_t)]
    output: OutputMode,
    /// Save trace and qlog logs to ./logs/
    #[clap(global = true, long, conflicts_with = "logs-path")]
    logs: bool,
    /// Save trace and qlog logs the specified path
    #[clap(global = true, long, conflicts_with = "logs")]
    logs_path: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, clap::ValueEnum, Serialize)]
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

#[derive(Serialize, Deserialize, ValueEnum, Default, Debug, Clone, Copy)]
enum Mode {
    /// We send data to the remote, measuring our upload speed.
    Upload,
    /// We receive data from the remote, measuring our download speed.
    #[default]
    Download,
    /// We send and receive data in parallel.
    Bidi,
    /// We send a ping every other second.
    Ping,
}

#[derive(Serialize, Deserialize, MaxSize, derive_more::Debug, Clone, Copy)]
enum Length {
    #[debug("Size({})", HumanBytes(*_0))]
    Size(u64),
    #[debug("Duration({_0:?})")]
    Duration(#[serde(with = "duration_micros")] Duration),
}

impl Length {
    fn remaining(&self, start: Instant, size: usize) -> (Duration, usize) {
        match self {
            Length::Duration(limit) => (limit.saturating_sub(start.elapsed()), usize::MAX),
            Length::Size(limit) => (Duration::MAX, (*limit as usize).saturating_sub(size)),
        }
    }
}

#[derive(Debug, Serialize, Clone, Copy)]
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
        let request = postcard::from_bytes(&buf).std_context("failed to decode request")?;
        debug!("received request {request:?}");
        Ok(request)
    }

    async fn write(&self, send: &mut SendStream) -> Result<()> {
        debug!("sending request {self:?}");
        let buf = postcard::to_stdvec(&self).unwrap();
        send.write_u32(buf.len() as u32).await.anyerr()?;
        send.write_all(&buf).await.anyerr()?;
        Ok(())
    }
}

#[derive(Debug, clap::Parser, Serialize)]
#[serde(tag = "kind")]
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
    /// Disable Address Lookup completely.
    #[clap(long, conflicts_with_all = ["pkarr_relay_url", "no_pkarr_publish", "dns_origin_domain", "no_dns_resolve"])]
    no_address_lookup: bool,
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
    /// Enable mDNS Address Lookup.
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

#[derive(Subcommand, Debug, derive_more::Display)]
enum Commands {
    /// Provide data.
    #[display("provide")]
    Provide {
        #[clap(flatten)]
        endpoint_args: EndpointArgs,
    },
    /// Fetch data.
    #[display("fetch")]
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
    let Cli {
        command,
        output,
        logs,
        logs_path,
    } = Cli::parse();

    let output = Output::new(output);

    // Create secret key if not set.
    let secret_key = match std::env::var("IROH_SECRET") {
        Ok(s) => SecretKey::from_str(&s)
            .context("Failed to parse IROH_SECRET environment variable as iroh secret key")?,
        Err(_) => {
            let s = SecretKey::generate(&mut rand::rng());
            output.emit(SecretGenerated {
                secret_key: HEXLOWER.encode(&s.to_bytes()),
            });
            s
        }
    };

    // Determine file logging path and init tracing subscriber.
    let log_dir = {
        let dir = match (logs_path, logs) {
            (Some(path), _) => Some(path),
            (_, true) => Some(PathBuf::from(format!(
                "./logs/transfer-{command}-{}-{}",
                Local::now().format("%y%m%d.%H%M%S"),
                secret_key.public().fmt_short()
            ))),
            _ => None,
        };
        let log_file = if let Some(dir) = dir.as_ref() {
            std::fs::create_dir_all(dir)
                .with_context(|_| format!("failed to create log directory at {}", dir.display()))?;
            Some(dir.join("logs"))
        } else {
            None
        };
        init_tracing(log_file.as_ref());
        dir
    };

    match command {
        Commands::Provide { endpoint_args } => {
            output.emit_if_json(&endpoint_args);
            let endpoint = endpoint_args
                .bind_endpoint(secret_key, output, log_dir.as_ref())
                .await?;
            provide(endpoint, output).await?
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
            output.emit_if_json(&endpoint_args);
            let length = match (size, duration) {
                (Some(size), None) => Length::Size(size),
                (None, Some(duration)) => Length::Duration(Duration::from_secs(duration)),
                (None, None) => Length::Duration(Duration::from_secs(10)),
                (Some(_), Some(_)) => unreachable!("--size and --duration args are conflicting"),
            };
            let endpoint = endpoint_args
                .bind_endpoint(secret_key, output, log_dir.as_ref())
                .await?;
            let addrs = remote_relay_url
                .into_iter()
                .map(TransportAddr::Relay)
                .chain(remote_direct_address.into_iter().map(TransportAddr::Ip));
            let remote_addr = EndpointAddr::from_parts(remote_id, addrs);
            fetch(endpoint, remote_addr, length, mode, output).await?
        }
    }

    if let Some(path) = log_dir {
        output.emit(LogsSaved { path });
    }

    Ok(())
}

impl EndpointArgs {
    async fn bind_endpoint(
        self,
        secret_key: SecretKey,
        output: Output,
        log_dir: Option<&PathBuf>,
    ) -> Result<Endpoint> {
        let relay_mode = if self.no_relay {
            RelayMode::Disabled
        } else if !self.relay_url.is_empty() {
            RelayMode::Custom(RelayMap::from_iter(self.relay_url))
        } else {
            self.env.relay_mode()
        };
        let mut builder = Endpoint::empty_builder(relay_mode);
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

        if !self.no_address_lookup {
            if !self.no_pkarr_publish {
                let url = self
                    .pkarr_relay_url
                    .unwrap_or_else(|| self.env.pkarr_relay_url());
                builder = builder.address_lookup(PkarrPublisher::builder(url));
            }

            if !self.no_dns_resolve {
                let domain = self
                    .dns_origin_domain
                    .unwrap_or_else(|| self.env.dns_origin_domain());
                builder = builder.address_lookup(DnsAddressLookup::builder(domain));
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
            let cfg = match log_dir {
                None => QuicTransportConfig::builder()
                    .qlog_from_env("transfer")
                    .build(),
                Some(path) => QuicTransportConfig::builder()
                    .qlog_from_path(path, "")
                    .build(),
            };
            builder = builder.transport_config(cfg)
        }
        #[cfg(not(feature = "qlog"))]
        let _ = log_dir;

        let endpoint = builder.alpns(vec![TRANSFER_ALPN.to_vec()]).bind().await?;

        if self.mdns {
            #[cfg(feature = "address-lookup-mdns")]
            {
                use iroh::address_lookup::MdnsAddressLookup;

                endpoint
                    .address_lookup()
                    .add(MdnsAddressLookup::builder().build(endpoint.id())?);
            }
            #[cfg(not(feature = "address-lookup-mdns"))]
            {
                n0_error::bail_any!("Must have the `mdns` enabled when using the `--mdns` flag");
            }
        }

        if self.relay_only {
            endpoint.online().await;
        } else if !self.no_relay {
            timeout(Duration::from_secs(3), endpoint.online())
                .await
                .ok();
        }

        let endpoint_addr = endpoint.addr();
        output.emit(EndpointBound {
            endpoint_id: endpoint.id(),
            direct_addresses: endpoint_addr.ip_addrs().copied().collect(),
            relay_url: endpoint_addr.relay_urls().next().cloned(),
        });

        Ok(endpoint)
    }
}

async fn provide(endpoint: Endpoint, output: Output) -> Result<()> {
    for id in 0.. {
        // Accept incoming connections until Ctrl-C is pressed.
        let incoming = tokio::select! {
            Some(incoming) = endpoint.accept() => incoming,
            _ = tokio::signal::ctrl_c() => break,
            else => break
        };
        // Spawn a task for each connection.
        tokio::spawn(
            async move {
                let accepting = match incoming.accept() {
                    Ok(accepting) => accepting,
                    Err(err) => {
                        warn!("incoming connection failed: {err:#}");
                        // we can carry on in these cases:
                        // this can be caused by retransmitted datagrams
                        return;
                    }
                };
                match accepting.await {
                    Ok(conn) => {
                        info!(remote = %conn.remote_id().fmt_short(), "connection accepted");
                        output.emit_with_remote(conn.remote_id(), ConnectionAccepted { id });
                        handle_connection(conn, output).await;
                    }
                    Err(err) => warn!("incoming connection failed during handshake: {err:#}"),
                }
            }
            .instrument(info_span!("accept", id, remote = tracing::field::Empty)),
        );
    }

    close_endpoint_with_timeout(&endpoint, output).await;

    Ok(())
}

async fn handle_connection(conn: Connection, output: Output) {
    let start = Instant::now();
    let remote_id = conn.remote_id();
    let _guard = watch_conn_type(conn.paths(), Some(remote_id), output);
    let stats_task = watch_path_stats(conn.clone());

    // Accept incoming streams in a loop until the connection is closed by the remote.
    let close_reason = loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(err) => break err,
        };
        let conn = conn.clone();
        tokio::spawn(
            async move {
                if let Err(err) = handle_request(&conn, send, recv, output).await {
                    warn!("[{}] Request failed: {err:#}", remote_id.fmt_short());
                }
            }
            .instrument(Span::current()),
        );
    };

    let is_graceful = matches!(
        &close_reason,
        ConnectionError::ApplicationClosed(f) if f.error_code == GRACEFUL_CLOSE
    );
    let error = (!is_graceful).then(|| format!("{close_reason:#}"));
    info!(?error, "connection closed");
    output.emit_with_remote(
        remote_id,
        ConnectionClosed {
            error,
            duration: start.elapsed(),
        },
    );
    let path_stats = stats_task.await.expect("path stats task panicked");
    output.emit_with_remote(remote_id, path_stats);
}

#[instrument("handle", skip_all, fields(id=send.id().index()))]
async fn handle_request(
    conn: &Connection,
    send: SendStream,
    mut recv: RecvStream,
    output: Output,
) -> Result<()> {
    let request = Request::read(&mut recv)
        .await
        .context("failed to read request")?;
    output.emit_with_remote(conn.remote_id(), HandleRequest { request: &request });
    match request {
        Request::Download(length) => {
            let stats = send_data(send, recv, length).await?;
            output.emit_with_remote(conn.remote_id(), UploadComplete { stats });
        }
        Request::Upload => {
            let stats = drain_stream(recv, send, None).await?;
            output.emit_with_remote(conn.remote_id(), DownloadComplete { stats });
        }
    }
    Ok(())
}

async fn fetch(
    endpoint: Endpoint,
    remote_addr: EndpointAddr,
    length: Length,
    mode: Mode,
    output: Output,
) -> Result<()> {
    // Attempt to connect, over the given ALPN. Returns a connection.
    let start = Instant::now();
    let conn = endpoint.connect(remote_addr, TRANSFER_ALPN).await?;
    let remote_id = conn.remote_id();
    output.emit(Connected {
        remote_id,
        duration: start.elapsed(),
    });
    // Spawn a background task that prints connection type changes. Will be aborted on drop.
    let _guard = watch_conn_type(conn.paths(), None, output);
    let stats_task = watch_path_stats(conn.clone());

    output.emit(StartRequest { mode, length });
    // Perform requests depending on the request mode.
    let request_fut = async {
        match mode {
            Mode::Upload => {
                perform_request(&conn, RequestKind::Upload, length, start, output).await?
            }
            Mode::Download => {
                perform_request(&conn, RequestKind::Download, length, start, output).await?
            }
            Mode::Bidi => {
                tokio::try_join!(
                    perform_request(&conn, RequestKind::Download, length, start, output),
                    perform_request(&conn, RequestKind::Upload, length, start, output),
                )?;
            }
            Mode::Ping => {
                let Length::Duration(duration) = length else {
                    n0_error::bail_any!("--mode ping needs --duration to be set")
                };
                while start.elapsed() < duration {
                    perform_request(
                        &conn,
                        RequestKind::Download,
                        Length::Size(1024),
                        start,
                        output,
                    )
                    .await?;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        // We finished our requests. Close the connection with our graceful error code.
        conn.close(GRACEFUL_CLOSE, b"done");
        n0_error::Ok(())
    };

    // Wait for the request to complete, or for the user to interrupt it with Ctrl-C
    let res = tokio::select! {
        res = request_fut => res,
        _ = tokio::signal::ctrl_c() => Err(anyerr!("Cancelled"))
    };

    let error = conn
        .close_reason()
        .filter(|reason| !matches!(reason, ConnectionError::LocallyClosed))
        .map(|reason| format!("{reason:#}"));
    output.emit(ConnectionClosed {
        error,
        duration: start.elapsed(),
    });

    close_endpoint_with_timeout(&endpoint, output).await;
    let path_stats = stats_task.await.expect("path stats task panicked");
    output.emit(path_stats);

    res
}

/// Close the endpoint, with a timeout, and emit emit once done.
async fn close_endpoint_with_timeout(endpoint: &Endpoint, output: Output) {
    let shutdown_start = Instant::now();
    let timed_out = timeout(SHUTDOWN_TIME, endpoint.close()).await.is_err();

    output.emit(EndpointClosed {
        duration: shutdown_start.elapsed(),
        timed_out,
    });
}

#[instrument("request", skip_all, fields(id = tracing::field::Empty))]
async fn perform_request(
    conn: &Connection,
    request_kind: RequestKind,
    length: Length,
    conn_start: Instant,
    output: Output,
) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await.anyerr()?;
    Span::current().record("id", send.id().index());
    match request_kind {
        RequestKind::Download => {
            Request::Download(length).write(&mut send).await?;
            let stats = drain_stream(recv, send, Some(conn_start)).await?;
            output.emit(DownloadComplete { stats });
        }
        RequestKind::Upload => {
            Request::Upload.write(&mut send).await?;
            let stats = send_data(send, recv, length).await?;
            output.emit(UploadComplete { stats });
        }
    }
    Ok(())
}

/// Drain `recv`, and once done finish `send`.
#[instrument("drain_stream", skip_all)]
async fn drain_stream(
    mut recv: RecvStream,
    mut send: SendStream,
    started_at: Option<Instant>,
) -> Result<DownloadStats> {
    debug!("start");
    let start = Instant::now();
    let mut read = 0;
    let mut num_chunks: u64 = 0;
    let mut time_to_first_byte = None;

    // These are 32 buffers, for reading approximately 32kB at once
    let mut bufs: [Bytes; 32] = std::array::from_fn(|_| Bytes::new());

    while let Some(n) = recv.read_chunks(&mut bufs[..]).await.anyerr()? {
        // Update time to first byte if still empty and started_at is set.
        if let (None, Some(started_at)) = (time_to_first_byte, started_at) {
            time_to_first_byte = Some(started_at.elapsed());
        }
        read += bufs.iter().take(n).map(Bytes::len).sum::<usize>();
        num_chunks += 1;
    }

    send.finish().anyerr()?;

    let stats = DownloadStats {
        size: read as u64,
        time_to_first_byte,
        num_chunks,
        duration: start.elapsed(),
    };
    debug!(?stats, "done");
    Ok(stats)
}

/// Send data on `send` for `length`, afterwards wait for `recv` to be closed.
#[instrument("send_data", skip_all)]
async fn send_data(
    mut send: SendStream,
    mut recv: RecvStream,
    length: Length,
) -> Result<UploadStats> {
    debug!(?length, "start");
    const DATA: &[u8] = &[0xAB; 1024 * 1024];
    let data = Bytes::from_static(DATA);

    let start = Instant::now();
    let mut total = 0;
    loop {
        let (remaining_time, remaining_size) = length.remaining(start, total);
        let chunk = if remaining_size == 0 || remaining_time == Duration::ZERO {
            break;
        } else if remaining_size < data.len() {
            data.slice(..remaining_size)
        } else {
            data.clone()
        };
        total += write_chunk_timeout(&mut send, chunk, remaining_time)
            .await
            .std_context("failed to send data")?;
    }

    send.finish().std_context("failed to finish stream")?;

    debug!("sending finished, wait for confirmation");
    recv.read_to_end(0).await.anyerr()?;

    let stats = UploadStats {
        size: total as u64,
        duration: start.elapsed(),
    };
    debug!(?stats, "done");
    Ok(stats)
}

/// Writes as much of [`Bytes`] to a [`SendStream`] as possible within `timeout`.
///
/// Completes once `chunk` is fully written or after `timeout` elapses, whatever comes first.
///
/// Returns the number of bytes written.
async fn write_chunk_timeout(
    send: &mut SendStream,
    chunk: Bytes,
    timeout: Duration,
) -> Result<usize, WriteError> {
    // This follows the pattern of [`SendStream::write_all_chunks`] but with a timeout applied.
    let timeout = tokio::time::sleep(timeout);
    tokio::pin!(timeout);
    let mut bufs = &mut [chunk][..];
    let mut total = 0;
    while !bufs.is_empty() {
        tokio::select! {
            _ = &mut timeout => break,
            res = send.write_chunks(bufs) => {
                let written = res?;
                total += written.bytes;
                bufs = &mut bufs[written.chunks..]
            }
        }
    }
    Ok(total)
}

fn parse_byte_size(s: &str) -> std::result::Result<u64, parse_size::Error> {
    let cfg = parse_size::Config::new().with_binary();
    cfg.parse_size(s)
}

fn watch_conn_type(
    paths_watcher: impl Watcher<Value = PathInfoList> + Send + Unpin + 'static,
    remote_id: Option<EndpointId>,
    output: Output,
) -> AbortOnDropHandle<()> {
    let print = move |path: SelectedPath| {
        let event = ConnectionTypeChanged { path };
        if let Some(remote_id) = remote_id {
            output.emit_with_remote(remote_id, event)
        } else {
            output.emit(event)
        }
    };
    let task = tokio::task::spawn(async move {
        let mut stream = paths_watcher.stream();
        let mut previous = None;
        while let Some(paths) = stream.next().await {
            if let Some(path) = paths.iter().find(|p| p.is_selected()) {
                // We can get path updates without the selected path changing. We don't want to log again in that case.
                if Some(path) == previous.as_ref() {
                    continue;
                }
                print(SelectedPath::Selected {
                    id: path.id(),
                    addr: path.remote_addr().clone(),
                    rtt: path.rtt(),
                });
                previous = Some(path.clone());
            } else if !paths.is_empty() {
                print(SelectedPath::Mixed { count: paths.len() });
                previous = None;
            } else {
                output.emit(SelectedPath::None);
                previous = None;
            }
        }
    });
    AbortOnDropHandle::new(task)
}

fn watch_path_stats(conn: iroh::endpoint::Connection) -> AbortOnDropHandle<PathStats> {
    let task = tokio::spawn(async move {
        let mut watcher = conn.paths();
        let mut latest_stats_by_path = BTreeMap::new();
        while conn.close_reason().is_none() {
            n0_future::future::race(
                async {
                    conn.closed().await;
                },
                async {
                    let _ = watcher.updated().await;
                },
            )
            .await;
            // Insert what could possibly be new path stats.
            for path in watcher.get() {
                let stats = path.stats();
                latest_stats_by_path.insert(path.remote_addr().clone(), (path, stats));
            }
            // Update all stat values, even for paths that are removed by now.
            for (path, stats) in latest_stats_by_path.values_mut() {
                *stats = path.stats();
            }
        }
        let list = latest_stats_by_path
            .into_iter()
            .map(|(addr, (info, stats))| PathData {
                id: info.id(),
                remote_addr: addr,
                rtt: stats.rtt,
                bytes_sent: stats.udp_tx.bytes,
                bytes_recv: stats.udp_tx.bytes,
            })
            .collect();
        PathStats { paths: list }
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

#[derive(ValueEnum, Default, Debug, Clone, Copy)]
enum OutputMode {
    /// Print human-readable text.
    #[default]
    Text,
    /// Print newline-delimited JSON.
    Json,
}

#[derive(Debug, Clone, Copy)]
struct Output {
    mode: OutputMode,
    start: Instant,
}

impl Output {
    fn new(mode: OutputMode) -> Self {
        Self {
            mode,
            start: Instant::now(),
        }
    }

    fn time(&self) -> impl fmt::Display {
        Style::new()
            .dim()
            .italic()
            .apply_to(format!("{:>6.3}s", self.start.elapsed().as_secs_f32()))
    }

    fn emit(&self, event: impl Serialize + fmt::Display) {
        match self.mode {
            OutputMode::Text => println!("{event} {}", self.time()),
            OutputMode::Json => println!("{}", serde_json::to_string(&event).unwrap()),
        }
    }

    fn emit_with_remote(&self, remote: EndpointId, event: impl Serialize + fmt::Display) {
        match self.mode {
            OutputMode::Text => println!(
                "{} {event} {}",
                Style::new()
                    .dim()
                    .apply_to(format!("[{}]", remote.fmt_short())),
                self.time()
            ),
            OutputMode::Json => println!(
                "{}",
                serde_json::to_string(&RemoteEvent::new(remote, event)).unwrap()
            ),
        }
    }

    fn emit_if_json(&self, event: &impl Serialize) {
        if matches!(self.mode, OutputMode::Json) {
            println!("{}", serde_json::to_string(&event).unwrap())
        }
    }
}

#[derive(Serialize, Debug, Clone, Display)]
#[display("Generated a new endpoint secret. To reuse, set\n\tIROH_SECRET={secret_key}")]
#[serde(tag = "kind")]
struct SecretGenerated {
    secret_key: String,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "kind")]
struct EndpointBound {
    endpoint_id: EndpointId,
    direct_addresses: Vec<SocketAddr>,
    relay_url: Option<RelayUrl>,
}

impl fmt::Display for EndpointBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Our endpoint id:\n\t{}", self.endpoint_id)?;
        writeln!(f, "Our direct addresses:")?;
        for addr in &self.direct_addresses {
            writeln!(f, "\t{addr}")?;
        }
        match &self.relay_url {
            Some(url) => write!(f, "Our home relay server:\t{url}")?,
            None => write!(f, "No home relay server found")?,
        }
        Ok(())
    }
}

#[derive(Serialize, Debug, Clone, Display)]
#[serde(tag = "kind")]
#[display("Connection type changed to {path}")]
struct ConnectionTypeChanged {
    #[serde(flatten)]
    path: SelectedPath,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "status")]
enum SelectedPath {
    Mixed {
        count: usize,
    },
    Selected {
        #[serde(skip)]
        id: PathId,
        addr: TransportAddr,
        #[serde(with = "duration_micros")]
        rtt: Duration,
    },
    None,
}

impl fmt::Display for SelectedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Mixed { count } => {
                write!(f, "mixed ({count} paths)")
            }
            Self::Selected { addr, rtt, id } => {
                write!(f, "{addr:?} [id:{id}] (RTT: {})", fmt_duration(*rtt))
            }
            Self::None => {
                write!(f, "none")
            }
        }
    }
}

#[derive(Serialize, Debug, Clone, Display)]
#[serde(tag = "kind")]
#[display("Connected to {remote_id} in {}", fmt_duration(*duration))]
struct Connected {
    remote_id: EndpointId,
    #[serde(with = "duration_micros")]
    duration: Duration,
}

#[derive(Serialize, Debug, Clone, Display)]
#[serde(tag = "kind")]
#[display("Starting {mode:?} request with {length:?}")]
struct StartRequest {
    mode: Mode,
    length: Length,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "kind")]
struct EndpointClosed {
    #[serde(with = "duration_micros")]
    duration: Duration,
    timed_out: bool,
}

impl fmt::Display for EndpointClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let duration = fmt_duration(self.duration);
        match self.timed_out {
            false => write!(f, "Shutdown took {duration}"),
            true => write!(f, "Shutdown timed out after {duration}",),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
struct PathData {
    #[serde(skip)]
    id: PathId,
    remote_addr: TransportAddr,
    #[serde(with = "duration_micros")]
    rtt: Duration,
    bytes_sent: u64,
    bytes_recv: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "kind")]
struct PathStats {
    paths: Vec<PathData>,
}

impl fmt::Display for PathStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Path stats:")?;
        for path in &self.paths {
            write!(
                f,
                "\n\t[{:>2}] {:?}: RTT {}, tx={}, rx={}",
                path.id,
                path.remote_addr,
                fmt_duration(path.rtt),
                path.bytes_sent,
                path.bytes_recv,
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize, Debug, Clone, Display)]
#[serde(tag = "kind")]
#[display("{stats}")]
struct DownloadComplete {
    #[serde(flatten)]
    stats: DownloadStats,
}

#[derive(Serialize, Debug, Clone, Display)]
#[serde(tag = "kind")]
#[display("{stats}")]
struct UploadComplete {
    #[serde(flatten)]
    stats: UploadStats,
}

#[derive(Serialize, Debug, Clone, Copy, Display)]
#[display("Accepted connection (trace id: {id})")]
#[serde(tag = "kind")]
struct ConnectionAccepted {
    id: u64,
}

#[derive(Serialize, Debug, Clone, Display)]
#[serde(tag = "kind")]
#[display("Handling {request:?} request")]
struct HandleRequest<'a> {
    request: &'a Request,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "kind")]
struct ConnectionClosed {
    #[serde(with = "duration_micros")]
    duration: Duration,
    error: Option<String>,
}

impl fmt::Display for ConnectionClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time = format!("(total time: {})", fmt_duration(self.duration));
        match &self.error {
            Some(err) => write!(f, "Connection closed with error: {err} {time}"),
            None => write!(f, "Connection closed {time}",),
        }
    }
}

#[derive(Serialize, Debug, Clone, Display)]
#[display(
    "Downloaded: {:>10} in {:.2}, {:>10}/s ({}{} chunks)",
    HumanBytes(self.size).to_string(),
    fmt_duration(self.duration),
    HumanBytes((self.size as f64 / self.duration.as_secs_f64()) as u64),
    self.time_to_first_byte
        .map(|t| format!("time to first byte {}, ", fmt_duration(t)))
        .unwrap_or_default(),
    self.num_chunks
)]
struct DownloadStats {
    size: u64,
    #[serde(
        serialize_with = "duration_micros_opt",
        skip_serializing_if = "Option::is_none"
    )]
    time_to_first_byte: Option<Duration>,
    num_chunks: u64,
    #[serde(with = "duration_micros")]
    duration: Duration,
}

#[derive(Serialize, Debug, Clone, Display)]
#[display(
    "Uploaded:   {:>10} in {:.2}s, {:>10}/s",
    HumanBytes(self.size).to_string(),
    self.duration.as_secs_f64(),
    HumanBytes((self.size as f64 / self.duration.as_secs_f64()) as u64)
)]
struct UploadStats {
    size: u64,
    #[serde(with = "duration_micros")]
    duration: Duration,
}

#[derive(Serialize, Debug, Clone, Display)]
#[display("Logs saved to {}", path.display())]
struct LogsSaved {
    path: PathBuf,
}

#[derive(Serialize, Debug, Clone, From, Display)]
#[display("[{}] {inner}", remote_id.fmt_short())]
struct RemoteEvent<T: Serialize + fmt::Display> {
    #[serde(flatten)]
    inner: T,
    remote_id: EndpointId,
}

impl<T: Serialize + fmt::Display> RemoteEvent<T> {
    fn new(remote_id: EndpointId, inner: T) -> Self {
        Self { remote_id, inner }
    }
}

fn duration_micros_opt<S: Serializer>(
    value: &Option<Duration>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(d) => serializer.serialize_u64(d.as_micros() as u64),
        None => serializer.serialize_none(),
    }
}

mod duration_micros {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(duration.as_micros() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_micros(millis))
    }
}

pub fn init_tracing(path: Option<impl AsRef<Path>>) {
    use tracing_subscriber::{fmt, registry};
    if let Some(path) = path {
        let file = File::create(path).expect("failed to create trace log file");
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("iroh=trace,transfer=trace"));
        let layer = fmt::layer().with_writer(file).with_filter(filter);
        registry().with(layer).init()
    } else {
        let layer = fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(EnvFilter::from_default_env());
        registry().with(layer).init()
    }
}

fn fmt_duration(d: Duration) -> impl fmt::Display {
    if d > Duration::from_secs(1) {
        format!("{:.2}s", d.as_secs_f32())
    } else if d > Duration::from_millis(1) {
        format!("{}ms", d.as_millis())
    } else {
        format!("{}µs", d.as_micros())
    }
}
