use std::{
    net::SocketAddr,
    str::FromStr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use clap::{Parser, Subcommand};
use data_encoding::HEXLOWER;
use indicatif::HumanBytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr,
    discovery::{
        dns::DnsDiscovery,
        pkarr::{N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING, PkarrPublisher},
    },
    dns::{DnsResolver, N0_DNS_ENDPOINT_ORIGIN_PROD, N0_DNS_ENDPOINT_ORIGIN_STAGING},
    endpoint::ConnectionError,
};
use n0_future::task::AbortOnDropHandle;
use n0_snafu::{Result, ResultExt};
use n0_watcher::Watcher as _;
use tokio_stream::StreamExt;
use tracing::{info, warn};
use url::Url;

// Transfer ALPN that we are using to communicate over the `Endpoint`
const TRANSFER_ALPN: &[u8] = b"n0/iroh/transfer/example/0";

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
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Provide data.
    Provide {
        #[clap(long, default_value = "100M", value_parser = parse_byte_size)]
        size: u64,
        #[clap(flatten)]
        endpoint_args: EndpointArgs,
    },
    /// Fetch data.
    Fetch {
        remote_id: EndpointId,
        #[clap(long)]
        remote_relay_url: Option<RelayUrl>,
        #[clap(long)]
        remote_direct_address: Vec<SocketAddr>,
        #[clap(flatten)]
        endpoint_args: EndpointArgs,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Provide {
            size,
            endpoint_args,
        } => {
            let endpoint = endpoint_args.bind_endpoint().await?;
            provide(endpoint, size).await?
        }
        Commands::Fetch {
            remote_id,
            remote_relay_url,
            remote_direct_address,
            endpoint_args,
        } => {
            let endpoint = endpoint_args.bind_endpoint().await?;
            let addrs = remote_relay_url
                .into_iter()
                .map(TransportAddr::Relay)
                .chain(remote_direct_address.into_iter().map(TransportAddr::Ip));
            let remote_addr = EndpointAddr::from_parts(remote_id, addrs);
            fetch(endpoint, remote_addr).await?
        }
    }

    Ok(())
}

impl EndpointArgs {
    async fn bind_endpoint(self) -> Result<Endpoint> {
        let mut builder = Endpoint::builder();

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
                snafu::whatever!(
                    "Must have the `test-utils` feature enabled when using the `--env=dev` flag"
                )
            }
        }

        let relay_mode = if self.no_relay {
            RelayMode::Disabled
        } else if !self.relay_url.is_empty() {
            RelayMode::Custom(RelayMap::from_iter(self.relay_url))
        } else {
            self.env.relay_mode()
        };
        builder = builder.relay_mode(relay_mode);

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

        if self.relay_only {
            #[cfg(feature = "test-utils")]
            {
                builder = builder.path_selection(iroh::endpoint::PathSelection::RelayOnly)
            }
            #[cfg(not(feature = "test-utils"))]
            {
                snafu::whatever!(
                    "Must have the `discovery-local-network` enabled when using the `--mdns` flag"
                );
            }
        }

        if let Some(host) = self.dns_server {
            let addr = tokio::net::lookup_host(host)
                .await
                .context("Failed to resolve DNS server address")?
                .next()
                .context("Failed to resolve DNS server address")?;
            builder = builder.dns_resolver(DnsResolver::with_nameserver(addr));
        } else if self.env == Env::Dev {
            let addr = DEV_DNS_SERVER.parse().expect("valid addr");
            builder = builder.dns_resolver(DnsResolver::with_nameserver(addr));
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
                snafu::whatever!(
                    "Must have the `test-utils` feature enabled when using the `--relay-only` flag"
                );
            }
        }

        let endpoint_id = endpoint.id();
        println!("Our endpoint id:\n\t{endpoint_id}");

        if self.relay_only {
            endpoint.online().await;
        } else if !self.no_relay {
            tokio::time::timeout(Duration::from_secs(4), endpoint.online())
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

async fn provide(endpoint: Endpoint, size: u64) -> Result<()> {
    let endpoint_id = endpoint.id();
    let endpoint_addr = endpoint.addr();

    println!("Endpoint id:\n{endpoint_id}");
    println!("Direct addresses:");
    for addr in endpoint_addr.ip_addrs() {
        println!("\t{addr}");
    }
    println!();

    // accept incoming connections, returns a normal QUIC connection
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
        // spawn a task to handle reading and writing off of the connection
        let endpoint_clone = endpoint.clone();
        tokio::spawn(async move {
            let conn = accepting.await.e()?;
            let endpoint_id = conn.remote_id();
            info!(
                "new connection from {endpoint_id} with ALPN {}",
                String::from_utf8_lossy(TRANSFER_ALPN),
            );

            let remote = endpoint_id.fmt_short();
            println!("[{remote}] Connected");

            // Spawn a background task that prints connection type changes. Will be aborted on drop.
            let _guard = watch_conn_type(&endpoint_clone, endpoint_id);

            // accept a bi-directional QUIC connection
            // use the `quinn` APIs to send and recv content
            let (mut send, mut recv) = conn.accept_bi().await.e()?;
            tracing::debug!("accepted bi stream, waiting for data...");
            let message = recv.read_to_end(100).await.e()?;
            let message = String::from_utf8(message).e()?;
            println!("[{remote}] Received: \"{message}\"");

            let start = Instant::now();
            send_data_on_stream(&mut send, size).await?;

            // We sent the last message, so wait for the client to close the connection once
            // it received this message.
            let res = tokio::time::timeout(Duration::from_secs(3), async move {
                let closed = conn.closed().await;
                let remote = endpoint_id.fmt_short();
                if !matches!(closed, ConnectionError::ApplicationClosed(_)) {
                    println!("[{remote}] Endpoint disconnected with an error: {closed:#}");
                }
            })
            .await;
            let duration = start.elapsed();

            println!(
                "[{remote}] Transferred {} in {:.4}s, {}/s",
                HumanBytes(size),
                duration.as_secs_f64(),
                HumanBytes((size as f64 / duration.as_secs_f64()) as u64)
            );
            if res.is_err() {
                println!("[{remote}] Did not disconnect within 3 seconds");
            } else {
                println!("[{remote}] Disconnected");
            }
            Ok::<_, n0_snafu::Error>(())
        });
    }

    // stop with SIGINT (ctrl-c)
    Ok(())
}

async fn fetch(endpoint: Endpoint, remote_addr: EndpointAddr) -> Result<()> {
    let me = endpoint.id().fmt_short();
    let start = Instant::now();
    let remote_id = remote_addr.id;

    // Attempt to connect, over the given ALPN.
    // Returns a Quinn connection.
    let conn = endpoint.connect(remote_addr, TRANSFER_ALPN).await?;
    println!("Connected to {}", remote_id);
    // Spawn a background task that prints connection type changes. Will be aborted on drop.
    let _guard = watch_conn_type(&endpoint, remote_id);

    // Use the Quinn API to send and recv content.
    let (mut send, mut recv) = conn.open_bi().await.e()?;

    let message = format!("{me} is saying hello!");
    send.write_all(message.as_bytes()).await.e()?;
    // Call `finish` to signal no more data will be sent on this stream.
    send.finish().e()?;
    println!("Sent: \"{message}\"");

    let (len, time_to_first_byte, chnk) = drain_stream(&mut recv, false).await?;

    // We received the last message: close all connections and allow for the close
    // message to be sent.
    tokio::time::timeout(Duration::from_secs(3), endpoint.close())
        .await
        .e()?;

    let duration = start.elapsed();
    println!(
        "Received {} in {:.4}s ({}/s, time to first byte {}s, {} chunks)",
        HumanBytes(len as u64),
        duration.as_secs_f64(),
        HumanBytes((len as f64 / duration.as_secs_f64()) as u64),
        time_to_first_byte.as_secs_f64(),
        chnk
    );
    Ok(())
}

async fn drain_stream(
    stream: &mut iroh::endpoint::RecvStream,
    read_unordered: bool,
) -> Result<(usize, Duration, u64)> {
    let mut read = 0;

    let download_start = Instant::now();
    let mut first_byte = true;
    let mut time_to_first_byte = download_start.elapsed();

    let mut num_chunks: u64 = 0;

    if read_unordered {
        while let Some(chunk) = stream.read_chunk(usize::MAX, false).await.e()? {
            if first_byte {
                time_to_first_byte = download_start.elapsed();
                first_byte = false;
            }
            read += chunk.bytes.len();
            num_chunks += 1;
        }
    } else {
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

        while let Some(n) = stream.read_chunks(&mut bufs[..]).await.e()? {
            if first_byte {
                time_to_first_byte = download_start.elapsed();
                first_byte = false;
            }
            read += bufs.iter().take(n).map(|buf| buf.len()).sum::<usize>();
            num_chunks += 1;
        }
    }

    Ok((read, time_to_first_byte, num_chunks))
}

async fn send_data_on_stream(
    stream: &mut iroh::endpoint::SendStream,
    stream_size: u64,
) -> Result<()> {
    const DATA: &[u8] = &[0xAB; 1024 * 1024];
    let bytes_data = Bytes::from_static(DATA);

    let full_chunks = stream_size / (DATA.len() as u64);
    let remaining = (stream_size % (DATA.len() as u64)) as usize;

    for _ in 0..full_chunks {
        stream
            .write_chunk(bytes_data.clone())
            .await
            .context("failed sending data")?;
    }

    if remaining != 0 {
        stream
            .write_chunk(bytes_data.slice(0..remaining))
            .await
            .context("failed sending data")?;
    }

    stream.finish().context("failed finishing stream")?;
    stream
        .stopped()
        .await
        .context("failed to wait for stream to be stopped")?;

    Ok(())
}

fn parse_byte_size(s: &str) -> std::result::Result<u64, parse_size::Error> {
    let cfg = parse_size::Config::new().with_binary();
    cfg.parse_size(s)
}

fn watch_conn_type(endpoint: &Endpoint, endpoint_id: EndpointId) -> AbortOnDropHandle<()> {
    let mut stream = endpoint.conn_type(endpoint_id).unwrap().stream();
    let task = tokio::task::spawn(async move {
        while let Some(conn_type) = stream.next().await {
            println!(
                "[{}] Connection type changed to: {conn_type}",
                endpoint_id.fmt_short()
            );
        }
    });
    AbortOnDropHandle::new(task)
}
