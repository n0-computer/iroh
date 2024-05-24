use std::{
    num::ParseIntError,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::Result;
use clap::Parser;
use stats::Stats;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::Semaphore;
use tracing::info;

pub mod iroh;
#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
pub mod quinn;
pub mod s2n;
pub mod stats;

#[derive(Parser, Debug, Clone, Copy)]
#[clap(name = "bulk")]
pub enum Commands {
    Iroh(Opt),
    #[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
    Quinn(Opt),
    S2n(s2n::Opt),
}

#[derive(Parser, Debug, Clone, Copy)]
#[clap(name = "options")]
pub struct Opt {
    /// The total number of clients which should be created
    #[clap(long = "clients", short = 'c', default_value = "1")]
    pub clients: usize,
    /// The total number of streams which should be created
    #[clap(long = "streams", short = 'n', default_value = "1")]
    pub streams: usize,
    /// The amount of concurrent streams which should be used
    #[clap(long = "max_streams", short = 'm', default_value = "1")]
    pub max_streams: usize,
    /// Number of bytes to transmit from server to client
    ///
    /// This can use SI prefixes for sizes. E.g. 1M will transfer 1MiB, 10G
    /// will transfer 10GiB.
    #[clap(long, default_value = "1G", value_parser = parse_byte_size)]
    pub download_size: u64,
    /// Number of bytes to transmit from client to server
    ///
    /// This can use SI prefixes for sizes. E.g. 1M will transfer 1MiB, 10G
    /// will transfer 10GiB.
    #[clap(long, default_value = "0", value_parser = parse_byte_size)]
    pub upload_size: u64,
    /// Show connection stats the at the end of the benchmark
    #[clap(long = "stats")]
    pub stats: bool,
    /// Whether to use the unordered read API
    #[clap(long = "unordered")]
    pub read_unordered: bool,
    /// Starting guess for maximum UDP payload size
    #[clap(long, default_value = "1200")]
    pub initial_mtu: u16,
}

pub enum EndpointSelector {
    Iroh(iroh_net::Endpoint),
    #[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
    Quinn(::quinn::Endpoint),
}

impl EndpointSelector {
    pub async fn close(self) -> Result<()> {
        match self {
            EndpointSelector::Iroh(endpoint) => {
                endpoint.close(0u32.into(), b"").await?;
            }
            #[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
            EndpointSelector::Quinn(endpoint) => {
                endpoint.close(0u32.into(), b"");
            }
        }
        Ok(())
    }
}

pub enum ConnectionSelector {
    Iroh(iroh_net::endpoint::Connection),
    #[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
    Quinn(::quinn::Connection),
}

impl ConnectionSelector {
    pub fn stats(&self) {
        match self {
            ConnectionSelector::Iroh(connection) => {
                println!("{:#?}", connection.stats());
            }
            #[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
            ConnectionSelector::Quinn(connection) => {
                println!("{:#?}", connection.stats());
            }
        }
    }

    pub fn close(&self, error_code: u32, reason: &[u8]) {
        match self {
            ConnectionSelector::Iroh(connection) => {
                connection.close(error_code.into(), reason);
            }
            #[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
            ConnectionSelector::Quinn(connection) => {
                connection.close(error_code.into(), reason);
            }
        }
    }
}

pub fn configure_tracing_subscriber() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
}

pub fn rt() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

fn parse_byte_size(s: &str) -> Result<u64, ParseIntError> {
    let s = s.trim();

    let multiplier = match s.chars().last() {
        Some('T') => 1024 * 1024 * 1024 * 1024,
        Some('G') => 1024 * 1024 * 1024,
        Some('M') => 1024 * 1024,
        Some('k') => 1024,
        _ => 1,
    };

    let s = if multiplier != 1 {
        &s[..s.len() - 1]
    } else {
        s
    };

    let base: u64 = u64::from_str(s)?;

    Ok(base * multiplier)
}

#[derive(Default)]
pub struct ClientStats {
    upload_stats: Stats,
    download_stats: Stats,
    connect_time: std::time::Duration,
}

impl ClientStats {
    pub fn print(&self, client_id: usize) {
        println!();
        println!("Client {client_id} stats:");

        let ct = self.connect_time.as_nanos() as f64 / 1_000_000.0;
        println!("Connect time: {ct}ms");

        if self.upload_stats.total_size != 0 {
            self.upload_stats.print("upload");
        }

        if self.download_stats.total_size != 0 {
            self.download_stats.print("download");
        }
    }
}

/// Take the provided endpoint and run the client benchmark
pub async fn client_handler(
    endpoint: EndpointSelector,
    connection: ConnectionSelector,
    opt: Opt,
) -> Result<ClientStats> {
    let start = Instant::now();

    let connection = Arc::new(connection);

    let mut stats = ClientStats::default();
    let mut first_error = None;

    let sem = Arc::new(Semaphore::new(opt.max_streams));
    let results = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..opt.streams {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let results = results.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            let result = match &*connection {
                ConnectionSelector::Iroh(connection) => {
                    iroh::handle_client_stream(connection, opt.upload_size, opt.read_unordered)
                        .await
                }
                #[cfg(not(any(
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd"
                )))]
                ConnectionSelector::Quinn(connection) => {
                    quinn::handle_client_stream(connection, opt.upload_size, opt.read_unordered)
                        .await
                }
            };
            // handle_client_stream(connection, opt.upload_size, opt.read_unordered).await;
            info!("stream finished: {:?}", result);
            results.lock().unwrap().push(result);
            drop(permit);
        });
    }

    // Wait for remaining streams to finish
    let _ = sem.acquire_many(opt.max_streams as u32).await.unwrap();

    stats.upload_stats.total_duration = start.elapsed();
    stats.download_stats.total_duration = start.elapsed();

    for result in results.lock().unwrap().drain(..) {
        match result {
            Ok((upload_result, download_result)) => {
                stats.upload_stats.stream_finished(upload_result);
                stats.download_stats.stream_finished(download_result);
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    // Explicit close of the connection, since handles can still be around due
    // to `Arc`ing them
    connection.close(0u32, b"Benchmark done");

    endpoint.close().await?;

    if opt.stats {
        println!("\nClient connection stats:\n{:#?}", connection.stats());
    }

    match first_error {
        None => Ok(stats),
        Some(e) => Err(e),
    }
}
