use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::{style, Emoji};
use futures::{Stream, StreamExt};
use indicatif::{
    HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressState,
    ProgressStyle,
};
use iroh::blobs::{Blob, Collection};
use iroh::get::get_response_machine::{ConnectedNext, EndBlobNext};
use iroh::get::{get_data_path, get_missing_range, get_missing_ranges, pathbuf_from_name};
use iroh::protocol::{GetRequest, RangeSpecSeq};
use iroh::provider::{Database, Provider, Ticket};
use iroh::rpc_protocol::*;
use iroh::rpc_protocol::{
    ListRequest, ProvideRequest, ProviderRequest, ProviderResponse, ProviderService, VersionRequest,
};
use quic_rpc::transport::quinn::{QuinnConnection, QuinnServerEndpoint};
use quic_rpc::{RpcClient, ServiceEndpoint};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing_subscriber::{prelude::*, EnvFilter};
mod main_util;
use iroh::tokio_util::{ConcatenateSliceWriter, ProgressSliceWriter, SeekOptimized};

use iroh::provider::FNAME_PATHS;
use iroh::{get, provider, Hash, Keypair, PeerId};
use main_util::Blake3Cid;

use crate::main_util::iroh_data_root;

#[cfg(feature = "metrics")]
use iroh::metrics::init_metrics;

const DEFAULT_RPC_PORT: u16 = 0x1337;
const RPC_ALPN: [u8; 17] = *b"n0/provider-rpc/1";
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;
const MAX_CONCURRENT_DIALS: u8 = 16;

/// Send data.
///
/// The iroh command line tool has two modes: provide and get.
///
/// The provide mode is a long-running process binding to a socket which the get mode
/// contacts to request data.  By default the provide process also binds to an RPC port
/// which allows adding additional data to be provided as well as a few other maintenance
/// commands.
///
/// The get mode retrieves data from the provider, for this it needs the hash, provider
/// address and PeerID as well as an authentication code.  The get-ticket subcommand is a
/// shortcut to provide all this information conveniently in a single ticket.
#[derive(Parser, Debug, Clone)]
#[clap(version)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
    /// Log SSL pre-master key to file in SSLKEYLOGFILE environment variable.
    #[clap(long)]
    keylog: bool,
    /// Bind address on which to serve Prometheus metrics
    #[cfg(feature = "metrics")]
    #[clap(long)]
    metrics_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
enum ProviderRpcPort {
    Enabled(u16),
    Disabled,
}

impl From<ProviderRpcPort> for Option<u16> {
    fn from(value: ProviderRpcPort) -> Self {
        match value {
            ProviderRpcPort::Enabled(port) => Some(port),
            ProviderRpcPort::Disabled => None,
        }
    }
}

impl fmt::Display for ProviderRpcPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderRpcPort::Enabled(port) => write!(f, "{port}"),
            ProviderRpcPort::Disabled => write!(f, "disabled"),
        }
    }
}

impl FromStr for ProviderRpcPort {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "disabled" {
            Ok(ProviderRpcPort::Disabled)
        } else {
            Ok(ProviderRpcPort::Enabled(s.parse()?))
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Serve data from the given path.
    ///
    /// If PATH is a folder all files in that folder will be served.  If no PATH is
    /// specified reads from STDIN.
    Provide {
        /// Path to initial file or directory to provide
        path: Option<PathBuf>,
        #[clap(long, short)]
        /// Listening address to bind to
        #[clap(long, short, default_value_t = SocketAddr::from(provider::DEFAULT_BIND_ADDR))]
        addr: SocketAddr,
        /// RPC port, set to "disabled" to disable RPC
        #[clap(long, default_value_t = ProviderRpcPort::Enabled(DEFAULT_RPC_PORT))]
        rpc_port: ProviderRpcPort,
    },
    /// List hashes on the running provider.
    List {
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Validate hashes on the running provider.
    Validate {
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Shutdown provider.
    Shutdown {
        /// Shutdown mode.
        ///
        /// Hard shutdown will immediately terminate the process, soft shutdown will wait
        /// for all connections to close.
        #[clap(long, default_value_t = false)]
        force: bool,
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Identify the running provider.
    Id {
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Add data from PATH to the running provider's database.
    Add {
        /// The path to the file or folder to add
        path: PathBuf,
        /// RPC port
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Fetch the data identified by HASH from a provider.
    Get {
        /// The hash to retrieve, as a Blake3 CID
        hash: Blake3Cid,
        /// PeerId of the provider
        #[clap(long, short)]
        peer: PeerId,
        /// Address of the provider
        #[clap(long, short, default_value_t = SocketAddr::from(get::DEFAULT_PROVIDER_ADDR))]
        addr: SocketAddr,
        /// Directory in which to save the file(s), defaults to writing to STDOUT
        #[clap(long, short)]
        out: Option<PathBuf>,
        /// True to download a single blob, false (default) to download a collection and its children.
        #[clap(long, default_value_t = false)]
        single: bool,
    },
    /// Fetch data from a provider using a ticket.
    ///
    /// The ticket contains all hash, authentication and connection information to connect
    /// to the provider.  It is a simpler, but slightly less flexible alternative to the
    /// `get` subcommand.
    GetTicket {
        /// Directory in which to save the file(s), defaults to writing to STDOUT
        #[clap(long, short)]
        out: Option<PathBuf>,
        /// Ticket containing everything to retrieve the data from a provider.
        ticket: Ticket,
    },
    /// List listening addresses of the provider.
    Addresses {
        /// RPC port
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
}

// Note about writing to STDOUT vs STDERR
// Looking at https://unix.stackexchange.com/questions/331611/do-progress-reports-logging-information-belong-on-stderr-or-stdout
// it is a little complicated.
// The current setup is to write all progress information to STDERR and all data to STDOUT.
macro_rules! progress {
    // Match a format string followed by any number of arguments
    ($fmt:expr $(, $args:expr)*) => {{
        eprintln!($fmt $(, $args)*);
    }};
}

async fn make_rpc_client(
    rpc_port: u16,
) -> anyhow::Result<RpcClient<ProviderService, QuinnConnection<ProviderResponse, ProviderRequest>>>
{
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
    let endpoint =
        iroh::get::make_client_endpoint(bind_addr, None, vec![RPC_ALPN.to_vec()], false)?;
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), rpc_port);
    let server_name = "localhost".to_string();
    let connection = QuinnConnection::new(endpoint, addr, server_name);
    let client = RpcClient::<ProviderService, _>::new(connection);
    // Do a version request to check if the server is running.
    let _version = tokio::time::timeout(Duration::from_secs(1), client.rpc(VersionRequest))
        .await
        .context("iroh server is not running")??;
    Ok(client)
}

struct ProvideProgressState {
    mp: MultiProgress,
    pbs: HashMap<u64, ProgressBar>,
}

impl ProvideProgressState {
    fn new() -> Self {
        Self {
            mp: MultiProgress::new(),
            pbs: HashMap::new(),
        }
    }

    fn found(&mut self, name: String, id: u64, size: u64) {
        let pb = self.mp.add(ProgressBar::new(size));
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {msg} {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})").unwrap()
            .progress_chars("=>-"));
        pb.set_message(name);
        pb.set_length(size);
        pb.set_position(0);
        pb.enable_steady_tick(Duration::from_millis(500));
        self.pbs.insert(id, pb);
    }

    fn progress(&mut self, id: u64, progress: u64) {
        if let Some(pb) = self.pbs.get_mut(&id) {
            pb.set_position(progress);
        }
    }

    fn done(&mut self, id: u64, _hash: Hash) {
        if let Some(pb) = self.pbs.remove(&id) {
            pb.finish_and_clear();
            self.mp.remove(&pb);
        }
    }

    fn all_done(self) {
        self.mp.clear().ok();
    }

    fn error(self) {
        self.mp.clear().ok();
    }
}

struct ValidateProgressState {
    mp: MultiProgress,
    pbs: HashMap<u64, ProgressBar>,
    overall: ProgressBar,
    total: u64,
    errors: u64,
    successes: u64,
}

impl ValidateProgressState {
    fn new() -> Self {
        let mp = MultiProgress::new();
        let overall = mp.add(ProgressBar::new(0));
        overall.enable_steady_tick(Duration::from_millis(500));
        Self {
            mp,
            pbs: HashMap::new(),
            overall,
            total: 0,
            errors: 0,
            successes: 0,
        }
    }

    fn starting(&mut self, total: u64) {
        self.total = total;
        self.errors = 0;
        self.successes = 0;
        self.overall.set_position(0);
        self.overall.set_length(total);
        self.overall.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:60.cyan/blue}] {msg}")
                .unwrap()
                .progress_chars("=>-"),
        );
    }

    fn add_entry(&mut self, id: u64, hash: Hash, path: Option<PathBuf>, size: u64) {
        let pb = self.mp.insert_before(&self.overall, ProgressBar::new(size));
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {msg} {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})").unwrap()
            .progress_chars("=>-"));
        let msg = if let Some(path) = path {
            path.display().to_string()
        } else {
            format!("outboard {}", Blake3Cid(hash))
        };
        pb.set_message(msg);
        pb.set_position(0);
        pb.set_length(size);
        pb.enable_steady_tick(Duration::from_millis(500));
        self.pbs.insert(id, pb);
    }

    fn progress(&mut self, id: u64, progress: u64) {
        if let Some(pb) = self.pbs.get_mut(&id) {
            pb.set_position(progress);
        }
    }

    fn abort(self, error: String) {
        let error_line = self.mp.add(ProgressBar::new(0));
        error_line.set_style(ProgressStyle::default_bar().template("{msg}").unwrap());
        error_line.set_message(error);
    }

    fn done(&mut self, id: u64, error: Option<String>) {
        if let Some(pb) = self.pbs.remove(&id) {
            let ok_char = style(Emoji("✔", "OK")).green();
            let fail_char = style(Emoji("✗", "Error")).red();
            let ok = error.is_none();
            let msg = match error {
                Some(error) => format!("{} {} {}", pb.message(), fail_char, error),
                None => format!("{} {}", pb.message(), ok_char),
            };
            if ok {
                self.successes += 1;
            } else {
                self.errors += 1;
            }
            self.overall.set_position(self.errors + self.successes);
            self.overall.set_message(format!(
                "Overall {} {}, {} {}",
                self.errors, fail_char, self.successes, ok_char
            ));
            if ok {
                pb.finish_and_clear();
            } else {
                pb.set_style(ProgressStyle::default_bar().template("{msg}").unwrap());
                pb.finish_with_message(msg);
            }
        }
    }
}

#[derive(Debug)]
struct ProvideResponseEntry {
    pub name: String,
    pub size: u64,
}

async fn aggregate_add_response<S, E>(
    stream: S,
) -> anyhow::Result<(Hash, Vec<ProvideResponseEntry>)>
where
    S: Stream<Item = std::result::Result<ProvideProgress, E>> + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut stream = stream;
    let mut collection_hash = None;
    let mut collections = BTreeMap::<u64, (String, u64, Option<Hash>)>::new();
    let mut mp = Some(ProvideProgressState::new());
    while let Some(item) = stream.next().await {
        match item? {
            ProvideProgress::Found { name, id, size } => {
                tracing::info!("Found({},{},{})", id, name, size);
                if let Some(mp) = mp.as_mut() {
                    mp.found(name.clone(), id, size);
                }
                collections.insert(id, (name, size, None));
            }
            ProvideProgress::Progress { id, offset } => {
                tracing::info!("Progress({}, {})", id, offset);
                if let Some(mp) = mp.as_mut() {
                    mp.progress(id, offset);
                }
            }
            ProvideProgress::Done { hash, id } => {
                tracing::info!("Done({},{:?})", id, hash);
                if let Some(mp) = mp.as_mut() {
                    mp.done(id, hash);
                }
                match collections.get_mut(&id) {
                    Some((_, _, ref mut h)) => {
                        *h = Some(hash);
                    }
                    None => {
                        anyhow::bail!("Got Done for unknown collection id {}", id);
                    }
                }
            }
            ProvideProgress::AllDone { hash } => {
                tracing::info!("AllDone({:?})", hash);
                if let Some(mp) = mp.take() {
                    mp.all_done();
                }
                collection_hash = Some(hash);
                break;
            }
            ProvideProgress::Abort(e) => {
                if let Some(mp) = mp.take() {
                    mp.error();
                }
                anyhow::bail!("Error while adding data: {}", e);
            }
        }
    }
    let hash = collection_hash.context("Missing hash for collection")?;
    let entries = collections
        .into_iter()
        .map(|(_, (name, size, hash))| {
            let _hash = hash.context(format!("Missing hash for {}", name))?;
            Ok(ProvideResponseEntry { name, size })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((hash, entries))
}

fn print_add_response(hash: Hash, entries: Vec<ProvideResponseEntry>) {
    let mut total_size = 0;
    for ProvideResponseEntry { name, size, .. } in entries {
        total_size += size;
        println!("- {}: {}", name, HumanBytes(size));
    }
    println!("Total: {}", HumanBytes(total_size));
    println!();
    println!("Collection: {}", Blake3Cid::new(hash));
}

const PROGRESS_STYLE: &str =
    "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})";

#[cfg(feature = "metrics")]
fn init_metrics_collection(
    metrics_addr: Option<SocketAddr>,
) -> Option<tokio::task::JoinHandle<()>> {
    init_metrics();
    // doesn't start the server if the address is None
    if let Some(metrics_addr) = metrics_addr {
        return Some(tokio::spawn(async move {
            iroh::metrics::start_metrics_server(metrics_addr)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("Failed to start metrics server: {}", e);
                });
        }));
    }
    tracing::info!("Metrics server not started, no address provided");
    None
}

fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(main_impl())?;
    // give the runtime some time to finish, but do not wait indefinitely.
    // there are cases where the a runtime thread is blocked doing io.
    // e.g. reading from stdin.
    rt.shutdown_timeout(Duration::from_millis(500));
    Ok(())
}

async fn main_impl() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    #[cfg(feature = "metrics")]
    let metrics_fut = init_metrics_collection(cli.metrics_addr);

    let r = match cli.command {
        Commands::Get {
            hash,
            peer,
            addr,
            out,
            single,
        } => {
            let opts = get::Options {
                addr,
                peer_id: Some(peer),
                keylog: cli.keylog,
            };
            let get = GetInteractive::Hash {
                hash: *hash.as_hash(),
                opts,
                single,
            };
            tokio::select! {
                biased;
                res = get_interactive(get, out) => res,
                _ = tokio::signal::ctrl_c() => {
                    println!("Ending transfer early...");
                    Ok(())
                }
            }
        }
        Commands::GetTicket { out, ticket } => {
            let get = GetInteractive::Ticket {
                ticket,
                keylog: cli.keylog,
            };
            tokio::select! {
                biased;
                res = get_interactive(get, out) => res,
                _ = tokio::signal::ctrl_c() => {
                    println!("Ending transfer early...");
                    Ok(())
                }
            }
        }
        Commands::Provide {
            path,
            addr,
            rpc_port,
        } => {
            let iroh_data_root = iroh_data_root()?;
            let marker = iroh_data_root.join(FNAME_PATHS);
            let db = {
                if iroh_data_root.is_dir() && marker.exists() {
                    // try to load db
                    Database::load(&iroh_data_root).await.with_context(|| {
                        format!(
                            "Failed to load iroh database from {}",
                            iroh_data_root.display()
                        )
                    })?
                } else {
                    // directory does not exist, create an empty db
                    Database::default()
                }
            };
            let key = Some(iroh_data_root.join("keypair"));

            let provider = provide(db.clone(), addr, key, cli.keylog, rpc_port.into()).await?;
            let controller = provider.controller();

            // task that will add data to the provider, either from a file or from stdin
            let fut = {
                let provider = provider.clone();
                tokio::spawn(async move {
                    let (path, tmp_path) = if let Some(path) = path {
                        let absolute = path.canonicalize()?;
                        println!("Adding {} as {}...", path.display(), absolute.display());
                        (absolute, None)
                    } else {
                        // Store STDIN content into a temporary file
                        let (file, path) = tempfile::NamedTempFile::new()?.into_parts();
                        let mut file = tokio::fs::File::from_std(file);
                        let path_buf = path.to_path_buf();
                        // Copy from stdin to the file, until EOF
                        tokio::io::copy(&mut tokio::io::stdin(), &mut file).await?;
                        println!("Adding from stdin...");
                        // return the TempPath to keep it alive
                        (path_buf, Some(path))
                    };
                    // tell the provider to add the data
                    let stream = controller.server_streaming(ProvideRequest { path }).await?;
                    let (hash, entries) = aggregate_add_response(stream).await?;
                    print_add_response(hash, entries);
                    let ticket = provider.ticket(hash)?;
                    println!("All-in-one ticket: {ticket}");
                    anyhow::Ok(tmp_path)
                })
            };

            let provider2 = provider.clone();
            tokio::select! {
                biased;
                _ = tokio::signal::ctrl_c() => {
                    println!("Shutting down provider...");
                    provider2.shutdown();
                }
                res = provider => {
                    res?;
                }
            }
            // persist the db to disk.
            db.save(&iroh_data_root).await?;

            // the future holds a reference to the temp file, so we need to
            // keep it for as long as the provider is running. The drop(fut)
            // makes this explicit.
            fut.abort();
            drop(fut);
            Ok(())
        }
        Commands::List { rpc_port } => {
            let client = make_rpc_client(rpc_port).await?;
            let mut response = client.server_streaming(ListRequest).await?;
            while let Some(item) = response.next().await {
                let item = item?;
                println!(
                    "{} {} ({})",
                    item.path.display(),
                    Blake3Cid(item.hash),
                    HumanBytes(item.size),
                );
            }
            Ok(())
        }
        Commands::Validate { rpc_port } => {
            let client = make_rpc_client(rpc_port).await?;
            let mut state = ValidateProgressState::new();
            let mut response = client.server_streaming(ValidateRequest).await?;

            while let Some(item) = response.next().await {
                match item? {
                    ValidateProgress::Starting { total } => {
                        state.starting(total);
                    }
                    ValidateProgress::Entry {
                        id,
                        hash,
                        path,
                        size,
                    } => {
                        state.add_entry(id, hash, path, size);
                    }
                    ValidateProgress::Progress { id, offset } => {
                        state.progress(id, offset);
                    }
                    ValidateProgress::Done { id, error } => {
                        state.done(id, error);
                    }
                    ValidateProgress::Abort(error) => {
                        state.abort(error.to_string());
                        break;
                    }
                    ValidateProgress::AllDone => {
                        break;
                    }
                }
            }
            Ok(())
        }
        Commands::Shutdown { force, rpc_port } => {
            let client = make_rpc_client(rpc_port).await?;
            client.rpc(ShutdownRequest { force }).await?;
            Ok(())
        }
        Commands::Id { rpc_port } => {
            let client = make_rpc_client(rpc_port).await?;
            let response = client.rpc(IdRequest).await?;

            println!("Listening address: {}", response.listen_addr);
            println!("PeerID: {}", response.peer_id);
            Ok(())
        }
        Commands::Add { path, rpc_port } => {
            let client = make_rpc_client(rpc_port).await?;
            let absolute = path.canonicalize()?;
            println!("Adding {} as {}...", path.display(), absolute.display());
            let stream = client
                .server_streaming(ProvideRequest { path: absolute })
                .await?;
            let (hash, entries) = aggregate_add_response(stream).await?;
            print_add_response(hash, entries);
            Ok(())
        }
        Commands::Addresses { rpc_port } => {
            let client = make_rpc_client(rpc_port).await?;
            let response = client.rpc(AddrsRequest).await?;
            println!("Listening addresses: {:?}", response.addrs);
            Ok(())
        }
    };

    #[cfg(feature = "metrics")]
    if let Some(metrics_fut) = metrics_fut {
        metrics_fut.abort();
        drop(metrics_fut);
    }
    r
}

async fn provide(
    db: Database,
    addr: SocketAddr,
    key: Option<PathBuf>,
    keylog: bool,
    rpc_port: Option<u16>,
) -> Result<Provider> {
    let keypair = get_keypair(key).await?;

    let builder = provider::Provider::builder(db)
        .keylog(keylog)
        .bind_addr(addr);
    let provider = if let Some(rpc_port) = rpc_port {
        let rpc_endpoint = make_rpc_endpoint(&keypair, rpc_port)?;
        builder
            .rpc_endpoint(rpc_endpoint)
            .keypair(keypair)
            .spawn()?
    } else {
        builder.keypair(keypair).spawn()?
    };

    println!("Listening address: {}", provider.local_address());
    println!("PeerID: {}", provider.peer_id());
    println!();
    Ok(provider)
}

fn make_rpc_endpoint(
    keypair: &Keypair,
    rpc_port: u16,
) -> Result<impl ServiceEndpoint<ProviderService>> {
    let rpc_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port));
    let rpc_quinn_endpoint = quinn::Endpoint::server(
        iroh::provider::make_server_config(
            keypair,
            MAX_RPC_STREAMS,
            MAX_RPC_CONNECTIONS,
            vec![RPC_ALPN.to_vec()],
        )?,
        rpc_addr,
    )?;
    let rpc_endpoint =
        QuinnServerEndpoint::<ProviderRequest, ProviderResponse>::new(rpc_quinn_endpoint)?;
    Ok(rpc_endpoint)
}

async fn get_keypair(key: Option<PathBuf>) -> Result<Keypair> {
    match key {
        Some(key_path) => {
            if key_path.exists() {
                let keystr = tokio::fs::read(key_path).await?;
                let keypair = Keypair::try_from_openssh(keystr)?;
                Ok(keypair)
            } else {
                let keypair = Keypair::generate();
                let ser_key = keypair.to_openssh()?;
                if let Some(parent) = key_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(key_path, ser_key).await?;
                Ok(keypair)
            }
        }
        None => {
            // No path provided, just generate one
            Ok(Keypair::generate())
        }
    }
}

#[derive(Debug)]
enum GetInteractive {
    Ticket {
        ticket: Ticket,
        keylog: bool,
    },
    Hash {
        hash: Hash,
        opts: get::Options,
        single: bool,
    },
}

impl GetInteractive {
    fn hash(&self) -> Hash {
        match self {
            GetInteractive::Ticket { ticket, .. } => ticket.hash(),
            GetInteractive::Hash { hash, .. } => *hash,
        }
    }

    fn single(&self) -> bool {
        match self {
            GetInteractive::Ticket { .. } => false,
            GetInteractive::Hash { single, .. } => *single,
        }
    }
}

/// Get into a file or directory
async fn get_to_dir(get: GetInteractive, out_dir: PathBuf) -> Result<()> {
    let hash = get.hash();
    let single = get.single();
    progress!("Fetching: {}", Blake3Cid::new(hash));
    progress!("{} Connecting ...", style("[1/3]").bold().dim());

    let temp_dir = out_dir.join(".iroh-tmp");
    let (query, collection) = if single {
        let name = Blake3Cid::new(hash).to_string();
        let query = get_missing_range(&get.hash(), name.as_str(), &temp_dir, &out_dir)?;
        (query, vec![Blob { hash, name }])
    } else {
        let (query, collection) = get_missing_ranges(get.hash(), &out_dir, &temp_dir)?;
        (
            query,
            collection.map(|x| x.into_inner()).unwrap_or_default(),
        )
    };

    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(50));
    pb.set_style(
        ProgressStyle::with_template(PROGRESS_STYLE)
            .unwrap()
            .with_key(
                "eta",
                |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                },
            )
            .progress_chars("#>-"),
    );

    let init_download_progress = |count: u64, missing_bytes: u64| {
        progress!("{} Downloading ...", style("[3/3]").bold().dim());
        progress!(
            "  {} file(s) with total transfer size {}",
            count,
            HumanBytes(missing_bytes)
        );
        pb.set_length(missing_bytes);
        pb.reset();
        pb.set_draw_target(ProgressDrawTarget::stderr());
    };

    // collection info, in case we won't get a callback with is_root
    let collection_info = if collection.is_empty() {
        None
    } else {
        Some((collection.len() as u64, 0))
    };

    let request = GetRequest::new(get.hash(), query).into();
    let response = match get {
        GetInteractive::Ticket { ticket, keylog } => {
            get::run_ticket(&ticket, request, keylog, MAX_CONCURRENT_DIALS).await?
        }
        GetInteractive::Hash { opts, .. } => get::run(request, opts).await?,
    };
    let connected = response.next().await?;
    progress!("{} Requesting ...", style("[2/3]").bold().dim());
    if let Some((count, missing_bytes)) = collection_info {
        init_download_progress(count, missing_bytes);
    }
    let (mut next, collection) = match connected.next().await? {
        ConnectedNext::StartRoot(curr) => {
            tokio::fs::create_dir_all(&temp_dir)
                .await
                .context("unable to create directory {temp_dir}")?;
            tokio::fs::create_dir_all(&out_dir)
                .await
                .context("Unable to create directory {out_dir}")?;
            let curr = curr.next();
            let (curr, collection_data) = curr.concatenate_into_vec().await?;
            let collection = Collection::from_bytes(&collection_data)?;
            init_download_progress(collection.total_entries(), collection.total_blobs_size());
            tokio::fs::write(get_data_path(&temp_dir, hash), collection_data).await?;
            (curr.next(), collection.into_inner())
        }
        ConnectedNext::StartChild(start_child) => {
            (EndBlobNext::MoreChildren(start_child), collection)
        }
        ConnectedNext::Closing(finish) => (EndBlobNext::Closing(finish), collection),
    };
    // read all the children
    let finishing = loop {
        let start = match next {
            EndBlobNext::MoreChildren(sc) => sc,
            EndBlobNext::Closing(finish) => break finish,
        };
        let child_offset = start.child_offset() as usize;
        let blob = match collection.get(child_offset) {
            Some(blob) => blob,
            None => break start.finish(),
        };

        let hash = blob.hash;
        let name = &blob.name;
        let name = if name.is_empty() {
            PathBuf::from(hash.to_string())
        } else {
            pathbuf_from_name(name)
        };
        pb.set_message(format!("Receiving '{}'...", name.display()));
        pb.reset();
        let header = start.next(blob.hash);

        let curr = {
            let final_path = out_dir.join(&name);
            let tempname = blake3::Hash::from(hash).to_hex();
            let data_path = temp_dir.join(format!("{}.data.part", tempname));
            let outboard_path = temp_dir.join(format!("{}.outboard.part", tempname));
            let data_file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&data_path)
                .await?;
            let data_file = SeekOptimized::new(data_file);
            tracing::debug!("piping data to {:?} and {:?}", data_path, outboard_path);
            let (curr, size) = header.next().await?;
            pb.set_length(size);
            let mut outboard_file = if size > 0 {
                let outboard_file = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&outboard_path)
                    .await?;
                let outboard_file = SeekOptimized::new(outboard_file).into();
                Some(outboard_file)
            } else {
                None
            };

            let (on_write, mut receive_on_write) = mpsc::channel(1);
            let pb2 = pb.clone();
            // create task that updates the progress bar
            let progress_task = tokio::task::spawn(async move {
                while let Some((offset, _)) = receive_on_write.recv().await {
                    pb2.set_position(offset);
                }
            });
            let mut data_file = ProgressSliceWriter::new(data_file, on_write).into();
            let curr = curr
                .write_all_with_outboard(&mut outboard_file, &mut data_file)
                .await?;
            // Flush the data file first, it is the only thing that matters at this point
            data_file.into_inner().into_inner().shutdown().await?;
            // wait for the progress task to finish, only after dropping the ProgressSliceWriter
            progress_task.await.ok();
            tokio::fs::create_dir_all(
                final_path
                    .parent()
                    .context("final path should have parent")?,
            )
            .await?;
            // Rename temp file, to target name
            // once this is done, the file is considered complete
            tokio::fs::rename(data_path, final_path).await?;
            if let Some(outboard_file) = outboard_file.take() {
                // not sure if we have to do this
                outboard_file.into_inner().shutdown().await?;
                // delete the outboard file
                tokio::fs::remove_file(outboard_path).await?;
            }
            curr
        };
        pb.finish();
        next = curr.next();
    };
    let stats = finishing.next().await?;
    tokio::fs::remove_dir_all(temp_dir).await?;
    pb.finish_and_clear();
    progress!(
        "Transferred {} in {}, {}/s",
        HumanBytes(stats.bytes_read),
        HumanDuration(stats.elapsed),
        HumanBytes((stats.bytes_read as f64 / stats.elapsed.as_secs_f64()) as u64)
    );

    Ok(())
}

/// get to stdout, no resume possible
async fn get_to_stdout(get: GetInteractive) -> Result<()> {
    let hash = get.hash();
    progress!("Fetching: {}", Blake3Cid::new(hash));
    progress!("{} Connecting ...", style("[1/3]").bold().dim());
    let query = RangeSpecSeq::all();

    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(50));
    pb.set_style(
        ProgressStyle::with_template(PROGRESS_STYLE)
            .unwrap()
            .with_key(
                "eta",
                |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                },
            )
            .progress_chars("#>-"),
    );

    let request = GetRequest::new(get.hash(), query).into();
    let response = match get {
        GetInteractive::Ticket { ticket, keylog } => {
            get::run_ticket(&ticket, request, keylog, MAX_CONCURRENT_DIALS).await?
        }
        GetInteractive::Hash { opts, .. } => get::run(request, opts).await?,
    };
    let connected = response.next().await?;
    progress!("{} Requesting ...", style("[2/3]").bold().dim());
    let ConnectedNext::StartRoot(curr) = connected.next().await? else {
        anyhow::bail!("expected a collection");
    };
    let (mut next, collection) = {
        let curr = curr.next();
        let (curr, collection_data) = curr.concatenate_into_vec().await?;
        let collection = Collection::from_bytes(&collection_data)?;
        let count = collection.total_entries();
        let missing_bytes = collection.total_blobs_size();
        progress!("{} Downloading ...", style("[3/3]").bold().dim());
        progress!(
            "  {} file(s) with total transfer size {}",
            count,
            HumanBytes(missing_bytes)
        );
        pb.set_length(missing_bytes);
        pb.reset();
        pb.set_draw_target(ProgressDrawTarget::stderr());
        (curr.next(), collection.into_inner())
    };
    // read all the children
    let finishing = loop {
        let start = match next {
            EndBlobNext::MoreChildren(sc) => sc,
            EndBlobNext::Closing(finish) => break finish,
        };
        let child_offset = start.child_offset() as usize;
        let blob = match collection.get(child_offset) {
            Some(blob) => blob,
            None => break start.finish(),
        };

        let hash = blob.hash;
        let name = &blob.name;
        let name = if name.is_empty() {
            PathBuf::from(hash.to_string())
        } else {
            pathbuf_from_name(name)
        };
        pb.set_message(format!("Receiving '{}'...", name.display()));
        pb.reset();
        let header = start.next(blob.hash);
        let (on_write, mut receive_on_write) = mpsc::channel(1);
        let pb2 = pb.clone();
        // create task that updates the progress bar
        let progress_task = tokio::task::spawn(async move {
            while let Some((offset, _)) = receive_on_write.recv().await {
                pb2.set_position(offset);
            }
        });
        let mut writer =
            ProgressSliceWriter::new(ConcatenateSliceWriter::new(tokio::io::stdout()), on_write)
                .into();
        let curr = header.write_all(&mut writer).await?;
        drop(writer);
        // wait for the progress task to finish, only after dropping the writer
        progress_task.await.ok();
        pb.finish();
        next = curr.next();
    };
    let stats = finishing.next().await?;
    pb.finish_and_clear();
    progress!(
        "Transferred {} in {}, {}/s",
        HumanBytes(stats.bytes_read),
        HumanDuration(stats.elapsed),
        HumanBytes((stats.bytes_read as f64 / stats.elapsed.as_secs_f64()) as u64)
    );

    Ok(())
}

async fn get_interactive(get: GetInteractive, out_dir: Option<PathBuf>) -> Result<()> {
    if let Some(out_dir) = out_dir {
        get_to_dir(get, out_dir).await
    } else {
        get_to_stdout(get).await
    }
}
