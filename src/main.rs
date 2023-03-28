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
use iroh::protocol::AuthToken;
use iroh::provider::{Database, Provider, Ticket};
use iroh::rpc_protocol::*;
use iroh::rpc_protocol::{
    ListRequest, ProvideRequest, ProviderRequest, ProviderResponse, ProviderService, VersionRequest,
};
use quic_rpc::transport::quinn::{QuinnConnection, QuinnServerEndpoint};
use quic_rpc::{RpcClient, ServiceEndpoint};
use tracing_subscriber::{prelude::*, EnvFilter};
mod main_util;

use iroh::{get, provider, Hash, Keypair, PeerId};
use main_util::Blake3Cid;

use crate::main_util::{iroh_data_root, pathbuf_from_name};

const DEFAULT_RPC_PORT: u16 = 0x1337;
const RPC_ALPN: [u8; 17] = *b"n0/provider-rpc/1";
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
#[clap(about = "Send data.")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
    /// Log SSL pre-master key to file in SSLKEYLOGFILE environment variable.
    #[clap(long)]
    keylog: bool,
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
    /// Serve the data from the given path. If it is a folder, all files in that folder will be served. If none is specified reads from STDIN.
    #[clap(about = "Serve the data from the given path")]
    Provide {
        path: Option<PathBuf>,
        #[clap(long, short)]
        /// Optional listening address, defaults to 127.0.0.1:4433.
        #[clap(long, short)]
        addr: Option<SocketAddr>,
        /// Auth token, defaults to random generated.
        #[clap(long)]
        auth_token: Option<String>,
        /// Optional rpc port, defaults to 4919. Set to 0 to disable RPC.
        #[clap(long, default_value_t = ProviderRpcPort::Enabled(DEFAULT_RPC_PORT))]
        rpc_port: ProviderRpcPort,
    },
    /// List hashes
    #[clap(about = "List hashes")]
    List {
        /// Optional rpc port, defaults to 4919
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Validate hashes
    #[clap(about = "Validate hashes")]
    Validate {
        /// Optional rpc port, defaults to 4919
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Shutdown
    #[clap(about = "Shutdown provider")]
    Shutdown {
        /// Shutdown mode.
        /// Hard shutdown will immediately terminate the process, soft shutdown will wait for all connections to close.
        #[clap(long, default_value_t = false)]
        force: bool,
        /// Optional rpc port, defaults to 4919
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Identity
    #[clap(about = "Identify provider")]
    Id {
        /// Optional rpc port, defaults to 4919
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Add some data to the database.
    #[clap(about = "Add data from the given path")]
    Add {
        /// The path to the file or folder to add.
        path: PathBuf,
        /// Optional rpc port, defaults to 4919
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Fetch some data by hash.
    #[clap(about = "Fetch the data from the hash")]
    Get {
        /// The root hash to retrieve.
        hash: Blake3Cid,
        /// PeerId of the provider.
        #[clap(long, short)]
        peer: PeerId,
        /// The authentication token to present to the server.
        #[clap(long)]
        auth_token: String,
        /// Optional address of the provider, defaults to 127.0.0.1:4433.
        #[clap(long, short)]
        addr: Option<SocketAddr>,
        /// Optional path to a new directory in which to save the file(s). If none is specified writes the data to STDOUT.
        #[clap(long, short)]
        out: Option<PathBuf>,
    },
    /// Fetches some data from a ticket,
    ///
    /// The ticket contains all hash, authentication and connection information to connect
    /// to the provider.  It is a simpler, but slightly less flexible alternative to the
    /// `get` subcommand.
    #[clap(
        about = "Fetch the data using a ticket for all provider information and authentication."
    )]
    GetTicket {
        /// Optional path to a new directory in which to save the file(s). If none is specified writes the data to STDOUT.
        #[clap(long, short)]
        out: Option<PathBuf>,
        /// Ticket containing everything to retrieve a hash from provider.
        ticket: Ticket,
    },
    /// List Provide Addresses
    #[clap(about = "List addresses")]
    Addresses {
        /// Optional rpc port, defaults to 4919
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

    match cli.command {
        Commands::Get {
            hash,
            peer,
            auth_token,
            addr,
            out,
        } => {
            let mut opts = get::Options {
                peer_id: Some(peer),
                keylog: cli.keylog,
                ..Default::default()
            };
            if let Some(addr) = addr {
                opts.addr = addr;
            }
            let token = AuthToken::from_str(&auth_token)
                .context("Wrong format for authentication token")?;
            tokio::select! {
                biased;
                res = get_interactive(*hash.as_hash(), opts, token, out) => {
                    res
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("Ending transfer early...");
                    Ok(())
                }
            }
        }
        Commands::GetTicket { out, ticket } => {
            let Ticket {
                hash,
                peer,
                addrs,
                token,
            } = ticket;
            let addr = addrs
                .get(0)
                .copied()
                .context("missing SocketAddr in ticket")?;
            let opts = get::Options {
                addr,
                peer_id: Some(peer),
                keylog: cli.keylog,
            };
            tokio::select! {
                biased;
                res = get_interactive(hash, opts, token, out) => {
                    res
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("Ending transfer early...");
                    Ok(())
                }
            }
        }
        Commands::Provide {
            path,
            addr,
            auth_token,
            rpc_port,
        } => {
            let iroh_data_root = iroh_data_root()?;
            let db = {
                if iroh_data_root.is_dir() {
                    // try to load db
                    Database::load(&iroh_data_root).await?
                } else {
                    // directory does not exist, create an empty db
                    Database::default()
                }
            };
            let key = Some(iroh_data_root.join("keypair"));

            let provider = provide(
                db.clone(),
                addr,
                auth_token,
                key,
                cli.keylog,
                rpc_port.into(),
            )
            .await?;
            let controller = provider.controller();
            let mut ticket = provider.ticket(Hash::from([0u8; 32]))?;

            // task that will add data to the provider, either from a file or from stdin
            let fut = tokio::spawn(async move {
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
                ticket.hash = hash;
                println!("All-in-one ticket: {ticket}");
                anyhow::Ok(tmp_path)
            });

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
            println!("Auth token: {}", response.auth_token);
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
    }
}

async fn provide(
    db: Database,
    addr: Option<SocketAddr>,
    auth_token: Option<String>,
    key: Option<PathBuf>,
    keylog: bool,
    rpc_port: Option<u16>,
) -> Result<Provider> {
    let keypair = get_keypair(key).await?;

    let mut builder = provider::Provider::builder(db).keylog(keylog);
    if let Some(addr) = addr {
        builder = builder.bind_addr(addr);
    }
    if let Some(ref encoded) = auth_token {
        let auth_token = AuthToken::from_str(encoded)?;
        builder = builder.auth_token(auth_token);
    }
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
    println!("Auth token: {}", provider.auth_token());
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

async fn get_interactive(
    hash: Hash,
    opts: get::Options,
    token: AuthToken,
    out: Option<PathBuf>,
) -> Result<()> {
    progress!("Fetching: {}", Blake3Cid::new(hash));

    progress!("{} Connecting ...", style("[1/3]").bold().dim());

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

    let on_connected = || async move {
        progress!("{} Requesting ...", style("[2/3]").bold().dim());
        Ok(())
    };
    let on_collection = |collection: &iroh::blobs::Collection| {
        let pb = &pb;
        let total_entries = collection.total_entries();
        let size = collection.total_blobs_size();
        async move {
            progress!("{} Downloading ...", style("[3/3]").bold().dim());
            progress!(
                "  {total_entries} file(s) with total transfer size {}",
                HumanBytes(size)
            );
            pb.set_length(size);
            pb.reset();
            pb.set_draw_target(ProgressDrawTarget::stderr());

            Ok(())
        }
    };

    let on_blob = |hash: Hash, mut reader, name: String| {
        let out = &out;
        let pb = &pb;
        async move {
            let name = if name.is_empty() {
                PathBuf::from(hash.to_string())
            } else {
                pathbuf_from_name(&name)
            };
            pb.set_message(format!("Receiving '{}'...", name.display()));

            // Wrap the reader to show progress.
            let mut wrapped_reader = pb.wrap_async_read(&mut reader);

            if let Some(ref outpath) = out {
                tokio::fs::create_dir_all(outpath)
                    .await
                    .context("Unable to create directory {outpath}")?;
                let dirpath = std::path::PathBuf::from(outpath);
                let filepath = dirpath.join(name);

                // Create temp file
                let (temp_file, dup) = tokio::task::spawn_blocking(|| {
                    let temp_file = tempfile::Builder::new()
                        .prefix("iroh-tmp-")
                        .tempfile_in(dirpath)
                        .context("Failed to create temporary output file")?;
                    let dup = temp_file.as_file().try_clone()?;
                    Ok::<_, anyhow::Error>((temp_file, dup))
                })
                .await??;

                let file = tokio::fs::File::from_std(dup);
                let mut file_buf = tokio::io::BufWriter::new(file);
                tokio::io::copy(&mut wrapped_reader, &mut file_buf).await?;

                // Rename temp file, to target name
                let filepath2 = filepath.clone();
                if let Some(parent) = filepath2.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .context("Unable to create directory {parent}")?;
                }
                tokio::task::spawn_blocking(|| temp_file.persist(filepath2))
                    .await?
                    .context("Failed to write output file")?;
            } else {
                // Write to OUT_WRITER
                let mut stdout = tokio::io::stdout();
                tokio::io::copy(&mut wrapped_reader, &mut stdout).await?;
            }

            Ok(reader)
        }
    };
    let stats = get::run(hash, token, opts, on_connected, on_collection, on_blob).await?;

    pb.finish_and_clear();
    progress!(
        "Transferred {} in {}, {}/s",
        HumanBytes(stats.data_len),
        HumanDuration(stats.elapsed),
        HumanBytes((stats.data_len as f64 / stats.elapsed.as_secs_f64()) as u64)
    );

    Ok(())
}
