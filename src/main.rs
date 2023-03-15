use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use futures::StreamExt;
use indicatif::{
    HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressState,
    ProgressStyle,
};
use iroh::protocol::AuthToken;
use iroh::provider::{Database, Provider, Ticket};
use iroh::rpc_protocol::*;
use quic_rpc::transport::quinn::{QuinnConnection, QuinnServerEndpoint};
use quic_rpc::{RpcClient, ServiceEndpoint};
use tracing_subscriber::{prelude::*, EnvFilter};
mod main_util;
use iroh::rpc_util::RpcClientExt;

use iroh::{get, provider, Hash, Keypair, PeerId};
use main_util::Blake3Cid;

use crate::main_util::iroh_data_root;

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
        /// Optional port, defaults to 127.0.01:4433.
        #[clap(long, short)]
        addr: Option<SocketAddr>,
        /// Auth token, defaults to random generated.
        #[clap(long)]
        auth_token: Option<String>,
        /// If this path is provided and it exists, the private key is read from this file and used, if it does not exist the private key will be persisted to this location.
        ///
        /// If this path is not provided and persistent is true, the private key will be persisted to the iroh data root.
        #[clap(long)]
        key: Option<PathBuf>,
        /// Optional rpc port, defaults to 4919. Set to 0 to disable RPC.
        #[clap(long, default_value_t = ProviderRpcPort::Enabled(DEFAULT_RPC_PORT))]
        rpc_port: ProviderRpcPort,
        /// If true, the provider will read and write from the iroh data root to persist data.
        #[clap(long, default_value = "true")]
        persistent: Option<bool>,
    },
    /// List hashes
    #[clap(about = "List hashes")]
    List {
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
                addr,
                token,
            } = ticket;
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
            key,
            rpc_port,
            persistent,
        } => {
            let use_data_root = persistent.unwrap_or_default();
            let iroh_data_root = iroh_data_root()?;
            let db = if use_data_root {
                if iroh_data_root.is_dir() {
                    // try to load db
                    Database::load(&iroh_data_root).await?
                } else {
                    // directory does not exist, create an empty db
                    Database::default()
                }
            } else {
                // no persistence, so use fresh db
                Database::default()
            };
            let key = if use_data_root & key.is_none() {
                Some(iroh_data_root.join("keypair"))
            } else {
                // no persistence, so use key from cli
                key
            };

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
            let mut ticket = provider.ticket(Hash::from([0u8; 32]));

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
                let ProvideResponse { hash, entries } = controller
                    .rpc_with_progress(ProvideRequest { path }, |_| async {})
                    .await??;

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
            // persist the db to disk. this is blocking code.
            if use_data_root {
                db.save(&iroh_data_root).await?;
            }
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
            let mp = MultiProgress::new();
            let pbs = Arc::new(Mutex::new(BTreeMap::<u64, ProgressBar>::new()));
            let progress_handler = move |pp: ProvideProgress| {
                let mp = mp.clone();
                let pbs = pbs.clone();
                async move {
                    let mut pbs = pbs.lock().unwrap();
                    match pp {
                        ProvideProgress::Found { name, id } => {
                            let pb = mp.add(ProgressBar::new(0));
                            pb.set_style(ProgressStyle::default_bar()
                                .template("{spinner:.green} {wide_msg} {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})").unwrap()
                                .progress_chars("=>-"));
                            pb.set_message(name);
                            pbs.insert(id, pb);
                        }
                        ProvideProgress::Progress { id, offset } => {
                            if let Some(pb) = pbs.get_mut(&id) {
                                pb.set_position(offset);
                            }
                        }
                        ProvideProgress::Done { id } => {
                            if let Some(pb) = pbs.remove(&id) {
                                pb.finish_and_clear();
                            }
                        }
                    }
                }
            };
            println!("Adding {} as {}...", path.display(), absolute.display());
            let ProvideResponse { hash, entries } = client
                .rpc_with_progress(ProvideRequest { path: absolute }, progress_handler)
                .await??;
            print_add_response(hash, entries);
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

    println!("Listening address: {}", provider.listen_addr());
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
        let name = collection.name().to_string();
        let total_entries = collection.total_entries();
        let size = collection.total_blobs_size();
        async move {
            progress!("{} Downloading {name}...", style("[3/3]").bold().dim());
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
                hash.to_string()
            } else {
                name
            };
            pb.set_message(format!("Receiving '{name}'..."));

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
