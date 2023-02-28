use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use futures::StreamExt;
use indicatif::{
    HumanBytes, HumanDuration, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle,
};
use iroh::protocol::AuthToken;
use iroh::provider::{Database, Provider, Ticket};
use iroh::rpc_protocol::{
    ListRequest, ProvideRequest, ProvideResponse, ProviderRequest, ProviderResponse,
    ProviderService, VersionRequest,
};
use quic_rpc::transport::quinn::{QuinnConnection, QuinnServerEndpoint};
use quic_rpc::{RpcClient, ServiceEndpoint};
use tokio::io::AsyncWriteExt;
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh::{get, provider, Hash, Keypair, PeerId};

const RPC_PORT: u16 = 0x1337;
const RPC_ALPN: [u8; 17] = *b"n0/provider-rpc/1";

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
        #[clap(long)]
        key: Option<PathBuf>,
        /// Optional rpc port, defaults to 4919
        #[clap(long, default_value_t = RPC_PORT)]
        rpc_port: u16,
    },
    /// List hashes
    #[clap(about = "List hashes")]
    List {
        /// Optional rpc port, defaults to 4919
        #[clap(long, default_value_t = RPC_PORT)]
        rpc_port: u16,
    },
    /// Add some data to the database.
    #[clap(about = "Add data from the given path")]
    Add {
        /// The path to the file or folder to add.
        path: PathBuf,
        /// Optional rpc port, defaults to 4919
        #[clap(long, default_value_t = RPC_PORT)]
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
        // Use the `format!` macro to format the string with the arguments
        let mut message = format!($fmt $(, $args)*);
        // Print the formatted string to the console with a newline
        message.push('\n');
        tokio::io::stderr().write_all(message.as_ref()).await.unwrap();
    }};
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Blake3Cid(Hash);

const CID_PREFIX: [u8; 4] = [
    0x01, // version
    0x55, // raw codec
    0x1e, // hash function, blake3
    0x20, // hash size, 32 bytes
];

impl Blake3Cid {
    pub fn new(hash: Hash) -> Self {
        Blake3Cid(hash)
    }

    pub fn as_hash(&self) -> &Hash {
        &self.0
    }

    pub fn as_bytes(&self) -> [u8; 36] {
        let hash: [u8; 32] = self.0.as_ref().try_into().unwrap();
        let mut res = [0u8; 36];
        res[0..4].copy_from_slice(&CID_PREFIX);
        res[4..36].copy_from_slice(&hash);
        res
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() == 36,
            "invalid cid length, expected 36, got {}",
            bytes.len()
        );
        anyhow::ensure!(bytes[0..4] == CID_PREFIX, "invalid cid prefix");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[4..36]);
        Ok(Blake3Cid(Hash::from(hash)))
    }
}

impl fmt::Display for Blake3Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // result will be 58 bytes plus prefix
        let mut res = [b'b'; 59];
        // write the encoded bytes
        data_encoding::BASE32_NOPAD.encode_mut(&self.as_bytes(), &mut res[1..]);
        // convert to string, this is guaranteed to succeed
        let t = std::str::from_utf8_mut(res.as_mut()).unwrap();
        // hack since data_encoding doesn't have BASE32LOWER_NOPAD as a const
        t.make_ascii_lowercase();
        // write the str, no allocations
        f.write_str(t)
    }
}

impl FromStr for Blake3Cid {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sb = s.as_bytes();
        if sb.len() == 59 && sb[0] == b'b' {
            // this is a base32 encoded cid, we can decode it directly
            let mut t = [0u8; 58];
            t.copy_from_slice(&sb[1..]);
            // hack since data_encoding doesn't have BASE32LOWER_NOPAD as a const
            std::str::from_utf8_mut(t.as_mut())
                .unwrap()
                .make_ascii_uppercase();
            // decode the bytes
            let mut res = [0u8; 36];
            data_encoding::BASE32_NOPAD
                .decode_mut(&t, &mut res)
                .map_err(|_e| anyhow::anyhow!("invalid base32"))?;
            // convert to cid, this will check the prefix
            Self::from_bytes(&res)
        } else {
            // if we want to support all the weird multibase prefixes, we have no choice
            // but to use the multibase crate
            let (_base, bytes) = multibase::decode(s)?;
            Self::from_bytes(bytes.as_ref())
        }
    }
}

async fn make_rpc_client(
    rpc_port: u16,
) -> anyhow::Result<RpcClient<ProviderService, QuinnConnection<ProviderResponse, ProviderRequest>>>
{
    let endpoint = iroh::get::make_client_endpoint(None, vec![RPC_ALPN.to_vec()], false, false)?;
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

const PROGRESS_STYLE: &str =
    "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})";

async fn close<C>(client: RpcClient<ProviderService, C>) -> anyhow::Result<()> {
    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
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
        } => {
            let provider = provide(addr, auth_token, key, cli.keylog, rpc_port).await?;
            let controller = provider.controller();
            let mut ticket = provider.ticket(Hash::from([0u8; 32]));

            // task that will add data to the provider, either from a file or from stdin
            let fut = tokio::spawn(async move {
                let (path, tmp_path) = if let Some(path) = path {
                    (path, None)
                } else {
                    // Store STDIN content into a temporary file
                    let (file, path) = tempfile::NamedTempFile::new()?.into_parts();
                    let mut file = tokio::fs::File::from_std(file);
                    let path_buf = path.to_path_buf();
                    // Copy from stdin to the file, until EOF
                    tokio::io::copy(&mut tokio::io::stdin(), &mut file).await?;
                    // return the TempPath to keep it alive
                    (path_buf, Some(path))
                };
                // tell the provider to add the data
                let ProvideResponse { hash } = controller.rpc(ProvideRequest { path }).await??;
                ticket.hash = hash;
                println!("Collection: {}", Blake3Cid::new(hash));
                println!("All-in-one ticket: {}", ticket);
                // println!("{}", response.hash);
                // let (db, hash) = provider::create_collection(sources).await?;
                // println!("Collection: {}\n", Blake3Cid::new(hash));
                // let mut total_size = 0;
                // for (_, path, size) in db.blobs() {
                //     total_size += size;
                //     println!("- {}: {}", path.display(), HumanBytes(size));
                // }
                // println!("Total: {}", HumanBytes(total_size));
                // println!();
                // return all the things that need to live even after this task
                // println!("All-in-one ticket: {}", provider.ticket(hash));
                anyhow::Ok(tmp_path)
            });

            tokio::signal::ctrl_c().await?;
            println!("Shutting down provider...");
            provider.shutdown();
            provider.await?;
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
                    "{} {} ({} bytes)",
                    item.path.display(),
                    item.hash,
                    item.size
                );
            }
            close(client).await
        }
        Commands::Add { path, rpc_port } => {
            let client = make_rpc_client(rpc_port).await?;
            let response = client.rpc(ProvideRequest { path: path.clone() }).await??;
            println!(
                "path {} added. Hash {}",
                path.display(),
                Blake3Cid(response.hash)
            );
            close(client).await
        }
    }
}

async fn provide(
    addr: Option<SocketAddr>,
    auth_token: Option<String>,
    key: Option<PathBuf>,
    keylog: bool,
    rpc_port: u16,
) -> Result<Provider> {
    let keypair = get_keypair(key).await?;
    // create the rpc endpoint as well as a handle that can be used to control the service locally.
    let rpc_endpoint = make_rpc_endpoint(&keypair, rpc_port)?;

    let db = Database::default();
    let mut builder = provider::Provider::builder(db)
        .rpc_endpoint(rpc_endpoint)
        .keypair(keypair)
        .keylog(keylog);
    if let Some(addr) = addr {
        builder = builder.bind_addr(addr);
    }
    if let Some(ref encoded) = auth_token {
        let auth_token = AuthToken::from_str(encoded)?;
        builder = builder.auth_token(auth_token);
    }
    let provider = builder.spawn()?;

    println!("Listening address: {}", provider.listen_addr());
    println!("PeerID: {}", provider.peer_id());
    println!("Auth token: {}", provider.auth_token());
    Ok(provider)
}

fn make_rpc_endpoint(
    keypair: &Keypair,
    rpc_port: u16,
) -> Result<impl ServiceEndpoint<ProviderService>> {
    let rpc_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port));
    let rpc_quinn_endpoint = quinn::Endpoint::server(
        iroh::provider::make_server_config(keypair, 1024, 32, vec![RPC_ALPN.to_vec()])?,
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
