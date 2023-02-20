use std::{fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use indicatif::{
    HumanBytes, HumanDuration, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle,
};
use sendme::protocol::AuthToken;
use sendme::provider::Ticket;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing_subscriber::{prelude::*, EnvFilter};

use sendme::{get, provider, Hash, Keypair, PeerId};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
#[clap(about = "Send data.")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
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
        /// Log SSL pre-master key to file in SSLKEYLOGFILE environment variable.
        #[clap(long)]
        keylog: bool,
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
        token: String,
        /// Optional address of the provider, defaults to 127.0.0.1:4433.
        #[clap(long, short)]
        addr: Option<SocketAddr>,
        /// Optional path to a new directory in which to save the file(s). If none is specified writes the data to STDOUT.
        #[clap(long, short)]
        out: Option<PathBuf>,
        /// Log SSL pre-master key to file in SSLKEYLOGFILE environment variable.
        #[clap(long)]
        keylog: bool,
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
        /// Log SSL pre-master key to file in SSLKEYLOGFILE environment variable.
        #[clap(long)]
        keylog: bool,
    },
}

// Note about writing to STDOUT vs STDERR
// Looking at https://unix.stackexchange.com/questions/331611/do-progress-reports-logging-information-belong-on-stderr-or-stdout
// it is a little complicated.
// The current setup is to write all progress information to STDERR and all data to STDOUT.

struct OutWriter {
    stderr: Mutex<tokio::io::Stderr>,
}

impl OutWriter {
    pub fn new() -> Self {
        let stderr = tokio::io::stderr();
        Self {
            stderr: Mutex::new(stderr),
        }
    }
}

impl OutWriter {
    pub async fn println(&self, content: impl AsRef<[u8]>) {
        let stderr = &mut *self.stderr.lock().await;
        stderr.write_all(content.as_ref()).await.unwrap();
        stderr.write_all(b"\n").await.unwrap();
    }
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

const PROGRESS_STYLE: &str =
    "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Get {
            hash,
            peer,
            token,
            addr,
            out,
            keylog,
        } => {
            let mut opts = get::Options {
                peer_id: Some(peer),
                keylog,
                ..Default::default()
            };
            if let Some(addr) = addr {
                opts.addr = addr;
            }
            let token =
                AuthToken::from_str(&token).context("Wrong format for authentication token")?;
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
        Commands::GetTicket {
            out,
            ticket,
            keylog,
        } => {
            let Ticket {
                hash,
                peer,
                addr,
                token,
            } = ticket;
            let opts = get::Options {
                addr,
                peer_id: Some(peer),
                keylog,
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
            keylog,
        } => {
            tokio::select! {
                biased;
                res = provide_interactive(path, addr, auth_token, key, keylog) => {
                    res
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\nShutting down provider...");
                    Ok(())
                }
            }
        }
    }
}

async fn provide_interactive(
    path: Option<PathBuf>,
    addr: Option<SocketAddr>,
    auth_token: Option<String>,
    key: Option<PathBuf>,
    keylog: bool,
) -> Result<()> {
    let out_writer = OutWriter::new();
    let keypair = get_keypair(key).await?;

    let mut tmp_path = None;

    let sources = if let Some(path) = path {
        out_writer
            .println(format!("Reading {}", path.display()))
            .await;
        if path.is_dir() {
            let mut paths = Vec::new();
            let mut iter = tokio::fs::read_dir(&path).await?;
            while let Some(el) = iter.next_entry().await? {
                if el.path().is_file() {
                    paths.push(el.path().into());
                }
            }
            paths
        } else if path.is_file() {
            vec![path.into()]
        } else {
            bail!("path must be either a Directory or a File");
        }
    } else {
        // Store STDIN content into a temporary file
        let (file, path) = tempfile::NamedTempFile::new()?.into_parts();
        let mut file = tokio::fs::File::from_std(file);
        let path_buf = path.to_path_buf();
        tmp_path = Some(path);
        tokio::io::copy(&mut tokio::io::stdin(), &mut file).await?;
        vec![path_buf.into()]
    };

    let (db, hash) = provider::create_collection(sources).await?;

    println!("Collection: {}\n", Blake3Cid::new(hash));
    for (_, path, size) in db.blobs() {
        println!("- {}: {} bytes", path.display(), size);
    }
    println!();
    let mut builder = provider::Provider::builder(db)
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

    out_writer
        .println(format!("PeerID: {}", provider.peer_id()))
        .await;
    out_writer
        .println(format!("Auth token: {}", provider.auth_token()))
        .await;
    out_writer
        .println(format!("All-in-one ticket: {}", provider.ticket(hash)))
        .await;
    provider.await?;

    // Drop tempath to signal it can be destroyed
    drop(tmp_path);
    Ok(())
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
    let out_writer = OutWriter::new();
    out_writer
        .println(format!("Fetching: {}", Blake3Cid::new(hash)))
        .await;

    out_writer
        .println(format!("{} Connecting ...", style("[1/3]").bold().dim()))
        .await;

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

    let on_connected = || {
        let out_writer = &out_writer;
        async move {
            out_writer
                .println(format!("{} Requesting ...", style("[2/3]").bold().dim()))
                .await;
            Ok(())
        }
    };
    let on_collection = |collection: &sendme::blobs::Collection| {
        let pb = &pb;
        let out_writer = &out_writer;
        let name = collection.name().to_string();
        let total_entries = collection.total_entries();
        let size = collection.total_blobs_size();
        async move {
            out_writer
                .println(format!(
                    "{} Downloading {name}...",
                    style("[3/3]").bold().dim()
                ))
                .await;
            out_writer
                .println(format!(
                    "  {total_entries} file(s) with total transfer size {}",
                    HumanBytes(size)
                ))
                .await;
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
                        .prefix("sendme-tmp-")
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
    out_writer
        .println(format!("Done in {}", HumanDuration(stats.elapsed)))
        .await;

    Ok(())
}
