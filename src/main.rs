use std::{io::Write, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use futures::StreamExt;
use indicatif::{HumanDuration, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle};
use is_terminal::IsTerminal;
use sendme::protocol::AuthToken;
use tracing::trace;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use sendme::{get, provider, Keypair, PeerId};

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
        /// If this path is provided and it exists, the private key ist read from this file and used, if it does not exist the private key will be persisted to this location.
        #[clap(long)]
        key: Option<PathBuf>,
    },
    /// Fetch some data
    #[clap(about = "Fetch the data from the hash")]
    Get {
        /// The authentication token to present to the server.
        #[clap(long, short)]
        token: String,
        /// The root hash to retrieve.
        hash: bao::Hash,
        #[clap(long, short)]
        /// PeerId of the provider.
        peer_id: PeerId,
        #[clap(long, short)]
        /// Optional address of the provider, defaults to 127.0.0.1:4433.
        addr: Option<SocketAddr>,
        /// Optional path to a new directory in which save the file(s). If none is specified writes the data to STDOUT.
        out: Option<PathBuf>,
    },
}

// Note about writing to STDOUT vs STDERR
// Looking at https://unix.stackexchange.com/questions/331611/do-progress-reports-logging-information-belong-on-stderr-or-stdout
// it is a little complicated.
// The current setup is to write all progress information to STDERR and all data to STDOUT.

struct OutWriter {
    is_atty: bool,
    stderr: std::io::Stderr,
}

impl OutWriter {
    pub fn new() -> Self {
        let stderr = std::io::stderr();
        let is_atty = stderr.is_terminal();
        Self { is_atty, stderr }
    }
}

impl OutWriter {
    pub fn println(&mut self, content: impl AsRef<[u8]>) {
        if self.is_atty {
            self.stderr.write_all(content.as_ref()).unwrap();
            self.stderr.write_all(b"\n").unwrap();
        }
    }
}

const PROGRESS_STYLE: &str =
    "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let mut out_writer = OutWriter::new();

    match cli.command {
        Commands::Get {
            hash,
            token,
            peer_id,
            addr,
            out,
        } => {
            out_writer.println(format!("Fetching: {}", hash.to_hex()));

            let mut opts = get::Options {
                peer_id: Some(peer_id),
                ..Default::default()
            };
            if let Some(addr) = addr {
                opts.addr = addr;
            }
            let token =
                AuthToken::from_str(&token).context("Wrong format for authentication token")?;

            out_writer.println(format!("{} Connecting ...", style("[1/3]").bold().dim()));

            let pb = ProgressBar::hidden();
            let stream = get::run(hash, token, opts);
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                trace!("client event: {:?}", event);
                match event? {
                    get::Event::Connected => {
                        out_writer
                            .println(format!("{} Requesting ...", style("[2/3]").bold().dim()));
                    }
                    get::Event::ReceivedCollection(collection) => {
                        let name = collection.name();
                        let total_entries = collection.total_entries();
                        let size = collection.total_blobs_size();
                        out_writer.println(format!(
                            "{} Downloading {name}...",
                            style("[3/3]").bold().dim()
                        ));
                        out_writer.println(format!(
                            "  {total_entries} file(s) with total transfer size {size}"
                        ));
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
                        pb.set_length(size);
                        pb.set_draw_target(ProgressDrawTarget::stderr());
                    }
                    get::Event::Receiving {
                        hash,
                        mut reader,
                        name,
                    } => {
                        let name = name.map_or_else(|| hash.to_string(), |n| n);
                        pb.set_message(format!("Receiving {name}..."));

                        if let Some(ref outpath) = out {
                            tokio::fs::create_dir_all(outpath)
                                .await
                                .context("Unable to create directory {outpath}")?;
                            let dirpath = std::path::PathBuf::from(outpath);
                            let filepath = dirpath.join(name);
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
                            let out = tokio::io::BufWriter::new(file);
                            // wrap for progress bar
                            let mut wrapped_out = pb.wrap_async_write(out);
                            tokio::io::copy(&mut reader, &mut wrapped_out).await?;
                            let filepath2 = filepath.clone();
                            tokio::task::spawn_blocking(|| temp_file.persist(filepath2))
                                .await?
                                .context("Failed to write output file")?;
                        } else {
                            // Write to OUT_WRITER
                            let mut stdout = tokio::io::stdout();
                            tokio::io::copy(&mut reader, &mut stdout).await?;
                        }
                    }
                    get::Event::Done(stats) => {
                        pb.finish_and_clear();
                        out_writer.println(format!("Done in {}", HumanDuration(stats.elapsed)));
                    }
                }
            }
        }
        Commands::Provide {
            path,
            addr,
            auth_token,
            key,
        } => {
            let keypair = get_keypair(key).await?;

            let mut tmp_path = None;

            let sources = if let Some(path) = path {
                out_writer.println(format!("Reading {}", path.display()));
                if path.is_dir() {
                    let mut paths = Vec::new();
                    let mut iter = tokio::fs::read_dir(&path).await?;
                    while let Some(el) = iter.next_entry().await? {
                        if el.path().is_file() {
                            paths.push(provider::DataSource::File(el.path()));
                        }
                    }
                    paths
                } else if path.is_file() {
                    vec![provider::DataSource::File(path)]
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
                vec![provider::DataSource::File(path_buf)]
            };

            let (db, _) = provider::create_db(sources).await?;
            let mut opts = provider::Options::default();
            if let Some(addr) = addr {
                opts.addr = addr;
            }
            let mut provider_builder = provider::Provider::builder().database(db).keypair(keypair);
            if let Some(ref hex) = auth_token {
                let auth_token = AuthToken::from_str(hex)?;
                provider_builder = provider_builder.auth_token(auth_token);
            }
            let mut provider = provider_builder.build()?;

            out_writer.println(format!("PeerID: {}", provider.peer_id()));
            out_writer.println(format!("Auth token: {}", provider.auth_token()));
            provider.run(opts).await?;

            // Drop tempath to signal it can be destroyed
            drop(tmp_path);
        }
    }

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
