use std::{net::SocketAddr, path::PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use futures::StreamExt;
use indicatif::{HumanDuration, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle};
use sendme::protocol::AuthToken;
use tracing::trace;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use sendme::{get, provider, PeerId};

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
    /// Serve the data from the given path. If none is specified reads from STDIN.
    #[clap(about = "Serve the data from the given path")]
    Provide {
        path: Option<PathBuf>,
        #[clap(long, short)]
        /// Optional port, defaults to 127.0.01:4433.
        addr: Option<SocketAddr>,
    },
    /// Fetch some data
    #[clap(about = "Fetch the data from the hash")]
    Get {
        /// The authentication token to present to the server.
        token: String,
        /// The root hash to retrieve.
        hash: bao::Hash,
        #[clap(long)]
        /// PeerId of the provider.
        peer_id: PeerId,
        #[clap(long, short)]
        /// Optional address of the provider, defaults to 127.0.0.1:4433.
        addr: Option<SocketAddr>,
        /// Optional path to save the file. If none is specified writes the data to STDOUT.
        out: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Get {
            hash,
            token,
            peer_id,
            addr,
            out,
        } => {
            println!("Fetching: {}", hash.to_hex());
            let mut opts = get::Options {
                peer_id: Some(peer_id),
                ..Default::default()
            };
            if let Some(addr) = addr {
                opts.addr = addr;
            }
            let token =
                AuthToken::from_hex(&token).context("Wrong format for authentication token")?;

            println!("{} Connecting ...", style("[1/3]").bold().dim());
            let pb = ProgressBar::hidden();
            let stream = get::run(hash, token, opts);
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                trace!("client event: {:?}", event);
                match event? {
                    get::Event::Connected => {
                        println!("{} Requesting ...", style("[2/3]").bold().dim());
                    }
                    get::Event::Requested { size } => {
                        println!("{} Downloading ...", style("[3/3]").bold().dim());
                        pb.set_style(
                            ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                                .unwrap()
                                .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
                                .progress_chars("#>-")
                        );
                        pb.set_length(size as u64);
                        pb.set_draw_target(ProgressDrawTarget::stderr());
                    }
                    get::Event::Receiving {
                        hash: new_hash,
                        mut reader,
                    } => {
                        ensure!(hash == new_hash, "invalid hash received");
                        if let Some(ref outpath) = out {
                            let parent =
                                outpath.parent().map(ToOwned::to_owned).ok_or_else(|| {
                                    anyhow!("No valid parent directory for output file")
                                })?;
                            let (temp_file, dup) = tokio::task::spawn_blocking(|| {
                                let temp_file = tempfile::Builder::new()
                                    .prefix("sendme-tmp-")
                                    .tempfile_in(parent)
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
                            let outpath2 = outpath.clone();
                            tokio::task::spawn_blocking(|| temp_file.persist(outpath2))
                                .await?
                                .context("Failed to write output file")?;
                        } else {
                            // Write to STDOUT
                            let mut stdout = tokio::io::stdout();
                            tokio::io::copy(&mut reader, &mut stdout).await?;
                        }
                    }
                    get::Event::Done(stats) => {
                        pb.finish_and_clear();

                        println!("Done in {}", HumanDuration(stats.elapsed));
                    }
                }
            }
        }
        Commands::Provide { path, addr } => {
            let mut tmp_path = None;

            let sources = if let Some(path) = path {
                vec![provider::DataSource::File(path)]
            } else {
                // Store STDIN content into a temporary file
                let (file, path) = tempfile::NamedTempFile::new()?.into_parts();
                let mut file = tokio::fs::File::from_std(file);
                let path_buf = path.to_path_buf();
                tmp_path = Some(path);
                tokio::io::copy(&mut tokio::io::stdin(), &mut file).await?;
                vec![provider::DataSource::File(path_buf)]
            };

            let db = provider::create_db(sources).await?;
            let mut opts = provider::Options::default();
            if let Some(addr) = addr {
                opts.addr = addr;
            }
            let mut provider = provider::Provider::new(db);

            println!("PeerID: {}", provider.peer_id());
            println!("Auth token: {}", provider.auth_token().to_hex());
            provider.run(opts).await?;

            // Drop tempath to signal it can be destroyed
            drop(tmp_path);
        }
    }

    Ok(())
}
