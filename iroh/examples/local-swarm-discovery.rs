//! Example that runs and iroh node with local node discovery and no relay server
//!
//! Run the follow command to run the "accept" side, that hosts the content:
//!  $ cargo run --example local_swarm_discovery --features="discovery-local-network" -- accept [FILE_PATH]
//! Wait for output that looks like the following:
//!  $ cargo run --example local_swarm_discovery --features="discovery-local-network" -- connect [NODE_ID] [HASH] -o [FILE_PATH]
//! Run that command on another machine in the same local network, replacing [FILE_PATH] to the path on which you want to save the transferred content.
use std::{path::PathBuf, sync::Arc};

use anyhow::ensure;
use clap::{Parser, Subcommand};
use iroh::{
    base::{hash::Hash, key::SecretKey},
    net::{discovery::local_swarm_discovery::LocalSwarmDiscovery, key::PublicKey, NodeAddr},
    node::DiscoveryConfig,
};
use iroh_blobs::{
    downloader::Downloader, net_protocol::Blobs, rpc::client::blobs::WrapOption,
    util::local_pool::LocalPool,
};
use tracing_subscriber::{prelude::*, EnvFilter};

use self::progress::show_download_progress;

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Commands {
    /// Launch an iroh node and provide the content at the given path
    Accept {
        /// path to the file you want to provide
        path: PathBuf,
    },
    /// Get the node_id and hash string from a node running accept in the local network
    /// Download the content from that node.
    Connect {
        /// Node ID of a node on the local network
        node_id: PublicKey,
        /// Hash of content you want to download from the node
        hash: Hash,
        /// save the content to a file
        #[clap(long, short)]
        out: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging();
    let cli = Cli::parse();

    let key = SecretKey::generate();
    let discovery = LocalSwarmDiscovery::new(key.public())?;
    let cfg = DiscoveryConfig::Custom(Box::new(discovery));

    println!("Starting iroh node with local node discovery...");
    // create a new node
    let mut builder = iroh::node::Node::memory()
        .secret_key(key)
        .node_discovery(cfg)
        .bind_random_port()
        .relay_mode(iroh_net::RelayMode::Disabled)
        .build()
        .await?;
    let local_pool = LocalPool::default();
    let store = iroh_blobs::store::mem::Store::new();
    let downloader = Downloader::new(
        store.clone(),
        builder.endpoint().clone(),
        local_pool.handle().clone(),
    );
    let blobs = Arc::new(Blobs::new_with_events(
        store,
        local_pool.handle().clone(),
        Default::default(),
        downloader,
        builder.endpoint().clone(),
    ));
    let blobs_client = blobs.clone().client();
    builder = builder.accept(iroh_blobs::protocol::ALPN.to_vec(), blobs);
    let node = builder.spawn().await?;

    match &cli.command {
        Commands::Accept { path } => {
            if !path.is_file() {
                println!("Content must be a file.");
                node.shutdown().await?;
                return Ok(());
            }
            let absolute = path.canonicalize()?;
            println!("Adding {} as {}...", path.display(), absolute.display());
            let stream = blobs_client
                .add_from_path(
                    absolute,
                    true,
                    iroh_blobs::util::SetTagOption::Auto,
                    WrapOption::NoWrap,
                )
                .await?;
            let outcome = stream.finish().await?;
            println!("To fetch the blob:\n\tcargo run --example local_swarm_discovery --features=\"local-swarm-discovery\" -- connect {} {} -o [FILE_PATH]", node.node_id(), outcome.hash);
            tokio::signal::ctrl_c().await?;
            node.shutdown().await?;
            std::process::exit(0);
        }
        Commands::Connect { node_id, hash, out } => {
            println!("NodeID: {}", node.node_id());
            let mut stream = blobs_client
                .download(*hash, NodeAddr::new(*node_id))
                .await?;
            show_download_progress(*hash, &mut stream).await?;
            if let Some(path) = out {
                let absolute = std::env::current_dir()?.join(path);
                ensure!(!absolute.is_dir(), "output must not be a directory");
                tracing::info!(
                    "exporting {hash} to {} -> {}",
                    path.display(),
                    absolute.display()
                );
                let stream = blobs_client
                    .export(
                        *hash,
                        absolute,
                        iroh_blobs::store::ExportFormat::Blob,
                        iroh_blobs::store::ExportMode::Copy,
                    )
                    .await?;
                stream.await?;
            }
        }
    }
    Ok(())
}

mod progress {
    use anyhow::{bail, Result};
    use console::style;
    use futures_lite::{Stream, StreamExt};
    use indicatif::{
        HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressState,
        ProgressStyle,
    };
    use iroh_blobs::{
        get::{db::DownloadProgress, progress::BlobProgress, Stats},
        Hash,
    };

    pub async fn show_download_progress(
        hash: Hash,
        mut stream: impl Stream<Item = Result<DownloadProgress>> + Unpin,
    ) -> Result<()> {
        eprintln!("Fetching: {}", hash);
        let mp = MultiProgress::new();
        mp.set_draw_target(ProgressDrawTarget::stderr());
        let op = mp.add(make_overall_progress());
        let ip = mp.add(make_individual_progress());
        op.set_message(format!("{} Connecting ...\n", style("[1/3]").bold().dim()));
        let mut seq = false;
        while let Some(x) = stream.next().await {
            match x? {
                DownloadProgress::InitialState(state) => {
                    if state.connected {
                        op.set_message(format!("{} Requesting ...\n", style("[2/3]").bold().dim()));
                    }
                    if let Some(count) = state.root.child_count {
                        op.set_message(format!(
                            "{} Downloading {} blob(s)\n",
                            style("[3/3]").bold().dim(),
                            count + 1,
                        ));
                        op.set_length(count + 1);
                        op.reset();
                        op.set_position(state.current.map(u64::from).unwrap_or(0));
                        seq = true;
                    }
                    if let Some(blob) = state.get_current() {
                        if let Some(size) = blob.size {
                            ip.set_length(size.value());
                            ip.reset();
                            match blob.progress {
                                BlobProgress::Pending => {}
                                BlobProgress::Progressing(offset) => ip.set_position(offset),
                                BlobProgress::Done => ip.finish_and_clear(),
                            }
                            if !seq {
                                op.finish_and_clear();
                            }
                        }
                    }
                }
                DownloadProgress::FoundLocal { .. } => {}
                DownloadProgress::Connected => {
                    op.set_message(format!("{} Requesting ...\n", style("[2/3]").bold().dim()));
                }
                DownloadProgress::FoundHashSeq { children, .. } => {
                    op.set_message(format!(
                        "{} Downloading {} blob(s)\n",
                        style("[3/3]").bold().dim(),
                        children + 1,
                    ));
                    op.set_length(children + 1);
                    op.reset();
                    seq = true;
                }
                DownloadProgress::Found { size, child, .. } => {
                    if seq {
                        op.set_position(child.into());
                    } else {
                        op.finish_and_clear();
                    }
                    ip.set_length(size);
                    ip.reset();
                }
                DownloadProgress::Progress { offset, .. } => {
                    ip.set_position(offset);
                }
                DownloadProgress::Done { .. } => {
                    ip.finish_and_clear();
                }
                DownloadProgress::AllDone(Stats {
                    bytes_read,
                    elapsed,
                    ..
                }) => {
                    op.finish_and_clear();
                    eprintln!(
                        "Transferred {} in {}, {}/s",
                        HumanBytes(bytes_read),
                        HumanDuration(elapsed),
                        HumanBytes((bytes_read as f64 / elapsed.as_secs_f64()) as u64)
                    );
                    break;
                }
                DownloadProgress::Abort(e) => {
                    bail!("download aborted: {}", e);
                }
            }
        }
        Ok(())
    }
    fn make_overall_progress() -> ProgressBar {
        let pb = ProgressBar::hidden();
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb.set_style(
            ProgressStyle::with_template(
                "{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}",
            )
            .unwrap()
            .progress_chars("#>-"),
        );
        pb
    }

    fn make_individual_progress() -> ProgressBar {
        let pb = ProgressBar::hidden();
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb.set_style(
        ProgressStyle::with_template("{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .with_key(
                "eta",
                |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                },
            )
            .progress_chars("#>-"),
    );
        pb
    }
}
