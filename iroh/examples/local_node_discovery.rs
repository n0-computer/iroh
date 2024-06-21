//! Example that runs and iroh node with local node discovery and no relay server
//!
//! Run the follow commands on two different machines in the same local network:
//!  $ cargo run --example local-node-discovery accept [PATH_TO_FILE]
//!  $ cargo run --example local-node-discovery connect [NODE_ID] [HASH]
use std::path::PathBuf;

use anyhow::ensure;
use clap::{Parser, Subcommand};
use iroh::base::key::SecretKey;
use iroh::client::blobs::WrapOption;
use iroh::net::discovery::mdns::LocalNodeDiscovery;
use iroh::node::{DiscoveryConfig, Node};
use iroh_blobs::Hash;
use iroh_net::key::PublicKey;
use iroh_net::NodeAddr;
use iroh_progress::show_download_progress;
use tracing_subscriber::{prelude::*, EnvFilter};

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
    let discovery = LocalNodeDiscovery::new(key.public(), None);
    let cfg = DiscoveryConfig::Custom(Box::new(discovery));

    println!("Starting iroh node with local node discovery...");
    let node = Node::memory()
        .node_discovery(cfg)
        .bind_port(0)
        .relay_mode(iroh_net::relay::RelayMode::Disabled)
        .spawn()
        .await?;

    match &cli.command {
        Commands::Accept { path } => {
            if !path.is_file() {
                println!("Content must be a file.");
                node.shutdown().await?;
                return Ok(());
            }
            let absolute = path.canonicalize()?;
            println!("Adding {} as {}...", path.display(), absolute.display());
            let stream = node
                .blobs()
                .add_from_path(
                    absolute,
                    true,
                    iroh_blobs::util::SetTagOption::Auto,
                    WrapOption::NoWrap,
                )
                .await?;
            let outcome = stream.finish().await?;
            println!("NodeId: {}", node.node_id());
            println!("Hash: {}", outcome.hash);
            tokio::signal::ctrl_c().await?;
            node.shutdown().await?;
            std::process::exit(0);
        }
        Commands::Connect { node_id, hash, out } => {
            println!("NodeID: {}", node.node_id());
            let mut stream = node
                .blobs()
                .download(*hash, NodeAddr::new(*node_id))
                .await?;
            show_download_progress(*hash, &mut stream).await?;
            if let Some(path) = out {
                let absolute = std::env::current_dir()?.join(&path);
                ensure!(!absolute.is_dir(), "output must not be a directory");
                tracing::info!(
                    "exporting {hash} to {} -> {}",
                    path.display(),
                    absolute.display()
                );
                let stream = node
                    .blobs()
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
