use std::path::PathBuf;

use clap::Parser;
use iroh_store::{rpc, Config, Store};
use iroh_util::block_until_sigint;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Path to the store
    #[clap(long, short)]
    path: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().pretty())
        .with(EnvFilter::from_default_env())
        .init();

    let version = env!("CARGO_PKG_VERSION");
    println!("Starting iroh-store, version {version}");

    let args = Args::parse();
    let config = Config::new(args.path.clone());
    let rpc_addr = config.rpc.store_addr;

    let store = if config.path.exists() {
        info!("Opening store at {}", config.path.display());
        Store::open(config).await?
    } else {
        info!("Creating store at {}", config.path.display());
        Store::create(config).await?
    };

    let rpc_task = tokio::spawn(async move { rpc::new(rpc_addr, store).await.unwrap() });

    block_until_sigint().await;
    rpc_task.abort();

    Ok(())
}
