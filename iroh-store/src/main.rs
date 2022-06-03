use std::path::PathBuf;

use clap::Parser;
use iroh_metrics::store::Metrics;
use iroh_store::{metrics, rpc, Config, Store};
use iroh_util::block_until_sigint;
use prometheus_client::registry::Registry;
use tracing::info;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Path to the store
    #[clap(long, short)]
    path: PathBuf,
    #[clap(long = "no-metrics")]
    no_metrics: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut prom_registry = Registry::default();
    let store_metrics = Metrics::new(&mut prom_registry);
    let metrics_handle =
        iroh_metrics::init_with_registry(metrics::metrics_config(args.no_metrics), prom_registry)
            .await
            .expect("failed to initialize metrics");

    let version = env!("CARGO_PKG_VERSION");
    println!("Starting iroh-store, version {version}");

    let config = Config::new(args.path.clone());
    let rpc_addr = config.rpc.store_addr;

    let store = if config.path.exists() {
        info!("Opening store at {}", config.path.display());
        Store::open(config, store_metrics).await?
    } else {
        info!("Creating store at {}", config.path.display());
        Store::create(config, store_metrics).await?
    };

    let rpc_task = tokio::spawn(async move { rpc::new(rpc_addr, store).await.unwrap() });

    block_until_sigint().await;
    rpc_task.abort();
    metrics_handle.shutdown();

    Ok(())
}
