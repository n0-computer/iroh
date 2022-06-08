use std::collections::HashMap;
use std::path::PathBuf;

use clap::Parser;
use iroh_metrics::store::Metrics;
use iroh_store::{
    config::{CONFIG_FILE_NAME, ENV_PREFIX},
    metrics, rpc, Config, Store,
};
use iroh_util::{block_until_sigint, iroh_home_path, make_config};
use prometheus_client::registry::Registry;
use tracing::info;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Path to the store
    #[clap(long, short, required_unless_present("cfg"))]
    path: Option<PathBuf>,
    #[clap(long = "no-metrics")]
    no_metrics: bool,
    /// Path to the config file
    #[clap(long)]
    cfg: Option<PathBuf>,
}

impl Args {
    fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Some(path) = self.path.clone() {
            map.insert("path".to_string(), path.to_str().unwrap_or("").to_string());
        }
        map
    }
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

    let sources = vec![iroh_home_path(CONFIG_FILE_NAME), args.cfg.clone()];
    let config = make_config(
        // default
        Config::new(args.path.clone().unwrap_or_else(|| PathBuf::from(""))),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .unwrap();

    let rpc_addr = config.rpc_addr;
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
