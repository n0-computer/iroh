/// A store instance listening on a memory rpc channel.
use iroh_metrics::store::Metrics;
use iroh_rpc_types::store::StoreServerAddr;
use iroh_store::{config::ENV_PREFIX, rpc, Config, Store};
use iroh_util::make_config;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::task::JoinHandle;
use tracing::info;

/// Starts a new store, using the given mem rpc channel.
/// TODO: refactor to share most of the setup with iroh-store/src/main.rs
pub async fn start(rpc_addr: StoreServerAddr) -> anyhow::Result<JoinHandle<()>> {
    println!("Starting memory store with addr {}", rpc_addr);

    let overrides: HashMap<String, String> = HashMap::new();
    let config: iroh_store::Config = make_config(
        // default
        Config::new_grpc(PathBuf::from("./iroh-store")),
        // potential config files
        vec![],
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        overrides,
    )
    .unwrap();

    let mut prom_registry = Registry::default();
    let store_metrics = Metrics::new(&mut prom_registry);

    let store = if config.path.exists() {
        info!("Opening store at {}", config.path.display());
        Store::open(config, store_metrics).await?
    } else {
        info!("Creating store at {}", config.path.display());
        Store::create(config, store_metrics).await?
    };

    let rpc_task = tokio::spawn(async move { rpc::new(rpc_addr, store).await.unwrap() });

    Ok(rpc_task)
}
