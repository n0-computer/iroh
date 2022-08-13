/// A store instance listening on a memory rpc channel.
use iroh_metrics::store::Metrics;
use iroh_rpc_types::store::StoreServerAddr;
use iroh_store::{rpc, Config, Store};
use prometheus_client::registry::Registry;
use tokio::task::JoinHandle;
use tracing::info;

/// Starts a new store, using the given mem rpc channel.
pub async fn start(rpc_addr: StoreServerAddr, config: Config) -> anyhow::Result<JoinHandle<()>> {
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
