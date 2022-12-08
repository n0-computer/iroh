/// A store instance listening on a memory rpc channel.
use iroh_rpc_types::store::StoreAddr;
use iroh_store::{rpc, Config, Store};
use tokio::task::JoinHandle;
use tracing::info;

/// Starts a new store, using the given mem rpc channel.
pub async fn start(rpc_addr: StoreAddr, config: Config) -> anyhow::Result<JoinHandle<()>> {
    let store = if config.path.exists() {
        info!("Opening store at {}", config.path.display());
        Store::open(config).await?
    } else {
        info!("Creating store at {}", config.path.display());
        Store::create(config).await?
    };

    let rpc_task = tokio::spawn(async move { rpc::new(rpc_addr, store).await.unwrap() });

    Ok(rpc_task)
}
