/// A store instance listening on a memory rpc channel.
use iroh_store::{
    rpc::{self, StoreServerAddr},
    Config, Store,
};
use tokio::task::JoinHandle;
use tracing::info;

/// Starts a new store, using the given mem rpc channel.
pub async fn start(rpc_addr: StoreServerAddr, config: Config) -> anyhow::Result<JoinHandle<()>> {
    let store = if config.path.exists() {
        info!("Opening store at {}", config.path.display());
        Store::open(config).await?
    } else {
        info!("Creating store at {}", config.path.display());
        Store::create(config).await?
    };

    let rpc_task = tokio::spawn(async move { rpc::serve(rpc_addr, store.into()).await.unwrap() });

    Ok(rpc_task)
}
