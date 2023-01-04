/// A store instance listening on a memory rpc channel.
use anyhow::Context;
use iroh_rpc_types::store::StoreAddr;
use iroh_store::{rpc, Config, Store};
use tokio::task::JoinHandle;
use tracing::info;

/// Starts a new store, using the given mem rpc channel.
pub async fn start(rpc_addr: StoreAddr, config: Config) -> anyhow::Result<JoinHandle<()>> {
    // This is the file RocksDB itself is looking for to determine if the database already
    // exists or not.  Just knowing the directory exists does not mean the database is
    // created.
    let marker = config.path.join("CURRENT");

    let store = if marker.exists() {
        info!("Opening store at {}", config.path.display());
        Store::open(config)
            .await
            .context("failed to open existing store")?
    } else {
        info!("Creating store at {}", config.path.display());
        Store::create(config)
            .await
            .context("failed to create new store")?
    };

    let rpc_task = tokio::spawn(async move { rpc::new(rpc_addr, store).await.unwrap() });

    Ok(rpc_task)
}
