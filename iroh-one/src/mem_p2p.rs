/// A p2p instance listening on a memory rpc channel.
use iroh_p2p::config::Config;
use iroh_p2p::{DiskStorage, Keychain, Node};
use iroh_rpc_types::p2p::P2pServerAddr;
use prometheus_client::registry::Registry;
use tokio::task;
use tokio::task::JoinHandle;
use tracing::error;

/// Starts a new p2p node, using the given mem rpc channel.
pub async fn start(rpc_addr: P2pServerAddr, config: Config) -> anyhow::Result<JoinHandle<()>> {
    let mut prom_registry = Registry::default();

    let kc = Keychain::<DiskStorage>::new().await?;

    let mut p2p = Node::new(config, rpc_addr, kc, &mut prom_registry).await?;

    // Start services
    let p2p_task = task::spawn(async move {
        if let Err(err) = p2p.run().await {
            error!("{:?}", err);
        }
    });

    Ok(p2p_task)
}
