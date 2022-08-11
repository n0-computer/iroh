/// A p2p instance listening on a memory rpc channel.
use iroh_p2p::config::{Config, ENV_PREFIX};
use iroh_p2p::{DiskStorage, Keychain, Node};
use iroh_rpc_types::p2p::P2pServerAddr;
use iroh_util::make_config;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use tokio::task;
use tokio::task::JoinHandle;
use tracing::error;

/// Starts a new p2p node, using the given mem rpc channel.
/// TODO: refactor to share most of the setup with iroh-p2p/src/main.rs
pub async fn start(rpc_addr: P2pServerAddr) -> anyhow::Result<JoinHandle<()>> {
    // TODO: configurable network
    let overrides: HashMap<String, String> = HashMap::new();
    let network_config = make_config(
        // default
        Config::default_grpc(),
        // potential config files
        vec![],
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        overrides,
    )
    .unwrap();

    let mut prom_registry = Registry::default();

    let kc = Keychain::<DiskStorage>::new().await?;

    let mut p2p = Node::new(network_config, rpc_addr, kc, &mut prom_registry).await?;

    // Start services
    let p2p_task = task::spawn(async move {
        if let Err(err) = p2p.run().await {
            error!("{:?}", err);
        }
    });

    Ok(p2p_task)
}
