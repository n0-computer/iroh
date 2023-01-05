use std::path::Path;

use anyhow::Result;
use iroh_embed::{Iroh, IrohBuilder, Libp2pConfig, P2pService, RocksStoreService};

pub async fn build(port: u16, db_path: &Path) -> Result<Iroh> {
    let db_path = db_path.to_path_buf();
    let store = RocksStoreService::new(db_path.clone()).await?;

    let mut libp2p_config = Libp2pConfig::default();
    libp2p_config.listening_multiaddrs = vec![format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap()];
    libp2p_config.bootstrap_peers = Default::default(); // disable bootstrap for now
    libp2p_config.relay_server = false;
    libp2p_config.max_conns_in = 8;
    libp2p_config.max_conns_out = 8;

    let p2p = P2pService::new(libp2p_config, db_path, store.addr()).await?;
    IrohBuilder::new().store(store).p2p(p2p).build().await
}
