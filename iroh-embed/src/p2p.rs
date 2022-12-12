//! The p2p service to use in an iroh system.

use std::path::PathBuf;

use anyhow::Result;
use iroh_one::mem_p2p;
use iroh_p2p::{Config as P2pConfig, Libp2pConfig};
use iroh_rpc_types::p2p::P2pAddr;
use iroh_rpc_types::store::StoreAddr;
use iroh_rpc_types::Addr;
use tokio::task::JoinHandle;

// TODO:
//
// - Need to allow configuring in memory keystore
// - make Lib2p2Config non_exhaustive and provide a builder

/// The iroh peer-to-peer (p2p) service.
///
/// An iroh system needs a p2p service to participate in the IPFS network.
#[derive(Debug)]
pub struct P2pService {
    task: JoinHandle<()>,
    addr: P2pAddr,
}

impl P2pService {
    /// Starts a new iroh peer-to-peer service.
    ///
    /// This implicitly starts a task on the tokio runtime to manage the storage node.
    ///
    /// The `key_store_path` is the directory where the cryptographic identity of this p2p
    /// node is stored.  This uses the ssh key files format.
    ///
    /// Note that [`Libp2pConfig::default`] binds to the `/ip4/0.0.0.0/tcp/4444` and
    /// `/ip4/0.0.0.0/udp/4445/quic-v1`.
    // TODO: Provide a way to use an in-memory keystore.
    pub async fn new(
        libp2p_config: Libp2pConfig,
        key_store_path: PathBuf,
        store_service: StoreAddr,
    ) -> Result<Self> {
        let addr = Addr::new_mem();
        let mut config = P2pConfig::default_with_rpc(addr.clone());

        config.rpc_client.store_addr = Some(store_service);
        config.libp2p = libp2p_config;
        config.key_store_path = key_store_path;
        let task = mem_p2p::start(addr.clone(), config).await?;
        Ok(Self { task, addr })
    }

    /// Returns the internal RPC address of this p2p service.
    ///
    /// This can be used to connect this service to other iroh services, like the gateway
    /// service.
    pub fn addr(&self) -> P2pAddr {
        self.addr.clone()
    }

    /// Stop this p2p node.
    // TODO: Will eventually become async.
    // TODO: Should this consume self?
    // TODO: This should be graceful termination.
    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for P2pService {
    fn drop(&mut self) {
        self.stop()
    }
}
