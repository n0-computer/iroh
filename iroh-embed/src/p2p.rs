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
    /// node is stored using the ssh key files format.  If no usable identity exists yet in
    /// this directory a new one is generated.
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

    /// Stop this p2p service.
    ///
    /// This function waits for the service to be fully terminated, returning once it is no
    /// longer running.
    // TODO: This should be graceful termination.
    pub async fn stop(mut self) -> Result<()> {
        // This dummy task will be aborted by Drop.
        let fut = futures::future::ready(());
        let dummy_task = tokio::spawn(fut);
        let task = std::mem::replace(&mut self.task, dummy_task);

        task.abort();

        // Because we currently don't do graceful termination we expect a cancelled error.
        match task.await {
            Ok(()) => Ok(()),
            Err(err) if err.is_cancelled() => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

impl Drop for P2pService {
    fn drop(&mut self) {
        // Abort the task without polling it.  It mor or may not ever be polled again and
        // actually abort.  If .stop() has been called though the task is already shut down
        // gracefully and not polling it anymore has no significance.
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use testdir::testdir;
    use tokio::time;

    use crate::RocksStoreService;

    use super::*;

    #[tokio::test]
    async fn test_create_and_stop() {
        let dir = testdir!();
        let store_dir = dir.join("store");
        let store = RocksStoreService::new(store_dir).await.unwrap();
        let mut cfg = Libp2pConfig::default();
        cfg.listening_multiaddrs = vec![
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        ];

        let svc = P2pService::new(cfg, dir.clone(), store.addr())
            .await
            .unwrap();

        let self_key = dir.join("id_ed25519_0");
        assert!(self_key.exists());

        let fut = svc.stop();
        let ret = time::timeout(Duration::from_millis(500), fut).await;

        assert!(ret.is_ok());

        // Dropping the store here, no need to shut it down nicely.
    }
}
