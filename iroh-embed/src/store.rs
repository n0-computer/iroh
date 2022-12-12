//! Store services to use in an iroh system.

use std::path::PathBuf;

use anyhow::Result;
use iroh_one::mem_store;
use iroh_rpc_client::Config as RpcClientConfig;
use iroh_rpc_types::store::StoreAddr;
use iroh_rpc_types::Addr;
use iroh_store::Config as StoreConfig;
use tokio::task::JoinHandle;

/// A iroh store backed by an on-disk RocksDB.
///
/// An iroh system needs a store service for keeping local state and IPFS data.  This one
/// uses RocksDB in a directory on disk.
#[derive(Debug)]
pub struct RocksStoreService {
    /// Handle to the task.
    ///
    /// Always exists if the task is running.  Once [`RocksStoreService::stop`] has been
    /// called it will be `None`.
    task: Option<JoinHandle<()>>,
    addr: StoreAddr,
}

impl RocksStoreService {
    /// Starts a new iroh Store service with RocksDB storage.
    ///
    /// This implicitly starts a task on the tokio runtime to manage the storage node.
    pub async fn new(path: PathBuf) -> Result<Self> {
        let addr = Addr::new_mem();
        let config = StoreConfig {
            path,
            rpc_client: RpcClientConfig {
                gateway_addr: None,
                p2p_addr: None,
                store_addr: Some(addr.clone()),
                channels: Some(1),
            },
            metrics: Default::default(),
        };
        let task = mem_store::start(addr.clone(), config).await?;
        Ok(Self {
            task: Some(task),
            addr,
        })
    }

    /// Returns the internal RPC address of this store node.
    ///
    /// This is used by the other iroh services, like the p2p and gateway services, to use
    /// the store.
    pub fn addr(&self) -> StoreAddr {
        self.addr.clone()
    }

    /// Stop this store node.
    // TODO: Will eventually become async.
    // TODO: Should this consume self?
    // TODO: This should be graceful termination.
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(task) = self.task.take() {
            task.abort();
            task.await?;
        }
        Ok(())
    }
}

impl Drop for RocksStoreService {
    fn drop(&mut self) {
        // Abort the task without polling it.  It may or may not ever be polled again and
        // actually abort.
        if let Some(ref task) = self.task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use testdir::testdir;
    use tokio::time;

    use super::*;

    #[tokio::test]
    async fn test_create_store_stop() {
        let dir = testdir!();
        let marker = dir.join("CURRENT");

        let mut store = RocksStoreService::new(dir).await.unwrap();
        assert!(marker.exists());

        let fut = store.stop();
        let ret = time::timeout(Duration::from_millis(500), fut).await;

        assert!(ret.is_ok());
    }
}
