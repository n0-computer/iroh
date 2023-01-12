//! Store services to use in an iroh system.

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use iroh_memstore::{MemStore, MemStoreHandle};
use iroh_one::mem_store;
use iroh_rpc_types::store::{StoreAddr, StoreService};
use iroh_rpc_types::Addr;
use iroh_store::Config as StoreConfig;
use tokio::task::JoinHandle;

use crate::IrohService;

/// A iroh store backed by an on-disk RocksDB.
///
/// An iroh system needs a store service for keeping local state and IPFS data.  This one
/// uses RocksDB in a directory on disk.
#[derive(Debug)]
pub struct RocksStoreService {
    task: JoinHandle<()>,
    addr: StoreAddr,
}

impl RocksStoreService {
    /// Starts a new iroh Store service with RocksDB storage.
    ///
    /// This implicitly starts a task on the tokio runtime to manage the storage node.
    pub async fn new(path: PathBuf) -> Result<Self> {
        let addr = Addr::new_mem();
        let config = StoreConfig::with_rpc_addr(path, addr.clone());
        let task = mem_store::start(addr.clone(), config).await?;
        Ok(Self { task, addr })
    }
}

#[async_trait]
impl IrohService<StoreService> for RocksStoreService {
    fn addr(&self) -> Addr<StoreService> {
        self.addr.clone()
    }

    // TODO: This should be graceful termination.
    async fn stop(mut self) -> Result<()> {
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

impl Drop for RocksStoreService {
    fn drop(&mut self) {
        // Abort the task without polling it.  It may or may not ever be polled again and
        // actually abort.  If .stop() has been called though the task is already shut down
        // gracefully and not polling it anymore has no significance.
        self.task.abort();
    }
}

#[derive(Debug)]
pub struct MemStoreService {
    handle: MemStoreHandle,
    addr: StoreAddr,
}

impl MemStoreService {
    /// Starts a new iroh store service with in-memory storage.
    ///
    /// This implicitly starts a task on the current tokio runtime to manage the storage
    /// node.
    pub async fn new() -> Result<Self> {
        let addr = Addr::new_mem();
        let handle = MemStore::spawn(addr.clone()).await?;
        Ok(Self { handle, addr })
    }
}

#[async_trait]
impl IrohService<StoreService> for MemStoreService {
    fn addr(&self) -> StoreAddr {
        self.addr.clone()
    }

    async fn stop(self) -> Result<()> {
        let join = self.handle.shutdown();
        join.await.context("Waiting for MemStore task to finish")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh_rpc_client::StoreClient;
    use testdir::testdir;
    use tokio::time;

    use super::*;

    #[tokio::test]
    async fn test_create_store_stop() {
        let dir = testdir!();
        let marker = dir.join("CURRENT");

        let store = RocksStoreService::new(dir).await.unwrap();
        assert!(marker.exists());

        let fut = store.stop();
        let ret = time::timeout(Duration::from_millis(500), fut).await;

        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_create_mem_store_stop() {
        let store = MemStoreService::new().await.unwrap();

        let client = StoreClient::new(store.addr()).await.unwrap();
        let version = client.version().await.unwrap();

        assert!(!version.is_empty());

        store.stop().await.unwrap();
        let res = client.version().await;

        assert!(res.is_err());
    }
}
