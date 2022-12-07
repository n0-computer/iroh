//! Store services to use in an iroh system.

use std::path::PathBuf;

use anyhow::Result;
use iroh_one::mem_store;
use iroh_rpc_client::Config as RpcClientConfig;
use iroh_rpc_types::store::StoreClientAddr;
use iroh_rpc_types::Addr;
use iroh_store::Config as StoreConfig;
use tokio::task::JoinHandle;

/// A iroh store backed by an on-disk RocksDB.
///
/// An iroh system needs a store service for keeping local state and IPFS data.  This one
/// uses RocksDB in a directory on disk.
#[derive(Debug)]
pub struct RocksStoreService {
    task: JoinHandle<()>,
    addr: StoreClientAddr,
}

impl RocksStoreService {
    /// Starts a new iroh Store service with RocksDB storage.
    ///
    /// This implicitly starts a task on the tokio runtime to manage the storage node.
    pub async fn new(path: PathBuf) -> Result<Self> {
        let (store_recv, store_sender) = Addr::new_mem();
        let config = StoreConfig {
            path,
            rpc_client: RpcClientConfig {
                gateway_addr: None,
                p2p_addr: None,
                store_addr: Some(store_sender.clone()),
                channels: Some(1),
            },
            metrics: Default::default(),
        };
        let task = mem_store::start(store_recv, config).await?;
        Ok(Self {
            task,
            addr: store_sender,
        })
    }

    /// Returns the internal RPC address of this store node.
    ///
    /// This is used by the other iroh services, like the p2p and gateway services, to use
    /// the store.
    pub fn addr(&self) -> StoreClientAddr {
        self.addr.clone()
    }

    /// Stop this store node.
    // TODO: Will eventually become async.
    // TODO: Should this consume self?
    // TODO: This should be graceful termination.
    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for RocksStoreService {
    fn drop(&mut self) {
        self.stop()
    }
}
