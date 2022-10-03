use std::path::Path;

use crate::getadd::{add, get};
use crate::p2p::{ClientP2p, MockP2p, P2p};
use crate::store::{ClientStore, MockStore, Store};
use anyhow::Result;
use async_trait::async_trait;
use cid::Cid;
use iroh_resolver::resolver::Path as IpfsPath;
use iroh_rpc_client::Client;
use iroh_rpc_client::{StatusRow, StatusTable};
use mockall::automock;

pub struct ClientApi<'a> {
    client: &'a Client,
}

#[automock(type P = MockP2p; type S = MockStore;)]
#[async_trait(?Send)]
pub trait Api {
    type P: P2p;
    type S: Store;

    // type StatusTableStream: futures::Stream<Item = Result<iroh_rpc_client::StatusTable>>;

    fn p2p(&self) -> Result<Self::P>;
    fn store(&self) -> Result<Self::S>;
    async fn get<'a>(&self, ipfs_path: &IpfsPath, output: Option<&'a Path>) -> Result<()>;
    async fn add(&self, path: &Path, recursive: bool, no_wrap: bool) -> Result<Cid>;
    async fn check(&self) -> iroh_rpc_client::StatusTable;
    // This won't work
    // async fn watch(&self) -> Self::StatusTableStream;
}

impl<'a> ClientApi<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }
}

#[async_trait(?Send)]
impl<'a> Api for ClientApi<'a> {
    type P = ClientP2p<'a>;
    type S = ClientStore<'a>;
    // type StatusTableStream = Box<dyn Stream<Item = StatusRow>>;

    fn p2p(&self) -> Result<ClientP2p<'a>> {
        let p2p_client = self.client.try_p2p()?;
        Ok(ClientP2p::new(p2p_client))
    }

    fn store(&self) -> Result<ClientStore<'a>> {
        let store_client = self.client.try_store()?;
        Ok(ClientStore::new(store_client))
    }

    async fn get<'b>(&self, ipfs_path: &IpfsPath, output: Option<&'b Path>) -> Result<()> {
        get(self.client, ipfs_path, output).await
    }

    async fn add(&self, path: &Path, recursive: bool, no_wrap: bool) -> Result<Cid> {
        add(self.client, path, recursive, no_wrap).await
    }

    async fn check(&self) -> iroh_rpc_client::StatusTable {
        self.client.check().await
    }

    // async fn watch(&self) -> impl Stream<Item = iroh_rpc_client::StatusTable> {
    //     self.client.watch()
    // }
}
