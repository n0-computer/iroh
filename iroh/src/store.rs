use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;

use crate::getadd::{add, get};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use iroh_resolver::resolver::Path as IpfsPath;
use iroh_rpc_client::{Client, P2pClient, StoreClient};
use libp2p::gossipsub::{MessageId, TopicHash};
use libp2p::{Multiaddr, PeerId};
use mockall::automock;
use tokio::{fs::File, io::stdin, io::AsyncReadExt};

pub struct ClientStore<'a> {
    client: &'a StoreClient,
}

impl<'a> ClientStore<'a> {
    pub fn new(client: &'a StoreClient) -> Self {
        Self { client }
    }
}

#[automock]
#[async_trait]
pub trait Store {
    async fn store_version(&self) -> Result<String>;
    async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>>;
    async fn block_get(&self, cid: &Cid) -> Result<Option<Bytes>>;
    async fn block_put(&self, _data: &Bytes) -> Result<Cid>;
    async fn block_has(&self, cid: &Cid) -> Result<bool>;
}

#[async_trait]
impl<'a> Store for ClientStore<'a> {
    async fn store_version(&self) -> Result<String> {
        self.client.version().await
    }

    async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>> {
        self.client.get_links(*cid).await
    }

    async fn block_get(&self, cid: &Cid) -> Result<Option<Bytes>> {
        self.client.get(*cid).await
    }

    async fn block_put(&self, _data: &Bytes) -> Result<Cid> {
        // this awaits ramfox's work in the resolver
        // would be nice if that work only relied on the store and not
        // on the full client
        todo!("not yet")
    }

    async fn block_has(&self, cid: &Cid) -> Result<bool> {
        self.client.has(*cid).await
    }
}
