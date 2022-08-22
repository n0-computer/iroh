use std::io::Cursor;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use cid::Cid;
use iroh_rpc_types::store::{
    GetLinksRequest, GetLinksResponse, GetRequest, GetResponse, HasRequest, HasResponse,
    PutRequest, Store as RpcStore, StoreServerAddr, VersionResponse,
};
use tracing::info;

use crate::store::Store;

#[cfg(feature = "rpc-grpc")]
impl iroh_rpc_types::NamedService for Store {
    const NAME: &'static str = "store";
}

#[async_trait]
impl RpcStore for Store {
    #[tracing::instrument(skip(self))]
    async fn version(&self, _: ()) -> Result<VersionResponse> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(VersionResponse { version })
    }

    #[tracing::instrument(skip(self, req))]
    async fn put(&self, req: PutRequest) -> Result<()> {
        let cid = cid_from_bytes(req.cid)?;
        let links = links_from_bytes(req.links)?;
        let res = self.put(cid, req.blob, links).await?;

        info!("store rpc call: put cid {}", cid);
        Ok(res)
    }

    #[tracing::instrument(skip(self))]
    async fn get(&self, req: GetRequest) -> Result<GetResponse> {
        let cid = cid_from_bytes(req.cid)?;
        if let Some(res) = self.get(&cid).await? {
            Ok(GetResponse {
                data: Some(BytesMut::from(&res[..]).freeze()),
            })
        } else {
            Ok(GetResponse { data: None })
        }
    }

    #[tracing::instrument(skip(self))]
    async fn has(&self, req: HasRequest) -> Result<HasResponse> {
        let cid = cid_from_bytes(req.cid)?;
        let has = self.has(&cid).await?;

        Ok(HasResponse { has })
    }

    #[tracing::instrument(skip(self))]
    async fn get_links(&self, req: GetLinksRequest) -> Result<GetLinksResponse> {
        let cid = cid_from_bytes(req.cid)?;
        if let Some(res) = self.get_links(&cid).await? {
            let links = res.into_iter().map(|cid| cid.to_bytes()).collect();
            Ok(GetLinksResponse { links })
        } else {
            Ok(GetLinksResponse { links: Vec::new() })
        }
    }
}

#[tracing::instrument(skip(store))]
pub async fn new(addr: StoreServerAddr, store: Store) -> Result<()> {
    info!("rpc listening on: {}", addr);
    iroh_rpc_types::store::serve(addr, store).await
}

#[tracing::instrument]
fn cid_from_bytes(b: Vec<u8>) -> Result<Cid> {
    Cid::read_bytes(Cursor::new(b)).context("invalid cid")
}

#[tracing::instrument]
fn links_from_bytes(l: Vec<Vec<u8>>) -> Result<Vec<Cid>> {
    l.into_iter().map(cid_from_bytes).collect()
}
