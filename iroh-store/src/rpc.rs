use bytes::{Bytes, BytesMut};
use cid::Cid;
use iroh_rpc_types::{
    impl_serve,
    store::{StoreRequest, StoreResponse},
    RpcError,
};
use tarpc::context::Context;

use crate::store::Store;

impl_serve!(Store, RpcStore, StoreRequest, StoreResponse);

#[derive(Clone)]
pub struct RpcStore {
    store: Store,
}

impl From<Store> for RpcStore {
    fn from(store: Store) -> Self {
        RpcStore { store }
    }
}

#[tarpc::server]
impl iroh_rpc_types::store::Store for RpcStore {
    async fn version(self, _ctx: Context) -> Result<String, RpcError> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(version)
    }

    async fn put(
        self,
        _ctx: Context,
        cid: Cid,
        blob: Bytes,
        links: Vec<Cid>,
    ) -> Result<(), RpcError> {
        let res = self.store.put(cid, blob, links)?;
        Ok(res)
    }

    async fn put_many(
        self,
        _ctx: Context,
        blocks: Vec<(Cid, Bytes, Vec<Cid>)>,
    ) -> Result<(), RpcError> {
        self.store.put_many(blocks)?;

        Ok(())
    }

    async fn get(self, _ctx: Context, cid: Cid) -> Result<Option<BytesMut>, RpcError> {
        if let Some(res) = self.store.get(&cid)? {
            Ok(Some(BytesMut::from(&res[..])))
        } else {
            Ok(None)
        }
    }

    async fn has(self, _ctx: Context, cid: Cid) -> Result<bool, RpcError> {
        let has = self.store.has(&cid)?;

        Ok(has)
    }

    async fn get_links(self, _ctx: Context, cid: Cid) -> Result<Vec<Cid>, RpcError> {
        let links = self.store.get_links(&cid)?.unwrap_or_default();
        Ok(links)
    }

    async fn get_size(self, _ctx: Context, cid: Cid) -> Result<Option<u64>, RpcError> {
        if let Some(size) = self.store.get_size(&cid).await? {
            Ok(Some(size as u64))
        } else {
            Ok(None)
        }
    }
}
