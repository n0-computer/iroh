use std::result;

use anyhow::Result;
use bytes::BytesMut;
use iroh_rpc_client::{create_server, ServerError, ServerSocket, StoreServer};
use iroh_rpc_types::store::{
    GetLinksRequest, GetLinksResponse, GetRequest, GetResponse, GetSizeRequest, GetSizeResponse,
    HasRequest, HasResponse, PutManyRequest, PutRequest, StoreAddr, StoreRequest, StoreService,
    VersionRequest, VersionResponse,
};
use tracing::info;

use crate::store::Store;
impl iroh_rpc_types::NamedService for Store {
    const NAME: &'static str = "store";
}

#[derive(Debug, Clone)]
pub struct RpcStore(Store);

impl RpcStore {
    #[tracing::instrument(skip(self))]
    async fn version(self, _: VersionRequest) -> VersionResponse {
        let version = env!("CARGO_PKG_VERSION").to_string();
        VersionResponse { version }
    }

    #[tracing::instrument(skip(self, req))]
    async fn put(self, req: PutRequest) -> Result<()> {
        let cid = req.cid;
        let links = req.links;
        self.0
            .spawn_blocking(move |x| x.put(cid, req.blob, links))
            .await?;

        info!("store rpc call: put cid {}", cid);
        Ok(())
    }

    #[tracing::instrument(skip(self, req))]
    async fn put_many(self, req: PutManyRequest) -> Result<()> {
        let req = req
            .blocks
            .into_iter()
            .map(|req| {
                let cid = req.cid;
                let links = req.links;
                (cid, req.blob, links)
            })
            .collect::<Vec<_>>();
        self.0.spawn_blocking(move |x| x.put_many(req)).await
    }

    #[tracing::instrument(skip(self))]
    async fn get(self, req: GetRequest) -> Result<GetResponse> {
        let cid = req.cid;
        self.0
            .spawn_blocking(move |x| {
                if let Some(res) = x.get(&cid)? {
                    Ok(GetResponse {
                        data: Some(BytesMut::from(&res[..]).freeze()),
                    })
                } else {
                    Ok(GetResponse { data: None })
                }
            })
            .await
    }

    #[tracing::instrument(skip(self))]
    async fn has(self, req: HasRequest) -> Result<HasResponse> {
        let cid = req.cid;
        self.0
            .spawn_blocking(move |x| {
                let has = x.has(&cid)?;
                Ok(HasResponse { has })
            })
            .await
    }

    #[tracing::instrument(skip(self))]
    async fn get_links(self, req: GetLinksRequest) -> Result<GetLinksResponse> {
        let cid = req.cid;
        self.0
            .spawn_blocking(move |x| {
                let links = x.get_links(&cid)?;
                Ok(GetLinksResponse { links })
            })
            .await
    }

    #[tracing::instrument(skip(self))]
    async fn get_size(self, req: GetSizeRequest) -> Result<GetSizeResponse> {
        let cid = req.cid;
        self.0
            .spawn_blocking(move |x| {
                let size = x.get_size(&cid)?.map(|x| x as u64);
                Ok(GetSizeResponse { size })
            })
            .await
    }
}

/// dispatch a single request from the server 
#[rustfmt::skip]
async fn dispatch(s: StoreServer, req: StoreRequest, chan: ServerSocket<StoreService>, target: RpcStore) -> result::Result<(), ServerError> {
    use StoreRequest::*;
    match req {
        Version(req) => s.rpc(req, chan, target, RpcStore::version).await,
        Put(req) => s.rpc_map_err(req, chan, target, RpcStore::put).await,
        PutMany(req) => s.rpc_map_err(req, chan, target, RpcStore::put_many).await,
        Get(req) => s.rpc_map_err(req, chan, target, RpcStore::get).await,
        Has(req) => s.rpc_map_err(req, chan, target, RpcStore::has).await,
        GetLinks(req) => s.rpc_map_err(req, chan, target, RpcStore::get_links).await,
        GetSize(req) => s.rpc_map_err(req, chan, target, RpcStore::get_size).await,
    }
}

#[tracing::instrument(skip(store))]
pub async fn new(addr: StoreAddr, store: Store) -> Result<()> {
    info!("store rpc listening on: {}", addr);
    let server = create_server::<StoreService>(addr).await?;
    let store = RpcStore(store);
    loop {
        match server.accept_one().await {
            Ok((req, chan)) => {
                tokio::spawn(dispatch(server.clone(), req, chan, store.clone()));
            }
            Err(cause) => {
                tracing::error!("store rpc accept error: {}", cause);
            }
        }
    }
}
