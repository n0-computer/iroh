use std::io::Cursor;

use anyhow::{Context, Result};
use cid::Cid;
use iroh_rpc_client::open_server;
use iroh_rpc_types::store::*;
use tracing::info;

use crate::store::Store;

#[cfg(feature = "rpc-grpc")]
impl iroh_rpc_types::NamedService for Store {
    const NAME: &'static str = "store";
}

impl Store {
    #[tracing::instrument(skip(self))]
    async fn version(self, _: VersionRequest) -> VersionResponse {
        let version = env!("CARGO_PKG_VERSION").to_string();
        VersionResponse { version }
    }

    #[tracing::instrument(skip(self, req))]
    async fn put(self, req: PutRequest) -> Result<()> {
        let cid = req.cid;
        let links = req.links;
        self.spawn_blocking(move |x| x.put0(cid, req.blob, links))
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
                Ok((cid, req.blob, links))
            })
            .collect::<Result<Vec<_>>>()?;
        self.spawn_blocking(move |x| x.put_many0(req)).await
    }

    #[tracing::instrument(skip(self))]
    async fn get(self, req: GetRequest) -> Result<GetResponse> {
        let cid = req.cid;
        self.spawn_blocking(move |x| {
            let data = x.get0(&cid)?.map(|x| x.to_vec().into());
            Ok(GetResponse { data })
        })
        .await
    }

    #[tracing::instrument(skip(self))]
    async fn has(self, req: HasRequest) -> Result<HasResponse> {
        let cid = req.cid;
        self.spawn_blocking(move |x| {
            let has = x.has0(&cid)?;
            Ok(HasResponse { has })
        })
        .await
    }

    #[tracing::instrument(skip(self))]
    async fn get_links(self, req: GetLinksRequest) -> Result<GetLinksResponse> {
        let cid = req.cid;
        self.spawn_blocking(move |x| {
            let links = x.get_links0(&cid)?;
            Ok(GetLinksResponse { links })
        })
        .await
    }

    #[tracing::instrument(skip(self))]
    async fn get_size(self, req: GetSizeRequest) -> Result<GetSizeResponse> {
        let cid = req.cid;
        self.spawn_blocking(move |x| {
            let size = x.get_size0(&cid)?.map(|x| x as u64);
            Ok(GetSizeResponse { size })
        })
        .await
    }
}

#[tracing::instrument(skip(store))]
pub async fn new(addr: StoreServerAddr, store: Store) -> Result<()> {
    use StoreRequest::*;
    info!("rpc listening on: {}", addr);
    let server = open_server::<StoreService>(addr).await?;
    loop {
        let s = server.clone();
        let (req, chan) = s.accept_one().await?;
        let store = store.clone();
        match req {
            Version(req) => s.rpc(req, chan, store, Store::version).await?,
            Put(req) => s.rpc_map_err(req, chan, store, Store::put).await?,
            PutMany(req) => s.rpc_map_err(req, chan, store, Store::put_many).await?,
            Get(req) => s.rpc_map_err(req, chan, store, Store::get).await?,
            Has(req) => s.rpc_map_err(req, chan, store, Store::has).await?,
            GetLinks(req) => s.rpc_map_err(req, chan, store, Store::get_links).await?,
            GetSize(req) => s.rpc_map_err(req, chan, store, Store::get_size).await?,
        }
    }
}
