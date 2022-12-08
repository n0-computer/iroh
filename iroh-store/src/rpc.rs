use anyhow::Result;
use bytes::BytesMut;
use futures::StreamExt;
use iroh_rpc_client::{create_server_stream, ChannelTypes, StoreServer};
use iroh_rpc_types::store::{
    GetLinksRequest, GetLinksResponse, GetRequest, GetResponse, GetSizeRequest, GetSizeResponse,
    HasRequest, HasResponse, PutManyRequest, PutRequest, StoreRequest, StoreServerAddr,
    StoreService, VersionRequest, VersionResponse,
};
use tracing::info;

use crate::store::Store;

#[cfg(feature = "rpc-grpc")]
impl iroh_rpc_types::NamedService for Store {
    const NAME: &'static str = "store";
}

#[derive(Clone)]
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
        let res = self
            .0
            .spawn_blocking(move |x| x.put(cid, req.blob, links))
            .await?;

        info!("store rpc call: put cid {}", cid);
        Ok(res)
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

/// Handle a session with a client. This will loop until either the client closes the connection or
/// one of the requests produces an error.
async fn handle_session(server: StoreServer, store: Store) -> Result<()> {
    use StoreRequest::*;
    let s = server.clone();
    let store = RpcStore(store);
    loop {
        let store = store.clone();
        let s = s.clone();
        let (req, chan) = s.accept_one().await?;
        let store = store.clone();
        #[rustfmt::skip]
        tokio::spawn(async move {
            match req {
                Version(req) => s.rpc(req, chan, store, RpcStore::version).await,
                Put(req) => s.rpc_map_err(req, chan, store, RpcStore::put).await,
                PutMany(req) => s.rpc_map_err(req, chan, store, RpcStore::put_many).await,
                Get(req) => s.rpc_map_err(req, chan, store, RpcStore::get).await,
                Has(req) => s.rpc_map_err(req, chan, store, RpcStore::has).await,
                GetLinks(req) => s.rpc_map_err(req, chan, store, RpcStore::get_links).await,
                GetSize(req) => s.rpc_map_err(req, chan, store, RpcStore::get_size).await,
            }
        });
    }
}

#[tracing::instrument(skip(store))]
pub async fn new(addr: StoreServerAddr, store: Store) -> Result<()> {
    info!("rpc listening on: {}", addr);
    let mut stream = create_server_stream::<StoreService>(addr).await?;
    while let Some(server) = stream.next().await {
        match server {
            Ok(server) => {
                handle_session(server, store.clone()).await?;
            }
            Err(e) => {
                tracing::error!("rpc server error: {}", e);
            }
        }
    }
    Ok(())
}
