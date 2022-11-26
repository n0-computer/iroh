use std::io::Cursor;

use anyhow::{Context, Result};
use cid::Cid;
use futures::StreamExt;
use iroh_rpc_client::{configure_server, create_server_stream, ChannelTypes};
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

/// Handle a session with a client. This will loop until either the client closes the connection or
/// one of the requests produces an error.
async fn handle_session(
    server: quic_rpc::RpcServer<StoreService, ChannelTypes>,
    store: Store,
) -> Result<()> {
    let s = server.clone();
    loop {
        let (req, chan) = s.accept_one().await?;
        println!("rpc request: {:?}", req);
        let store = store.clone();
        use StoreRequest::*;
        let res = match req {
            Version(req) => s.rpc(req, chan, store, Store::version).await,
            Put(req) => s.rpc_map_err(req, chan, store, Store::put).await,
            PutMany(req) => s.rpc_map_err(req, chan, store, Store::put_many).await,
            Get(req) => s.rpc_map_err(req, chan, store, Store::get).await,
            Has(req) => s.rpc_map_err(req, chan, store, Store::has).await,
            GetLinks(req) => s.rpc_map_err(req, chan, store, Store::get_links).await,
            GetSize(req) => s.rpc_map_err(req, chan, store, Store::get_size).await,
        };
        if let Err(res) = res {
            println!("rpc error: {:?}", res);
            break Err(res.into());
        }
    }
}

#[tracing::instrument(skip(store))]
pub async fn new(addr: StoreServerAddr, store: Store) -> Result<()> {
    info!("rpc listening on: {}", addr);
    let (server_config, _server_cert) = configure_server()?;
    let mut stream = create_server_stream::<StoreService>(server_config, addr).await?;
    while let Some(server) = stream.next().await {
        match server {
            Ok(server) => {
                tokio::spawn(handle_session(server, store.clone()));
            }
            Err(e) => {
                tracing::error!("rpc server error: {}", e);
            }
        }
    }
    Ok(())
}
