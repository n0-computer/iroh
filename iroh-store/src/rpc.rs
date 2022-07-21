use std::io::Cursor;

use anyhow::Result;
use bytes::BytesMut;
use cid::Cid;
use iroh_rpc_client::Addr;
use iroh_rpc_types::store::store_server;
use iroh_rpc_types::store::{
    GetLinksRequest, GetLinksResponse, GetRequest, GetResponse, HasRequest, HasResponse,
    PutRequest, VersionResponse,
};
use tonic::{
    transport::{NamedService, Server as TonicServer},
    Request, Response, Status,
};
use tracing::info;

use crate::store::Store;

struct Rpc {
    store: Store,
}

#[tonic::async_trait]
impl store_server::Store for Rpc {
    #[tracing::instrument(skip(self))]
    async fn version(
        &self,
        _request: Request<()>,
    ) -> Result<Response<VersionResponse>, tonic::Status> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(Response::new(VersionResponse { version }))
    }

    #[tracing::instrument(skip(self, request))]
    async fn put(&self, request: Request<PutRequest>) -> Result<Response<()>, tonic::Status> {
        let req = request.into_inner();
        let cid = cid_from_bytes(req.cid)?;
        let links = links_from_bytes(req.links)?;
        let res = self
            .store
            .put(cid, req.blob, links)
            .await
            .map_err(|e| Status::internal(format!("{:?}", e)))?;

        info!("store rpc call: put cid {}", cid);
        Ok(Response::new(res))
    }

    #[tracing::instrument(skip(self))]
    async fn get(
        &self,
        request: Request<GetRequest>,
    ) -> Result<Response<GetResponse>, tonic::Status> {
        let req = request.into_inner();
        let cid = cid_from_bytes(req.cid)?;
        if let Some(res) = self
            .store
            .get(&cid)
            .await
            .map_err(|e| Status::internal(format!("{:?}", e)))?
        {
            Ok(Response::new(GetResponse {
                data: Some(BytesMut::from(&res[..]).freeze()),
            }))
        } else {
            Ok(Response::new(GetResponse { data: None }))
        }
    }

    #[tracing::instrument(skip(self))]
    async fn has(
        &self,
        request: Request<HasRequest>,
    ) -> Result<Response<HasResponse>, tonic::Status> {
        let req = request.into_inner();
        let cid = cid_from_bytes(req.cid)?;
        let has = self
            .store
            .has(&cid)
            .await
            .map_err(|e| Status::internal(format!("{:?}", e)))?;

        Ok(Response::new(HasResponse { has }))
    }

    #[tracing::instrument(skip(self))]
    async fn get_links(
        &self,
        request: Request<GetLinksRequest>,
    ) -> Result<Response<GetLinksResponse>, tonic::Status> {
        let req = request.into_inner();
        let cid = cid_from_bytes(req.cid)?;
        if let Some(res) = self
            .store
            .get_links(&cid)
            .await
            .map_err(|e| Status::internal(format!("{:?}", e)))?
        {
            let links = res.into_iter().map(|cid| cid.to_bytes()).collect();
            Ok(Response::new(GetLinksResponse { links }))
        } else {
            Ok(Response::new(GetLinksResponse { links: Vec::new() }))
        }
    }
}

impl NamedService for Rpc {
    const NAME: &'static str = "store";
}

#[tracing::instrument(skip(store))]
pub async fn new(addr: Addr, store: Store) -> Result<()> {
    let rpc = Rpc { store };
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<store_server::StoreServer<Rpc>>()
        .await;

    match addr {
        Addr::GrpcHttp2(addr) => {
            TonicServer::builder()
                .add_service(health_service)
                .add_service(store_server::StoreServer::new(rpc))
                .serve(addr)
                .await?;
        }
        Addr::GrpcUds(_) => unimplemented!(),
        Addr::Mem => unimplemented!(),
    }
    Ok(())
}

#[tracing::instrument]
fn cid_from_bytes(b: Vec<u8>) -> Result<Cid, tonic::Status> {
    Cid::read_bytes(Cursor::new(b))
        .map_err(|e| Status::invalid_argument(format!("invalid cid: {:?}", e)))
}

#[tracing::instrument]
fn links_from_bytes(l: Vec<Vec<u8>>) -> Result<Vec<Cid>, tonic::Status> {
    l.into_iter().map(cid_from_bytes).collect()
}
