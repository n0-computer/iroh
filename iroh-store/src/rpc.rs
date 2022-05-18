use std::io::Cursor;
use std::net::SocketAddr;

// use bytes::Bytes;
use anyhow::Result;
use cid::Cid;
use iroh_rpc_types::store::store_server;
use iroh_rpc_types::store::{
    GetLinksRequest, GetLinksResponse, GetRequest, GetResponse, PutRequest,
};
use tonic::{transport::Server as TonicServer, Request, Response, Status};
use tracing::info;

use crate::store::Store;

struct Rpc {
    store: Store,
}

#[tonic::async_trait]
impl store_server::Store for Rpc {
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
            todo!("return DBPinnableSlice as Bytes")
            // Ok(Response::new(GetResponse {
            //     data: Some(Bytes::from(res)),
            // }))
        } else {
            Ok(Response::new(GetResponse { data: None }))
        }
    }

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

pub async fn new(addr: SocketAddr, store: Store) -> Result<()> {
    let rpc = Rpc { store };
    TonicServer::builder()
        .add_service(store_server::StoreServer::new(rpc))
        .serve(addr)
        .await?;
    Ok(())
}

fn cid_from_bytes(b: Vec<u8>) -> Result<Cid, tonic::Status> {
    Cid::read_bytes(Cursor::new(b))
        .map_err(|e| Status::invalid_argument(format!("invalid cid: {:?}", e)))
}

fn links_from_bytes(l: Vec<Vec<u8>>) -> Result<Vec<Cid>, tonic::Status> {
    l.into_iter().map(cid_from_bytes).collect()
}
