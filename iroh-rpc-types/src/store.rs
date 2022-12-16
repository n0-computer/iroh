use std::fmt::{self, Debug};

use bytes::Bytes;
use cid::Cid;
use derive_more::{From, TryInto};
use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming},
    Service,
};
use serde::{Deserialize, Serialize};

use crate::{RpcResult, VersionRequest, VersionResponse, WatchRequest, WatchResponse};

pub type StoreAddr = super::addr::Addr<StoreService>;

#[derive(Serialize, Deserialize)]
pub struct PutRequest {
    pub cid: Cid,
    pub blob: Bytes,
    pub links: Vec<Cid>,
}

impl fmt::Debug for PutRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PutRequest")
            .field("cid", &self.cid)
            .field("blob", &self.blob.len())
            .field("links", &self.links)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PutManyRequest {
    pub blocks: Vec<PutRequest>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetRequest {
    pub cid: Cid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetResponse {
    pub data: Option<Bytes>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HasRequest {
    pub cid: Cid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HasResponse {
    pub has: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetLinksRequest {
    pub cid: Cid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetLinksResponse {
    pub links: Option<Vec<Cid>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetSizeRequest {
    pub cid: Cid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetSizeResponse {
    pub size: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, From, TryInto)]
pub enum StoreRequest {
    Watch(WatchRequest),
    Version(VersionRequest),
    Put(PutRequest),
    PutMany(PutManyRequest),
    Get(GetRequest),
    Has(HasRequest),
    GetLinks(GetLinksRequest),
    GetSize(GetSizeRequest),
}

#[derive(Serialize, Deserialize, Debug, From, TryInto)]
pub enum StoreResponse {
    Watch(WatchResponse),
    Version(VersionResponse),
    Get(RpcResult<GetResponse>),
    Has(RpcResult<HasResponse>),
    GetLinks(RpcResult<GetLinksResponse>),
    GetSize(RpcResult<GetSizeResponse>),
    Unit(()),
    UnitResult(RpcResult<()>),
}

#[derive(Debug, Clone, Copy)]
pub struct StoreService;

impl Service for StoreService {
    type Req = StoreRequest;

    type Res = StoreResponse;
}

impl Msg<StoreService> for WatchRequest {
    type Response = WatchResponse;

    type Update = Self;

    type Pattern = ServerStreaming;
}

impl RpcMsg<StoreService> for VersionRequest {
    type Response = VersionResponse;
}

impl RpcMsg<StoreService> for GetRequest {
    type Response = RpcResult<GetResponse>;
}

impl RpcMsg<StoreService> for PutRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<StoreService> for HasRequest {
    type Response = RpcResult<HasResponse>;
}

impl RpcMsg<StoreService> for PutManyRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<StoreService> for GetLinksRequest {
    type Response = RpcResult<GetLinksResponse>;
}

impl RpcMsg<StoreService> for GetSizeRequest {
    type Response = RpcResult<GetSizeResponse>;
}
