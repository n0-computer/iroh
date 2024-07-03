use iroh_base::rpc::RpcResult;
use iroh_docs::{Author, AuthorId};
use quic_rpc::message::{Msg, RpcMsg, ServerStreaming, ServerStreamingMsg};
use serde::{Deserialize, Serialize};

use super::RpcService;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Request)]
pub enum Request {
    List(ListRequest),
    Create(CreateRequest),
    GetDefault(GetDefaultRequest),
    SetDefault(SetDefaultRequest),
    Import(ImportRequest),
    Export(ExportRequest),
    Delete(DeleteRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Response)]
pub enum Response {
    List(RpcResult<ListResponse>),
    Create(RpcResult<CreateResponse>),
    GetDefault(RpcResult<GetDefaultResponse>),
    SetDefault(RpcResult<SetDefaultResponse>),
    Import(RpcResult<ImportResponse>),
    Export(RpcResult<ExportResponse>),
    Delete(RpcResult<DeleteResponse>),
}

/// List document authors for which we have a secret key.
#[derive(Serialize, Deserialize, Debug)]
pub struct ListRequest {}

impl Msg<RpcService> for ListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for ListRequest {
    type Response = RpcResult<ListResponse>;
}

/// Response for [`ListRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ListResponse {
    /// The author id
    pub author_id: AuthorId,
}

/// Create a new document author.
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateRequest;

impl RpcMsg<RpcService> for CreateRequest {
    type Response = RpcResult<CreateResponse>;
}

/// Response for [`CreateRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateResponse {
    /// The id of the created author
    pub author_id: AuthorId,
}

/// Get the default author.
#[derive(Serialize, Deserialize, Debug)]
pub struct GetDefaultRequest;

impl RpcMsg<RpcService> for GetDefaultRequest {
    type Response = RpcResult<GetDefaultResponse>;
}

/// Response for [`GetDefaultRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct GetDefaultResponse {
    /// The id of the author
    pub author_id: AuthorId,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetDefaultRequest {
    /// The id of the author
    pub author_id: AuthorId,
}

impl RpcMsg<RpcService> for SetDefaultRequest {
    type Response = RpcResult<SetDefaultResponse>;
}

/// Response for [`GetDefaultRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct SetDefaultResponse;

/// Delete an author
#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteRequest {
    /// The id of the author to delete
    pub author: AuthorId,
}

impl RpcMsg<RpcService> for DeleteRequest {
    type Response = RpcResult<DeleteResponse>;
}

/// Response for [`DeleteRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteResponse;

/// Exports an author
#[derive(Serialize, Deserialize, Debug)]
pub struct ExportRequest {
    /// The id of the author to delete
    pub author: AuthorId,
}

impl RpcMsg<RpcService> for ExportRequest {
    type Response = RpcResult<ExportResponse>;
}

/// Response for [`ExportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ExportResponse {
    /// The author
    pub author: Option<Author>,
}

/// Import author from secret key
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportRequest {
    /// The author to import
    pub author: Author,
}

impl RpcMsg<RpcService> for ImportRequest {
    type Response = RpcResult<ImportResponse>;
}

/// Response to [`ImportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportResponse {
    /// The author id of the imported author
    pub author_id: AuthorId,
}
