use iroh_base::rpc::RpcResult;
use iroh_docs::{Author, AuthorId};
use nested_enum_utils::enum_conversions;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use super::RpcService;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[server_streaming(response = RpcResult<ListResponse>)]
    List(ListRequest),
    #[rpc(response = RpcResult<CreateResponse>)]
    Create(CreateRequest),
    #[rpc(response = RpcResult<GetDefaultResponse>)]
    GetDefault(GetDefaultRequest),
    #[rpc(response = RpcResult<SetDefaultResponse>)]
    SetDefault(SetDefaultRequest),
    #[rpc(response = RpcResult<ImportResponse>)]
    Import(ImportRequest),
    #[rpc(response = RpcResult<ExportResponse>)]
    Export(ExportRequest),
    #[rpc(response = RpcResult<DeleteResponse>)]
    Delete(DeleteRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Response)]
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

/// Response for [`ListRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ListResponse {
    /// The author id
    pub author_id: AuthorId,
}

/// Create a new document author.
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateRequest;

/// Response for [`CreateRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateResponse {
    /// The id of the created author
    pub author_id: AuthorId,
}

/// Get the default author.
#[derive(Serialize, Deserialize, Debug)]
pub struct GetDefaultRequest;

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

/// Response for [`GetDefaultRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct SetDefaultResponse;

/// Delete an author
#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteRequest {
    /// The id of the author to delete
    pub author: AuthorId,
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

/// Response to [`ImportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportResponse {
    /// The author id of the imported author
    pub author_id: AuthorId,
}
