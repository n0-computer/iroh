use iroh_base::rpc::RpcResult;
use iroh_docs::{Author, AuthorId};
use quic_rpc::message::{Msg, RpcMsg, ServerStreaming, ServerStreamingMsg};
use serde::{Deserialize, Serialize};

use super::RpcService;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Request)]
pub enum Request {
    List(AuthorListRequest),
    Create(AuthorCreateRequest),
    GetDefault(AuthorGetDefaultRequest),
    SetDefault(AuthorSetDefaultRequest),
    Import(AuthorImportRequest),
    Export(AuthorExportRequest),
    Delete(AuthorDeleteRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Response)]
pub enum Response {
    List(RpcResult<AuthorListResponse>),
    Create(RpcResult<AuthorCreateResponse>),
    GetDefault(RpcResult<AuthorGetDefaultResponse>),
    SetDefault(RpcResult<AuthorSetDefaultResponse>),
    Import(RpcResult<AuthorImportResponse>),
    Export(RpcResult<AuthorExportResponse>),
    Delete(RpcResult<AuthorDeleteResponse>),
}

/// List document authors for which we have a secret key.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorListRequest {}

impl Msg<RpcService> for AuthorListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for AuthorListRequest {
    type Response = RpcResult<AuthorListResponse>;
}

/// Response for [`AuthorListRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorListResponse {
    /// The author id
    pub author_id: AuthorId,
}

/// Create a new document author.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorCreateRequest;

impl RpcMsg<RpcService> for AuthorCreateRequest {
    type Response = RpcResult<AuthorCreateResponse>;
}

/// Response for [`AuthorCreateRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorCreateResponse {
    /// The id of the created author
    pub author_id: AuthorId,
}

/// Get the default author.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorGetDefaultRequest;

impl RpcMsg<RpcService> for AuthorGetDefaultRequest {
    type Response = RpcResult<AuthorGetDefaultResponse>;
}

/// Response for [`AuthorGetDefaultRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorGetDefaultResponse {
    /// The id of the author
    pub author_id: AuthorId,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorSetDefaultRequest {
    /// The id of the author
    pub author_id: AuthorId,
}

impl RpcMsg<RpcService> for AuthorSetDefaultRequest {
    type Response = RpcResult<AuthorSetDefaultResponse>;
}

/// Response for [`AuthorGetDefaultRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorSetDefaultResponse;

/// Delete an author
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorDeleteRequest {
    /// The id of the author to delete
    pub author: AuthorId,
}

impl RpcMsg<RpcService> for AuthorDeleteRequest {
    type Response = RpcResult<AuthorDeleteResponse>;
}

/// Response for [`AuthorDeleteRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorDeleteResponse;

/// Exports an author
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorExportRequest {
    /// The id of the author to delete
    pub author: AuthorId,
}

impl RpcMsg<RpcService> for AuthorExportRequest {
    type Response = RpcResult<AuthorExportResponse>;
}

/// Response for [`AuthorExportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorExportResponse {
    /// The author
    pub author: Option<Author>,
}

/// Import author from secret key
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorImportRequest {
    /// The author to import
    pub author: Author,
}

impl RpcMsg<RpcService> for AuthorImportRequest {
    type Response = RpcResult<AuthorImportResponse>;
}

/// Response to [`AuthorImportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorImportResponse {
    /// The author id of the imported author
    pub author_id: AuthorId,
}
