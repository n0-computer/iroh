use iroh_base::rpc::RpcResult;
use iroh_blobs::Tag;
use nested_enum_utils::enum_conversions;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use crate::client::tags::TagInfo;

use super::RpcService;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[rpc(response = RpcResult<()>)]
    DeleteTag(DeleteRequest),
    #[server_streaming(response = TagInfo)]
    ListTags(ListRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Response)]
pub enum Response {
    ListTags(TagInfo),
    DeleteTag(RpcResult<()>),
}

/// List all collections
///
/// Lists all collections that have been explicitly added to the database.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListRequest {
    /// List raw tags
    pub raw: bool,
    /// List hash seq tags
    pub hash_seq: bool,
}

impl ListRequest {
    /// List all tags
    pub fn all() -> Self {
        Self {
            raw: true,
            hash_seq: true,
        }
    }

    /// List raw tags
    pub fn raw() -> Self {
        Self {
            raw: true,
            hash_seq: false,
        }
    }

    /// List hash seq tags
    pub fn hash_seq() -> Self {
        Self {
            raw: false,
            hash_seq: true,
        }
    }
}

/// Delete a tag
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    /// Name of the tag
    pub name: Tag,
}
