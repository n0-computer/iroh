//! API for tag management.

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use iroh_blobs::{BlobFormat, Hash, Tag};
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};

use super::RpcClient;
use crate::rpc_protocol::{DeleteTagRequest, ListTagsRequest};

/// Iroh tags client.
#[derive(Debug, Clone, RefCast)]
#[repr(transparent)]
pub struct Client {
    pub(super) rpc: RpcClient,
}

impl Client {
    /// List all tags.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<TagInfo>>> {
        let stream = self.rpc.server_streaming(ListTagsRequest::all()).await?;
        Ok(stream.map(|res| res.map_err(anyhow::Error::from)))
    }

    /// List all tags with a hash_seq format.
    pub async fn list_hash_seq(&self) -> Result<impl Stream<Item = Result<TagInfo>>> {
        let stream = self
            .rpc
            .server_streaming(ListTagsRequest::hash_seq())
            .await?;
        Ok(stream.map(|res| res.map_err(anyhow::Error::from)))
    }

    /// Delete a tag.
    pub async fn delete(&self, name: Tag) -> Result<()> {
        self.rpc.rpc(DeleteTagRequest { name }).await??;
        Ok(())
    }
}

/// Information about a tag.
#[derive(Debug, Serialize, Deserialize)]
pub struct TagInfo {
    /// Name of the tag
    pub name: Tag,
    /// Format of the data
    pub format: BlobFormat,
    /// Hash of the data
    pub hash: Hash,
}
