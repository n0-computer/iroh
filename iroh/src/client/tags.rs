//! API for tag management.

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use iroh_blobs::{BlobFormat, Hash, HashAndFormat, Tag};
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};

use super::RpcClient;
use crate::rpc_protocol::{CreateTagRequest, ListTagsRequest, SetTagRequest};

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

    /// Create a tag, where the name is automatically generated.
    ///
    /// Use this method if you want a new tag with a unique name.
    pub async fn create(&self, value: HashAndFormat) -> Result<Tag> {
        Ok(self
            .rpc
            .rpc(CreateTagRequest { value, batch: None })
            .await??)
    }

    /// Set a tag to a value, overwriting any existing value.
    ///
    /// This is a convenience wrapper around `set_opt`.
    pub async fn set(&self, name: Tag, value: HashAndFormat) -> Result<()> {
        self.set_with_opts(name, Some(value)).await
    }

    /// Delete a tag.
    ///
    /// This is a convenience wrapper around `set_opt`.
    pub async fn delete(&self, name: Tag) -> Result<()> {
        self.set_with_opts(name, None).await
    }

    /// Set a tag to a value, overwriting any existing value.
    ///
    /// Setting the value to `None` deletes the tag. Setting the value to `Some` creates or updates the tag.
    pub async fn set_with_opts(&self, name: Tag, value: Option<HashAndFormat>) -> Result<()> {
        self.rpc
            .rpc(SetTagRequest {
                name,
                value,
                batch: None,
            })
            .await??;
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
