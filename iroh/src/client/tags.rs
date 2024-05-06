//! API for tag management.

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use iroh_bytes::{BlobFormat, Hash, Tag};
use quic_rpc::{RpcClient, ServiceConnection};
use serde::{Deserialize, Serialize};

use crate::rpc_protocol::{DeleteTagRequest, ListTagsRequest, RpcService};

/// Iroh tags client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<RpcService, C>,
}

impl<C> Client<C>
where
    C: ServiceConnection<RpcService>,
{
    /// List all tags.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<TagInfo>>> {
        let stream = self.rpc.server_streaming(ListTagsRequest).await?;
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
