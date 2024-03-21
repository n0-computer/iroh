use anyhow::Result;
use futures::{Stream, TryStreamExt};
use iroh_bytes::Tag;
use quic_rpc::{RpcClient, ServiceConnection};

use crate::rpc_protocol::{DeleteTagRequest, ListTagsRequest, ListTagsResponse, ProviderService};

/// Iroh tags client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<ProviderService, C>,
}

impl<C> Client<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// List all tags.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<ListTagsResponse>>> {
        let stream = self.rpc.server_streaming(ListTagsRequest).await?;
        Ok(stream.map_err(anyhow::Error::from))
    }

    /// Delete a tag.
    pub async fn delete(&self, name: Tag) -> Result<()> {
        self.rpc.rpc(DeleteTagRequest { name }).await??;
        Ok(())
    }
}
