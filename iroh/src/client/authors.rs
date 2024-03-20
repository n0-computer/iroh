use anyhow::Result;
use futures::{Stream, TryStreamExt};
use iroh_sync::AuthorId;
use quic_rpc::{RpcClient, ServiceConnection};

use crate::rpc_protocol::{AuthorCreateRequest, AuthorListRequest, ProviderService};

use super::flatten;

/// Iroh authors client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<ProviderService, C>,
}

impl<C> Client<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Create a new document author.
    pub async fn create(&self) -> Result<AuthorId> {
        let res = self.rpc.rpc(AuthorCreateRequest).await??;
        Ok(res.author_id)
    }

    /// List document authors for which we have a secret key.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<AuthorId>>> {
        let stream = self.rpc.server_streaming(AuthorListRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| res.author_id))
    }
}
