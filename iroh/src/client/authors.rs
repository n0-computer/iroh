use anyhow::Result;
use futures_lite::{stream::StreamExt, Stream};
use iroh_sync::{Author, AuthorId};
use quic_rpc::{RpcClient, ServiceConnection};

use crate::rpc_protocol::{
    AuthorCreateRequest, AuthorDeleteRequest, AuthorExportRequest, AuthorImportRequest,
    AuthorListRequest, ProviderService,
};

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
        Ok(flatten(stream).map(|res| res.map(|res| res.author_id)))
    }

    /// Export the given author.
    ///
    /// Warning: This contains sensitive data.
    pub async fn export(&self, author: AuthorId) -> Result<Option<Author>> {
        let res = self.rpc.rpc(AuthorExportRequest { author }).await??;
        Ok(res.author)
    }

    /// Import the given author.
    ///
    /// Warning: This contains sensitive data.
    pub async fn import(&self, author: Author) -> Result<()> {
        self.rpc.rpc(AuthorImportRequest { author }).await??;
        Ok(())
    }

    /// Deletes the given author by id.
    ///
    /// Warning: This permanently removes this author.
    pub async fn delete(&self, author: AuthorId) -> Result<()> {
        self.rpc.rpc(AuthorDeleteRequest { author }).await??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::node::Node;

    use super::*;

    #[tokio::test]
    async fn test_authors() -> Result<()> {
        let node = Node::memory().spawn().await?;

        let author_id = node.authors.create().await?;

        assert_eq!(
            node.authors
                .list()
                .await?
                .try_collect::<Vec<_>>()
                .await?
                .len(),
            1
        );

        let author = node
            .authors
            .export(author_id)
            .await?
            .expect("should have author");
        node.authors.delete(author_id).await?;
        assert!(node
            .authors
            .list()
            .await?
            .try_collect::<Vec<_>>()
            .await?
            .is_empty());

        node.authors.import(author).await?;
        assert_eq!(
            node.authors
                .list()
                .await?
                .try_collect::<Vec<_>>()
                .await?
                .len(),
            1
        );

        Ok(())
    }
}
