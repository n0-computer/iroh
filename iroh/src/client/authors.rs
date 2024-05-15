//! API for author management.

use anyhow::Result;
use futures_lite::{stream::StreamExt, Stream};
use iroh_docs::{Author, AuthorId};
use quic_rpc::{RpcClient, ServiceConnection};

use crate::rpc_protocol::{
    AuthorCreateRequest, AuthorDefaultRequest, AuthorDeleteRequest, AuthorExportRequest,
    AuthorImportRequest, AuthorListRequest, RpcService,
};

use super::flatten;

/// Iroh authors client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<RpcService, C>,
}

impl<C> Client<C>
where
    C: ServiceConnection<RpcService>,
{
    /// Create a new document author.
    ///
    /// You likely want to save the returned [`AuthorId`] somewhere so that you can use this author
    /// again.
    ///
    /// If you need only a single author, use [`Self::default`].
    pub async fn create(&self) -> Result<AuthorId> {
        let res = self.rpc.rpc(AuthorCreateRequest).await??;
        Ok(res.author_id)
    }

    /// Returns the default document author of this node.
    ///
    /// On persistent nodes, the author is created on first start and its public key is saved
    /// in the data directory.
    ///
    /// The default author can neither be changed nor deleted. If you need more semantics around
    /// authors than a single author per node, use [`Self::create`].
    pub async fn default(&self) -> Result<AuthorId> {
        let res = self.rpc.rpc(AuthorDefaultRequest).await?;
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
    ///
    /// Returns an error if attempting to delete the default author.
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

        // default author always exists
        let authors: Vec<_> = node.authors.list().await?.try_collect().await?;
        assert_eq!(authors.len(), 1);
        let default_author = node.authors.default().await?;
        assert_eq!(authors, vec![default_author]);

        let author_id = node.authors.create().await?;

        let authors: Vec<_> = node.authors.list().await?.try_collect().await?;
        assert_eq!(authors.len(), 2);

        let author = node
            .authors
            .export(author_id)
            .await?
            .expect("should have author");
        node.authors.delete(author_id).await?;
        let authors: Vec<_> = node.authors.list().await?.try_collect().await?;
        assert!(authors.is_empty());

        node.authors.import(author).await?;

        let authors: Vec<_> = node.authors.list().await?.try_collect().await?;
        assert_eq!(authors.len(), 2);

        Ok(())
    }
}
