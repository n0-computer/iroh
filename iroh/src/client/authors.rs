//! API for author management.
//!
//! The main entry point is the [`Client`].
//!
//! You obtain a [`Client`] via [`Iroh::authors()`](crate::client::Iroh::authors).

use anyhow::Result;
use futures_lite::{stream::StreamExt, Stream};
use iroh_docs::{Author, AuthorId};
use ref_cast::RefCast;

use crate::rpc_protocol::authors::{
    CreateRequest, DeleteRequest, ExportRequest, GetDefaultRequest, ImportRequest, ListRequest,
    SetDefaultRequest,
};

use super::{flatten, RpcClient};

/// Iroh authors client.
#[derive(Debug, Clone, RefCast)]
#[repr(transparent)]
pub struct Client {
    pub(super) rpc: RpcClient,
}

impl Client {
    /// Creates a new document author.
    ///
    /// You likely want to save the returned [`AuthorId`] somewhere so that you can use this author
    /// again.
    ///
    /// If you need only a single author, use [`Self::default`].
    pub async fn create(&self) -> Result<AuthorId> {
        let res = self.rpc.rpc(CreateRequest).await??;
        Ok(res.author_id)
    }

    /// Returns the default document author of this node.
    ///
    /// On persistent nodes, the author is created on first start and its public key is saved
    /// in the data directory.
    ///
    /// The default author can be set with [`Self::set_default`].
    pub async fn default(&self) -> Result<AuthorId> {
        let res = self.rpc.rpc(GetDefaultRequest).await??;
        Ok(res.author_id)
    }

    /// Sets the node-wide default author.
    ///
    /// If the author does not exist, an error is returned.
    ///
    /// On a persistent node, the author id will be saved to a file in the data directory and
    /// reloaded after a restart.
    pub async fn set_default(&self, author_id: AuthorId) -> Result<()> {
        self.rpc.rpc(SetDefaultRequest { author_id }).await??;
        Ok(())
    }

    /// Lists document authors for which we have a secret key.
    ///
    /// It's only possible to create writes from authors that we have the secret key of.
    pub async fn list(&self) -> Result<impl Stream<Item = Result<AuthorId>>> {
        let stream = self.rpc.server_streaming(ListRequest {}).await?;
        Ok(flatten(stream).map(|res| res.map(|res| res.author_id)))
    }

    /// Exports the given author.
    ///
    /// Warning: The [`Author`] struct contains sensitive data.
    pub async fn export(&self, author: AuthorId) -> Result<Option<Author>> {
        let res = self.rpc.rpc(ExportRequest { author }).await??;
        Ok(res.author)
    }

    /// Imports the given author.
    ///
    /// Warning: The [`Author`] struct contains sensitive data.
    pub async fn import(&self, author: Author) -> Result<()> {
        self.rpc.rpc(ImportRequest { author }).await??;
        Ok(())
    }

    /// Deletes the given author by id.
    ///
    /// Warning: This permanently removes this author.
    ///
    /// Returns an error if attempting to delete the default author.
    pub async fn delete(&self, author: AuthorId) -> Result<()> {
        self.rpc.rpc(DeleteRequest { author }).await??;
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
        let authors: Vec<_> = node.authors().list().await?.try_collect().await?;
        assert_eq!(authors.len(), 1);
        let default_author = node.authors().default().await?;
        assert_eq!(authors, vec![default_author]);

        let author_id = node.authors().create().await?;

        let authors: Vec<_> = node.authors().list().await?.try_collect().await?;
        assert_eq!(authors.len(), 2);

        let author = node
            .authors()
            .export(author_id)
            .await?
            .expect("should have author");
        node.authors().delete(author_id).await?;
        let authors: Vec<_> = node.authors().list().await?.try_collect().await?;
        assert_eq!(authors.len(), 1);

        node.authors().import(author).await?;

        let authors: Vec<_> = node.authors().list().await?.try_collect().await?;
        assert_eq!(authors.len(), 2);

        assert!(node.authors().default().await? != author_id);
        node.authors().set_default(author_id).await?;
        assert_eq!(node.authors().default().await?, author_id);

        Ok(())
    }
}
