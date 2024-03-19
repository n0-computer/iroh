//! Client to an iroh node. Is generic over the connection (in-memory or RPC).
//!
//! TODO: Contains only iroh sync related methods. Add other methods.

use futures::{Stream, StreamExt};
use quic_rpc::{RpcClient, ServiceConnection};

use crate::rpc_protocol::ProviderService;

pub mod mem;
pub mod quic;

mod authors;
mod blobs;
mod docs;
mod node;
mod tags;

pub use self::authors::Client as AuthorsClient;
pub use self::blobs::{
    BlobAddOutcome, BlobAddProgress, BlobDownloadOutcome, BlobDownloadProgress, BlobStatus,
    Client as BlobsClient, ShareTicketOptions,
};
pub use self::docs::{Client as DocsClient, Doc, Entry, LiveEvent};
pub use self::node::Client as NodeClient;
pub use self::tags::Client as TagsClient;

/// Iroh client
#[derive(Debug, Clone)]
pub struct Iroh<C> {
    /// Client for node operations.
    pub node: NodeClient<C>,
    /// Client for blobs operations.
    pub blobs: BlobsClient<C>,
    /// Client for docs operations.
    pub docs: DocsClient<C>,
    /// Client for author operations.
    pub authors: AuthorsClient<C>,
    /// Client for tags operations.
    pub tags: TagsClient<C>,
}

impl<C> Iroh<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Create a new high-level client to a Iroh node from the low-level RPC client.
    pub fn new(rpc: RpcClient<ProviderService, C>) -> Self {
        Self {
            node: NodeClient { rpc: rpc.clone() },
            blobs: BlobsClient { rpc: rpc.clone() },
            docs: DocsClient { rpc: rpc.clone() },
            authors: AuthorsClient { rpc: rpc.clone() },
            tags: TagsClient { rpc },
        }
    }
}

fn flatten<T, E1, E2>(
    s: impl Stream<Item = Result<Result<T, E1>, E2>>,
) -> impl Stream<Item = anyhow::Result<T>>
where
    E1: std::error::Error + Send + Sync + 'static,
    E2: std::error::Error + Send + Sync + 'static,
{
    s.map(|res| match res {
        Ok(Ok(res)) => Ok(res),
        Ok(Err(err)) => Err(err.into()),
        Err(err) => Err(err.into()),
    })
}
