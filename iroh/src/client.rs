//! Client to an Iroh node.

use futures_lite::{Stream, StreamExt};
use ref_cast::RefCast;

#[doc(inline)]
pub use crate::rpc_protocol::RpcService;

mod quic;

#[deprecated]
pub use self::docs::Doc as MemDoc;
#[deprecated]
pub use self::docs::Doc as QuicDoc;
pub use self::docs::Doc;
pub use self::node::NodeStatus;
#[deprecated]
pub use self::Iroh as MemIroh;
#[deprecated]
pub use self::Iroh as QuicIroh;

pub(crate) use self::quic::{connect_raw as quic_connect_raw, RPC_ALPN};

pub mod authors;
pub mod blobs;
pub mod docs;
pub mod tags;

mod node;

/// Iroh rpc client - boxed so that we can have a concrete type.
pub(crate) type RpcClient =
    quic_rpc::RpcClient<RpcService, quic_rpc::transport::boxed::Connection<RpcService>>;

/// Iroh client.
#[derive(Debug, Clone)]
pub struct Iroh {
    rpc: RpcClient,
}

impl Iroh {
    /// Create a new high-level client to a Iroh node from the low-level RPC client.
    pub fn new(rpc: RpcClient) -> Self {
        Self { rpc }
    }

    /// Blobs client
    pub fn blobs(&self) -> &blobs::Client {
        blobs::Client::ref_cast(&self.rpc)
    }

    /// Docs client
    pub fn docs(&self) -> &docs::Client {
        docs::Client::ref_cast(&self.rpc)
    }

    /// Authors client
    pub fn authors(&self) -> &authors::Client {
        authors::Client::ref_cast(&self.rpc)
    }

    /// Tags client
    pub fn tags(&self) -> &tags::Client {
        tags::Client::ref_cast(&self.rpc)
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
