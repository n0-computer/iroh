#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    TonicTransport(#[from] tonic::transport::Error),

    #[error(transparent)]
    RpcError(#[from] iroh_rpc_types::error::Error),

    #[error(transparent)]
    Libp2pMultiHash(#[from] libp2p::core::multiaddr::multihash::Error),

    #[error(transparent)]
    Libp2pMultiaddr(#[from] libp2p::core::multiaddr::Error),

    #[error(transparent)]
    Cid(#[from] cid::Error),

    // TODO: See https://github.com/libp2p/rust-libp2p/pull/3113
    #[error("Parsing PeerId failed: {}", .0)]
    ParsingPeerId(String),

    #[error("Could not create gateway rpc client")]
    CreateGatewayRpcClient,

    #[error("missing rpc p2p connnection")]
    MissingP2pConn,

    #[error("missing rpc gateway connnection")]
    MissingRpcGatewayConn,

    #[error("missing rpc store connnection")]
    MissingRpcStoreConn,

    #[error("Unknown Service {}", .0)]
    UnknownService(String),
}
