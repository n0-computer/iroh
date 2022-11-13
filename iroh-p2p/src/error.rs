use libp2p::PeerId;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RpcTypes(#[from] iroh_rpc_types::error::Error),

    #[error(transparent)]
    RpcClient(#[from] iroh_rpc_client::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Libp2pMultiHash(#[from] libp2p::core::multiaddr::multihash::Error),

    #[error(transparent)]
    Libp2pMultiaddr(#[from] libp2p::core::multiaddr::Error),

    #[error(transparent)]
    Cid(#[from] cid::Error),

    #[error("bitswap req shut down")]
    BitswapReqShutdown,

    #[error("No bitswap available")]
    NoBitswapAvailable,

    #[error("Failed to find peer {} on the DHT", .0)]
    FailedToFindPeer(PeerId),

    #[error("Failed to find peer {} on the DHT: Timeout", .0)]
    FailedToFindPeerTimeout(PeerId),

    #[error("Error upgrading connection to peer {}: {}", .0, .1)]
    UpgradingConnectionToPeer(PeerId, String),

    #[error("Unexpected bitswap response, expected {}, got {}", .expected, .got)]
    UnexpBitswapResponse { expected: cid::Cid, got: cid::Cid },

    #[error("Missing providers for: {}", .0)]
    MissingProviders(cid::Cid),

    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("Not found")]
    NotFound,

    #[error(transparent)]
    TokioMpscSendRpcMessage(#[from] tokio::sync::mpsc::error::SendError<crate::rpc::RpcMessage>),

    #[error(transparent)]
    TokioMpscRecv(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("{}", .0)]
    Gossipsub(&'static str),

    // TODO: See https://github.com/libp2p/rust-libp2p/pull/3114
    #[error("No known peers")]
    NoKnownPeers,

    #[error(transparent)]
    GossipsubPublish(#[from] libp2p::gossipsub::error::PublishError),

    #[error(transparent)]
    GossipsubSubscription(#[from] libp2p::gossipsub::error::SubscriptionError),

    #[error("Kademila is not available")]
    KademilaNotAvailable,

    #[error("Failed to get Libp2p listeners")]
    FailedToGetLibp2pListeners,

    #[error("Failed to get Libp2p peers")]
    FailedToGetLibp2pPeers,

    #[error("Error dialing peer {:?}: {}", .0, .1)]
    ErrorDialingPeer(PeerId, String),

    #[error("Sender dropped")]
    SenderDropped,

    #[error("inconsistent keystate")]
    InconsistentKeyState,

    #[error("Unsupported key format: {}", .0.as_str())]
    UnsupportedKeyFormat(ssh_key::Algorithm),

    #[error(transparent)]
    Ssh(#[from] ssh_key::Error),

    #[error(transparent)]
    Kad(#[from] libp2p::kad::store::Error),

    #[error("Invalid RPC address")]
    InvalidRpcAddr,

    #[error("can not derive rpc_addr for mem addr")]
    CannotDeriveRpcAddrFromMemAddr,

    // TODO: Make me nice
    #[error("{}", .0)]
    Str(String),
}
