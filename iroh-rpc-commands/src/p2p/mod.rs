/// Events emitted by this Service.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum NetworkEvent {
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    BitswapBlock { cid: Cid },
}

/// Messages into the service to handle.
#[derive(Debug)]
pub enum NetworkMessage {
    BitswapRequest {
        cids: Vec<Cid>,
        response_channels: Vec<OneShotSender<()>>,
        providers: Option<HashSet<PeerId>>,
    },
    RpcRequest {
        method: NetRPCMethods,
    },
    ProviderRequest {
        key: Key,
        response_channel: OneShotSender<Option<Result<HashSet<PeerId>, String>>>,
    },
}

/// Network RPC API methods used to gather data from libp2p node.
#[derive(Debug)]
pub enum NetRPCMethods {
    NetAddrsListen(OneShotSender<(PeerId, Vec<Multiaddr>)>),
    NetPeers(OneShotSender<HashMap<PeerId, Vec<Multiaddr>>>),
    NetConnect(OneShotSender<bool>, PeerId, Vec<Multiaddr>),
    NetDisconnect(OneShotSender<()>, PeerId),
}
