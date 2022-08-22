include_proto!("p2p");

proxy!(
    P2p,
    version: () => VersionResponse,
    shutdown: () => (),
    fetch_bitswap: BitswapRequest => BitswapResponse,
    fetch_provider_dht: Key => Providers,
    fetch_provider_bitswap: Key => Providers,
    get_listening_addrs: () => GetListeningAddrsResponse,
    get_peers: () => GetPeersResponse,
    peer_connect: ConnectRequest => ConnectResponse,
    peer_disconnect: DisconnectRequest => (),
    gossipsub_add_explicit_peer: GossipsubPeerIdMsg => (),
    gossipsub_all_mesh_peers: () => GossipsubPeersResponse,
    gossipsub_all_peers: () => GossipsubAllPeersResponse,
    gossipsub_mesh_peers: GossipsubTopicHashMsg => GossipsubPeersResponse,
    gossipsub_publish: GossipsubPublishRequest => GossipsubPublishResponse,
    gossipsub_remove_explicit_peer: GossipsubPeerIdMsg => (),
    gossipsub_subscribe: GossipsubTopicHashMsg => GossipsubSubscribeResponse,
    gossipsub_topics: () => GossipsubTopicsResponse,
    gossipsub_unsubscribe: GossipsubTopicHashMsg => GossipsubSubscribeResponse
);
