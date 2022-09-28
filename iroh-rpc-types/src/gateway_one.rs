include_proto!("gatewayone");

#[allow(clippy::all)]
pub mod gateway {
    include!(concat!(env!("OUT_DIR"), "/gateway.rs"));
}

#[allow(clippy::all)]
pub mod store {
    include!(concat!(env!("OUT_DIR"), "/store.rs"));
}
use crate::gateway_one::store::{
    GetLinksRequest, GetLinksResponse, GetRequest, GetResponse, HasRequest, HasResponse, PutRequest,
};

#[allow(clippy::all)]
pub mod p2p {
    include!(concat!(env!("OUT_DIR"), "/p2p.rs"));
}
use crate::gateway_one::p2p::{
    BitswapRequest, BitswapResponse, ConnectRequest, ConnectResponse, DisconnectRequest,
    GetListeningAddrsResponse, GetPeersResponse, GossipsubAllPeersResponse, GossipsubPeerIdMsg,
    GossipsubPeersResponse, GossipsubPublishRequest, GossipsubPublishResponse,
    GossipsubSubscribeResponse, GossipsubTopicHashMsg, GossipsubTopicsResponse, Key, Providers,
};

// Note: Keep in sync with iroh-one/src/rpc.rs
proxy!(GatewayOne,
(
    Gateway,
    version: () => gateway::VersionResponse
),
(
    Store,
    put: PutRequest => (),
    get: GetRequest => GetResponse,
    has: HasRequest => HasResponse,
    get_links: GetLinksRequest => GetLinksResponse
),
(
    P2p,
    shutdown: () => (),
    fetch_bitswap: BitswapRequest => BitswapResponse,
    fetch_provider: Key => Providers,
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
)
);
