include_proto!("p2p");

proxy!(
    P2p,
    version: () => VersionResponse => VersionResponse,
    shutdown: () => () => (),
    fetch_bitswap: BitswapRequest => BitswapResponse => BitswapResponse,
    fetch_provider_dht: Key =>
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<Providers, tonic::Status>> + Send>> =>
        std::pin::Pin<Box<dyn futures::Stream<Item = anyhow::Result<Providers>> + Send>> [FetchProviderDhtStream],
    stop_session_bitswap: StopSessionBitswapRequest => () => (),
    notify_new_blocks_bitswap: NotifyNewBlocksBitswapRequest => () => (),
    get_listening_addrs: () => GetListeningAddrsResponse =>  GetListeningAddrsResponse,
    get_peers: () => GetPeersResponse =>  GetPeersResponse,
    peer_connect: ConnectRequest => () => (),
    peer_connect_by_peer_id: ConnectByPeerIdRequest => () => (),
    peer_disconnect: DisconnectRequest => () =>  (),
    lookup: LookupRequest => PeerInfo => PeerInfo,
    gossipsub_add_explicit_peer: GossipsubPeerIdMsg => () =>  (),
    gossipsub_all_mesh_peers: () => GossipsubPeersResponse =>  GossipsubPeersResponse,
    gossipsub_all_peers: () => GossipsubAllPeersResponse =>  GossipsubAllPeersResponse,
    gossipsub_mesh_peers: GossipsubTopicHashMsg => GossipsubPeersResponse =>  GossipsubPeersResponse,
    gossipsub_publish: GossipsubPublishRequest => GossipsubPublishResponse =>  GossipsubPublishResponse,
    gossipsub_remove_explicit_peer: GossipsubPeerIdMsg => () =>  (),
    gossipsub_subscribe: GossipsubTopicHashMsg => GossipsubSubscribeResponse =>  GossipsubSubscribeResponse,
    gossipsub_topics: () => GossipsubTopicsResponse =>  GossipsubTopicsResponse,
    gossipsub_unsubscribe: GossipsubTopicHashMsg => GossipsubSubscribeResponse => GossipsubSubscribeResponse,
    start_providing: Key => () => (),
    stop_providing: Key => () => (),
    local_peer_id: () => PeerIdResponse => PeerIdResponse,
    external_addrs: () => Multiaddrs => Multiaddrs,
    listeners: () => Multiaddrs => Multiaddrs
);

mod qrpc {
    use bytes::Bytes;
    use cid::{multihash::Multihash, Cid};
    use derive_more::{From, TryInto};
    use multiaddr::Multiaddr;
    use quic_rpc::{message::RpcMsg, Service};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    /// wrap multihash instead of using peerid from libp2p to avoid the dependency
    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct PeerId(Multihash);

    #[derive(Serialize, Deserialize, Debug)]
    struct DhtKey(Bytes);

    // rpc Version(google.protobuf.Empty) returns (VersionResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct VersionRequest;

    #[derive(Serialize, Deserialize, Debug)]
    struct VersionResponse {
        version: String,
    }

    // rpc LocalPeerId(google.protobuf.Empty) returns (PeerIdResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct LocalPeerIdRequest;

    #[derive(Serialize, Deserialize, Debug)]
    struct LocalPeerIdResponse {
        peer_id: PeerId,
    }

    // rpc ExternalAddrs(google.protobuf.Empty) returns (Multiaddrs) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct ExternalAddrsRequest;

    #[derive(Serialize, Deserialize, Debug)]
    struct ExternalAddrsResponse {
        addrs: Vec<Multiaddr>,
    }

    // rpc Listeners(google.protobuf.Empty) returns (Multiaddrs) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct ListenersRequest;

    #[derive(Serialize, Deserialize, Debug)]
    struct ListenersResponse {
        addrs: Vec<Multiaddr>,
    }

    // rpc FetchBitswap(BitswapRequest) returns (BitswapResponse) {}
    // message BitswapRequest {
    //     // Serialized CID of the requested block.
    //     bytes cid = 1;
    //     Providers providers = 2;
    //     uint64 ctx = 3;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct FetchBitswapRequest {
        cid: Cid,
        providers: Vec<PeerId>,
        ctx: u64,
    }

    // message BitswapResponse {
    //     bytes data = 1;
    //     uint64 ctx = 2;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct FetchBitswapResponse {
        data: Bytes,
        ctx: u64,
    }

    // rpc FetchProviderDht(Key) returns (stream Providers) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct FetchProviderDhtRequest {
        key: DhtKey,
    }

    // message Providers {
    //     // List of providers. Serialized PeerIds
    //     repeated bytes providers = 1;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct FetchProviderDhtResponse {
        providers: Vec<PeerId>,
    }

    // rpc NotifyNewBlocksBitswap(NotifyNewBlocksBitswapRequest) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct NotifyNewBlocksBitswapRequest {
        blocks: Vec<BitswapBlock>,
    }

    // message BitswapBlock {
    //     bytes cid = 1;
    // .   bytes data = 2;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct BitswapBlock {
        cid: Cid,
        data: Bytes,
    }

    // rpc StopSessionBitswap(StopSessionBitswapRequest) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct StopSessionBitswapRequest {
        ctx: u64,
    }

    // rpc StartProviding(Key) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct StartProvidingRequest {
        key: DhtKey,
    }

    // rpc StopProviding(Key) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct StopProvidingRequest {
        key: DhtKey,
    }

    // rpc GetListeningAddrs(google.protobuf.Empty) returns (GetListeningAddrsResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GetListeningAddrsRequest;

    // message GetListeningAddrsResponse {
    //     // Serialized peer id
    //     bytes peer_id = 1;
    //     // Serialized list of multiaddrs
    //     repeated bytes addrs = 2;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct GetListeningAddrsResponse {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    }

    // rpc GetPeers(google.protobuf.Empty) returns (GetPeersResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GetPeersRequest;

    // message GetPeersResponse {
    //     // map of peer ids to a list of multiaddrs
    //     // gRpc maps cannot have `bytes` as a key, so using `string` instead
    //     // gRpc maps cannot have `repeated` as part of the value, so abstrating
    //     // the list of serialized Multiaddr as a protobuf type `Multiaddrs`
    //     map<string, Multiaddrs> peers = 1;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct GetPeersResponse {
        peers: BTreeMap<PeerId, Vec<Multiaddr>>,
    }

    // rpc PeerConnect(ConnectRequest) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct PeerConnectRequest {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    }

    // rpc PeerConnectByPeerId(ConnectByPeerIdRequest) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct PeerConnectByPeerIdRequest {
        peer_id: PeerId,
    }

    // rpc PeerDisconnect(DisconnectRequest) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct PeerDisconnectRequest {
        peer_id: PeerId,
    }
    // rpc Shutdown(google.protobuf.Empty) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct ShutdownRequest;

    // rpc Lookup(LookupRequest) returns (PeerInfo) {}
    // message LookupRequest {
    //     // PeerId
    //     bytes peer_id = 1;
    //     // Serialized multiaddr
    //     optional bytes addr = 2;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct LookupRequest {
        peer_id: PeerId,
        addr: Option<Multiaddr>,
    }

    // message PeerInfo {
    //     // PublicKey
    //     bytes peer_id = 1;
    //     // String
    //     string protocol_version = 2;
    //     // string
    //     string agent_version = 3;
    //     // vec of Multiaddrs
    //     repeated bytes listen_addrs = 4;
    //     // vec of Strings
    //     repeated string protocols = 5;
    //     // Multiaddr
    //     bytes observed_addr = 6;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct LookupResponse {
        peer_id: PeerId,
        protocol_version: String,
        agent_version: String,
        listen_addrs: Vec<Multiaddr>,
        protocols: Vec<String>,
        observed_addr: Multiaddr,
    }

    // rpc GossipsubAddExplicitPeer(GossipsubPeerIdMsg) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubAddExplicitPeerRequest {
        peer_id: PeerId,
    }

    // rpc GossipsubAllMeshPeers(google.protobuf.Empty) returns (GossipsubPeersResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubAllMeshPeersRequest;

    // message GossipsubPeersResponse {
    //     // List of PeerIds
    //     repeated bytes peers = 1;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubPeersResponse {
        peers: Vec<PeerId>,
    }

    // rpc GossipsubAllPeers(google.protobuf.Empty) returns (GossipsubAllPeersResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubAllPeersRequest;

    // rpc GossipsubMeshPeers(GossipsubTopicHashMsg) returns (GossipsubPeersResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubMeshPeersRequest {
        topic_hash: Bytes,
    }
    // rpc GossipsubPublish(GossipsubPublishRequest) returns (GossipsubPublishResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubPublishRequest {
        topic_hash: Bytes,
        data: Bytes,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubPublishResponse {
        message_id: Bytes,
    }
    // rpc GossipsubRemoveExplicitPeer(GossipsubPeerIdMsg) returns (google.protobuf.Empty) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubRemoveExplicitPeerRequest {
        peer_id: PeerId,
    }

    // rpc GossipsubSubscribe(GossipsubTopicHashMsg) returns (GossipsubSubscribeResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubSubscribeRequest {
        topic_hash: Bytes,
    }

    // message GossipsubSubscribeResponse {
    //     bool was_subscribed = 1;
    // }
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubSubscribeResponse {
        was_subscribed: bool,
    }
    // rpc GossipsubTopics(google.protobuf.Empty) returns (GossipsubTopicsResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubTopicsRequest;

    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubTopicsResponse {
        topics: Vec<Bytes>,
    }
    // rpc GossipsubUnsubscribe(GossipsubTopicHashMsg) returns (GossipsubSubscribeResponse) {}
    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubUnsubscribeRequest {
        topic_hash: Bytes,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct GossipsubUnsubscribeResponse {
        was_subscribed: bool,
    }

    #[derive(Serialize, Deserialize, Debug, From, TryInto)]
    enum P2pRequest {
        Version(VersionRequest),
        Shutdown(ShutdownRequest),
        FetchBitswap(FetchBitswapRequest),
        FetchProviderDht(FetchProviderDhtRequest),
        StopSessionBitswap(StopSessionBitswapRequest),
        NotifyNewBlocksBitswap(NotifyNewBlocksBitswapRequest),
        GetListeningAddrs(GetListeningAddrsRequest),
        GetPeers(GetPeersRequest),
        PeerConnect(PeerConnectRequest),
        PeerConnectByPeerId(PeerConnectByPeerIdRequest),
        PeerDisconnect(PeerDisconnectRequest),
        Lookup(LookupRequest),
        GossipsubAddExplicitPeer(GossipsubAddExplicitPeerRequest),
        GossipsubAllMeshPeers(GossipsubAllMeshPeersRequest),
        GossipsubAllPeers(GossipsubAllPeersRequest),
        GossipsubMeshPeers(GossipsubMeshPeersRequest),
        GossipsubPublish(GossipsubPublishRequest),
        GossipsubRemoveExplicitPeer(GossipsubRemoveExplicitPeerRequest),
        GossipsubSubscribe(GossipsubSubscribeRequest),
        GossipsubTopics(GossipsubTopicsRequest),
        GossipsubUnsubscribe(GossipsubUnsubscribeRequest),
        StartProviding(StartProvidingRequest),
        StopProviding(StopProvidingRequest),
        LocalPeerId(LocalPeerIdRequest),
        ExternalAddrs(ExternalAddrsRequest),
        Listeners(ListenersRequest),
    }

    #[derive(Serialize, Deserialize, Debug, From, TryInto)]
    enum P2pResponse {
        Version(VersionResponse),
        FetchBitswap(FetchBitswapResponse),
        FetchProviderDht(FetchProviderDhtResponse),
        GetListeningAddrs(GetListeningAddrsResponse),
        GetPeers(GetPeersResponse),
        Lookup(LookupResponse),
        GossipsubPeers(GossipsubPeersResponse),
        GossipsubPublish(GossipsubPublishResponse),
        GossipsubSubscribe(GossipsubSubscribeResponse),
        GossipsubTopics(GossipsubTopicsResponse),
        GossipsubUnsubscribe(GossipsubUnsubscribeResponse),
        LocalPeerId(LocalPeerIdResponse),
        ExternalAddrs(ExternalAddrsResponse),
        Listeners(ListenersResponse),
        Void(()),
    }

    #[derive(Debug, Clone)]
    struct P2pService;

    impl Service for P2pService {
        type Req = P2pRequest;
        type Res = P2pResponse;
    }

    impl RpcMsg<P2pService> for VersionRequest {
        type Response = VersionResponse;
    }

    impl RpcMsg<P2pService> for ShutdownRequest {
        type Response = ();
    }

    impl RpcMsg<P2pService> for FetchBitswapRequest {
        type Response = FetchBitswapResponse;
    }

    impl RpcMsg<P2pService> for FetchProviderDhtRequest {
        type Response = FetchProviderDhtResponse;
    }

    impl RpcMsg<P2pService> for StopSessionBitswapRequest {
        type Response = ();
    }

    impl RpcMsg<P2pService> for NotifyNewBlocksBitswapRequest {
        type Response = ();
    }

    impl RpcMsg<P2pService> for GetListeningAddrsRequest {
        type Response = GetListeningAddrsResponse;
    }

    impl RpcMsg<P2pService> for GetPeersRequest {
        type Response = GetPeersResponse;
    }

    impl RpcMsg<P2pService> for PeerConnectRequest {
        type Response = ();
    }

    impl RpcMsg<P2pService> for PeerConnectByPeerIdRequest {
        type Response = ();
    }

    impl RpcMsg<P2pService> for PeerDisconnectRequest {
        type Response = ();
    }

    impl RpcMsg<P2pService> for LookupRequest {
        type Response = LookupResponse;
    }

    impl RpcMsg<P2pService> for GossipsubAddExplicitPeerRequest {
        type Response = ();
    }

    impl RpcMsg<P2pService> for GossipsubAllMeshPeersRequest {
        type Response = GossipsubPeersResponse;
    }

    impl RpcMsg<P2pService> for GossipsubMeshPeersRequest {
        type Response = GossipsubPeersResponse;
    }

    impl RpcMsg<P2pService> for GossipsubAllPeersRequest {
        type Response = GossipsubPeersResponse;
    }

    impl RpcMsg<P2pService> for GossipsubPublishRequest {
        type Response = GossipsubPublishResponse;
    }

    impl RpcMsg<P2pService> for GossipsubTopicsRequest {
        type Response = GossipsubTopicsResponse;
    }

    impl RpcMsg<P2pService> for GossipsubUnsubscribeRequest {
        type Response = GossipsubUnsubscribeResponse;
    }

    impl RpcMsg<P2pService> for StartProvidingRequest {
        type Response = ();
    }

    impl RpcMsg<P2pService> for StopProvidingRequest {
        type Response = ();
    }

    impl RpcMsg<P2pService> for LocalPeerIdRequest {
        type Response = LocalPeerIdResponse;
    }

    impl RpcMsg<P2pService> for ExternalAddrsRequest {
        type Response = ExternalAddrsResponse;
    }

    impl RpcMsg<P2pService> for ListenersRequest {
        type Response = ListenersResponse;
    }
}
