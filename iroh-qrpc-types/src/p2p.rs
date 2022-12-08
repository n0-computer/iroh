use bytes::Bytes;
use cid::Cid;
use derive_more::{From, TryInto};
use libp2p::{Multiaddr, PeerId};
use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming},
    Service,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::RpcResult;

pub type P2pAddr = super::addr::Addr<P2pService>;

#[derive(Serialize, Deserialize, Debug)]
pub struct Key(pub Bytes);

// rpc Version(google.protobuf.Empty) returns (VersionResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct VersionRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionResponse {
    pub version: String,
}

// rpc LocalPeerId(google.protobuf.Empty) returns (PeerIdResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct LocalPeerIdRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct LocalPeerIdResponse {
    pub peer_id: PeerId,
}

// rpc ExternalAddrs(google.protobuf.Empty) returns (Multiaddrs) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct ExternalAddrsRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct ExternalAddrsResponse {
    pub addrs: Vec<Multiaddr>,
}

// rpc Listeners(google.protobuf.Empty) returns (Multiaddrs) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct ListenersRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct ListenersResponse {
    pub addrs: Vec<Multiaddr>,
}

// rpc FetchBitswap(BitswapRequest) returns (BitswapResponse) {}
// message BitswapRequest {
//     // Serialized CID of the requested block.
//     bytes cid = 1;
//     Providers providers = 2;
//     uint64 ctx = 3;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct BitswapRequest {
    pub cid: Cid,
    pub providers: Vec<PeerId>,
    pub ctx: u64,
}

// message BitswapResponse {
//     bytes data = 1;
//     uint64 ctx = 2;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct BitswapResponse {
    pub data: Bytes,
    pub ctx: u64,
}

// rpc FetchProviderDht(Key) returns (stream Providers) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct FetchProvidersDhtRequest {
    pub key: Key,
}

// message Providers {
//     // List of providers. Serialized PeerIds
//     repeated bytes providers = 1;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct FetchProvidersDhtResponse {
    pub providers: Vec<PeerId>,
}

// rpc NotifyNewBlocksBitswap(NotifyNewBlocksBitswapRequest) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct NotifyNewBlocksBitswapRequest {
    pub blocks: Vec<BitswapBlock>,
}

// message BitswapBlock {
//     bytes cid = 1;
// .   bytes data = 2;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct BitswapBlock {
    pub cid: Cid,
    pub data: Bytes,
}

// rpc StopSessionBitswap(StopSessionBitswapRequest) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct StopSessionBitswapRequest {
    pub ctx: u64,
}

// rpc StartProviding(Key) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct StartProvidingRequest {
    pub key: Key,
}

// rpc StopProviding(Key) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct StopProvidingRequest {
    pub key: Key,
}

// rpc GetListeningAddrs(google.protobuf.Empty) returns (GetListeningAddrsResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GetListeningAddrsRequest;

// message GetListeningAddrsResponse {
//     // Serialized peer id
//     bytes peer_id = 1;
//     // Serialized list of multiaddrs
//     repeated bytes addrs = 2;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct GetListeningAddrsResponse {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
}

// rpc GetPeers(google.protobuf.Empty) returns (GetPeersResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GetPeersRequest;

// message GetPeersResponse {
//     // map of peer ids to a list of multiaddrs
//     // gRpc maps cannot have `bytes` as a key, so using `string` instead
//     // gRpc maps cannot have `repeated` as part of the value, so abstrating
//     // the list of serialized Multiaddr as a protobuf type `Multiaddrs`
//     map<string, Multiaddrs> peers = 1;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct GetPeersResponse {
    pub peers: BTreeMap<PeerId, Vec<Multiaddr>>,
}

// rpc PeerConnect(ConnectRequest) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectRequest {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
}

// rpc PeerConnectByPeerId(ConnectByPeerIdRequest) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectByPeerIdRequest {
    pub peer_id: PeerId,
}

// rpc PeerDisconnect(DisconnectRequest) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct DisconnectRequest {
    pub peer_id: PeerId,
}
// rpc Shutdown(google.protobuf.Empty) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct ShutdownRequest;

// rpc Lookup(LookupRequest) returns (PeerInfo) {}
// message LookupRequest {
//     // PeerId
//     bytes peer_id = 1;
//     // Serialized multiaddr
//     optional bytes addr = 2;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct LookupRequest {
    pub peer_id: PeerId,
    pub addr: Option<Multiaddr>,
}

// rpc LookupLocal(google.protobuf.Empty) returns (PeerInfo) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct LookupLocalRequest;

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
pub struct LookupResponse {
    pub peer_id: PeerId,
    pub protocol_version: String,
    pub agent_version: String,
    pub listen_addrs: Vec<Multiaddr>,
    pub protocols: Vec<String>,
    pub observed_addrs: Vec<Multiaddr>,
}

// rpc GossipsubAddExplicitPeer(GossipsubPeerIdMsg) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubAddExplicitPeerRequest {
    pub peer_id: PeerId,
}

// rpc GossipsubAllMeshPeers(google.protobuf.Empty) returns (GossipsubPeersResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubAllMeshPeersRequest;

// message GossipsubPeersResponse {
//     // List of PeerIds
//     repeated bytes peers = 1;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubPeersResponse {
    pub peers: Vec<PeerId>,
}

// rpc GossipsubAllPeers(google.protobuf.Empty) returns (GossipsubAllPeersResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubAllPeersRequest;

// message GossipsubAllPeersResponse {
//     repeated GossipsubPeerAndTopics all = 1;
// }
//
// message GossipsubPeerAndTopics {
//     bytes peer_id = 1;
//     repeated string topics = 2;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubAllPeersResponse {
    pub all: Vec<(PeerId, Vec<String>)>,
}

// rpc GossipsubMeshPeers(GossipsubTopicHashMsg) returns (GossipsubPeersResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubMeshPeersRequest {
    pub topic_hash: String,
}
// rpc GossipsubPublish(GossipsubPublishRequest) returns (GossipsubPublishResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubPublishRequest {
    pub topic_hash: String,
    pub data: Bytes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubPublishResponse {
    pub message_id: Bytes,
}
// rpc GossipsubRemoveExplicitPeer(GossipsubPeerIdMsg) returns (google.protobuf.Empty) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubRemoveExplicitPeerRequest {
    pub peer_id: PeerId,
}

// rpc GossipsubSubscribe(GossipsubTopicHashMsg) returns (GossipsubSubscribeResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubSubscribeRequest {
    pub topic_hash: String,
}

// message GossipsubSubscribeResponse {
//     bool was_subscribed = 1;
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubSubscribeResponse {
    pub was_subscribed: bool,
}
// rpc GossipsubTopics(google.protobuf.Empty) returns (GossipsubTopicsResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubTopicsRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubTopicsResponse {
    pub topics: Vec<String>,
}
// rpc GossipsubUnsubscribe(GossipsubTopicHashMsg) returns (GossipsubSubscribeResponse) {}
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubUnsubscribeRequest {
    pub topic_hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GossipsubUnsubscribeResponse {
    pub was_subscribed: bool,
}

#[derive(Serialize, Deserialize, Debug, From, TryInto)]
pub enum P2pRequest {
    Version(VersionRequest),
    Shutdown(ShutdownRequest),
    FetchBitswap(BitswapRequest),
    FetchProviderDht(FetchProvidersDhtRequest),
    StopSessionBitswap(StopSessionBitswapRequest),
    NotifyNewBlocksBitswap(NotifyNewBlocksBitswapRequest),
    GetListeningAddrs(GetListeningAddrsRequest),
    GetPeers(GetPeersRequest),
    PeerConnect(ConnectRequest),
    PeerConnectByPeerId(ConnectByPeerIdRequest),
    PeerDisconnect(DisconnectRequest),
    Lookup(LookupRequest),
    LookupLocal(LookupLocalRequest),
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
pub enum P2pResponse {
    Version(VersionResponse),
    FetchBitswap(RpcResult<BitswapResponse>),
    FetchProviderDht(RpcResult<FetchProvidersDhtResponse>),
    GetListeningAddrs(RpcResult<GetListeningAddrsResponse>),
    GetPeers(RpcResult<GetPeersResponse>),
    Lookup(RpcResult<LookupResponse>),
    GossipsubPeers(RpcResult<GossipsubPeersResponse>),
    GossipsubAllPeers(RpcResult<GossipsubAllPeersResponse>),
    GossipsubPublish(RpcResult<GossipsubPublishResponse>),
    GossipsubSubscribe(RpcResult<GossipsubSubscribeResponse>),
    GossipsubTopics(RpcResult<GossipsubTopicsResponse>),
    GossipsubUnsubscribe(RpcResult<GossipsubUnsubscribeResponse>),
    LocalPeerId(RpcResult<LocalPeerIdResponse>),
    ExternalAddrs(RpcResult<ExternalAddrsResponse>),
    Listeners(RpcResult<ListenersResponse>),
    ResultVoid(RpcResult<()>),
}

#[derive(Debug, Clone)]
pub struct P2pService;

impl Service for P2pService {
    type Req = P2pRequest;
    type Res = P2pResponse;
}

impl RpcMsg<P2pService> for VersionRequest {
    type Response = VersionResponse;
}

impl RpcMsg<P2pService> for ShutdownRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for BitswapRequest {
    type Response = RpcResult<BitswapResponse>;
}

impl Msg<P2pService> for FetchProvidersDhtRequest {
    type Response = RpcResult<FetchProvidersDhtResponse>;

    type Update = Self;

    type Pattern = ServerStreaming;
}

impl RpcMsg<P2pService> for StopSessionBitswapRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for NotifyNewBlocksBitswapRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for GetListeningAddrsRequest {
    type Response = RpcResult<GetListeningAddrsResponse>;
}

impl RpcMsg<P2pService> for GetPeersRequest {
    type Response = RpcResult<GetPeersResponse>;
}

impl RpcMsg<P2pService> for ConnectRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for ConnectByPeerIdRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for DisconnectRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for LookupRequest {
    type Response = RpcResult<LookupResponse>;
}

impl RpcMsg<P2pService> for LookupLocalRequest {
    type Response = RpcResult<LookupResponse>;
}

impl RpcMsg<P2pService> for GossipsubAddExplicitPeerRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for GossipsubAllMeshPeersRequest {
    type Response = RpcResult<GossipsubPeersResponse>;
}

impl RpcMsg<P2pService> for GossipsubMeshPeersRequest {
    type Response = RpcResult<GossipsubPeersResponse>;
}

impl RpcMsg<P2pService> for GossipsubAllPeersRequest {
    type Response = RpcResult<GossipsubAllPeersResponse>;
}

impl RpcMsg<P2pService> for GossipsubPublishRequest {
    type Response = RpcResult<GossipsubPublishResponse>;
}

impl RpcMsg<P2pService> for GossipsubTopicsRequest {
    type Response = RpcResult<GossipsubTopicsResponse>;
}

impl RpcMsg<P2pService> for GossipsubSubscribeRequest {
    type Response = RpcResult<GossipsubSubscribeResponse>;
}

impl RpcMsg<P2pService> for GossipsubUnsubscribeRequest {
    type Response = RpcResult<GossipsubUnsubscribeResponse>;
}

impl RpcMsg<P2pService> for GossipsubRemoveExplicitPeerRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for StartProvidingRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for StopProvidingRequest {
    type Response = RpcResult<()>;
}

impl RpcMsg<P2pService> for LocalPeerIdRequest {
    type Response = RpcResult<LocalPeerIdResponse>;
}

impl RpcMsg<P2pService> for ExternalAddrsRequest {
    type Response = RpcResult<ExternalAddrsResponse>;
}

impl RpcMsg<P2pService> for ListenersRequest {
    type Response = RpcResult<ListenersResponse>;
}
