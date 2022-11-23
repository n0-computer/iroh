use bytes::Bytes;
use cid::{multihash::Multihash, Cid};
use derive_more::{From, TryInto};
use multiaddr::Multiaddr;
use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming},
    Service,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

pub type P2pClientAddr = super::addr::Addr<P2pResponse, P2pRequest>;
pub type P2pServerAddr = super::addr::Addr<P2pRequest, P2pResponse>;

/// wrap multihash instead of using peerid from libp2p to avoid the dependency
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub struct PeerId(pub Multihash);

impl PeerId {
    pub fn from_libp2p(peer_id: impl Into<Multihash>) -> Self {
        Self(peer_id.into())
    }
    pub fn try_into_libp2p<T: TryFrom<Multihash>>(self) -> anyhow::Result<T> {
        T::try_from(self.0).map_err(|_| anyhow::anyhow!("invalid peer id"))
    }
}

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
    pub observed_addr: Multiaddr,
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
    FetchBitswap(P2pResult<BitswapResponse>),
    FetchProviderDht(FetchProvidersDhtResponse),
    GetListeningAddrs(P2pResult<GetListeningAddrsResponse>),
    GetPeers(P2pResult<GetPeersResponse>),
    Lookup(P2pResult<LookupResponse>),
    GossipsubPeers(P2pResult<GossipsubPeersResponse>),
    GossipsubAllPeers(P2pResult<GossipsubAllPeersResponse>),
    GossipsubPublish(P2pResult<GossipsubPublishResponse>),
    GossipsubSubscribe(P2pResult<GossipsubSubscribeResponse>),
    GossipsubTopics(P2pResult<GossipsubTopicsResponse>),
    GossipsubUnsubscribe(P2pResult<GossipsubUnsubscribeResponse>),
    LocalPeerId(P2pResult<LocalPeerIdResponse>),
    ExternalAddrs(P2pResult<ExternalAddrsResponse>),
    Listeners(P2pResult<ListenersResponse>),
    ResultVoid(P2pResult<()>),
}

#[derive(Serialize, Deserialize, Debug, From, TryInto)]
pub enum P2pError {
    Anyhow(serde_error::Error),
    SendError,
    RecvError,
}

impl std::error::Error for P2pError {}

impl fmt::Display for P2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<anyhow::Error> for P2pError {
    fn from(e: anyhow::Error) -> Self {
        P2pError::Anyhow(serde_error::Error::new(&*e))
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for P2pError {
    fn from(_: tokio::sync::mpsc::error::SendError<T>) -> Self {
        P2pError::SendError
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for P2pError {
    fn from(_: tokio::sync::oneshot::error::RecvError) -> Self {
        P2pError::RecvError
    }
}

impl From<tokio::sync::oneshot::error::TryRecvError> for P2pError {
    fn from(_: tokio::sync::oneshot::error::TryRecvError) -> Self {
        P2pError::RecvError
    }
}

pub type P2pResult<T> = std::result::Result<T, P2pError>;

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
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for BitswapRequest {
    type Response = P2pResult<BitswapResponse>;
}

impl Msg<P2pService> for FetchProvidersDhtRequest {
    type Response = FetchProvidersDhtResponse;

    type Update = Self;

    type Pattern = ServerStreaming;
}

impl RpcMsg<P2pService> for StopSessionBitswapRequest {
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for NotifyNewBlocksBitswapRequest {
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for GetListeningAddrsRequest {
    type Response = P2pResult<GetListeningAddrsResponse>;
}

impl RpcMsg<P2pService> for GetPeersRequest {
    type Response = P2pResult<GetPeersResponse>;
}

impl RpcMsg<P2pService> for ConnectRequest {
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for ConnectByPeerIdRequest {
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for DisconnectRequest {
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for LookupRequest {
    type Response = P2pResult<LookupResponse>;
}

impl RpcMsg<P2pService> for GossipsubAddExplicitPeerRequest {
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for GossipsubAllMeshPeersRequest {
    type Response = P2pResult<GossipsubPeersResponse>;
}

impl RpcMsg<P2pService> for GossipsubMeshPeersRequest {
    type Response = P2pResult<GossipsubPeersResponse>;
}

impl RpcMsg<P2pService> for GossipsubAllPeersRequest {
    type Response = P2pResult<GossipsubAllPeersResponse>;
}

impl RpcMsg<P2pService> for GossipsubPublishRequest {
    type Response = P2pResult<GossipsubPublishResponse>;
}

impl RpcMsg<P2pService> for GossipsubTopicsRequest {
    type Response = P2pResult<GossipsubTopicsResponse>;
}

impl RpcMsg<P2pService> for GossipsubSubscribeRequest {
    type Response = P2pResult<GossipsubSubscribeResponse>;
}

impl RpcMsg<P2pService> for GossipsubUnsubscribeRequest {
    type Response = P2pResult<GossipsubUnsubscribeResponse>;
}

impl RpcMsg<P2pService> for GossipsubRemoveExplicitPeerRequest {
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for StartProvidingRequest {
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for StopProvidingRequest {
    type Response = P2pResult<()>;
}

impl RpcMsg<P2pService> for LocalPeerIdRequest {
    type Response = P2pResult<LocalPeerIdResponse>;
}

impl RpcMsg<P2pService> for ExternalAddrsRequest {
    type Response = P2pResult<ExternalAddrsResponse>;
}

impl RpcMsg<P2pService> for ListenersRequest {
    type Response = P2pResult<ListenersResponse>;
}
