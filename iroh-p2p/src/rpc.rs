use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;

use anyhow::Result;
use async_channel::Sender;
use bytes::Bytes;
use cid::Cid;
use futures::channel::oneshot;
use libp2p::gossipsub::{
    error::{PublishError, SubscriptionError},
    MessageId, TopicHash,
};
use libp2p::kad::record::Key;
use libp2p::Multiaddr;
use libp2p::PeerId;
use tokio::sync::mpsc;
use tonic::{transport::Server as TonicServer, Request, Response, Status};
use tracing::{trace, warn};

use iroh_bitswap::{Block, QueryError};
use iroh_rpc_types::p2p::p2p_server;
use iroh_rpc_types::p2p::{gossipsub_server, VersionResponse};
use iroh_rpc_types::p2p::{
    AllPeersResponse, BitswapRequest, BitswapResponse, ConnectRequest, ConnectResponse,
    DisconnectRequest, GetListeningAddrsResponse, GetPeersResponse, Key as ProviderKey, Multiaddrs,
    PeerAndTopics, PeerIdMsg, PeersResponse, Providers, PublishRequest, PublishResponse,
    SubscribeResponse, TopicHashMsg, TopicsResponse,
};

struct P2p {
    sender: Sender<RpcMessage>,
}

#[tonic::async_trait]
impl p2p_server::P2p for P2p {
    #[tracing::instrument(skip(self))]
    async fn version(
        &self,
        _request: Request<()>,
    ) -> Result<Response<VersionResponse>, tonic::Status> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(Response::new(VersionResponse { version }))
    }

    #[tracing::instrument(skip(self))]
    async fn shutdown(&self, _request: Request<()>) -> Result<Response<()>, tonic::Status> {
        self.sender
            .send(RpcMessage::Shutdown)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;
        Ok(Response::new(()))
    }

    // TODO: expand to handle multiple cids at once. Probably not a tough fix, just want to push
    // forward right now
    #[tracing::instrument(skip(self, request))]
    async fn fetch_bitswap(
        &self,
        request: Request<BitswapRequest>,
    ) -> Result<Response<BitswapResponse>, tonic::Status> {
        iroh_metrics::req::set_trace_ctx(&request);
        let req = request.into_inner();
        let cid = Cid::read_bytes(io::Cursor::new(req.cid))
            .map_err(|e| Status::invalid_argument(format!("invalid cid: {:?}", e)))?;

        trace!("received BitswapRequest: {:?}", cid);
        let providers = req
            .providers
            .ok_or_else(|| Status::invalid_argument(format!("missing providers for: {}", cid)))?;

        let providers: HashSet<PeerId> = providers
            .providers
            .into_iter()
            .map(|p| {
                PeerId::from_bytes(&p)
                    .map_err(|e| Status::invalid_argument(format!("invalid provider: {:?}", e)))
            })
            .collect::<Result<_, Status>>()?;

        if providers.is_empty() {
            return Err(Status::invalid_argument(format!(
                "missing providers for: {}",
                cid
            )));
        }

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapRequest {
            cids: vec![cid],
            providers,
            response_channels: vec![s],
        };
        trace!("making bitswap request for {:?}", cid);
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let block = r
            .await
            .map_err(|_| Status::internal("sender dropped"))?
            .map_err(|e| Status::deadline_exceeded(format!("bitswap failed: {}", e)))?;

        trace!("bitswap response for {:?}", cid);
        Ok(Response::new(BitswapResponse { data: block.data }))
    }

    #[tracing::instrument(skip(self, request))]
    async fn fetch_provider(
        &self,
        request: Request<ProviderKey>,
    ) -> Result<Response<Providers>, tonic::Status> {
        iroh_metrics::req::set_trace_ctx(&request);
        let req = request.into_inner();
        trace!("received ProviderRequest: {:?}", req.key);
        let (s, mut r) = mpsc::channel(1024);
        let msg = RpcMessage::ProviderRequest {
            key: req.key.clone().into(),
            response_channel: s,
        };

        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        // TODO: streaming response
        let mut providers = Vec::new();
        while let Some(provider) = r.recv().await {
            match provider {
                Ok(provider) => providers.push(provider.to_bytes()),
                Err(e) => {
                    if providers.is_empty() {
                        return Err(Status::internal(e));
                    } else {
                        warn!("error fetching providers for key {:?}: {:?}", req.key, e);
                        break;
                    }
                }
            }
        }

        Ok(Response::new(Providers { providers }))
    }

    async fn get_listening_addrs(
        &self,
        _request: Request<()>,
    ) -> Result<Response<GetListeningAddrsResponse>, tonic::Status> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetListeningAddrs(s);
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let (peer_id, addrs) = r.await.map_err(|_| Status::internal("sender dropped"))?;
        Ok(Response::new(GetListeningAddrsResponse {
            peer_id: peer_id.to_bytes(),
            addrs: addrs.into_iter().map(|addr| addr.to_vec()).collect(),
        }))
    }

    async fn get_peers(
        &self,
        _request: Request<()>,
    ) -> Result<Response<GetPeersResponse>, tonic::Status> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetPeers(s);
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let peers = r.await.map_err(|_| Status::internal("sender dropped"))?;
        let mut p: HashMap<String, Multiaddrs> = Default::default();
        for (id, addrs) in peers.into_iter() {
            p.insert(
                id.to_string(),
                Multiaddrs {
                    addrs: addrs.into_iter().map(|addr| addr.to_vec()).collect(),
                },
            );
        }
        Ok(Response::new(GetPeersResponse { peers: p }))
    }

    async fn peer_connect(
        &self,
        request: Request<ConnectRequest>,
    ) -> Result<Response<ConnectResponse>, tonic::Status> {
        let req = request.into_inner();
        let peer_id = peer_id_from_bytes(req.peer_id)?;
        let addrs = addrs_from_bytes(req.addrs)?;
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetConnect(s, peer_id, addrs);
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let success = r.await.map_err(|_| Status::internal("sender dropped"))?;
        Ok(Response::new(ConnectResponse { success }))
    }

    async fn peer_disconnect(
        &self,
        request: Request<DisconnectRequest>,
    ) -> Result<Response<()>, tonic::Status> {
        let req = request.into_inner();
        let peer_id = peer_id_from_bytes(req.peer_id)?;
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetDisconnect(s, peer_id);
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;
        let ack = r.await.map_err(|_| Status::internal("sender dropped"))?;
        Ok(Response::new(ack))
    }
}

#[tonic::async_trait]
impl gossipsub_server::Gossipsub for P2p {
    async fn add_explicit_peer(
        &self,
        request: Request<PeerIdMsg>,
    ) -> Result<Response<()>, tonic::Status> {
        let req = request.into_inner();
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AddExplicitPeer(
            s,
            peer_id_from_bytes(req.peer_id)?,
        ));
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        r.await.map_err(|_| Status::internal("sender dropped"))?;
        Ok(Response::new(()))
    }

    async fn all_mesh_peers(
        &self,
        _request: Request<()>,
    ) -> Result<Response<PeersResponse>, tonic::Status> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AllMeshPeers(s));
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let peers = r.await.map_err(|_| Status::internal("sender dropped"))?;

        let peers = peers.into_iter().map(|p| p.to_bytes()).collect();
        Ok(Response::new(PeersResponse { peers }))
    }

    async fn all_peers(
        &self,
        _request: Request<()>,
    ) -> Result<Response<AllPeersResponse>, tonic::Status> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AllPeers(s));
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let all_peers = r.await.map_err(|_| Status::internal("sender dropped"))?;
        let all = all_peers
            .into_iter()
            .map(|(p, t)| PeerAndTopics {
                peer_id: p.to_bytes(),
                topics: t.into_iter().map(|t| t.into_string()).collect(),
            })
            .collect();
        Ok(Response::new(AllPeersResponse { all }))
    }

    async fn mesh_peers(
        &self,
        request: Request<TopicHashMsg>,
    ) -> Result<Response<PeersResponse>, tonic::Status> {
        let req = request.into_inner();
        let topic = TopicHash::from_raw(req.topic_hash);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::MeshPeers(s, topic));
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let res = r.await.map_err(|_| Status::internal("sender dropped"))?;
        let peers = res.into_iter().map(|p| p.to_bytes()).collect();
        Ok(Response::new(PeersResponse { peers }))
    }

    async fn publish(
        &self,
        request: Request<PublishRequest>,
    ) -> Result<Response<PublishResponse>, tonic::Status> {
        let req = request.into_inner();
        let data = req.data;
        let topic_hash = TopicHash::from_raw(req.topic_hash);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Publish(s, topic_hash, data));
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let message_id = r
            .await
            .map_err(|_| Status::internal("sender dropped"))?
            .map_err(publish_error_to_status)?;

        Ok(Response::new(PublishResponse {
            message_id: message_id.0,
        }))
    }

    async fn remove_explicit_peer(
        &self,
        request: Request<PeerIdMsg>,
    ) -> Result<Response<()>, tonic::Status> {
        let req = request.into_inner();
        let peer_id = peer_id_from_bytes(req.peer_id)?;
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::RemoveExplicitPeer(s, peer_id));
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        r.await.map_err(|_| Status::internal("sender dropped"))?;
        Ok(Response::new(()))
    }

    async fn subscribe(
        &self,
        request: Request<TopicHashMsg>,
    ) -> Result<Response<SubscribeResponse>, tonic::Status> {
        let req = request.into_inner();
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Subscribe(
            s,
            TopicHash::from_raw(req.topic_hash),
        ));

        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let was_subscribed = r
            .await
            .map_err(|_| Status::internal("sender dropped"))?
            .map_err(|e| match e {
                SubscriptionError::PublishError(p) => publish_error_to_status(p),
                SubscriptionError::NotAllowed => Status::permission_denied(e.to_string()),
            })?;

        Ok(Response::new(SubscribeResponse { was_subscribed }))
    }

    async fn topics(
        &self,
        _request: Request<()>,
    ) -> Result<Response<TopicsResponse>, tonic::Status> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Topics(s));

        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let topics: Vec<String> = r
            .await
            .map_err(|_| Status::internal("sender dropped"))?
            .into_iter()
            .map(|t| t.into_string())
            .collect();
        Ok(Response::new(TopicsResponse { topics }))
    }

    async fn unsubscribe(
        &self,
        request: Request<TopicHashMsg>,
    ) -> Result<Response<SubscribeResponse>, tonic::Status> {
        let req = request.into_inner();
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Unsubscribe(
            s,
            TopicHash::from_raw(req.topic_hash),
        ));

        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let was_subscribed = r
            .await
            .map_err(|_| Status::internal("sender dropped"))?
            .map_err(publish_error_to_status)?;
        Ok(Response::new(SubscribeResponse { was_subscribed }))
    }
}

pub fn publish_error_to_status(p: PublishError) -> Status {
    match p {
        PublishError::Duplicate => Status::already_exists(p.to_string()),
        PublishError::InsufficientPeers => Status::failed_precondition(p.to_string()),
        _ => Status::internal(p.to_string()),
    }
}

pub async fn new(addr: SocketAddr, sender: Sender<RpcMessage>) -> Result<()> {
    let p2p = P2p {
        sender: sender.clone(),
    };
    let gossipsub = P2p { sender };
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<p2p_server::P2pServer<P2p>>()
        .await;
    let p2p_service = p2p_server::P2pServer::new(p2p);
    let gossipsub_service = gossipsub_server::GossipsubServer::new(gossipsub);

    TonicServer::builder()
        .add_service(health_service)
        .add_service(p2p_service)
        .add_service(gossipsub_service)
        .serve(addr)
        .await?;
    Ok(())
}

fn peer_id_from_bytes(p: Vec<u8>) -> Result<PeerId, tonic::Status> {
    PeerId::from_bytes(&p[..]).map_err(|e| Status::internal(format!("invalid peer_id: {:?}", e)))
}

fn addr_from_bytes(m: Vec<u8>) -> Result<Multiaddr, tonic::Status> {
    Multiaddr::try_from(m).map_err(|e| Status::internal(format!("invalid multiaddr: {:?}", e)))
}

fn addrs_from_bytes(a: Vec<Vec<u8>>) -> Result<Vec<Multiaddr>, tonic::Status> {
    a.into_iter().map(addr_from_bytes).collect()
}

/// Rpc specific messages handled by the p2p node
#[derive(Debug)]
pub enum RpcMessage {
    BitswapRequest {
        cids: Vec<Cid>,
        response_channels: Vec<oneshot::Sender<Result<Block, QueryError>>>,
        providers: HashSet<PeerId>,
    },
    ProviderRequest {
        // TODO: potentially change this to Cid, as that is the only key we use for providers
        key: Key,
        response_channel: mpsc::Sender<Result<PeerId, String>>,
    },
    NetListeningAddrs(oneshot::Sender<(PeerId, Vec<Multiaddr>)>),
    NetPeers(oneshot::Sender<HashMap<PeerId, Vec<Multiaddr>>>),
    NetConnect(oneshot::Sender<bool>, PeerId, Vec<Multiaddr>),
    NetDisconnect(oneshot::Sender<()>, PeerId),
    Gossipsub(GossipsubMessage),
    Shutdown,
}

#[derive(Debug)]
pub enum GossipsubMessage {
    AddExplicitPeer(oneshot::Sender<()>, PeerId),
    AllMeshPeers(oneshot::Sender<Vec<PeerId>>),
    AllPeers(oneshot::Sender<Vec<(PeerId, Vec<TopicHash>)>>),
    MeshPeers(oneshot::Sender<Vec<PeerId>>, TopicHash),
    Publish(
        oneshot::Sender<Result<MessageId, PublishError>>,
        TopicHash,
        Bytes,
    ),
    RemoveExplicitPeer(oneshot::Sender<()>, PeerId),
    Subscribe(oneshot::Sender<Result<bool, SubscriptionError>>, TopicHash),
    Topics(oneshot::Sender<Vec<TopicHash>>),
    Unsubscribe(oneshot::Sender<Result<bool, PublishError>>, TopicHash),
}
