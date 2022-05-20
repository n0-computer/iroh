use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;

use anyhow::Result;
use async_channel::Sender;
use cid::Cid;
use futures::channel::oneshot;
use libp2p::kad::record::Key;
use libp2p::Multiaddr;
use libp2p::PeerId;
use tonic::{transport::Server as TonicServer, Request, Response, Status};
use tracing::trace;

use iroh_bitswap::Block;
use iroh_rpc_types::p2p::p2p_server;
use iroh_rpc_types::p2p::{
    BitswapRequest, BitswapResponse, ConnectRequest, ConnectResponse, DisconnectRequest, Empty,
    GetListeningAddrsResponse, GetPeersResponse, Key as ProviderKey, Multiaddrs, Providers,
};

struct P2p {
    sender: Sender<RpcMessage>,
}

#[tonic::async_trait]
impl p2p_server::P2p for P2p {
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
            .map(|providers| {
                providers
                    .providers
                    .into_iter()
                    .map(|p| {
                        PeerId::from_bytes(&p).map_err(|e| {
                            Status::invalid_argument(format!("invalid provider: {:?}", e))
                        })
                    })
                    .collect::<Result<_, Status>>()
            })
            .transpose()?;

        let providers = match providers {
            Some(p) => p,
            None => {
                trace!("looking for providers for {:?}", cid);
                let (s, r) = oneshot::channel();
                self.sender
                    .send(RpcMessage::ProviderRequest {
                        key: cid.to_bytes().into(),
                        response_channel: s,
                    })
                    .await
                    .unwrap();

                let p = r
                    .await
                    .expect("sender dropped")
                    .map_err(|e| Status::internal(format!("failed to get providers: {:?}", e)))?;
                trace!("found providers: {:?}", providers);
                p
            }
        };

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

        let block = r.await.map_err(|_| Status::internal("sender dropped"))?;

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
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::ProviderRequest {
            key: req.key.into(),
            response_channel: s,
        };
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let providers = r
            .await
            .map_err(|_| Status::internal("sender dropped"))?
            .map_err(|e| Status::internal(format!("failed to retrieve provider: {:?}", e)))?;

        let providers = providers.into_iter().map(|p| p.to_bytes()).collect();
        Ok(Response::new(Providers { providers }))
    }

    async fn get_listening_addrs(
        &self,
        _request: Request<Empty>,
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
        _request: Request<Empty>,
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

pub async fn new(addr: SocketAddr, sender: Sender<RpcMessage>) -> Result<()> {
    let p2p = P2p { sender };
    TonicServer::builder()
        .add_service(p2p_server::P2pServer::new(p2p))
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
        response_channels: Vec<oneshot::Sender<Block>>,
        providers: HashSet<PeerId>,
    },
    ProviderRequest {
        // TODO: potentially change this to Cid, as that is the only key we use for providers
        key: Key,
        response_channel: oneshot::Sender<Result<HashSet<PeerId>, String>>,
    },
    NetListeningAddrs(oneshot::Sender<(PeerId, Vec<Multiaddr>)>),
    NetPeers(oneshot::Sender<HashMap<PeerId, Vec<Multiaddr>>>),
    NetConnect(oneshot::Sender<bool>, PeerId, Vec<Multiaddr>),
    NetDisconnect(oneshot::Sender<()>, PeerId),
}
