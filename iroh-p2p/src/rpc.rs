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
use tracing::info;

use iroh_bitswap::Block;
use iroh_rpc_types::p2p::p2p_server;
use iroh_rpc_types::p2p::{BitswapRequest, BitswapResponse, Providers};

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

        let providers = if providers.is_none() {
            let (s, r) = oneshot::channel();
            self.sender
                .send(RpcMessage::ProviderRequest {
                    key: cid.to_bytes().into(),
                    response_channel: s,
                })
                .await
                .unwrap();
            Some(
                r.await
                    .expect("sender dropped")
                    .map_err(|e| Status::internal(format!("failed to get providers: {:?}", e)))?,
            )
        } else {
            providers
        };

        info!("found providers: {:?}", providers);

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapRequest {
            cids: vec![cid],
            providers,
            response_channels: vec![s],
        };
        self.sender
            .send(msg)
            .await
            .map_err(|_| Status::internal("receiver dropped"))?;

        let block = r.await.map_err(|_| Status::internal("sender dropped"))?;

        Ok(Response::new(BitswapResponse { data: block.data }))
    }

    #[tracing::instrument(skip(self, request))]
    async fn fetch_provider(
        &self,
        request: Request<iroh_rpc_types::p2p::Key>,
    ) -> Result<Response<Providers>, tonic::Status> {
        iroh_metrics::req::set_trace_ctx(&request);
        let req = request.into_inner();
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
}

pub async fn new(addr: SocketAddr, sender: Sender<RpcMessage>) -> Result<()> {
    let p2p = P2p { sender };
    TonicServer::builder()
        .add_service(p2p_server::P2pServer::new(p2p))
        .serve(addr)
        .await?;
    Ok(())
}

/// Rpc specific messages handled by the p2p node
#[derive(Debug)]
pub enum RpcMessage {
    BitswapRequest {
        cids: Vec<Cid>,
        response_channels: Vec<oneshot::Sender<Block>>,
        providers: Option<HashSet<PeerId>>,
    },
    ProviderRequest {
        key: Key,
        response_channel: oneshot::Sender<Result<HashSet<PeerId>, String>>,
    },
    NetAddrsListen(oneshot::Sender<(PeerId, Vec<Multiaddr>)>),
    NetPeers(oneshot::Sender<HashMap<PeerId, Vec<Multiaddr>>>),
    NetConnect(oneshot::Sender<bool>, PeerId, Vec<Multiaddr>),
    NetDisconnect(oneshot::Sender<()>, PeerId),
}

// pub async fn handle_get_listening_addrs(
//     state: handler::State<Sender<RpcMessage>>,
//     _cfg: Option<StreamConfig>,
//     _params: Vec<u8>,
// ) -> Result<Vec<u8>, RpcError> {
//     let (s, r) = oneshot::channel();
//     state
//         .0
//         .send(RpcMessage::NetAddrsListen(s))
//         .await
//         .expect("P2p network message receiver closed.");
//     let res = r.await.expect("Sender dropped.");
//     let res = Responses::NetAddrsListen {
//         peer_id: res.0,
//         listeners: res.1,
//     };
//     // TODO: serde should happen in rpc
//     let res = serialize_response(res)?;
//     Ok(res)
// }

// pub async fn handle_get_peers(
//     state: handler::State<Sender<RpcMessage>>,
//     _cfg: Option<StreamConfig>,
//     _params: Vec<u8>,
// ) -> Result<Vec<u8>, RpcError> {
//     let (s, r) = oneshot::channel();
//     state
//         .0
//         .send(RpcMessage::NetPeers(s))
//         .await
//         .expect("P2p network message receiver closed.");
//     let res = r.await.expect("Sender dropped.");
//     let res = Responses::NetPeers(res);
//     // TODO: serde should happen in rpc
//     let res = serialize_response(res)?;
//     Ok(res)
// }

// pub async fn handle_connect(
//     state: handler::State<Sender<RpcMessage>>,
//     _cfg: Option<StreamConfig>,
//     params: Vec<u8>,
// ) -> Result<Vec<u8>, RpcError> {
//     let req = deserialize_request::<Requests>(&params)?;
//     let (peer_id, addrs) = match req {
//         Requests::NetConnect { peer_id, addrs } => (peer_id, addrs),
//         r => return Err(RpcError::UnexpectedRequestType(r.to_string())),
//     };
//     let (s, r) = oneshot::channel();
//     state
//         .0
//         .send(RpcMessage::NetConnect(s, peer_id, addrs))
//         .await
//         .expect("P2p network message receiver closed.");
//     let res = r.await.expect("Sender dropped.");
//     let res = Responses::NetConnect(res);
//     // TODO: serde should happen in rpc
//     let res = serialize_response(res)?;
//     Ok(res)
// }

// pub async fn handle_disconnect(
//     state: handler::State<Sender<RpcMessage>>,
//     _cfg: Option<StreamConfig>,
//     params: Vec<u8>,
// ) -> Result<Vec<u8>, RpcError> {
//     // TODO: serde should happen in rpc
//     let req = deserialize_request::<Requests>(&params)?;
//     let id = match req {
//         Requests::NetDisconnect(id) => id,
//         r => return Err(RpcError::UnexpectedRequestType(r.to_string())),
//     };

//     let (s, r) = oneshot::channel();

//     state
//         .0
//         .send(RpcMessage::NetDisconnect(s, id))
//         .await
//         .expect("P2p network message receiver closed.");
//     let res = r.await.expect("Sender dropped.");
//     let res = Responses::NetDisconnect(res);
//     // TODO: serde should happen in rpc
//     let res = serialize_response(res)?;
//     Ok(res)
// }
