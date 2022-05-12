use async_channel::Sender;
use futures::channel::oneshot;
use libp2p::{Multiaddr, PeerId};

use iroh_p2p::{NetRPCMethods, NetworkMessage};
use iroh_rpc::handler;
use iroh_rpc::serde::{deserialize_request, serialize_response, Deserialize, Serialize};
use iroh_rpc::stream::StreamConfig;
use iroh_rpc::RpcError;
use iroh_rpc_commands::p2p::{NetworkMessage, NetRPCMethods}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum NetRPCRequests {
    NetConnect{
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    }
    NetDisconnect(PeerId),
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum NetRPCResponses {
    NetAddrsListen {
        peer_id: PeerId,
        listeners: Vec<Multiaddr>,
    },
    NetPeers(HashMap<PeerId, Vec<Multiaddr>>),
    NetConnect(bool),
    NetDisconnect(()),
}

pub async fn handle_addrs_listen(
    state: handler::State<Sender<NetworkMessage>>,
    _cfg: Option<StreamConfig>,
    _params: Vec<u8>,
) -> Result<Vec<u8>, RpcError> {
    let (s, r) = oneshot::channel();
    state
        .0
        .send(NetworkMessage::RpcRequest {
            method: NetRPCMethods::NetAddrsListen(s),
        })
        .await
        .expect("P2p network message receiver closed.");
    let res = r.recv().expect("Sender dropped.");
    let res = NetRPCResponses::NetAddrsListen {
        peer_id: res.0,
        listeners: res.1,
    };
    // TODO: serde should happen in rpc
    let res = serialize_response(res)?;
    Ok(res)
}

pub async fn handle_net_peers(
    state: handler::State<Sender<NetworkMessage>>,
    _cfg: Option<StreamConfig>,
    _params: Vec<u8>,
    ) -> Result<Vec<u8>, RpcError> {
    let (s, r) = oneshot::channel();
    state.0.send(NetworkMessage::RpcRequest {
        method: NetRPCMethods::NetPeers(s),
    })
    .await
    .expect("P2p network message receiver closed.")
    let res = r.recv().expect("Sender dropped.")
    let res = NetRPCResponses::NetPeers(res);
    // TODO: serde should happen in rpc
    let res = serialize_response(res)?;
    Ok(res)
}

pub async fn handle_net_connect(
    state: handler::State<Sender<NetworkMessage>>,
    _cfg: Option<StreamConfig>,
    params: Vec<u8>,
    ) -> Result<Vec<u8>, RpcError> {
    let req = deserialize_request(params)?;
    let (s, r) = oneshot::channel();
    state.0.send(NetworkMessage::RpcRequest {
        method: NetRPCMethods::NetConnect(s, req.peer_id, req.addrs),
    })
    .await
        .expect("P2p network message receiver closed.");
    let res = r.recv().expect("Sender dropped.");
    let res = NetRPCResponses::NetPeers(res);
    // TODO: serde should happen in rpc
    let res = serialize_response(res)?;
    Ok(res)
}

pub async fn handle_net_disconnect(
    state: handler::State<Sender<NetworkMessage>>,
    _cfg: Option<StreamConfig>,
    params: Vec<u8>,
    ) -> Result<Vec<u8>, RpcError> {
    // TODO: serde should happen in rpc
    let req = deserialize_request(params)?;
    let (s, r) = oneshot::channel();
    
    state.0.send(NetworkMessage::RpcRequest {
        method: NetRPCMethods::NetDisconnect(s, req.0),
    })
    .await
        .expect("P2p network message receiver closed.");
    let res = r.recv().expect("Sender dropped.");
    let res = NetRPCResponses::NetDisconnect(res);
    // TODO: serde should happen in rpc
    let res = serialize_response(res)?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
