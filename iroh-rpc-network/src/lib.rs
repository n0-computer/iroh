use async_channel::Sender;
use bytes::Buf;
use futures::channel::oneshot;
use libp2p::identity::Keypair;
use libp2p::Swarm;

use iroh_rpc::handler;
use iroh_rpc::serde::{deserialize_request, serialize_response};
use iroh_rpc::stream::{Header, OutStream, StreamConfig, DEFAULT_CHUNK_SIZE};
use iroh_rpc::{new_mem_swarm, new_tcp_swarm, Behaviour, RpcBuilder, RpcError, Server, State};
use iroh_rpc_client::Client;
use iroh_rpc_types::p2p::{Methods, Namespace, Requests, Responses, RpcMessage};

pub async fn tcp_p2p_rpc(
    keys: Keypair,
    sender: Sender<RpcMessage>,
) -> Result<(Client, Server<Sender<RpcMessage>>), RpcError> {
    let swarm = new_tcp_swarm(keys).await?;
    new_p2p_rpc(swarm, sender)
}

pub fn mem_p2p_rpc(
    keys: Keypair,
    sender: Sender<RpcMessage>,
) -> Result<(Client, Server<Sender<RpcMessage>>), RpcError> {
    new_p2p_rpc(new_mem_swarm(keys), sender)
}

fn new_p2p_rpc(
    swarm: Swarm<Behaviour>,
    sender: Sender<RpcMessage>,
) -> Result<(Client, Server<Sender<RpcMessage>>), RpcError> {
    let (client, server) = RpcBuilder::new(Namespace)
        .with_swarm(swarm)
        .with_state(State::new(sender))
        .with_namespace(Namespace, |n| {
            n.with_method(Methods::FetchBitswap, handle_fetch_bitswap)
                .with_method(Methods::FetchProvider, handle_fetch_provider)
                .with_method(Methods::GetListeningAddrs, handle_get_listening_addrs)
                .with_method(Methods::GetPeers, handle_get_peers)
                .with_method(Methods::Connect, handle_connect)
                .with_method(Methods::Disconnect, handle_disconnect)
        })
        .build()?;
    let client = Client::new(client);
    Ok((client, server))
}

pub async fn handle_get_listening_addrs(
    state: handler::State<Sender<RpcMessage>>,
    _cfg: Option<StreamConfig>,
    _params: Vec<u8>,
) -> Result<Vec<u8>, RpcError> {
    let (s, r) = oneshot::channel();
    state
        .0
        .send(RpcMessage::NetAddrsListen(s))
        .await
        .expect("P2p network message receiver closed.");
    let res = r.await.expect("Sender dropped.");
    let res = Responses::NetAddrsListen {
        peer_id: res.0,
        listeners: res.1,
    };
    // TODO: serde should happen in rpc
    let res = serialize_response(res)?;
    Ok(res)
}

pub async fn handle_get_peers(
    state: handler::State<Sender<RpcMessage>>,
    _cfg: Option<StreamConfig>,
    _params: Vec<u8>,
) -> Result<Vec<u8>, RpcError> {
    let (s, r) = oneshot::channel();
    state
        .0
        .send(RpcMessage::NetPeers(s))
        .await
        .expect("P2p network message receiver closed.");
    let res = r.await.expect("Sender dropped.");
    let res = Responses::NetPeers(res);
    // TODO: serde should happen in rpc
    let res = serialize_response(res)?;
    Ok(res)
}

pub async fn handle_connect(
    state: handler::State<Sender<RpcMessage>>,
    _cfg: Option<StreamConfig>,
    params: Vec<u8>,
) -> Result<Vec<u8>, RpcError> {
    let req = deserialize_request::<Requests>(&params)?;
    let (peer_id, addrs) = match req {
        Requests::NetConnect { peer_id, addrs } => (peer_id, addrs),
        r => return Err(RpcError::UnexpectedRequestType(r.to_string())),
    };
    let (s, r) = oneshot::channel();
    state
        .0
        .send(RpcMessage::NetConnect(s, peer_id, addrs))
        .await
        .expect("P2p network message receiver closed.");
    let res = r.await.expect("Sender dropped.");
    let res = Responses::NetConnect(res);
    // TODO: serde should happen in rpc
    let res = serialize_response(res)?;
    Ok(res)
}

pub async fn handle_disconnect(
    state: handler::State<Sender<RpcMessage>>,
    _cfg: Option<StreamConfig>,
    params: Vec<u8>,
) -> Result<Vec<u8>, RpcError> {
    // TODO: serde should happen in rpc
    let req = deserialize_request::<Requests>(&params)?;
    let id = match req {
        Requests::NetDisconnect(id) => id,
        r => return Err(RpcError::UnexpectedRequestType(r.to_string())),
    };

    let (s, r) = oneshot::channel();

    state
        .0
        .send(RpcMessage::NetDisconnect(s, id))
        .await
        .expect("P2p network message receiver closed.");
    let res = r.await.expect("Sender dropped.");
    let res = Responses::NetDisconnect(res);
    // TODO: serde should happen in rpc
    let res = serialize_response(res)?;
    Ok(res)
}

// TODO: expand to handle multiple cids at once. Probably not a tough fix, just want to push
// forward right now
pub async fn handle_fetch_bitswap(
    state: handler::State<Sender<RpcMessage>>,
    cfg: Option<StreamConfig>,
    params: Vec<u8>,
) -> Result<Vec<u8>, RpcError> {
    let cfg = match cfg {
        Some(c) => c,
        None => return Err(RpcError::NoStreamConfig),
    };

    // TODO: serde should happen in rpc
    let req = deserialize_request::<Requests>(&params)?;
    let (cid, providers) = match req {
        Requests::FetchBitswap { cid, providers } => (cid, providers),
        r => return Err(RpcError::UnexpectedRequestType(r.to_string())),
    };

    let (s, r) = oneshot::channel();

    state
        .0
        .send(RpcMessage::BitswapRequest {
            cids: vec![cid],
            providers,
            response_channels: vec![s],
        })
        .await
        .expect("P2p network message receiver closed.");
    let block = r.await.expect("Sender dropped.");
    let bytes = block.data();
    let header = Header::new(cfg.id, bytes.len() as u64, DEFAULT_CHUNK_SIZE);
    let r = std::io::BufReader::new(bytes.to_owned().reader());

    let mut stream = OutStream::new(cfg, header.clone(), Box::new(r));

    let _ = tokio::spawn(async move {
        stream.send_packets().await;
    });

    // TODO: serde should happen in rpc
    let header = rkyv::to_bytes::<_, 1024>(&header).expect("header to serialize");
    Ok(header.to_vec())
}

pub async fn handle_fetch_provider(
    state: handler::State<Sender<RpcMessage>>,
    _cfg: Option<StreamConfig>,
    params: Vec<u8>,
) -> Result<Vec<u8>, RpcError> {
    // TODO: serde should happen in rpc
    let req = deserialize_request::<Requests>(&params)?;
    let key = match req {
        Requests::FetchProvider { key } => key,
        r => return Err(RpcError::UnexpectedRequestType(r.to_string())),
    };

    let (s, r) = oneshot::channel();

    state
        .0
        .send(RpcMessage::ProviderRequest {
            key,
            response_channel: s,
        })
        .await
        .expect("P2p network message receiver closed.");
    let res = r.await.expect("Sender dropped.");
    let res = Responses::ProviderResponse(res);
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
