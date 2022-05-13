use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cid::Cid;
use futures::Stream;
use libp2p::kad::record::Key;
use libp2p::{Multiaddr, PeerId};

use iroh_rpc::Client as RpcClient;
use iroh_rpc::RpcError;
use iroh_rpc_types::p2p::{Methods, Namespace, Requests};

#[derive(Debug, Clone)]
pub struct P2pClient(Arc<RpcClient>);

impl P2pClient {
    pub fn new(client: Arc<RpcClient>) -> Self {
        P2pClient(Arc::clone(&client))
    }

    // fetch a block directly from the network
    // returns a stream of bytes of block data
    // TODO: current set up does not allow us to examine the header to
    // determine if we actually want to receive the block data
    pub async fn fetch_bitswap(
        &self,
        cid: Cid,
        providers: Option<HashSet<PeerId>>,
    ) -> Result<impl Stream<Item = Result<Vec<u8>, RpcError>>, RpcError> {
        let req = Requests::FetchBitswap { cid, providers };
        self.0
            .streaming_call(Namespace, Methods::FetchBitswap, req)
            .await
    }

    pub async fn fetch_provider(&self, key: Key) -> Result<HashSet<PeerId>, RpcError> {
        let req = Requests::FetchProvider { key };
        self.0.call(Namespace, Methods::FetchProvider, req).await
    }

    pub async fn get_listening_addrs(&self) -> Result<(), RpcError> {
        self.0.call(Namespace, Methods::GetListeningAddrs, ()).await
    }

    pub async fn get_peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>, RpcError> {
        self.0.call(Namespace, Methods::GetPeers, ()).await
    }

    pub async fn connect(
        &self,
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    ) -> Result<HashMap<PeerId, Vec<Multiaddr>>, RpcError> {
        self.0
            .call(
                Namespace,
                Methods::Connect,
                Requests::NetConnect { peer_id, addrs },
            )
            .await
    }

    pub async fn disconnect(&self, peer_id: PeerId) -> Result<(), RpcError> {
        self.0
            .call(
                Namespace,
                Methods::Disconnect,
                Requests::NetDisconnect(peer_id),
            )
            .await
    }
}
