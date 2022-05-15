use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use cid::Cid;
use iroh_rpc_types::p2p;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct P2pClient(Arc<Mutex<p2p::p2p_client::P2pClient<tonic::transport::Channel>>>);

impl P2pClient {
    pub async fn new(addr: &str) -> Result<Self> {
        let client = p2p::p2p_client::P2pClient::connect(addr.to_string()).await?;

        Ok(P2pClient(Arc::new(Mutex::new(client))))
    }

    // fetch a block directly from the network
    // returns a stream of bytes of block data
    // TODO: current set up does not allow us to examine the header to
    // determine if we actually want to receive the block data
    pub async fn fetch_bitswap(
        &self,
        cid: Cid,
        providers: Option<HashSet<PeerId>>,
    ) -> Result<Bytes> {
        let providers = providers.map(|p| {
            let list = p.into_iter().map(|id| id.to_bytes()).collect::<Vec<_>>();
            p2p::Providers { providers: list }
        });

        let req = p2p::BitswapRequest {
            cid: cid.to_bytes(),
            providers,
        };
        let res = self.0.lock().await.fetch_bitswap(req).await?;
        Ok(res.into_inner().data)
    }

    pub async fn fetch_provider(&self, key: &[u8]) -> Result<HashSet<PeerId>> {
        // let req = Requests::FetchProvider { key };
        // self.0.call(Namespace, Methods::FetchProvider, req).await
        todo!()
    }

    pub async fn get_listening_addrs(&self) -> Result<()> {
        todo!()
    }

    pub async fn get_peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        todo!()
    }

    pub async fn connect(
        &self,
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    ) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        todo!()
    }

    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        todo!()
    }
}
