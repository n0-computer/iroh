use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
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
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let conn = tonic::transport::Endpoint::new(addr.to_string())?
            .keep_alive_while_idle(true)
            .connect_lazy();

        let client = p2p::p2p_client::P2pClient::new(conn);

        Ok(P2pClient(Arc::new(Mutex::new(client))))
    }

    // Fetches a block directly from the network.
    #[tracing::instrument(skip(self))]
    pub async fn fetch_bitswap(
        &self,
        cid: Cid,
        providers: Option<HashSet<PeerId>>,
    ) -> Result<Bytes> {
        let providers = providers.map(|p| {
            let list = p.into_iter().map(|id| id.to_bytes()).collect::<Vec<_>>();
            p2p::Providers { providers: list }
        });

        let req = iroh_metrics::req::trace_tonic_req(p2p::BitswapRequest {
            cid: cid.to_bytes(),
            providers,
        });
        let res = self.0.lock().await.fetch_bitswap(req).await?;
        Ok(res.into_inner().data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn fetch_provider(&self, _key: &[u8]) -> Result<HashSet<PeerId>> {
        // let req = Requests::FetchProvider { key };
        // self.0.call(Namespace, Methods::FetchProvider, req).await
        todo!()
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_listening_addrs(&self) -> Result<()> {
        todo!()
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        todo!()
    }

    #[tracing::instrument(skip(self))]
    pub async fn connect(
        &self,
        _peer_id: PeerId,
        _addrs: Vec<Multiaddr>,
    ) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        todo!()
    }

    #[tracing::instrument(skip(self))]
    pub async fn disconnect(&self, _peer_id: PeerId) -> Result<()> {
        todo!()
    }
}
