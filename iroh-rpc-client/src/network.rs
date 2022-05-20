use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use cid::Cid;
use iroh_rpc_types::p2p::{
    self, BitswapRequest, ConnectRequest, DisconnectRequest, Empty, Key, Providers,
};
use libp2p::{Multiaddr, PeerId};
use tokio::sync::Mutex;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct P2pClient(Arc<Mutex<p2p::p2p_client::P2pClient<tonic::transport::Channel>>>);

impl P2pClient {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let conn = tonic::transport::Endpoint::new(format!("http://{}", addr))?
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
            Providers { providers: list }
        });

        let req = iroh_metrics::req::trace_tonic_req(BitswapRequest {
            cid: cid.to_bytes(),
            providers,
        });
        let res = self.0.lock().await.fetch_bitswap(req).await?;
        Ok(res.into_inner().data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn fetch_providers(&self, key: &Cid) -> Result<HashSet<PeerId>> {
        let req = iroh_metrics::req::trace_tonic_req(Key {
            key: key.hash().to_bytes(),
        });
        let res = self.0.lock().await.fetch_provider(req).await?;
        let mut providers = HashSet::new();
        for provider in res.into_inner().providers.into_iter() {
            providers.insert(PeerId::from_bytes(&provider[..])?);
        }
        Ok(providers)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_listening_addrs(&self) -> Result<(PeerId, Vec<Multiaddr>)> {
        let req = iroh_metrics::req::trace_tonic_req(Empty {});
        let res = self
            .0
            .lock()
            .await
            .get_listening_addrs(req)
            .await?
            .into_inner();
        let peer_id = PeerId::from_bytes(&res.peer_id[..])?;
        let addrs = addrs_from_bytes(res.addrs)?;
        Ok((peer_id, addrs))
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        let req = iroh_metrics::req::trace_tonic_req(Empty {});
        let peers = self.0.lock().await.get_peers(req).await?.into_inner().peers;
        let mut peers_map = HashMap::new();
        for (peer, addrs) in peers.into_iter() {
            let peer = peer.parse()?;
            let addrs = addrs_from_bytes(addrs.addrs)?;
            peers_map.insert(peer, addrs);
        }
        Ok(peers_map)
    }

    #[tracing::instrument(skip(self))]
    pub async fn connect(&self, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Result<bool> {
        let req = iroh_metrics::req::trace_tonic_req(ConnectRequest {
            peer_id: peer_id.to_bytes(),
            addrs: addrs.iter().map(|a| a.to_vec()).collect(),
        });
        let res = self.0.lock().await.peer_connect(req).await?.into_inner();
        Ok(res.success)
    }

    #[tracing::instrument(skip(self))]
    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        warn!("NetDisconnect not yet implemented on p2p node");
        let req = iroh_metrics::req::trace_tonic_req(DisconnectRequest {
            peer_id: peer_id.to_bytes(),
        });
        let res = self.0.lock().await.peer_disconnect(req).await?.into_inner();
        Ok(res)
    }
}

fn addr_from_bytes(m: Vec<u8>) -> Result<Multiaddr> {
    Multiaddr::try_from(m).context("invalid multiaddr")
}

fn addrs_from_bytes(a: Vec<Vec<u8>>) -> Result<Vec<Multiaddr>> {
    a.into_iter().map(addr_from_bytes).collect()
}
