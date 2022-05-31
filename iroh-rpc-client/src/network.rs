use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use anyhow::{Context, Result};
use bytes::Bytes;
use cid::Cid;
use futures::Stream;
use iroh_rpc_types::p2p::{
    self, BitswapRequest, ConnectRequest, DisconnectRequest, Empty, Key, Providers,
};
use libp2p::{Multiaddr, PeerId};
use tonic::transport::{Channel, Endpoint};
use tonic_health::proto::health_client::HealthClient;
use tracing::{debug, warn};

use crate::status::{self, StatusRow};

// name that the health service registers the p2p client as
// this is derived from the protobuf definition of a `P2pServer`
pub(crate) const SERVICE_NAME: &str = "p2p.P2p";

// the display name that we expect to see in the StatusTable
pub(crate) const NAME: &str = "p2p";

#[derive(Debug, Clone)]
pub struct P2pClient {
    p2p: p2p::p2p_client::P2pClient<Channel>,
    health: HealthClient<Channel>,
}

impl P2pClient {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let conn = Endpoint::new(format!("http://{}", addr))?
            .keep_alive_while_idle(true)
            .connect_lazy();

        let client = p2p::p2p_client::P2pClient::new(conn.clone());
        let health_client = HealthClient::new(conn);

        Ok(P2pClient {
            p2p: client,
            health: health_client,
        })
    }

    // Fetches a block directly from the network.
    #[tracing::instrument(skip(self))]
    pub async fn fetch_bitswap(&self, cid: Cid, providers: HashSet<PeerId>) -> Result<Bytes> {
        debug!("rpc p2p client fetch_bitswap: {:?}", cid);
        let providers = Providers {
            providers: providers.into_iter().map(|id| id.to_bytes()).collect(),
        };

        let req = iroh_metrics::req::trace_tonic_req(BitswapRequest {
            cid: cid.to_bytes(),
            providers: Some(providers),
        });
        let res = self.p2p.clone().fetch_bitswap(req).await?;
        Ok(res.into_inner().data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn fetch_providers(&self, key: &Cid) -> Result<HashSet<PeerId>> {
        let req = iroh_metrics::req::trace_tonic_req(Key {
            key: key.hash().to_bytes(),
        });
        let res = self.p2p.clone().fetch_provider(req).await?;
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
            .p2p
            .clone()
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
        let peers = self.p2p.clone().get_peers(req).await?.into_inner().peers;
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
        let res = self.p2p.clone().peer_connect(req).await?.into_inner();
        Ok(res.success)
    }

    #[tracing::instrument(skip(self))]
    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        warn!("NetDisconnect not yet implemented on p2p node");
        let req = iroh_metrics::req::trace_tonic_req(DisconnectRequest {
            peer_id: peer_id.to_bytes(),
        });
        let res = self.p2p.clone().peer_disconnect(req).await?.into_inner();
        Ok(res)
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        status::check(self.health.clone(), SERVICE_NAME, NAME).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        status::watch(self.health.clone(), SERVICE_NAME, NAME).await
    }
}

fn addr_from_bytes(m: Vec<u8>) -> Result<Multiaddr> {
    Multiaddr::try_from(m).context("invalid multiaddr")
}

fn addrs_from_bytes(a: Vec<Vec<u8>>) -> Result<Vec<Multiaddr>> {
    a.into_iter().map(addr_from_bytes).collect()
}
