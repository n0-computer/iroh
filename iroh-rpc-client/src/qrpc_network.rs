use crate::status::StatusRow;
use crate::ServiceStatus;
use anyhow::{Context, Result};
use bytes::Bytes;
use cid::Cid;
use futures::{Stream, StreamExt};
use iroh_rpc_types::p2p::{GossipsubPeerAndTopics, PeerInfo};
use iroh_rpc_types::qrpc;
use iroh_rpc_types::qrpc::p2p::*;
use libp2p::gossipsub::{MessageId, TopicHash};
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};

pub(crate) const NAME: &str = "p2p";

#[derive(Debug, Clone)]
pub struct P2pClient {
    client: quic_rpc::RpcClient<P2pService, crate::ChannelTypes>,
}

impl P2pClient {
    pub async fn new(addr: iroh_rpc_types::qrpc::addr::Addr<P2pService>) -> anyhow::Result<Self> {
        match addr {
            iroh_rpc_types::qrpc::addr::Addr::Qrpc(addr) => {
                todo!()
            }
            iroh_rpc_types::qrpc::addr::Addr::Mem(channel) => {
                let channel = quic_rpc::combined::Channel::new(Some(channel), None);
                Ok(Self {
                    client: quic_rpc::RpcClient::new(channel),
                })
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.client.rpc(qrpc::p2p::VersionRequest).await?;
        Ok(res.version)
    }

    // #[tracing::instrument(skip(self))]
    pub async fn local_peer_id(&self) -> Result<PeerId> {
        let res = self.client.rpc(qrpc::p2p::LocalPeerIdRequest).await?;
        let peer_id = PeerId::from_multihash(res.peer_id.0)
            .map_err(|e| anyhow::anyhow!("invalid peer id"))?;
        Ok(peer_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn external_addresses(&self) -> Result<Vec<Multiaddr>> {
        let res = self.client.rpc(qrpc::p2p::ExternalAddrsRequest).await?;
        Ok(res.addrs)
    }

    #[tracing::instrument(skip(self))]
    pub async fn listeners(&self) -> Result<Vec<Multiaddr>> {
        let res = self.client.rpc(qrpc::p2p::ListenersRequest).await?;
        Ok(res.addrs)
    }

    // Fetches a block directly from the network.
    #[tracing::instrument(skip(self))]
    pub async fn fetch_bitswap(
        &self,
        ctx: u64,
        cid: Cid,
        providers: HashSet<PeerId>,
    ) -> Result<Bytes> {
        debug!("rpc p2p client fetch_bitswap: {:?}", cid);
        let providers = providers
            .into_iter()
            .map(qrpc::p2p::PeerId::from_libp2p)
            .collect();
        let res = self
            .client
            .rpc(qrpc::p2p::FetchBitswapRequest {
                ctx,
                cid,
                providers,
            })
            .await?;
        Ok(res.data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn stop_session_bitswap(&self, ctx: u64) -> Result<()> {
        self.client
            .rpc(qrpc::p2p::StopSessionBitswapRequest { ctx })
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn notify_new_blocks_bitswap(&self, blocks: Vec<(Cid, Bytes)>) -> Result<()> {
        let req = qrpc::p2p::NotifyNewBlocksBitswapRequest {
            blocks: blocks
                .into_iter()
                .map(|(cid, data)| qrpc::p2p::BitswapBlock { cid, data })
                .collect(),
        };

        self.client.rpc(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn fetch_providers_dht(
        &self,
        key: &Cid,
    ) -> Result<impl Stream<Item = Result<HashSet<PeerId>>>> {
        let key = qrpc::p2p::DhtKey(key.hash().to_bytes().into());
        let res = self
            .client
            .server_streaming(qrpc::p2p::FetchProvidersDhtRequest { key })
            .await?;
        let providers_stream = res.map(|p| {
            p?.providers
                .into_iter()
                .map(qrpc::p2p::PeerId::try_into_libp2p)
                .collect::<Result<HashSet<PeerId>>>()
        });
        Ok(providers_stream)
    }

    #[tracing::instrument(skip(self))]
    pub async fn start_providing(&self, key: &Cid) -> Result<()> {
        let key = qrpc::p2p::DhtKey(key.hash().to_bytes().into());
        self.client
            .rpc(qrpc::p2p::StartProvidingRequest { key })
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn stop_providing(&self, key: &Cid) -> Result<()> {
        let key = qrpc::p2p::DhtKey(key.hash().to_bytes().into());
        self.client
            .rpc(qrpc::p2p::StopProvidingRequest { key })
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_listening_addrs(&self) -> Result<(PeerId, Vec<Multiaddr>)> {
        let res = self.client.rpc(qrpc::p2p::GetListeningAddrsRequest).await?;
        let peer_id = res.peer_id.try_into_libp2p()?;
        Ok((peer_id, res.addrs))
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        let res = self.client.rpc(qrpc::p2p::GetPeersRequest).await?;
        let peers_map = res
            .peers
            .into_iter()
            .map(|(peer_id, values)| {
                let peer_id = peer_id.try_into_libp2p()?;
                Ok((peer_id, values))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(peers_map)
    }

    #[tracing::instrument(skip(self))]
    /// Attempts to connect to the given node. If only the `PeerId` is present, it will
    /// attempt to find the given peer on the DHT before connecting. If the `PeerId` and any
    /// `Multiaddr`s are present, it will attempt to connect to the peer directly.
    pub async fn connect(&self, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Result<()> {
        if !addrs.is_empty() {
            let req = qrpc::p2p::PeerConnectRequest {
                peer_id: qrpc::p2p::PeerId::from_libp2p(peer_id),
                addrs,
            };
            self.client.rpc(req).await?;
        } else {
            let req = qrpc::p2p::PeerConnectByPeerIdRequest {
                peer_id: qrpc::p2p::PeerId::from_libp2p(peer_id),
            };
            self.client.rpc(req).await?;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn lookup(&self, peer_id: PeerId, addr: Option<Multiaddr>) -> Result<Lookup> {
        let req = qrpc::p2p::LookupRequest {
            peer_id: qrpc::p2p::PeerId::from_libp2p(peer_id),
            addr,
        };
        let res = self.client.rpc(req).await?;
        Ok(Lookup {
            peer_id: res.peer_id.try_into_libp2p()?,
            listen_addrs: res.listen_addrs,
            observed_addrs: vec![res.observed_addr],
            protocols: res.protocols,
            agent_version: res.agent_version,
            protocol_version: res.protocol_version,
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        warn!("NetDisconnect not yet implemented on p2p node");
        let req = qrpc::p2p::PeerDisconnectRequest {
            peer_id: qrpc::p2p::PeerId::from_libp2p(peer_id),
        };
        self.client.rpc(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<()> {
        self.client.rpc(qrpc::p2p::ShutdownRequest).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_add_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        self.client
            .rpc(qrpc::p2p::GossipsubAddExplicitPeerRequest {
                peer_id: qrpc::p2p::PeerId::from_libp2p(peer_id),
            })
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_all_mesh_peers(&self) -> Result<Vec<PeerId>> {
        let res = self
            .client
            .rpc(qrpc::p2p::GossipsubAllMeshPeersRequest)
            .await?;
        Ok(res
            .peers
            .into_iter()
            .map(|p| p.try_into_libp2p())
            .collect::<anyhow::Result<_>>()?)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_all_peers(&self) -> Result<Vec<(PeerId, Vec<TopicHash>)>> {
        let res = self.client.rpc(qrpc::p2p::GossipsubAllPeersRequest).await?;
        let res = res
            .all
            .into_iter()
            .map(|(peer_id, topics)| {
                let peer_id = peer_id.try_into_libp2p()?;
                let topics = topics.into_iter().map(TopicHash::from_raw).collect();
                Ok((peer_id, topics))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(res)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_mesh_peers(&self, topic: TopicHash) -> Result<Vec<PeerId>> {
        let res = self
            .client
            .rpc(qrpc::p2p::GossipsubMeshPeersRequest {
                topic_hash: topic.to_string(),
            })
            .await?;
        res.peers
            .into_iter()
            .map(|p| p.try_into_libp2p())
            .collect::<anyhow::Result<_>>()
    }

    #[tracing::instrument(skip(self, data))]
    pub async fn gossipsub_publish(&self, topic_hash: TopicHash, data: Bytes) -> Result<MessageId> {
        let req = qrpc::p2p::GossipsubPublishRequest {
            topic_hash: topic_hash.to_string(),
            data,
        };
        let res = self.client.rpc(req).await?;
        let message_id = MessageId::new(&res.message_id);
        Ok(message_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_remove_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        let req = qrpc::p2p::GossipsubRemoveExplicitPeerRequest {
            peer_id: qrpc::p2p::PeerId::from_libp2p(peer_id),
        };
        self.client.rpc(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_subscribe(&self, topic: TopicHash) -> Result<bool> {
        let req = qrpc::p2p::GossipsubSubscribeRequest {
            topic_hash: topic.to_string(),
        };
        let res = self.client.rpc(req).await?;
        Ok(res.was_subscribed)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_topics(&self) -> Result<Vec<TopicHash>> {
        let res = self.client.rpc(qrpc::p2p::GossipsubTopicsRequest).await?;
        let topics = res.topics.into_iter().map(TopicHash::from_raw).collect();
        Ok(topics)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_unsubscribe(&self, topic: TopicHash) -> Result<bool> {
        let req = qrpc::p2p::GossipsubUnsubscribeRequest {
            topic_hash: topic.to_string(),
        };
        let res = self.client.rpc(req).await?;
        Ok(res.was_subscribed)
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        let status: ServiceStatus = self
            .version()
            .await
            .map(|_| ServiceStatus::Serving)
            .unwrap_or_else(|e| ServiceStatus::Unknown);
        StatusRow {
            name: "p2p",
            number: 2,
            status,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        futures::stream::pending()
    }
}

#[derive(Debug)]
pub struct Lookup {
    pub peer_id: PeerId,
    pub listen_addrs: Vec<Multiaddr>,
    pub observed_addrs: Vec<Multiaddr>,
    pub protocol_version: String,
    pub agent_version: String,
    pub protocols: Vec<String>,
}

impl Lookup {
    fn from_peer_info(p: PeerInfo) -> Result<Self> {
        let peer_id = peer_id_from_bytes(p.peer_id)?;
        let listen_addrs = addrs_from_bytes(p.listen_addrs)?;
        let addr = addr_from_bytes(p.observed_addr)?;
        Ok(Self {
            peer_id,
            protocol_version: p.protocol_version,
            agent_version: p.agent_version,
            listen_addrs,
            protocols: p.protocols,
            observed_addrs: vec![addr],
        })
    }
}

fn peers_and_topics_from_bytes(pt: GossipsubPeerAndTopics) -> Result<(PeerId, Vec<TopicHash>)> {
    let peer_id = peer_id_from_bytes(pt.peer_id)?;
    let topics = pt.topics.into_iter().map(TopicHash::from_raw).collect();
    Ok((peer_id, topics))
}

fn all_peers_from_bytes(a: Vec<GossipsubPeerAndTopics>) -> Result<Vec<(PeerId, Vec<TopicHash>)>> {
    a.into_iter().map(peers_and_topics_from_bytes).collect()
}

fn peer_id_from_bytes(p: Vec<u8>) -> Result<PeerId> {
    PeerId::from_bytes(&p).context("invalid PeerId")
}

fn peer_ids_from_bytes(p: Vec<Vec<u8>>) -> Result<Vec<PeerId>> {
    p.into_iter().map(peer_id_from_bytes).collect()
}

fn addr_from_bytes(m: Vec<u8>) -> Result<Multiaddr> {
    Multiaddr::try_from(m).context("invalid multiaddr")
}

fn addrs_from_bytes(a: Vec<Vec<u8>>) -> Result<Vec<Multiaddr>> {
    a.into_iter().map(addr_from_bytes).collect()
}
