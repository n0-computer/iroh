use anyhow::Result;
use async_stream::stream;
use bytes::Bytes;
use cid::Cid;
use futures::{Stream, StreamExt};
use iroh_rpc_types::{p2p::*, GossipsubEvent, VersionRequest, WatchRequest};
use libp2p::gossipsub::{MessageId, TopicHash};
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};

use crate::{StatusType, HEALTH_POLL_WAIT};

#[derive(Debug, Clone)]
pub struct P2pClient {
    client: quic_rpc::RpcClient<P2pService, crate::ChannelTypes>,
}

impl P2pClient {
    pub async fn new(addr: P2pAddr) -> anyhow::Result<Self> {
        let client = crate::open_client(addr).await?;
        Ok(Self { client })
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.client.rpc(VersionRequest).await?;
        Ok(res.version)
    }

    #[tracing::instrument(skip(self))]
    pub async fn local_peer_id(&self) -> Result<PeerId> {
        let res = self.client.rpc(LocalPeerIdRequest).await??;
        Ok(res.peer_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn external_addresses(&self) -> Result<Vec<Multiaddr>> {
        let res = self.client.rpc(ExternalAddrsRequest).await??;
        Ok(res.addrs)
    }

    #[tracing::instrument(skip(self))]
    pub async fn listeners(&self) -> Result<Vec<Multiaddr>> {
        let res = self.client.rpc(ListenersRequest).await??;
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
        let providers = providers.into_iter().collect();
        let res = self
            .client
            .rpc(BitswapRequest {
                ctx,
                cid,
                providers,
            })
            .await??;
        Ok(res.data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn stop_session_bitswap(&self, ctx: u64) -> Result<()> {
        self.client.rpc(StopSessionBitswapRequest { ctx }).await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn notify_new_blocks_bitswap(&self, blocks: Vec<(Cid, Bytes)>) -> Result<()> {
        let req = NotifyNewBlocksBitswapRequest {
            blocks: blocks
                .into_iter()
                .map(|(cid, data)| BitswapBlock { cid, data })
                .collect(),
        };

        self.client.rpc(req).await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn fetch_providers_dht(
        &self,
        key: &Cid,
    ) -> Result<impl Stream<Item = Result<HashSet<PeerId>>>> {
        let key = Key(key.hash().to_bytes().into());
        let res = self
            .client
            .server_streaming(FetchProvidersDhtRequest { key })
            .await?;
        let providers_stream =
            res.map(|p| Ok(p??.providers.into_iter().collect::<HashSet<PeerId>>()));
        Ok(providers_stream)
    }

    #[tracing::instrument(skip(self))]
    pub async fn start_providing(&self, key: &Cid) -> Result<()> {
        let key = Key(key.hash().to_bytes().into());
        self.client.rpc(StartProvidingRequest { key }).await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn stop_providing(&self, key: &Cid) -> Result<()> {
        let key = Key(key.hash().to_bytes().into());
        self.client.rpc(StopProvidingRequest { key }).await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_listening_addrs(&self) -> Result<(PeerId, Vec<Multiaddr>)> {
        let res = self.client.rpc(GetListeningAddrsRequest).await??;
        Ok((res.peer_id, res.addrs))
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        let res = self.client.rpc(GetPeersRequest).await??;
        let peers_map = res.peers.into_iter().collect();
        Ok(peers_map)
    }

    #[tracing::instrument(skip(self))]
    /// Attempts to connect to the given node. If only the `PeerId` is present, it will
    /// attempt to find the given peer on the DHT before connecting. If the `PeerId` and any
    /// `Multiaddr`s are present, it will attempt to connect to the peer directly.
    pub async fn connect(&self, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Result<()> {
        if !addrs.is_empty() {
            let req = ConnectRequest { peer_id, addrs };
            self.client.rpc(req).await??;
        } else {
            let req = ConnectByPeerIdRequest { peer_id };
            self.client.rpc(req).await??;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn lookup(&self, peer_id: PeerId, addr: Option<Multiaddr>) -> Result<Lookup> {
        let req = LookupRequest { peer_id, addr };
        let res = self.client.rpc(req).await??;
        Ok(Lookup {
            peer_id: res.peer_id,
            listen_addrs: res.listen_addrs,
            observed_addrs: res.observed_addrs,
            protocols: res.protocols,
            agent_version: res.agent_version,
            protocol_version: res.protocol_version,
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn lookup_local(&self) -> Result<Lookup> {
        let req = LookupLocalRequest;
        let res = self.client.rpc(req).await??;
        Ok(Lookup {
            peer_id: res.peer_id,
            listen_addrs: res.listen_addrs,
            observed_addrs: res.observed_addrs,
            protocols: res.protocols,
            agent_version: res.agent_version,
            protocol_version: res.protocol_version,
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        warn!("NetDisconnect not yet implemented on p2p node");
        let req = DisconnectRequest { peer_id };
        self.client.rpc(req).await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<()> {
        self.client.rpc(ShutdownRequest).await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_add_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        self.client
            .rpc(GossipsubAddExplicitPeerRequest { peer_id })
            .await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_all_mesh_peers(&self) -> Result<Vec<PeerId>> {
        let res = self.client.rpc(GossipsubAllMeshPeersRequest).await??;
        Ok(res.peers)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_all_peers(&self) -> Result<Vec<(PeerId, Vec<TopicHash>)>> {
        let res = self.client.rpc(GossipsubAllPeersRequest).await??;
        let res = res
            .all
            .into_iter()
            .map(|(peer_id, topics)| {
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
            .rpc(GossipsubMeshPeersRequest {
                topic_hash: topic.to_string(),
            })
            .await??;
        Ok(res.peers)
    }

    #[tracing::instrument(skip(self, data))]
    pub async fn gossipsub_publish(&self, topic_hash: TopicHash, data: Bytes) -> Result<MessageId> {
        let req = GossipsubPublishRequest {
            topic_hash: topic_hash.to_string(),
            data,
        };
        let res = self.client.rpc(req).await??;
        let message_id = MessageId::new(&res.message_id);
        Ok(message_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_remove_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        let req = GossipsubRemoveExplicitPeerRequest { peer_id };
        self.client.rpc(req).await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_subscribe(
        &self,
        topic: TopicHash,
    ) -> Result<impl Stream<Item = Result<GossipsubEvent>>> {
        let res = self
            .client
            .server_streaming(GossipsubSubscribeRequest {
                topic_hash: topic.to_string(),
            })
            .await?;
        let events = res.map(|e| {
            let e = e?.event;
            Ok(e)
        });
        Ok(events)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_topics(&self) -> Result<Vec<TopicHash>> {
        let res = self.client.rpc(GossipsubTopicsRequest).await??;
        let topics = res.topics.into_iter().map(TopicHash::from_raw).collect();
        Ok(topics)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_unsubscribe(&self, topic: TopicHash) -> Result<bool> {
        let req = GossipsubUnsubscribeRequest {
            topic_hash: topic.to_string(),
        };
        let res = self.client.rpc(req).await??;
        Ok(res.was_subscribed)
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> (StatusType, String) {
        match self.version().await {
            Ok(version) => (StatusType::Serving, version),
            Err(_) => (StatusType::Down, String::new()),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = (StatusType, String)> {
        let client = self.client.clone();
        stream! {
            loop {
                let res = client.server_streaming(WatchRequest).await;
                if let Ok(mut res) = res {
                    while let Some(Ok(version)) = res.next().await {
                        yield (StatusType::Serving, version.version);
                    }
                }
                yield (StatusType::Down, String::new());
                tokio::time::sleep(HEALTH_POLL_WAIT).await;
            }
        }
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
