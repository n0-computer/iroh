use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Context as _};
use bytes::Bytes;
use cid::Cid;
use iroh_bitswap::Block;
use iroh_rpc_types::p2p::PeerInfo;
use iroh_rpc_types::RpcError;
use iroh_rpc_types::{
    impl_serve,
    p2p::{P2p as RpcP2p, P2pRequest, P2pResponse},
};
use libp2p::gossipsub::{
    error::{PublishError, SubscriptionError},
    MessageId, TopicHash,
};
use libp2p::identify::Info as IdentifyInfo;
use libp2p::kad::record::Key;
use libp2p::Multiaddr;
use libp2p::PeerId;
use tarpc::context::Context;
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::oneshot;
use tracing::trace;

// use super::node::DEFAULT_PROVIDER_LIMIT;

impl_serve!(P2p, P2p, P2pRequest, P2pResponse);

#[derive(Debug, Clone)]
pub struct P2p {
    sender: Sender<RpcMessage>,
}

impl From<Sender<RpcMessage>> for P2p {
    fn from(sender: Sender<RpcMessage>) -> Self {
        P2p { sender }
    }
}

#[tarpc::server]
impl RpcP2p for P2p {
    async fn version(self, _ctx: Context) -> Result<String, RpcError> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(version)
    }

    async fn shutdown(self, _ctx: Context) -> Result<(), RpcError> {
        self.sender
            .send(RpcMessage::Shutdown)
            .await
            .map_err(RpcError::from_any)?;

        Ok(())
    }

    async fn external_addrs(self, _ctx: Context) -> Result<Vec<Multiaddr>, RpcError> {
        trace!("received ExternalAddrs request");

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::ExternalAddrs(s);

        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let addrs = r.await.map_err(RpcError::from_any)?;

        Ok(addrs)
    }

    async fn local_peer_id(self, _ctx: Context) -> Result<PeerId, RpcError> {
        trace!("received LocalPeerId request");

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::LocalPeerId(s);

        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let peer_id = r.await.map_err(RpcError::from_any)?;

        Ok(peer_id)
    }

    // TODO: expand to handle multiple cids at once. Probably not a tough fix, just want to push
    // forward right now
    async fn fetch_bitswap(
        self,
        _ctx: Context,
        context_id: u64,
        cid: Cid,
        providers: Vec<PeerId>,
    ) -> Result<Bytes, RpcError> {
        trace!("context:{}, received fetch_bitswap: {:?}", context_id, cid);
        let providers: HashSet<PeerId> = providers.into_iter().collect();

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapRequest {
            ctx: context_id,
            cids: vec![cid],
            providers,
            response_channels: vec![s],
        };

        trace!(
            "context:{} making bitswap request for {:?}",
            context_id,
            cid
        );
        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let block = r
            .await
            .map_err(|_| anyhow!("bitswap req shut down"))?
            .map_err(|e| anyhow!("bitswap: {}", e))?;

        if cid != block.cid {
            return Err(RpcError::from(anyhow!(
                "unexpected bitswap response: expected: {} got: {}",
                cid,
                block.cid
            )));
        }

        trace!("context:{} got bitswap response for {:?}", context_id, cid);

        Ok(block.data)
    }

    async fn stop_session_bitswap(self, _ctx: Context, context_id: u64) -> Result<(), RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapStopSession {
            ctx: context_id,
            response_channel: s,
        };

        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        r.await
            .map_err(RpcError::from_any)?
            .context("stop session")?;

        Ok(())
    }

    async fn notify_new_blocks_bitswap(
        self,
        _ctx: Context,
        blocks: Vec<(Cid, Bytes)>,
    ) -> Result<(), RpcError> {
        let blocks = blocks
            .into_iter()
            .map(|(cid, data)| Block::new(data, cid))
            .collect::<Vec<Block>>();

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapNotifyNewBlocks {
            blocks,
            response_channel: s,
        };

        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        r.await
            .map_err(RpcError::from_any)?
            .map_err(|e| anyhow!(e))?;

        Ok(())
    }

    async fn fetch_provider_dht(
        self,
        _ctx: Context,
        key: Cid,
        limit: usize,
    ) -> Result<HashSet<PeerId>, RpcError> {
        let (s, mut r) = mpsc::channel(limit.min(32));

        let msg = RpcMessage::ProviderRequest {
            key: ProviderRequestKey::Dht(key.hash().to_bytes().into()),
            response_channel: s,
            limit,
        };

        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let mut results = HashSet::with_capacity(limit);
        while let Some(provider) = r.recv().await {
            let provider = provider?;
            results.extend(provider);
        }

        Ok(results)
    }

    async fn start_providing(self, _ctx: Context, key: Vec<u8>) -> Result<(), RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::StartProviding(s, key.into());

        self.sender.send(msg).await.map_err(RpcError::from_any)?;

        let _query_id = r.await.map_err(RpcError::from_any)??;
        Ok(())
    }

    async fn stop_providing(self, _ctx: Context, key: Vec<u8>) -> Result<(), RpcError> {
        trace!("received StopProviding request: {:?}", key);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::StopProviding(s, key.into());

        self.sender.send(msg).await.map_err(RpcError::from_any)?;

        r.await.map_err(RpcError::from_any)??;
        Ok(())
    }

    async fn get_listening_addrs(
        self,
        _ctx: Context,
    ) -> Result<(PeerId, Vec<Multiaddr>), RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetListeningAddrs(s);
        self.sender.send(msg).await.map_err(RpcError::from_any)?;

        let (peer_id, addrs) = r.await.map_err(RpcError::from_any)?;

        Ok((peer_id, addrs))
    }

    async fn get_peers(self, _ctx: Context) -> Result<HashMap<PeerId, Vec<Multiaddr>>, RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetPeers(s);
        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let peers = r.await.map_err(RpcError::from_any)?;

        Ok(peers)
    }

    /// Dial the peer directly using the PeerId and Multiaddr
    /// If no addrs are provided it first attempts to find the peer on the DHT, if found, it will then ensure we have
    /// a connection to the peer.
    async fn peer_connect(
        self,
        _ctx: Context,
        peer_id: PeerId,
        addrs: Option<Vec<Multiaddr>>,
    ) -> Result<(), RpcError> {
        if let Some(addrs) = addrs {
            let (s, r) = oneshot::channel();
            let msg = RpcMessage::NetConnect(s, peer_id, addrs);
            self.sender.send(msg).await.map_err(RpcError::from_any)?;
            let ack = r.await.map_err(RpcError::from_any)??;
            Ok(ack)
        } else {
            let (s, r) = oneshot::channel();
            // ask the swarm if we already have address for this peer
            let msg = RpcMessage::AddressesOfPeer(s, peer_id);
            self.sender.send(msg).await.map_err(RpcError::from_any)?;
            let addrs = r.await.map_err(RpcError::from_any)?;

            if addrs.is_empty() {
                // if we don't have the addr info for this peer, we need to try to
                // find it on the dht
                let (s, r) = oneshot::channel();
                let msg = RpcMessage::FindPeerOnDHT(s, peer_id);
                self.sender.send(msg).await.map_err(RpcError::from_any)?;
                r.await.map_err(RpcError::from_any)??;
            }

            // now we know we have found the peer on the dht,
            // we can attempt to dial it
            let (s, r) = oneshot::channel();
            let msg = RpcMessage::NetConnectByPeerId(s, peer_id);
            self.sender.send(msg).await.map_err(RpcError::from_any)?;
            let ack = r.await.map_err(RpcError::from_any)??;
            Ok(ack)
        }
    }

    async fn peer_disconnect(self, _ctx: Context, peer: PeerId) -> Result<(), RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetDisconnect(s, peer);
        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let ack = r.await.map_err(RpcError::from_any)?;

        Ok(ack)
    }

    async fn lookup(
        self,
        ctx: Context,
        peer_id: PeerId,
        addr: Option<Multiaddr>,
    ) -> Result<PeerInfo, RpcError> {
        let (s, r) = oneshot::channel();

        // check if we have already encountered this peer, and already
        // that the peer info
        let msg = RpcMessage::LookupPeerInfo(s, peer_id);
        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        if let Some(info) = r.await.map_err(RpcError::from_any)? {
            return Ok(peer_info_from_identify_info(info));
        }

        // listen for if any peer info for this peer gets sent to us
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::ListenForIdentify(s, peer_id);
        self.sender.send(msg).await.map_err(RpcError::from_any)?;

        // once we connect to the peer, the idenitfy protocol
        // will attempt to exchange peer info
        let res = match addr {
            Some(addr) => {
                self.clone()
                    .peer_connect(ctx, peer_id, Some(vec![addr]))
                    .await
            }
            None => self.clone().peer_connect(ctx, peer_id, None).await,
        };

        if let Err(e) = res {
            let (s, r) = oneshot::channel();
            self.sender
                .send(RpcMessage::CancelListenForIdentify(s, peer_id))
                .await
                .map_err(RpcError::from_any)?;
            r.await.map_err(RpcError::from_any)?;
            return Err(anyhow!("Cannot get peer information: {}", e).into());
        }

        let info = r.await.map_err(RpcError::from_any)??;

        Ok(peer_info_from_identify_info(info))
    }

    async fn gossipsub_add_explicit_peer(
        self,
        _ctx: Context,
        peer: PeerId,
    ) -> Result<(), RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AddExplicitPeer(s, peer));
        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        r.await.map_err(RpcError::from_any)?;

        Ok(())
    }

    async fn gossipsub_all_mesh_peers(self, _ctx: Context) -> Result<Vec<PeerId>, RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AllMeshPeers(s));
        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let peers = r.await.map_err(RpcError::from_any)?;

        Ok(peers)
    }

    async fn gossipsub_all_peers(
        self,
        _ctx: Context,
    ) -> Result<Vec<(PeerId, Vec<String>)>, RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AllPeers(s));
        self.sender.send(msg).await.map_err(RpcError::from_any)?;

        let all_peers = r.await.map_err(RpcError::from_any)?;
        let all_peers = all_peers
            .into_iter()
            .map(|(peer, topics)| (peer, topics.into_iter().map(|t| t.to_string()).collect()))
            .collect();
        Ok(all_peers)
    }

    async fn gossipsub_mesh_peers(
        self,
        _ctx: Context,
        topic_hash: String,
    ) -> Result<Vec<PeerId>, RpcError> {
        let topic = TopicHash::from_raw(topic_hash);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::MeshPeers(s, topic));
        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let peers = r.await.map_err(RpcError::from_any)?;

        Ok(peers)
    }

    async fn gossipsub_publish(
        self,
        _ctx: Context,
        topic_hash: String,
        data: Bytes,
    ) -> Result<Vec<u8>, RpcError> {
        let topic_hash = TopicHash::from_raw(topic_hash);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Publish(s, topic_hash, data));
        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let message_id = r
            .await
            .map_err(RpcError::from_any)?
            .map_err(RpcError::from_any)?;

        Ok(message_id.0)
    }

    async fn gossipsub_remove_explicit_peer(
        self,
        _ctx: Context,
        peer: PeerId,
    ) -> Result<(), RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::RemoveExplicitPeer(s, peer));
        self.sender.send(msg).await.map_err(RpcError::from_any)?;

        r.await.map_err(RpcError::from_any)?;
        Ok(())
    }

    async fn gossipsub_subscribe(
        self,
        _ctx: Context,
        topic_hash: String,
    ) -> Result<bool, RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Subscribe(
            s,
            TopicHash::from_raw(topic_hash),
        ));
        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let was_subscribed = r
            .await
            .map_err(RpcError::from_any)?
            .map_err(RpcError::from_any)?;

        Ok(was_subscribed)
    }

    async fn gossipsub_topics(self, _ctx: Context) -> Result<Vec<String>, RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Topics(s));

        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let topics: Vec<String> = r
            .await
            .map_err(RpcError::from_any)?
            .into_iter()
            .map(|t| t.into_string())
            .collect();

        Ok(topics)
    }

    async fn gossipsub_unsubscribe(
        self,
        _ctx: Context,
        topic_hash: String,
    ) -> Result<bool, RpcError> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Unsubscribe(
            s,
            TopicHash::from_raw(topic_hash),
        ));

        self.sender.send(msg).await.map_err(RpcError::from_any)?;
        let was_subscribed = r
            .await
            .map_err(RpcError::from_any)?
            .map_err(RpcError::from_any)?;

        Ok(was_subscribed)
    }
}

#[derive(Debug)]
pub enum ProviderRequestKey {
    // TODO: potentially change this to Cid, as that is the only key we use for providers
    Dht(Key),
    Bitswap(u64, Cid),
}

/// Rpc specific messages handled by the p2p node
#[derive(Debug)]
pub enum RpcMessage {
    ExternalAddrs(oneshot::Sender<Vec<Multiaddr>>),
    LocalPeerId(oneshot::Sender<PeerId>),
    BitswapRequest {
        ctx: u64,
        cids: Vec<Cid>,
        response_channels: Vec<oneshot::Sender<Result<Block, String>>>,
        providers: HashSet<PeerId>,
    },
    BitswapNotifyNewBlocks {
        blocks: Vec<Block>,
        response_channel: oneshot::Sender<Result<(), String>>,
    },
    BitswapStopSession {
        ctx: u64,
        response_channel: oneshot::Sender<anyhow::Result<()>>,
    },
    ProviderRequest {
        key: ProviderRequestKey,
        response_channel: Sender<Result<HashSet<PeerId>, String>>,
        limit: usize,
    },
    StartProviding(oneshot::Sender<anyhow::Result<libp2p::kad::QueryId>>, Key),
    StopProviding(oneshot::Sender<anyhow::Result<()>>, Key),
    NetListeningAddrs(oneshot::Sender<(PeerId, Vec<Multiaddr>)>),
    NetPeers(oneshot::Sender<HashMap<PeerId, Vec<Multiaddr>>>),
    NetConnectByPeerId(oneshot::Sender<anyhow::Result<()>>, PeerId),
    NetConnect(oneshot::Sender<anyhow::Result<()>>, PeerId, Vec<Multiaddr>),
    NetDisconnect(oneshot::Sender<()>, PeerId),
    Gossipsub(GossipsubMessage),
    FindPeerOnDHT(oneshot::Sender<anyhow::Result<()>>, PeerId),
    LookupPeerInfo(oneshot::Sender<Option<IdentifyInfo>>, PeerId),
    ListenForIdentify(oneshot::Sender<anyhow::Result<IdentifyInfo>>, PeerId),
    CancelListenForIdentify(oneshot::Sender<()>, PeerId),
    AddressesOfPeer(oneshot::Sender<Vec<Multiaddr>>, PeerId),
    Shutdown,
}

#[derive(Debug)]
pub enum GossipsubMessage {
    AddExplicitPeer(oneshot::Sender<()>, PeerId),
    AllMeshPeers(oneshot::Sender<Vec<PeerId>>),
    AllPeers(oneshot::Sender<Vec<(PeerId, Vec<TopicHash>)>>),
    MeshPeers(oneshot::Sender<Vec<PeerId>>, TopicHash),
    Publish(
        oneshot::Sender<Result<MessageId, PublishError>>,
        TopicHash,
        Bytes,
    ),
    RemoveExplicitPeer(oneshot::Sender<()>, PeerId),
    Subscribe(oneshot::Sender<Result<bool, SubscriptionError>>, TopicHash),
    Topics(oneshot::Sender<Vec<TopicHash>>),
    Unsubscribe(oneshot::Sender<Result<bool, PublishError>>, TopicHash),
}

fn peer_info_from_identify_info(i: IdentifyInfo) -> PeerInfo {
    let peer_id = i.public_key.to_peer_id();
    PeerInfo {
        peer_id,
        protocol_version: i.protocol_version,
        agent_version: i.agent_version,
        listen_addrs: i.listen_addrs.into_iter().collect(),
        protocols: i.protocols,
        observed_addr: i.observed_addr,
    }
}
