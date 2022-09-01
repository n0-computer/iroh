use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::Pin;

use anyhow::{anyhow, ensure, Context, Result};
use bytes::Bytes;
use cid::Cid;
use futures::{channel::oneshot, Stream, StreamExt};
use libp2p::gossipsub::{
    error::{PublishError, SubscriptionError},
    MessageId, TopicHash,
};
use libp2p::kad::record::Key;
use libp2p::Multiaddr;
use libp2p::PeerId;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tracing::trace;

use async_trait::async_trait;
use iroh_bitswap::{Block, QueryError};
use iroh_rpc_types::p2p::{
    BitswapRequest, BitswapResponse, ConnectRequest, ConnectResponse, DisconnectRequest,
    GetListeningAddrsResponse, GetPeersResponse, GossipsubAllPeersResponse, GossipsubPeerAndTopics,
    GossipsubPeerIdMsg, GossipsubPeersResponse, GossipsubPublishRequest, GossipsubPublishResponse,
    GossipsubSubscribeResponse, GossipsubTopicHashMsg, GossipsubTopicsResponse, Key as ProviderKey,
    Multiaddrs, P2p as RpcP2p, P2pServerAddr, Providers, VersionResponse,
};

struct P2p {
    sender: Sender<RpcMessage>,
}

#[async_trait]
impl RpcP2p for P2p {
    #[tracing::instrument(skip(self))]
    async fn version(&self, _: ()) -> Result<VersionResponse> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(VersionResponse { version })
    }

    #[tracing::instrument(skip(self))]
    async fn shutdown(&self, _: ()) -> Result<()> {
        self.sender.send(RpcMessage::Shutdown).await?;
        Ok(())
    }

    // TODO: expand to handle multiple cids at once. Probably not a tough fix, just want to push
    // forward right now
    #[tracing::instrument(skip(self, req))]
    async fn fetch_bitswap(&self, req: BitswapRequest) -> Result<BitswapResponse> {
        let cid = Cid::read_bytes(io::Cursor::new(req.cid))?;

        trace!("received BitswapRequest: {:?}", cid);
        let providers = req
            .providers
            .with_context(|| format!("missing providers for: {}", cid))?;

        let providers: HashSet<PeerId> = providers
            .providers
            .into_iter()
            .map(|p| PeerId::from_bytes(&p).context("invalid provider"))
            .collect::<Result<_>>()?;

        ensure!(!providers.is_empty(), "missing providers for: {}", cid);

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapRequest {
            cids: vec![cid],
            providers,
            response_channels: vec![s],
        };
        trace!("making bitswap request for {:?}", cid);
        self.sender.send(msg).await?;
        let block = r.await?.context("bitswap")?;

        ensure!(
            cid == block.cid,
            "unexpected bitswap response: expected: {} got: {}",
            cid,
            block.cid
        );

        trace!("bitswap response for {:?}", cid);
        Ok(BitswapResponse { data: block.data })
    }

    #[tracing::instrument(skip(self, req))]
    async fn inject_provider_bitswap(&self, req: BitswapRequest) -> Result<()> {
        let cid = Cid::read_bytes(io::Cursor::new(req.cid))?;

        trace!("received BitswapRequest: {:?}", cid);
        let providers = req
            .providers
            .with_context(|| format!("missing providers for: {}", cid))?;

        let providers: HashSet<PeerId> = providers
            .providers
            .into_iter()
            .map(|p| PeerId::from_bytes(&p).context("invalid provider"))
            .collect::<Result<_>>()?;

        ensure!(!providers.is_empty(), "missing providers for: {}", cid);

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapInjectProviders {
            cid,
            providers,
            response_channel: s,
        };

        self.sender.send(msg).await?;
        r.await?.context("bitswap inject provider")?;

        Ok(())
    }

    #[tracing::instrument(skip(self, req))]
    async fn fetch_provider_dht(
        &self,
        req: ProviderKey,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Providers>> + Send>>> {
        trace!("received ProviderRequest: {:?}", req.key);
        let (s, r) = mpsc::channel(1024);
        let msg = RpcMessage::ProviderRequest {
            key: ProviderRequestKey::Dht(req.key.clone().into()),
            response_channel: s,
        };

        self.sender.send(msg).await?;

        let r = tokio_stream::wrappers::ReceiverStream::new(r);
        Ok(Box::pin(r.map(|providers| {
            let providers = providers.map_err(|e| anyhow!(e))?;
            let providers = providers.into_iter().map(|p| p.to_bytes()).collect();

            Ok(Providers { providers })
        })))
    }

    #[tracing::instrument(skip(self, req))]
    async fn fetch_provider_bitswap(
        &self,
        req: ProviderKey,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Providers>> + Send>>> {
        trace!("received ProviderRequest: {:?}", req.key);
        let (s, r) = mpsc::channel(1024);
        let msg = RpcMessage::ProviderRequest {
            key: ProviderRequestKey::Bitswap(Cid::try_from(&req.key[..])?),
            response_channel: s,
        };

        self.sender.send(msg).await?;

        let r = tokio_stream::wrappers::ReceiverStream::new(r);
        Ok(Box::pin(r.map(|providers| {
            let providers = providers.map_err(|e| anyhow!(e))?;
            let providers = providers.into_iter().map(|p| p.to_bytes()).collect();

            Ok(Providers { providers })
        })))
    }

    #[tracing::instrument(skip(self))]
    async fn get_listening_addrs(&self, _: ()) -> Result<GetListeningAddrsResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetListeningAddrs(s);
        self.sender.send(msg).await?;

        let (peer_id, addrs) = r.await?;

        Ok(GetListeningAddrsResponse {
            peer_id: peer_id.to_bytes(),
            addrs: addrs.into_iter().map(|addr| addr.to_vec()).collect(),
        })
    }

    #[tracing::instrument(skip(self))]
    async fn get_peers(&self, _: ()) -> Result<GetPeersResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetPeers(s);
        self.sender.send(msg).await?;

        let peers = r.await?;
        let mut p: HashMap<String, Multiaddrs> = Default::default();
        for (id, addrs) in peers.into_iter() {
            p.insert(
                id.to_string(),
                Multiaddrs {
                    addrs: addrs.into_iter().map(|addr| addr.to_vec()).collect(),
                },
            );
        }
        Ok(GetPeersResponse { peers: p })
    }

    #[tracing::instrument(skip(self, req))]
    async fn peer_connect(&self, req: ConnectRequest) -> Result<ConnectResponse> {
        let peer_id = peer_id_from_bytes(req.peer_id)?;
        let addrs = addrs_from_bytes(req.addrs)?;
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetConnect(s, peer_id, addrs);
        self.sender.send(msg).await?;

        let success = r.await?;
        Ok(ConnectResponse { success })
    }

    #[tracing::instrument(skip(self, req))]
    async fn peer_disconnect(&self, req: DisconnectRequest) -> Result<()> {
        let peer_id = peer_id_from_bytes(req.peer_id)?;
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetDisconnect(s, peer_id);
        self.sender.send(msg).await?;
        let ack = r.await?;

        Ok(ack)
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_add_explicit_peer(&self, req: GossipsubPeerIdMsg) -> Result<()> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AddExplicitPeer(
            s,
            peer_id_from_bytes(req.peer_id)?,
        ));
        self.sender.send(msg).await?;
        r.await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn gossipsub_all_mesh_peers(&self, _: ()) -> Result<GossipsubPeersResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AllMeshPeers(s));
        self.sender.send(msg).await?;
        let peers = r.await?;

        let peers = peers.into_iter().map(|p| p.to_bytes()).collect();
        Ok(GossipsubPeersResponse { peers })
    }

    #[tracing::instrument(skip(self))]
    async fn gossipsub_all_peers(&self, _: ()) -> Result<GossipsubAllPeersResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AllPeers(s));
        self.sender.send(msg).await?;

        let all_peers = r.await?;
        let all = all_peers
            .into_iter()
            .map(|(p, t)| GossipsubPeerAndTopics {
                peer_id: p.to_bytes(),
                topics: t.into_iter().map(|t| t.into_string()).collect(),
            })
            .collect();

        Ok(GossipsubAllPeersResponse { all })
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_mesh_peers(
        &self,
        req: GossipsubTopicHashMsg,
    ) -> Result<GossipsubPeersResponse> {
        let topic = TopicHash::from_raw(req.topic_hash);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::MeshPeers(s, topic));
        self.sender.send(msg).await?;

        let res = r.await?;
        let peers = res.into_iter().map(|p| p.to_bytes()).collect();

        Ok(GossipsubPeersResponse { peers })
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_publish(
        &self,
        req: GossipsubPublishRequest,
    ) -> Result<GossipsubPublishResponse> {
        let data = req.data;
        let topic_hash = TopicHash::from_raw(req.topic_hash);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Publish(s, topic_hash, data));
        self.sender.send(msg).await?;

        let message_id = r.await??;

        Ok(GossipsubPublishResponse {
            message_id: message_id.0,
        })
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_remove_explicit_peer(&self, req: GossipsubPeerIdMsg) -> Result<()> {
        let peer_id = peer_id_from_bytes(req.peer_id)?;
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::RemoveExplicitPeer(s, peer_id));
        self.sender.send(msg).await?;

        r.await?;
        Ok(())
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_subscribe(
        &self,
        req: GossipsubTopicHashMsg,
    ) -> Result<GossipsubSubscribeResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Subscribe(
            s,
            TopicHash::from_raw(req.topic_hash),
        ));

        self.sender.send(msg).await?;

        let was_subscribed = r.await??;

        Ok(GossipsubSubscribeResponse { was_subscribed })
    }

    #[tracing::instrument(skip(self))]
    async fn gossipsub_topics(&self, _: ()) -> Result<GossipsubTopicsResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Topics(s));

        self.sender.send(msg).await?;

        let topics: Vec<String> = r.await?.into_iter().map(|t| t.into_string()).collect();

        Ok(GossipsubTopicsResponse { topics })
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_unsubscribe(
        &self,
        req: GossipsubTopicHashMsg,
    ) -> Result<GossipsubSubscribeResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Unsubscribe(
            s,
            TopicHash::from_raw(req.topic_hash),
        ));

        self.sender.send(msg).await?;
        let was_subscribed = r.await??;

        Ok(GossipsubSubscribeResponse { was_subscribed })
    }
}

pub async fn new(addr: P2pServerAddr, sender: Sender<RpcMessage>) -> Result<()> {
    let p2p = P2p { sender };

    iroh_rpc_types::p2p::serve(addr, p2p).await
}

fn peer_id_from_bytes(p: Vec<u8>) -> Result<PeerId> {
    PeerId::from_bytes(&p[..]).context("invalid peer_id")
}

fn addr_from_bytes(m: Vec<u8>) -> Result<Multiaddr> {
    Multiaddr::try_from(m).context("invalid multiaddr")
}

fn addrs_from_bytes(a: Vec<Vec<u8>>) -> Result<Vec<Multiaddr>> {
    a.into_iter().map(addr_from_bytes).collect()
}

#[derive(Debug)]
pub enum ProviderRequestKey {
    // TODO: potentially change this to Cid, as that is the only key we use for providers
    Dht(Key),
    Bitswap(Cid),
}

/// Rpc specific messages handled by the p2p node
#[derive(Debug)]
pub enum RpcMessage {
    BitswapRequest {
        cids: Vec<Cid>,
        response_channels: Vec<oneshot::Sender<Result<Block, QueryError>>>,
        providers: HashSet<PeerId>,
    },
    BitswapInjectProviders {
        cid: Cid,
        response_channel: oneshot::Sender<Result<()>>,
        providers: HashSet<PeerId>,
    },
    ProviderRequest {
        key: ProviderRequestKey,
        response_channel: mpsc::Sender<Result<HashSet<PeerId>, String>>,
    },
    NetListeningAddrs(oneshot::Sender<(PeerId, Vec<Multiaddr>)>),
    NetPeers(oneshot::Sender<HashMap<PeerId, Vec<Multiaddr>>>),
    NetConnect(oneshot::Sender<bool>, PeerId, Vec<Multiaddr>),
    NetDisconnect(oneshot::Sender<()>, PeerId),
    Gossipsub(GossipsubMessage),
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
