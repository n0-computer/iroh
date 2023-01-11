use anyhow::{anyhow, ensure, Context, Result};
use bytes::Bytes;
use cid::Cid;
use futures::StreamExt;
use futures::{
    stream::{BoxStream, Stream},
    FutureExt, TryFutureExt,
};
use iroh_bitswap::Block;
use iroh_rpc_client::{
    create_server, Lookup, P2pServer, ServerError, ServerSocket, HEALTH_POLL_WAIT,
};
use iroh_rpc_types::{
    p2p::*, RpcError, RpcResult, VersionRequest, VersionResponse, WatchRequest, WatchResponse,
};
use libp2p::gossipsub::{error::PublishError, MessageId, TopicHash};
use libp2p::identify::Info as IdentifyInfo;
use libp2p::kad::record::Key;
use libp2p::Multiaddr;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::result;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, trace};

use crate::{GossipsubEvent, GossipsubEventStream, NetworkEvent, DEFAULT_PROVIDER_LIMIT, VERSION};

#[derive(Clone)]
pub(crate) struct P2p {
    sender: Sender<RpcMessage>,
}

impl P2p {
    pub fn new(sender: Sender<RpcMessage>) -> Self {
        Self { sender }
    }

    #[tracing::instrument(skip(self))]
    fn watch(self, _: WatchRequest) -> impl Stream<Item = WatchResponse> {
        async_stream::stream! {
            loop {
                yield WatchResponse { version: VERSION.to_string() };
                tokio::time::sleep(HEALTH_POLL_WAIT).await;
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn version(self, _: VersionRequest) -> VersionResponse {
        VersionResponse {
            version: VERSION.to_string(),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn shutdown(self, _: ShutdownRequest) -> Result<()> {
        self.sender.send(RpcMessage::Shutdown).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn external_addrs(self, _: ExternalAddrsRequest) -> Result<ExternalAddrsResponse> {
        trace!("received ExternalAddrs request");

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::ExternalAddrs(s);

        self.sender.send(msg).await?;

        let addrs = r.await?;

        Ok(ExternalAddrsResponse { addrs })
    }

    #[tracing::instrument(skip(self))]
    async fn listeners(self, _: ListenersRequest) -> Result<ListenersResponse> {
        trace!("received Listeners request");

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Listeners(s);

        self.sender.send(msg).await?;

        let addrs = r.await?;

        Ok(ListenersResponse { addrs })
    }

    #[tracing::instrument(skip(self))]
    async fn local_peer_id(self, _: LocalPeerIdRequest) -> Result<LocalPeerIdResponse> {
        trace!("received LocalPeerId request");

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::LocalPeerId(s);

        self.sender.send(msg).await?;

        let peer_id = r.await?;

        Ok(LocalPeerIdResponse { peer_id })
    }

    // TODO: expand to handle multiple cids at once. Probably not a tough fix, just want to push
    // forward right now
    #[tracing::instrument(skip(self, req))]
    async fn fetch_bitswap(self, req: BitswapRequest) -> Result<BitswapResponse> {
        let ctx = req.ctx;
        let cid = req.cid;

        trace!("context:{}, received fetch_bitswap: {:?}", ctx, cid);
        let providers = req.providers.into_iter().collect();

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapRequest {
            ctx,
            cids: vec![cid],
            providers,
            response_channels: vec![s],
        };

        trace!("context:{} making bitswap request for {:?}", ctx, cid);
        self.sender.send(msg).await?;
        let block = r
            .await
            .map_err(|_| anyhow!("bitswap req shut down"))?
            .map_err(|e| anyhow!("bitswap: {}", e))?;

        ensure!(
            cid == block.cid,
            "unexpected bitswap response: expected: {} got: {}",
            cid,
            block.cid
        );

        trace!("context:{} got bitswap response for {:?}", ctx, cid);

        Ok(BitswapResponse {
            data: block.data,
            ctx,
        })
    }

    #[tracing::instrument(skip(self, req))]
    async fn stop_session_bitswap(self, req: StopSessionBitswapRequest) -> Result<()> {
        let ctx = req.ctx;
        debug!("stop session bitswap {}", ctx);

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapStopSession {
            ctx,
            response_channel: s,
        };

        self.sender.send(msg).await?;
        r.await?.context("stop session")?;
        debug!("stop session bitwap {} done", ctx);

        Ok(())
    }

    #[tracing::instrument(skip(self, req))]
    async fn notify_new_blocks_bitswap(self, req: NotifyNewBlocksBitswapRequest) -> Result<()> {
        let blocks = req
            .blocks
            .into_iter()
            .map(|block| Block::new(block.data, block.cid))
            .collect::<Vec<Block>>();

        let (s, r) = oneshot::channel();
        let msg = RpcMessage::BitswapNotifyNewBlocks {
            blocks,
            response_channel: s,
        };

        self.sender.send(msg).await?;
        r.await?.context("bitswap notify new blocks")?;

        Ok(())
    }

    /// Wrap the inner method fetch_provider_dht0 to get the signature expected
    /// by a server_streaming request. Convert errors into something serializable
    /// and flatten to get a single stream of responses.
    #[tracing::instrument(skip(self, req))]
    fn fetch_provider_dht(
        self,
        req: FetchProvidersDhtRequest,
    ) -> BoxStream<'static, RpcResult<FetchProvidersDhtResponse>> {
        async move {
            let stream = self.fetch_provider_dht0(req).await?;
            Ok(stream.map(|x| x.map_err(RpcError::from)))
        }
        .try_flatten_stream()
        .boxed()
    }

    /// Implementation of fetch_provider_dht
    async fn fetch_provider_dht0(
        self,
        req: FetchProvidersDhtRequest,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<FetchProvidersDhtResponse>>> {
        let key_bytes: &[u8] = req.key.0.as_ref();
        let key = libp2p::kad::record::Key::new(&key_bytes);
        let cid: Cid = key_bytes.try_into()?;
        trace!("received fetch_provider_dht: {}", cid);
        let (s, r) = channel(64);

        let msg = RpcMessage::ProviderRequest {
            key: ProviderRequestKey::Dht(key),
            response_channel: s,
            limit: DEFAULT_PROVIDER_LIMIT,
        };

        self.sender.send(msg).await?;
        let r = ReceiverStream::new(r);

        let stream = r
            .map(|providers| {
                let providers = providers.map_err(|e| anyhow!(e))?;
                let providers = providers.into_iter().collect();

                anyhow::Ok::<FetchProvidersDhtResponse>(FetchProvidersDhtResponse { providers })
            })
            .boxed();

        Ok(stream)
    }

    #[tracing::instrument(skip(self, req))]
    async fn start_providing(self, req: StartProvidingRequest) -> Result<()> {
        trace!("received StartProviding request: {:?}", req.key);
        let key_bytes: &[u8] = req.key.0.as_ref();
        let key = libp2p::kad::record::Key::new(&key_bytes);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::StartProviding(s, key);

        self.sender.send(msg).await?;

        let query_id = r.await??;

        tracing::debug!("StartProviding query_id: {:?}", query_id);
        Ok(())
    }

    #[tracing::instrument(skip(self, req))]
    async fn stop_providing(self, req: StopProvidingRequest) -> Result<()> {
        trace!("received StopProviding request: {:?}", req.key);
        let key_bytes: &[u8] = req.key.0.as_ref();
        let key = libp2p::kad::record::Key::new(&key_bytes);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::StopProviding(s, key);

        self.sender.send(msg).await?;

        r.await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_listening_addrs(
        self,
        _: GetListeningAddrsRequest,
    ) -> Result<GetListeningAddrsResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetListeningAddrs(s);
        self.sender.send(msg).await?;

        let (peer_id, addrs) = r.await?;

        Ok(GetListeningAddrsResponse { peer_id, addrs })
    }

    #[tracing::instrument(skip(self))]
    async fn get_peers(self, _: GetPeersRequest) -> Result<GetPeersResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetPeers(s);
        self.sender.send(msg).await?;

        let peers = r.await?;
        let peers = peers.into_iter().collect();
        Ok(GetPeersResponse { peers })
    }

    #[tracing::instrument(skip(self, req))]
    /// First attempts to find the peer on the DHT, if found, it will then ensure we have
    /// a connection to the peer.
    async fn peer_connect_by_peer_id(self, req: ConnectByPeerIdRequest) -> Result<()> {
        let peer_id = req.peer_id;
        let (s, r) = oneshot::channel();
        // ask the swarm if we already have address for this peer
        let msg = RpcMessage::AddressesOfPeer(s, peer_id);
        self.sender.send(msg).await?;
        let res = r.await?;
        if res.is_empty() {
            // if we don't have the addr info for this peer, we need to try to
            // find it on the dht
            let (s, r) = oneshot::channel();
            let msg = RpcMessage::FindPeerOnDHT(s, peer_id);
            self.sender.send(msg).await?;
            r.await??;
        }
        // now we know we have found the peer on the dht,
        // we can attempt to dial it
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetConnectByPeerId(s, peer_id);
        self.sender.send(msg).await?;
        r.await?
    }

    #[tracing::instrument(skip(self, req))]
    /// Dial the peer directly using the PeerId and Multiaddr
    async fn peer_connect(self, req: ConnectRequest) -> Result<()> {
        let peer_id = req.peer_id;
        let addrs = req.addrs;
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetConnect(s, peer_id, addrs);
        self.sender.send(msg).await?;
        r.await?
    }

    #[tracing::instrument(skip(self, req))]
    async fn peer_disconnect(self, req: DisconnectRequest) -> Result<()> {
        let peer_id = req.peer_id;
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::NetDisconnect(s, peer_id);
        self.sender.send(msg).await?;
        r.await?;

        Ok(())
    }

    #[tracing::instrument(skip(self, req))]
    async fn lookup(self, req: LookupRequest) -> Result<LookupResponse> {
        let (s, r) = oneshot::channel();
        let peer_id = req.peer_id;

        // check if we have already encountered this peer, and already
        // that the peer info
        let msg = RpcMessage::LookupPeerInfo(s, peer_id);
        self.sender.send(msg).await?;
        if let Some(info) = r.await? {
            return Ok(peer_info_from_identify_info(info));
        }

        // listen for if any peer info for this peer gets sent to us
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::ListenForIdentify(s, peer_id);
        self.sender.send(msg).await?;

        // once we connect to the peer, the idenitfy protocol
        // will attempt to exchange peer info
        let res = match req.addr {
            Some(addr) => {
                self.clone()
                    .peer_connect(ConnectRequest {
                        peer_id: req.peer_id,
                        addrs: vec![addr],
                    })
                    .await
            }
            None => {
                self.clone()
                    .peer_connect_by_peer_id(ConnectByPeerIdRequest {
                        peer_id: req.peer_id,
                    })
                    .await
            }
        };

        if let Err(e) = res {
            let (s, r) = oneshot::channel();
            self.sender
                .send(RpcMessage::CancelListenForIdentify(s, peer_id))
                .await?;
            r.await?;
            anyhow::bail!("Cannot get peer information: {}", e);
        }

        let info = r.await??;

        Ok(peer_info_from_identify_info(info))
    }

    #[tracing::instrument(skip(self))]
    async fn lookup_local(self, _: LookupLocalRequest) -> Result<LookupResponse> {
        let (s, r) = oneshot::channel();
        self.sender.send(RpcMessage::LookupLocalPeerInfo(s)).await?;
        let lookup = r.await?;
        Ok(peer_info_from_lookup(lookup))
    }

    #[tracing::instrument(skip(self))]
    fn gossipsub_subscribe(self, req: GossipsubSubscribeRequest) -> GossipsubEventStream {
        async move {
            self.gossipsub_subscribe_0(req)
                .await
                .expect("FIX THIS - NEEDS TO BE ABLE TO RETURN A RESULT")
        }
        .flatten_stream()
        .boxed()
    }

    #[tracing::instrument(skip(self))]
    async fn gossipsub_subscribe_0(
        self,
        req: GossipsubSubscribeRequest,
    ) -> Result<BoxStream<'static, Box<GossipsubSubscribeResponse>>> {
        let t = TopicHash::from_raw(req.topic_hash);
        let (s, r) = oneshot::channel();
        self.sender
            .send(RpcMessage::Gossipsub(GossipsubMessage::Subscribe(
                s,
                t.clone(),
            )))
            .await?;

        let mut r = r.await??;
        let stream = async_stream::stream! {
            while let Some(network_event) = r.recv().await {
                if let NetworkEvent::Gossipsub(event) = network_event {
                    match &event {
                        GossipsubEvent::Subscribed { topic, .. } |
                            GossipsubEvent::Unsubscribed {topic, .. } |
                            GossipsubEvent::Message { topic, .. } => {
                                println!("gossipsub event: {:#?}", event);
                                println!("in message topic {:#?}, expected topic {:#?}", topic, t);
                                if *topic == t {
                                    println!("topic match!");
                                    yield Box::new(GossipsubSubscribeResponse {event});
                                }
                            },
                    };
                }
            }
        }
        .boxed();
        Ok(stream)
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_add_explicit_peer(self, req: GossipsubAddExplicitPeerRequest) -> Result<()> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AddExplicitPeer(s, req.peer_id));
        self.sender.send(msg).await?;
        r.await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn gossipsub_all_mesh_peers(
        self,
        _: GossipsubAllMeshPeersRequest,
    ) -> Result<GossipsubPeersResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AllMeshPeers(s));
        self.sender.send(msg).await?;
        let peers = r.await?;
        Ok(GossipsubPeersResponse { peers })
    }

    #[tracing::instrument(skip(self))]
    async fn gossipsub_all_peers(
        self,
        _: GossipsubAllPeersRequest,
    ) -> Result<GossipsubAllPeersResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::AllPeers(s));
        self.sender.send(msg).await?;

        let all_peers = r.await?;
        let all = all_peers
            .into_iter()
            .map(|(peer_id, topics)| {
                (
                    peer_id,
                    topics.into_iter().map(|t| t.into_string()).collect(),
                )
            })
            .collect();

        Ok(GossipsubAllPeersResponse { all })
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_mesh_peers(
        self,
        req: GossipsubMeshPeersRequest,
    ) -> Result<GossipsubPeersResponse> {
        let topic = TopicHash::from_raw(req.topic_hash);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::MeshPeers(s, topic));
        self.sender.send(msg).await?;

        let peers = r.await?;
        Ok(GossipsubPeersResponse { peers })
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_publish(
        self,
        req: GossipsubPublishRequest,
    ) -> Result<GossipsubPublishResponse> {
        let data = req.data;
        let topic_hash = TopicHash::from_raw(req.topic_hash);
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Publish(s, topic_hash, data));
        self.sender.send(msg).await?;

        let message_id = r.await??;

        Ok(GossipsubPublishResponse {
            message_id: message_id.0.into(),
        })
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_remove_explicit_peer(
        self,
        req: GossipsubRemoveExplicitPeerRequest,
    ) -> Result<()> {
        let peer_id = req.peer_id;
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::RemoveExplicitPeer(s, peer_id));
        self.sender.send(msg).await?;

        r.await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn gossipsub_topics(self, _: GossipsubTopicsRequest) -> Result<GossipsubTopicsResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Topics(s));

        self.sender.send(msg).await?;

        let topics: Vec<String> = r.await?.into_iter().map(|t| t.into_string()).collect();

        Ok(GossipsubTopicsResponse { topics })
    }

    #[tracing::instrument(skip(self, req))]
    async fn gossipsub_unsubscribe(
        self,
        req: GossipsubUnsubscribeRequest,
    ) -> Result<GossipsubUnsubscribeResponse> {
        let (s, r) = oneshot::channel();
        let msg = RpcMessage::Gossipsub(GossipsubMessage::Unsubscribe(
            s,
            TopicHash::from_raw(req.topic_hash),
        ));

        self.sender.send(msg).await?;
        let was_subscribed = r.await??;

        Ok(GossipsubUnsubscribeResponse { was_subscribed })
    }
}

/// dispatch a single request from the server 
#[rustfmt::skip]
async fn dispatch(s: P2pServer, req: P2pRequest, chan: ServerSocket<P2pService>, target: P2p) -> result::Result<(), ServerError> {
    use P2pRequest::*;
    match req {
        Watch(req) => s.server_streaming(req, chan, target, P2p::watch).await,
        Version(req) => s.rpc(req, chan, target, P2p::version).await,
        Shutdown(req) => s.rpc_map_err(req, chan, target, P2p::shutdown).await,
        FetchBitswap(req) => s.rpc_map_err(req, chan, target, P2p::fetch_bitswap).await,
        GossipsubAddExplicitPeer(req) => s.rpc_map_err(req, chan, target, P2p::gossipsub_add_explicit_peer).await,
        GossipsubAllPeers(req) => s.rpc_map_err(req, chan, target, P2p::gossipsub_all_peers).await,
        GossipsubMeshPeers(req) => s.rpc_map_err(req, chan, target, P2p::gossipsub_mesh_peers).await,
        GossipsubAllMeshPeers(req) => s.rpc_map_err(req, chan, target, P2p::gossipsub_all_mesh_peers).await,
        GossipsubPublish(req) => s.rpc_map_err(req, chan, target, P2p::gossipsub_publish).await,
        GossipsubRemoveExplicitPeer(req) => s.rpc_map_err(req, chan, target, P2p::gossipsub_remove_explicit_peer).await,
        GossipsubSubscribe(req) => s.server_streaming(req, chan, target, P2p::gossipsub_subscribe).await,
        GossipsubTopics(req) => s.rpc_map_err(req, chan, target, P2p::gossipsub_topics).await,
        GossipsubUnsubscribe(req) => s.rpc_map_err(req, chan, target, P2p::gossipsub_unsubscribe).await,
        StopSessionBitswap(req) => s.rpc_map_err(req, chan, target, P2p::stop_session_bitswap).await,
        StartProviding(req) => s.rpc_map_err(req, chan, target, P2p::start_providing).await,
        StopProviding(req) => s.rpc_map_err(req, chan, target, P2p::stop_providing).await,
        LocalPeerId(req) => s.rpc_map_err(req, chan, target, P2p::local_peer_id).await,
        NotifyNewBlocksBitswap(req) => s.rpc_map_err(req, chan, target, P2p::notify_new_blocks_bitswap).await,
        GetListeningAddrs(req) => s.rpc_map_err(req, chan, target, P2p::get_listening_addrs).await,
        GetPeers(req) => s.rpc_map_err(req, chan, target, P2p::get_peers).await,
        PeerConnect(req) => s.rpc_map_err(req, chan, target, P2p::peer_connect).await,
        PeerDisconnect(req) => s.rpc_map_err(req, chan, target, P2p::peer_disconnect).await,
        PeerConnectByPeerId(req) => s.rpc_map_err(req, chan, target, P2p::peer_connect_by_peer_id).await,
        Lookup(req) => s.rpc_map_err(req, chan, target, P2p::lookup).await,
        LookupLocal(req) => s.rpc_map_err(req, chan, target, P2p::lookup_local).await,
        ExternalAddrs(req) => s.rpc_map_err(req, chan, target, P2p::external_addrs).await,
        Listeners(req) => s.rpc_map_err(req, chan, target, P2p::listeners).await,
        FetchProviderDht(req) => s.server_streaming(req, chan, target, P2p::fetch_provider_dht).await,
    }
}

#[tracing::instrument(skip(p2p))]
pub(crate) async fn new(addr: P2pAddr, p2p: P2p) -> Result<()> {
    info!("p2p rpc listening on: {}", addr);
    let server = create_server::<P2pService>(addr).await?;
    loop {
        match server.accept_one().await {
            Ok((req, chan)) => {
                tokio::spawn(dispatch(server.clone(), req, chan, p2p.clone()));
            }
            Err(cause) => {
                tracing::debug!("p2p rpc accept error: {}", cause);
            }
        }
    }
}

fn peer_info_from_identify_info(i: IdentifyInfo) -> LookupResponse {
    LookupResponse {
        peer_id: i.public_key.to_peer_id(),
        protocol_version: i.protocol_version,
        agent_version: i.agent_version,
        listen_addrs: i.listen_addrs,
        protocols: i.protocols,
        observed_addrs: vec![i.observed_addr],
    }
}

fn peer_info_from_lookup(l: Lookup) -> LookupResponse {
    LookupResponse {
        peer_id: l.peer_id,
        protocol_version: l.protocol_version,
        agent_version: l.agent_version,
        listen_addrs: l.listen_addrs,
        protocols: l.protocols,
        observed_addrs: l.observed_addrs,
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
    Listeners(oneshot::Sender<Vec<Multiaddr>>),
    LocalPeerId(oneshot::Sender<PeerId>),
    BitswapRequest {
        ctx: u64,
        cids: Vec<Cid>,
        response_channels: Vec<oneshot::Sender<Result<Block, String>>>,
        providers: HashSet<PeerId>,
    },
    BitswapNotifyNewBlocks {
        blocks: Vec<Block>,
        response_channel: oneshot::Sender<Result<()>>,
    },
    BitswapStopSession {
        ctx: u64,
        response_channel: oneshot::Sender<Result<()>>,
    },
    ProviderRequest {
        key: ProviderRequestKey,
        response_channel: Sender<Result<HashSet<PeerId>, String>>,
        limit: usize,
    },
    StartProviding(oneshot::Sender<Result<libp2p::kad::QueryId>>, Key),
    StopProviding(oneshot::Sender<Result<()>>, Key),
    NetListeningAddrs(oneshot::Sender<(PeerId, Vec<Multiaddr>)>),
    NetPeers(oneshot::Sender<HashMap<PeerId, Vec<Multiaddr>>>),
    NetConnectByPeerId(oneshot::Sender<Result<()>>, PeerId),
    NetConnect(oneshot::Sender<Result<()>>, PeerId, Vec<Multiaddr>),
    NetDisconnect(oneshot::Sender<()>, PeerId),
    Gossipsub(GossipsubMessage),
    FindPeerOnDHT(oneshot::Sender<Result<()>>, PeerId),
    LookupPeerInfo(oneshot::Sender<Option<IdentifyInfo>>, PeerId),
    ListenForIdentify(oneshot::Sender<Result<IdentifyInfo>>, PeerId),
    CancelListenForIdentify(oneshot::Sender<()>, PeerId),
    AddressesOfPeer(oneshot::Sender<Vec<Multiaddr>>, PeerId),
    LookupLocalPeerInfo(oneshot::Sender<Lookup>),
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
    Subscribe(
        oneshot::Sender<Result<Receiver<crate::node::NetworkEvent>>>,
        TopicHash,
    ),
    Topics(oneshot::Sender<Vec<TopicHash>>),
    Unsubscribe(oneshot::Sender<Result<bool, PublishError>>, TopicHash),
}
