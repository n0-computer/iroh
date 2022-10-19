use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use bytes::Bytes;
use cid::Cid;

use iroh_rpc_types::p2p::PeerInfo;
use libp2p::gossipsub::{MessageId, TopicHash};
use libp2p::{Multiaddr, PeerId};
use tarpc::context::Context;
use tracing::{debug, warn};

// #[cfg(feature = "grpc")]
//use crate::status::{self, StatusRow};

impl_client!(P2p);

const DEFAULT_DEADLINE: Duration = Duration::from_secs(60);

fn default_context() -> Context {
    let mut ctx = Context::current();
    ctx.deadline = SystemTime::now() + DEFAULT_DEADLINE;
    ctx
}

impl P2pClient {
    pub async fn version(&self) -> Result<String> {
        let version = self.backend().await?.version(default_context()).await??;
        Ok(version)
    }

    pub async fn local_peer_id(&self) -> Result<PeerId> {
        let peer_id = self
            .backend()
            .await?
            .local_peer_id(default_context())
            .await??;
        Ok(peer_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn external_addresses(&self) -> Result<Vec<Multiaddr>> {
        let addrs = self
            .backend()
            .await?
            .external_addrs(default_context())
            .await??;
        Ok(addrs)
    }

    /// Fetches a block directly from the network.
    pub async fn fetch_bitswap(
        &self,
        ctx: u64,
        cid: Cid,
        providers: HashSet<PeerId>,
    ) -> Result<Bytes> {
        debug!("rpc p2p client fetch_bitswap: {:?}", cid);
        let bytes = self
            .backend()
            .await?
            .fetch_bitswap(default_context(), ctx, cid, providers.into_iter().collect())
            .await??;
        Ok(bytes)
    }

    pub async fn stop_session_bitswap(&self, ctx: u64) -> Result<()> {
        self.backend()
            .await?
            .stop_session_bitswap(default_context(), ctx)
            .await??;
        Ok(())
    }

    pub async fn notify_new_blocks_bitswap(&self, blocks: Vec<(Cid, Bytes)>) -> Result<()> {
        self.backend()
            .await?
            .notify_new_blocks_bitswap(default_context(), blocks)
            .await??;
        Ok(())
    }

    pub async fn fetch_providers_dht(&self, key: Cid, limit: usize) -> Result<HashSet<PeerId>> {
        let res = self
            .backend()
            .await?
            .fetch_provider_dht(default_context(), key, limit)
            .await??;

        Ok(res)
    }

    pub async fn start_providing(&self, key: Cid) -> Result<()> {
        let key = key.hash().to_bytes();
        self.backend()
            .await?
            .start_providing(default_context(), key)
            .await??;
        Ok(())
    }

    pub async fn stop_providing(&self, key: &Cid) -> Result<()> {
        let key = key.hash().to_bytes();
        self.backend()
            .await?
            .stop_providing(default_context(), key)
            .await??;
        Ok(())
    }

    pub async fn get_listening_addrs(&self) -> Result<(PeerId, Vec<Multiaddr>)> {
        let res = self
            .backend()
            .await?
            .get_listening_addrs(default_context())
            .await??;

        Ok(res)
    }

    pub async fn get_peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        let peers = self.backend().await?.get_peers(default_context()).await??;
        Ok(peers)
    }

    /// Attempts to connect to the given node. If only the `PeerId` is present, it will
    /// attempt to find the given peer on the DHT before connecting. If the `PeerId` and any
    /// `Multiaddr`s are present, it will attempt to connect to the peer directly.
    pub async fn connect(&self, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Result<()> {
        if !addrs.is_empty() {
            self.backend()
                .await?
                .peer_connect(default_context(), peer_id, Some(addrs))
                .await??;
        } else {
            self.backend()
                .await?
                .peer_connect(default_context(), peer_id, None)
                .await??;
        }

        Ok(())
    }

    pub async fn lookup(&self, peer_id: PeerId, addr: Option<Multiaddr>) -> Result<PeerInfo> {
        let peer_info = self
            .backend()
            .await?
            .lookup(default_context(), peer_id, addr)
            .await??;

        Ok(peer_info)
    }

    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        warn!("NetDisconnect not yet implemented on p2p node");
        self.backend()
            .await?
            .peer_disconnect(default_context(), peer_id)
            .await??;
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.backend().await?.shutdown(default_context()).await??;
        Ok(())
    }

    pub async fn gossipsub_add_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        self.backend()
            .await?
            .gossipsub_add_explicit_peer(default_context(), peer_id)
            .await??;
        Ok(())
    }

    pub async fn gossipsub_all_mesh_peers(&self) -> Result<Vec<PeerId>> {
        let peer_ids = self
            .backend()
            .await?
            .gossipsub_all_mesh_peers(default_context())
            .await??;
        Ok(peer_ids)
    }

    pub async fn gossipsub_all_peers(&self) -> Result<Vec<(PeerId, Vec<TopicHash>)>> {
        let res = self
            .backend()
            .await?
            .gossipsub_all_peers(default_context())
            .await??;

        let peers_and_topics = res
            .into_iter()
            .map(|(peer, topics)| (peer, topics.into_iter().map(TopicHash::from_raw).collect()))
            .collect();
        Ok(peers_and_topics)
    }

    pub async fn gossipsub_mesh_peers(&self, topic: TopicHash) -> Result<Vec<PeerId>> {
        let peer_ids = self
            .backend()
            .await?
            .gossipsub_mesh_peers(default_context(), topic.into_string())
            .await??;
        Ok(peer_ids)
    }

    pub async fn gossipsub_publish(&self, topic_hash: TopicHash, data: Bytes) -> Result<MessageId> {
        let res = self
            .backend()
            .await?
            .gossipsub_publish(default_context(), topic_hash.to_string(), data)
            .await??;
        let message_id = MessageId::new(&res);
        Ok(message_id)
    }

    pub async fn gossipsub_remove_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        self.backend()
            .await?
            .gossipsub_remove_explicit_peer(default_context(), peer_id)
            .await??;
        Ok(())
    }

    pub async fn gossipsub_subscribe(&self, topic: TopicHash) -> Result<bool> {
        let res = self
            .backend()
            .await?
            .gossipsub_subscribe(default_context(), topic.to_string())
            .await??;
        Ok(res)
    }

    pub async fn gossipsub_topics(&self) -> Result<Vec<TopicHash>> {
        let res = self
            .backend()
            .await?
            .gossipsub_topics(default_context())
            .await??;
        let topics = res.into_iter().map(TopicHash::from_raw).collect();
        Ok(topics)
    }

    pub async fn gossipsub_unsubscribe(&self, topic: TopicHash) -> Result<bool> {
        let res = self
            .backend()
            .await?
            .gossipsub_unsubscribe(default_context(), topic.to_string())
            .await??;
        Ok(res)
    }
}

// // TODO: mem tests
// #[cfg(all(test, feature = "grpc"))]
// mod tests {
//     use std::pin::Pin;
//     use super::*;
//     use async_trait::async_trait;
//     use iroh_rpc_types::p2p::{
//         p2p_server, BitswapResponse, ConnectResponse, GetListeningAddrsResponse, GetPeersResponse,
//         GossipsubAllPeersResponse, GossipsubPeersResponse, GossipsubPublishResponse,
//         GossipsubSubscribeResponse, GossipsubTopicsResponse, Multiaddrs, PeerIdResponse,
//         VersionResponse,
//     };
//     use libp2p::gossipsub::IdentTopic;
//     use tokio::net::TcpListener;
//     use tonic::{transport::Server as TonicServer, Request, Response};

//     struct TestRpcServer {}

//     impl TestRpcServer {
//         async fn serve(listener: TcpListener) {
//             let test_rpc_service = TestRpcServer {};
//             let p2p_service = p2p_server::P2pServer::new(test_rpc_service);

//             TonicServer::builder()
//                 .add_service(p2p_service)
//                 .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
//                 .await
//                 .unwrap()
//         }
//     }

//     fn test_peer_id() -> PeerId {
//         "12D3KooWGQmdpzHXCqLno4mMxWXKNFQHASBeF99gTm2JR8Vu5Bdc"
//             .parse()
//             .unwrap()
//     }

//     fn test_peers() -> Vec<PeerId> {
//         vec![test_peer_id()]
//     }

//     fn test_topic() -> TopicHash {
//         TopicHash::from_raw("test_topic")
//     }

//     fn test_topics() -> Vec<TopicHash> {
//         vec![test_topic()]
//     }

//     fn test_peers_and_topics() -> Vec<(PeerId, Vec<TopicHash>)> {
//         test_peers()
//             .into_iter()
//             .map(|p| (p, test_topics()))
//             .collect()
//     }

//     fn test_message_id() -> MessageId {
//         MessageId::new(b"test_message_id")
//     }

//     fn test_bytes() -> Bytes {
//         Bytes::from_static(b"hello world!")
//     }

//     #[async_trait]
//     impl p2p_server::P2p for TestRpcServer {
//         type FetchProviderDhtStream =
//             Pin<Box<dyn Stream<Item = std::result::Result<Providers, tonic::Status>> + Send>>;

//         async fn version(
//             &self,
//             _request: Request<()>,
//         ) -> Result<tonic::Response<VersionResponse>, tonic::Status> {
//             todo!()
//         }

//         async fn local_peer_id(
//             &self,
//             _request: Request<()>,
//         ) -> Result<tonic::Response<PeerIdResponse>, tonic::Status> {
//             todo!()
//         }

//         async fn external_addrs(
//             &self,
//             _request: Request<()>,
//         ) -> Result<tonic::Response<Multiaddrs>, tonic::Status> {
//             todo!()
//         }

//         async fn start_providing(
//             &self,
//             _request: Request<Key>,
//         ) -> Result<tonic::Response<()>, tonic::Status> {
//             todo!()
//         }

//         async fn stop_providing(
//             &self,
//             _request: Request<Key>,
//         ) -> Result<tonic::Response<()>, tonic::Status> {
//             todo!()
//         }

//         async fn fetch_bitswap(
//             &self,
//             _request: Request<BitswapRequest>,
//         ) -> Result<tonic::Response<BitswapResponse>, tonic::Status> {
//             todo!()
//         }

//         async fn stop_session_bitswap(
//             &self,
//             _request: Request<StopSessionBitswapRequest>,
//         ) -> Result<tonic::Response<()>, tonic::Status> {
//             todo!()
//         }

//         async fn notify_new_blocks_bitswap(
//             &self,
//             _request: Request<NotifyNewBlocksBitswapRequest>,
//         ) -> Result<tonic::Response<()>, tonic::Status> {
//             todo!()
//         }

//         async fn fetch_provider_dht(
//             &self,
//             _request: Request<Key>,
//         ) -> Result<tonic::Response<Self::FetchProviderDhtStream>, tonic::Status> {
//             todo!()
//         }

//         async fn get_listening_addrs(
//             &self,
//             _request: Request<()>,
//         ) -> Result<tonic::Response<GetListeningAddrsResponse>, tonic::Status> {
//             todo!()
//         }

//         async fn get_peers(
//             &self,
//             _request: Request<()>,
//         ) -> Result<tonic::Response<GetPeersResponse>, tonic::Status> {
//             todo!()
//         }
//         async fn peer_connect(
//             &self,
//             _request: Request<ConnectRequest>,
//         ) -> Result<tonic::Response<ConnectResponse>, tonic::Status> {
//             todo!()
//         }
//         async fn peer_disconnect(
//             &self,
//             _request: Request<DisconnectRequest>,
//         ) -> Result<tonic::Response<()>, tonic::Status> {
//             todo!()
//         }

//         async fn shutdown(
//             &self,
//             _request: Request<()>,
//         ) -> Result<tonic::Response<()>, tonic::Status> {
//             todo!()
//         }

//         async fn gossipsub_add_explicit_peer(
//             &self,
//             _request: Request<GossipsubPeerIdMsg>,
//         ) -> Result<Response<()>, tonic::Status> {
//             Ok(Response::new(()))
//         }

//         async fn gossipsub_all_mesh_peers(
//             &self,
//             _request: Request<()>,
//         ) -> Result<Response<GossipsubPeersResponse>, tonic::Status> {
//             let peers = test_peers().into_iter().map(|p| p.to_bytes()).collect();
//             Ok(Response::new(GossipsubPeersResponse { peers }))
//         }

//         async fn gossipsub_all_peers(
//             &self,
//             _request: Request<()>,
//         ) -> Result<Response<GossipsubAllPeersResponse>, tonic::Status> {
//             let all = test_peers_and_topics()
//                 .into_iter()
//                 .map(|(peer_id, topics)| GossipsubPeerAndTopics {
//                     peer_id: peer_id.to_bytes(),
//                     topics: topics.into_iter().map(|t| t.to_string()).collect(),
//                 })
//                 .collect();
//             Ok(Response::new(GossipsubAllPeersResponse { all }))
//         }

//         async fn gossipsub_mesh_peers(
//             &self,
//             request: Request<GossipsubTopicHashMsg>,
//         ) -> Result<Response<GossipsubPeersResponse>, tonic::Status> {
//             let _topic_hash = request.into_inner().topic_hash;
//             let peers = test_peers()
//                 .into_iter()
//                 .map(|peer| peer.to_bytes())
//                 .collect();
//             Ok(Response::new(GossipsubPeersResponse { peers }))
//         }

//         async fn gossipsub_publish(
//             &self,
//             request: Request<GossipsubPublishRequest>,
//         ) -> Result<Response<GossipsubPublishResponse>, tonic::Status> {
//             let req = request.into_inner();
//             let _topic_hash = IdentTopic::new(req.topic_hash);
//             let _data = req.data;
//             Ok(Response::new(GossipsubPublishResponse {
//                 message_id: test_message_id().0,
//             }))
//         }

//         async fn gossipsub_remove_explicit_peer(
//             &self,
//             request: Request<GossipsubPeerIdMsg>,
//         ) -> Result<Response<()>, tonic::Status> {
//             let _peer_id = PeerId::from_bytes(&request.into_inner().peer_id);
//             Ok(Response::new(()))
//         }

//         async fn gossipsub_subscribe(
//             &self,
//             request: Request<GossipsubTopicHashMsg>,
//         ) -> Result<Response<GossipsubSubscribeResponse>, tonic::Status> {
//             let _topic_hash = TopicHash::from_raw(request.into_inner().topic_hash);
//             Ok(Response::new(GossipsubSubscribeResponse {
//                 was_subscribed: true,
//             }))
//         }

//         async fn gossipsub_topics(
//             &self,
//             _request: Request<()>,
//         ) -> Result<Response<GossipsubTopicsResponse>, tonic::Status> {
//             Ok(Response::new(GossipsubTopicsResponse {
//                 topics: test_topics().into_iter().map(|t| t.to_string()).collect(),
//             }))
//         }

//         async fn gossipsub_unsubscribe(
//             &self,
//             request: Request<GossipsubTopicHashMsg>,
//         ) -> Result<Response<GossipsubSubscribeResponse>, tonic::Status> {
//             let _topic_hash = TopicHash::from_raw(request.into_inner().topic_hash);
//             Ok(Response::new(GossipsubSubscribeResponse {
//                 was_subscribed: true,
//             }))
//         }
//     }

//     #[tokio::test]
//     async fn test_gossipsub_rpc() {
//         let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
//         let addr = listener.local_addr().unwrap();
//         let server_task = tokio::spawn(async move { TestRpcServer::serve(listener).await });
//         let client = P2pClient::new(Addr::Tcp(addr)).await.unwrap();

//         // check the gossipsub methods serialize and deserialize correctly
//         client
//             .gossipsub_add_explicit_peer(test_peer_id())
//             .await
//             .unwrap();

//         let got = client.gossipsub_all_mesh_peers().await.unwrap();
//         let expect = test_peers();
//         assert_eq!(expect, got);

//         let got = client.gossipsub_all_peers().await.unwrap();
//         let expect = test_peers_and_topics();
//         assert_eq!(expect, got);

//         let got = client.gossipsub_mesh_peers(test_topic()).await.unwrap();
//         let expect = test_peers();
//         assert_eq!(expect, got);

//         let got = client
//             .gossipsub_publish(test_topic(), test_bytes())
//             .await
//             .unwrap();
//         let expect = test_message_id();
//         assert_eq!(expect, got);

//         client
//             .gossipsub_remove_explicit_peer(test_peer_id())
//             .await
//             .unwrap();

//         let got = client.gossipsub_subscribe(test_topic()).await.unwrap();
//         let expect = true;
//         assert_eq!(expect, got);

//         let got = client.gossipsub_topics().await.unwrap();
//         let expect = test_topics();
//         assert_eq!(expect, got);

//         let got = client.gossipsub_unsubscribe(test_topic()).await.unwrap();
//         let expect = true;
//         assert_eq!(expect, got);

//         server_task.abort();
//         server_task.await.unwrap_err();
//     }
// }
