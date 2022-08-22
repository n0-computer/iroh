use std::collections::{HashMap, HashSet};

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use cid::Cid;
#[cfg(feature = "grpc")]
use futures::Stream;
#[cfg(feature = "grpc")]
use iroh_rpc_types::p2p::p2p_client::P2pClient as GrpcP2pClient;
use iroh_rpc_types::p2p::{
    BitswapRequest, ConnectRequest, DisconnectRequest, GossipsubPeerAndTopics, GossipsubPeerIdMsg,
    GossipsubPublishRequest, GossipsubTopicHashMsg, Key, P2p, P2pClientAddr, P2pClientBackend,
    Providers,
};
use iroh_rpc_types::Addr;
use libp2p::gossipsub::{MessageId, TopicHash};
use libp2p::{Multiaddr, PeerId};
#[cfg(feature = "grpc")]
use tonic::transport::Endpoint;
#[cfg(feature = "grpc")]
use tonic_health::proto::health_client::HealthClient;
use tracing::{debug, warn};

#[cfg(feature = "grpc")]
use crate::status::{self, StatusRow};

impl_client!(P2p);

impl P2pClient {
    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.backend.version(()).await?;
        Ok(res.version)
    }

    // Fetches a block directly from the network.
    #[tracing::instrument(skip(self))]
    pub async fn fetch_bitswap(&self, cid: Cid, providers: HashSet<PeerId>) -> Result<Bytes> {
        debug!("rpc p2p client fetch_bitswap: {:?}", cid);
        let providers = Providers {
            providers: providers.into_iter().map(|id| id.to_bytes()).collect(),
        };

        let req = BitswapRequest {
            cid: cid.to_bytes(),
            providers: Some(providers),
        };
        let res = self.backend.fetch_bitswap(req).await?;
        Ok(res.data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn fetch_providers_dht(&self, key: &Cid) -> Result<HashSet<PeerId>> {
        let req = Key {
            key: key.hash().to_bytes(),
        };
        let res = self.backend.fetch_provider_dht(req).await?;
        let mut providers = HashSet::new();
        for provider in res.providers.into_iter() {
            providers.insert(PeerId::from_bytes(&provider[..])?);
        }
        Ok(providers)
    }

    #[tracing::instrument(skip(self))]
    pub async fn fetch_providers_bitswap(&self, key: &Cid) -> Result<HashSet<PeerId>> {
        let req = Key {
            key: key.to_bytes(),
        };
        let res = self.backend.fetch_provider_bitswap(req).await?;
        let mut providers = HashSet::new();
        for provider in res.providers.into_iter() {
            providers.insert(PeerId::from_bytes(&provider[..])?);
        }
        Ok(providers)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_listening_addrs(&self) -> Result<(PeerId, Vec<Multiaddr>)> {
        let res = self.backend.get_listening_addrs(()).await?;
        let peer_id = PeerId::from_bytes(&res.peer_id[..])?;
        let addrs = addrs_from_bytes(res.addrs)?;
        Ok((peer_id, addrs))
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        let peers = self.backend.get_peers(()).await?.peers;
        let mut peers_map = HashMap::new();
        for (peer, addrs) in peers.into_iter() {
            let peer = peer.parse()?;
            let addrs = addrs_from_bytes(addrs.addrs)?;
            peers_map.insert(peer, addrs);
        }
        Ok(peers_map)
    }

    #[tracing::instrument(skip(self))]
    pub async fn connect(&self, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Result<()> {
        let req = ConnectRequest {
            peer_id: peer_id.to_bytes(),
            addrs: addrs.iter().map(|a| a.to_vec()).collect(),
        };
        let res = self.backend.peer_connect(req).await?;
        ensure!(res.success, "dial failed");
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        warn!("NetDisconnect not yet implemented on p2p node");
        let req = DisconnectRequest {
            peer_id: peer_id.to_bytes(),
        };
        self.backend.peer_disconnect(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<()> {
        self.backend.shutdown(()).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_add_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        let req = GossipsubPeerIdMsg {
            peer_id: peer_id.to_bytes(),
        };
        self.backend.gossipsub_add_explicit_peer(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_all_mesh_peers(&self) -> Result<Vec<PeerId>> {
        let res = self.backend.gossipsub_all_mesh_peers(()).await?;
        let peer_ids = peer_ids_from_bytes(res.peers)?;
        Ok(peer_ids)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_all_peers(&self) -> Result<Vec<(PeerId, Vec<TopicHash>)>> {
        let res = self.backend.gossipsub_all_peers(()).await?.all;
        let peers_and_topics = all_peers_from_bytes(res)?;
        Ok(peers_and_topics)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_mesh_peers(&self, topic: TopicHash) -> Result<Vec<PeerId>> {
        let req = GossipsubTopicHashMsg {
            topic_hash: topic.into_string(),
        };
        let res = self.backend.gossipsub_mesh_peers(req).await?;
        let peer_ids = peer_ids_from_bytes(res.peers)?;
        Ok(peer_ids)
    }

    #[tracing::instrument(skip(self, data))]
    pub async fn gossipsub_publish(&self, topic_hash: TopicHash, data: Bytes) -> Result<MessageId> {
        let req = GossipsubPublishRequest {
            topic_hash: topic_hash.to_string(),
            data,
        };
        let res = self.backend.gossipsub_publish(req).await?;
        let message_id = MessageId::new(&res.message_id);
        Ok(message_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_remove_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        let req = GossipsubPeerIdMsg {
            peer_id: peer_id.to_bytes(),
        };
        self.backend.gossipsub_remove_explicit_peer(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_subscribe(&self, topic: TopicHash) -> Result<bool> {
        let req = GossipsubTopicHashMsg {
            topic_hash: topic.to_string(),
        };
        let res = self.backend.gossipsub_subscribe(req).await?;
        Ok(res.was_subscribed)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_topics(&self) -> Result<Vec<TopicHash>> {
        let res = self.backend.gossipsub_topics(()).await?;
        let topics = res.topics.into_iter().map(TopicHash::from_raw).collect();
        Ok(topics)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_unsubscribe(&self, topic: TopicHash) -> Result<bool> {
        let req = GossipsubTopicHashMsg {
            topic_hash: topic.to_string(),
        };
        let res = self.backend.gossipsub_unsubscribe(req).await?;
        Ok(res.was_subscribed)
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

// TODO: mem tests
#[cfg(all(test, feature = "grpc"))]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use iroh_rpc_types::p2p::{
        p2p_server, BitswapResponse, ConnectResponse, GetListeningAddrsResponse, GetPeersResponse,
        GossipsubAllPeersResponse, GossipsubPeersResponse, GossipsubPublishResponse,
        GossipsubSubscribeResponse, GossipsubTopicsResponse, VersionResponse,
    };
    use libp2p::gossipsub::IdentTopic;
    use tokio::net::TcpListener;
    use tonic::{transport::Server as TonicServer, Request, Response};

    struct TestRpcServer {}

    impl TestRpcServer {
        async fn serve(listener: TcpListener) {
            let test_rpc_service = TestRpcServer {};
            let p2p_service = p2p_server::P2pServer::new(test_rpc_service);

            TonicServer::builder()
                .add_service(p2p_service)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap()
        }
    }

    fn test_peer_id() -> PeerId {
        "12D3KooWGQmdpzHXCqLno4mMxWXKNFQHASBeF99gTm2JR8Vu5Bdc"
            .parse()
            .unwrap()
    }

    fn test_peers() -> Vec<PeerId> {
        vec![test_peer_id()]
    }

    fn test_topic() -> TopicHash {
        TopicHash::from_raw("test_topic")
    }

    fn test_topics() -> Vec<TopicHash> {
        vec![test_topic()]
    }

    fn test_peers_and_topics() -> Vec<(PeerId, Vec<TopicHash>)> {
        test_peers()
            .into_iter()
            .map(|p| (p, test_topics()))
            .collect()
    }

    fn test_message_id() -> MessageId {
        MessageId::new(b"test_message_id")
    }

    fn test_bytes() -> Bytes {
        Bytes::from_static(b"hello world!")
    }

    #[async_trait]
    impl p2p_server::P2p for TestRpcServer {
        async fn version(
            &self,
            _request: Request<()>,
        ) -> Result<tonic::Response<VersionResponse>, tonic::Status> {
            todo!()
        }

        async fn fetch_bitswap(
            &self,
            _request: Request<BitswapRequest>,
        ) -> Result<tonic::Response<BitswapResponse>, tonic::Status> {
            todo!()
        }

        async fn fetch_provider_dht(
            &self,
            _request: Request<Key>,
        ) -> Result<tonic::Response<Providers>, tonic::Status> {
            todo!()
        }

        async fn fetch_provider_bitswap(
            &self,
            _request: Request<Key>,
        ) -> Result<tonic::Response<Providers>, tonic::Status> {
            todo!()
        }

        async fn get_listening_addrs(
            &self,
            _request: Request<()>,
        ) -> Result<tonic::Response<GetListeningAddrsResponse>, tonic::Status> {
            todo!()
        }

        async fn get_peers(
            &self,
            _request: Request<()>,
        ) -> Result<tonic::Response<GetPeersResponse>, tonic::Status> {
            todo!()
        }
        async fn peer_connect(
            &self,
            _request: Request<ConnectRequest>,
        ) -> Result<tonic::Response<ConnectResponse>, tonic::Status> {
            todo!()
        }
        async fn peer_disconnect(
            &self,
            _request: Request<DisconnectRequest>,
        ) -> Result<tonic::Response<()>, tonic::Status> {
            todo!()
        }

        async fn shutdown(
            &self,
            _request: Request<()>,
        ) -> Result<tonic::Response<()>, tonic::Status> {
            todo!()
        }

        async fn gossipsub_add_explicit_peer(
            &self,
            _request: Request<GossipsubPeerIdMsg>,
        ) -> Result<Response<()>, tonic::Status> {
            Ok(Response::new(()))
        }

        async fn gossipsub_all_mesh_peers(
            &self,
            _request: Request<()>,
        ) -> Result<Response<GossipsubPeersResponse>, tonic::Status> {
            let peers = test_peers().into_iter().map(|p| p.to_bytes()).collect();
            Ok(Response::new(GossipsubPeersResponse { peers }))
        }

        async fn gossipsub_all_peers(
            &self,
            _request: Request<()>,
        ) -> Result<Response<GossipsubAllPeersResponse>, tonic::Status> {
            let all = test_peers_and_topics()
                .into_iter()
                .map(|(peer_id, topics)| GossipsubPeerAndTopics {
                    peer_id: peer_id.to_bytes(),
                    topics: topics.into_iter().map(|t| t.to_string()).collect(),
                })
                .collect();
            Ok(Response::new(GossipsubAllPeersResponse { all }))
        }

        async fn gossipsub_mesh_peers(
            &self,
            request: Request<GossipsubTopicHashMsg>,
        ) -> Result<Response<GossipsubPeersResponse>, tonic::Status> {
            let _topic_hash = request.into_inner().topic_hash;
            let peers = test_peers()
                .into_iter()
                .map(|peer| peer.to_bytes())
                .collect();
            Ok(Response::new(GossipsubPeersResponse { peers }))
        }

        async fn gossipsub_publish(
            &self,
            request: Request<GossipsubPublishRequest>,
        ) -> Result<Response<GossipsubPublishResponse>, tonic::Status> {
            let req = request.into_inner();
            let _topic_hash = IdentTopic::new(req.topic_hash);
            let _data = req.data;
            Ok(Response::new(GossipsubPublishResponse {
                message_id: test_message_id().0,
            }))
        }

        async fn gossipsub_remove_explicit_peer(
            &self,
            request: Request<GossipsubPeerIdMsg>,
        ) -> Result<Response<()>, tonic::Status> {
            let _peer_id = PeerId::from_bytes(&request.into_inner().peer_id);
            Ok(Response::new(()))
        }

        async fn gossipsub_subscribe(
            &self,
            request: Request<GossipsubTopicHashMsg>,
        ) -> Result<Response<GossipsubSubscribeResponse>, tonic::Status> {
            let _topic_hash = TopicHash::from_raw(request.into_inner().topic_hash);
            Ok(Response::new(GossipsubSubscribeResponse {
                was_subscribed: true,
            }))
        }

        async fn gossipsub_topics(
            &self,
            _request: Request<()>,
        ) -> Result<Response<GossipsubTopicsResponse>, tonic::Status> {
            Ok(Response::new(GossipsubTopicsResponse {
                topics: test_topics().into_iter().map(|t| t.to_string()).collect(),
            }))
        }

        async fn gossipsub_unsubscribe(
            &self,
            request: Request<GossipsubTopicHashMsg>,
        ) -> Result<Response<GossipsubSubscribeResponse>, tonic::Status> {
            let _topic_hash = TopicHash::from_raw(request.into_inner().topic_hash);
            Ok(Response::new(GossipsubSubscribeResponse {
                was_subscribed: true,
            }))
        }
    }

    #[tokio::test]
    async fn test_gossipsub_rpc() {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move { TestRpcServer::serve(listener).await });
        let client = P2pClient::new(Addr::GrpcHttp2(addr)).await.unwrap();

        // check the gossipsub methods serialize and deserialize correctly
        client
            .gossipsub_add_explicit_peer(test_peer_id())
            .await
            .unwrap();

        let got = client.gossipsub_all_mesh_peers().await.unwrap();
        let expect = test_peers();
        assert_eq!(expect, got);

        let got = client.gossipsub_all_peers().await.unwrap();
        let expect = test_peers_and_topics();
        assert_eq!(expect, got);

        let got = client.gossipsub_mesh_peers(test_topic()).await.unwrap();
        let expect = test_peers();
        assert_eq!(expect, got);

        let got = client
            .gossipsub_publish(test_topic(), test_bytes())
            .await
            .unwrap();
        let expect = test_message_id();
        assert_eq!(expect, got);

        client
            .gossipsub_remove_explicit_peer(test_peer_id())
            .await
            .unwrap();

        let got = client.gossipsub_subscribe(test_topic()).await.unwrap();
        let expect = true;
        assert_eq!(expect, got);

        let got = client.gossipsub_topics().await.unwrap();
        let expect = test_topics();
        assert_eq!(expect, got);

        let got = client.gossipsub_unsubscribe(test_topic()).await.unwrap();
        let expect = true;
        assert_eq!(expect, got);

        server_task.abort();
        server_task.await.unwrap_err();
    }
}
