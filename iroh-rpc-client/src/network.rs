use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use cid::Cid;
use futures::Stream;
use iroh_rpc_types::p2p::{
    self, BitswapRequest, ConnectRequest, DisconnectRequest, Key, PeerAndTopics, PeerIdMsg,
    Providers, PublishRequest, TopicHashMsg,
};
use libp2p::gossipsub::{MessageId, TopicHash};
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
    gossipsub: p2p::gossipsub_client::GossipsubClient<Channel>,
    health: HealthClient<Channel>,
}

impl P2pClient {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let conn = Endpoint::new(format!("http://{}", addr))?
            .keep_alive_while_idle(true)
            .connect_lazy();

        let client = p2p::p2p_client::P2pClient::new(conn.clone());
        let gossipsub_client = p2p::gossipsub_client::GossipsubClient::new(conn.clone());
        let health_client = HealthClient::new(conn);

        Ok(P2pClient {
            p2p: client,
            gossipsub: gossipsub_client,
            health: health_client,
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let req = iroh_metrics::req::trace_tonic_req(());
        let res = self.p2p.clone().version(req).await?;
        Ok(res.into_inner().version)
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
        let req = iroh_metrics::req::trace_tonic_req(());
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
        let req = iroh_metrics::req::trace_tonic_req(());
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
    pub async fn connect(&self, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Result<()> {
        let req = iroh_metrics::req::trace_tonic_req(ConnectRequest {
            peer_id: peer_id.to_bytes(),
            addrs: addrs.iter().map(|a| a.to_vec()).collect(),
        });
        let res = self.p2p.clone().peer_connect(req).await?.into_inner();
        ensure!(res.success, "dial failed");
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        warn!("NetDisconnect not yet implemented on p2p node");
        let req = iroh_metrics::req::trace_tonic_req(DisconnectRequest {
            peer_id: peer_id.to_bytes(),
        });
        self.p2p.clone().peer_disconnect(req).await?.into_inner();
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        status::check(self.health.clone(), SERVICE_NAME, NAME).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        status::watch(self.health.clone(), SERVICE_NAME, NAME).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<()> {
        let req = iroh_metrics::req::trace_tonic_req(());
        self.p2p.clone().shutdown(req).await?.into_inner();
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_add_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        let req = iroh_metrics::req::trace_tonic_req(PeerIdMsg {
            peer_id: peer_id.to_bytes(),
        });
        self.gossipsub
            .clone()
            .add_explicit_peer(req)
            .await?
            .into_inner();
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_all_mesh_peers(&self) -> Result<Vec<PeerId>> {
        let req = iroh_metrics::req::trace_tonic_req(());
        let res = self
            .gossipsub
            .clone()
            .all_mesh_peers(req)
            .await?
            .into_inner();
        let peer_ids = peer_ids_from_bytes(res.peers)?;
        Ok(peer_ids)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_all_peers(&self) -> Result<Vec<(PeerId, Vec<TopicHash>)>> {
        let req = iroh_metrics::req::trace_tonic_req(());
        let res = self
            .gossipsub
            .clone()
            .all_peers(req)
            .await?
            .into_inner()
            .all;
        let peers_and_topics = all_peers_from_bytes(res)?;
        Ok(peers_and_topics)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_mesh_peers(&self, topic: TopicHash) -> Result<Vec<PeerId>> {
        let req = iroh_metrics::req::trace_tonic_req(TopicHashMsg {
            topic_hash: topic.into_string(),
        });
        let res = self.gossipsub.clone().mesh_peers(req).await?.into_inner();
        let peer_ids = peer_ids_from_bytes(res.peers)?;
        Ok(peer_ids)
    }

    #[tracing::instrument(skip(self, data))]
    pub async fn gossipsub_publish(&self, topic_hash: TopicHash, data: Bytes) -> Result<MessageId> {
        let req = iroh_metrics::req::trace_tonic_req(PublishRequest {
            topic_hash: topic_hash.to_string(),
            data,
        });
        let res = self.gossipsub.clone().publish(req).await?.into_inner();
        let message_id = MessageId::new(&res.message_id);
        Ok(message_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_remove_explicit_peer(&self, peer_id: PeerId) -> Result<()> {
        let req = iroh_metrics::req::trace_tonic_req(PeerIdMsg {
            peer_id: peer_id.to_bytes(),
        });
        self.gossipsub.clone().remove_explicit_peer(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_subscribe(&self, topic: TopicHash) -> Result<bool> {
        let req = iroh_metrics::req::trace_tonic_req(TopicHashMsg {
            topic_hash: topic.to_string(),
        });
        let res = self.gossipsub.clone().subscribe(req).await?.into_inner();
        Ok(res.was_subscribed)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_topics(&self) -> Result<Vec<TopicHash>> {
        let req = iroh_metrics::req::trace_tonic_req(());
        let res = self.gossipsub.clone().topics(req).await?.into_inner();
        let topics = res.topics.into_iter().map(TopicHash::from_raw).collect();
        Ok(topics)
    }

    #[tracing::instrument(skip(self))]
    pub async fn gossipsub_unsubscribe(&self, topic: TopicHash) -> Result<bool> {
        let req = iroh_metrics::req::trace_tonic_req(TopicHashMsg {
            topic_hash: topic.to_string(),
        });
        let res = self.gossipsub.clone().unsubscribe(req).await?.into_inner();
        Ok(res.was_subscribed)
    }
}

fn peers_and_topics_from_bytes(pt: PeerAndTopics) -> Result<(PeerId, Vec<TopicHash>)> {
    let peer_id = peer_id_from_bytes(pt.peer_id)?;
    let topics = pt.topics.into_iter().map(TopicHash::from_raw).collect();
    Ok((peer_id, topics))
}

fn all_peers_from_bytes(a: Vec<PeerAndTopics>) -> Result<Vec<(PeerId, Vec<TopicHash>)>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_rpc_types::p2p::{
        gossipsub_server, AllPeersResponse, PeersResponse, PublishResponse, SubscribeResponse,
        TopicsResponse,
    };
    use libp2p::gossipsub::IdentTopic;
    use tokio::net::TcpListener;
    use tonic::{transport::Server as TonicServer, Request, Response};

    struct TestRpcServer {}

    impl TestRpcServer {
        async fn serve(listener: TcpListener) {
            let test_rpc_service = TestRpcServer {};
            let gossipsub_service = gossipsub_server::GossipsubServer::new(test_rpc_service);

            TonicServer::builder()
                .add_service(gossipsub_service)
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

    #[tonic::async_trait]
    impl gossipsub_server::Gossipsub for TestRpcServer {
        async fn add_explicit_peer(
            &self,
            _request: Request<PeerIdMsg>,
        ) -> Result<Response<()>, tonic::Status> {
            Ok(Response::new(()))
        }

        async fn all_mesh_peers(
            &self,
            _request: Request<()>,
        ) -> Result<Response<PeersResponse>, tonic::Status> {
            let peers = test_peers().into_iter().map(|p| p.to_bytes()).collect();
            Ok(Response::new(PeersResponse { peers }))
        }

        async fn all_peers(
            &self,
            _request: Request<()>,
        ) -> Result<Response<AllPeersResponse>, tonic::Status> {
            let all = test_peers_and_topics()
                .into_iter()
                .map(|(peer_id, topics)| PeerAndTopics {
                    peer_id: peer_id.to_bytes(),
                    topics: topics.into_iter().map(|t| t.to_string()).collect(),
                })
                .collect();
            Ok(Response::new(AllPeersResponse { all }))
        }

        async fn mesh_peers(
            &self,
            request: Request<TopicHashMsg>,
        ) -> Result<Response<PeersResponse>, tonic::Status> {
            let _topic_hash = request.into_inner().topic_hash;
            let peers = test_peers()
                .into_iter()
                .map(|peer| peer.to_bytes())
                .collect();
            Ok(Response::new(PeersResponse { peers }))
        }

        async fn publish(
            &self,
            request: Request<PublishRequest>,
        ) -> Result<Response<PublishResponse>, tonic::Status> {
            let req = request.into_inner();
            let _topic_hash = IdentTopic::new(req.topic_hash);
            let _data = req.data;
            Ok(Response::new(PublishResponse {
                message_id: test_message_id().0,
            }))
        }

        async fn remove_explicit_peer(
            &self,
            request: Request<PeerIdMsg>,
        ) -> Result<Response<()>, tonic::Status> {
            let _peer_id = PeerId::from_bytes(&request.into_inner().peer_id);
            Ok(Response::new(()))
        }

        async fn subscribe(
            &self,
            request: Request<TopicHashMsg>,
        ) -> Result<Response<SubscribeResponse>, tonic::Status> {
            let _topic_hash = TopicHash::from_raw(request.into_inner().topic_hash);
            Ok(Response::new(SubscribeResponse {
                was_subscribed: true,
            }))
        }

        async fn topics(
            &self,
            _request: Request<()>,
        ) -> Result<Response<TopicsResponse>, tonic::Status> {
            Ok(Response::new(TopicsResponse {
                topics: test_topics().into_iter().map(|t| t.to_string()).collect(),
            }))
        }

        async fn unsubscribe(
            &self,
            request: Request<TopicHashMsg>,
        ) -> Result<Response<SubscribeResponse>, tonic::Status> {
            let _topic_hash = TopicHash::from_raw(request.into_inner().topic_hash);
            Ok(Response::new(SubscribeResponse {
                was_subscribed: true,
            }))
        }
    }

    #[tokio::test]
    async fn test_gossipsub_rpc() {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move { TestRpcServer::serve(listener).await });
        let client = P2pClient::new(addr).await.unwrap();

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
