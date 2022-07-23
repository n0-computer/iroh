use async_trait::async_trait;

use crate::Addr;

include_proto!("p2p");

pub async fn serve<P: P2p>(addr: Addr, p2p: P) -> anyhow::Result<()> {
    match addr {
        #[cfg(feature = "grpc")]
        Addr::GrpcHttp2(addr) => {
            let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
            health_reporter
                .set_serving::<p2p_server::P2pServer<P>>()
                .await;
            let p2p_service = p2p_server::P2pServer::new(p2p);

            tonic::transport::Server::builder()
                .add_service(health_service)
                .add_service(p2p_service)
                .serve(addr)
                .await?;
            Ok(())
        }
        #[cfg(feature = "grpc")]
        Addr::GrpcUds(_) => unimplemented!(),
        #[cfg(feature = "mem")]
        Addr::Mem => unimplemented!(),
    }
}

macro_rules! proxy {
    ($($name:ident: $req:ty => $res:ty),+) => {
        #[async_trait]
        pub trait P2p: Send + Sync + 'static {
            $(
                async fn $name(&self, request: $req) -> anyhow::Result<$res>;
            )+
        }


        #[cfg(feature = "grpc")]
        mod grpc {
            use self::p2p_client::P2pClient;
            use super::*;
            use tonic::{transport::Channel, Request, Response, Status};

            #[async_trait]
            impl<P: P2p> p2p_server::P2p for P {
                $(
                    async fn $name(
                        &self,
                        req: Request<$req>,
                    ) -> Result<Response<$res>, Status> {
                        let req = req.into_inner();
                        let res = P2p::$name(self, req).await.map_err(|err| Status::internal(err.to_string()))?;
                        Ok(Response::new(res))
                    }
                )+
            }

            #[async_trait]
            impl P2p for P2pClient<Channel> {
                $(
                    async fn $name(&self, req: $req) -> anyhow::Result<$res> {
                        let req = iroh_metrics::req::trace_tonic_req(req);
                        let mut c = self.clone();
                        let res = P2pClient::$name(&mut c, req).await?;

                        Ok(res.into_inner())
                    }
                )+
            }
        }
    }
}

proxy!(
    version: () => VersionResponse,
    shutdown: () => (),
    fetch_bitswap: BitswapRequest => BitswapResponse,
    fetch_provider: Key => Providers,
    get_listening_addrs: () => GetListeningAddrsResponse,
    get_peers: () => GetPeersResponse,
    peer_connect: ConnectRequest => ConnectResponse,
    peer_disconnect: DisconnectRequest => (),
    gossipsub_add_explicit_peer: GossipsubPeerIdMsg => (),
    gossipsub_all_mesh_peers: () => GossipsubPeersResponse,
    gossipsub_all_peers: () => GossipsubAllPeersResponse,
    gossipsub_mesh_peers: GossipsubTopicHashMsg => GossipsubPeersResponse,
    gossipsub_publish: GossipsubPublishRequest => GossipsubPublishResponse,
    gossipsub_remove_explicit_peer: GossipsubPeerIdMsg => (),
    gossipsub_subscribe: GossipsubTopicHashMsg => GossipsubSubscribeResponse,
    gossipsub_topics: () => GossipsubTopicsResponse,
    gossipsub_unsubscribe: GossipsubTopicHashMsg => GossipsubSubscribeResponse
);
