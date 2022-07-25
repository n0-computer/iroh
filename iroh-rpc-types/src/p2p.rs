use async_trait::async_trait;

use crate::Addr;

include_proto!("p2p");

pub async fn serve<P: P2p>(addr: P2pServerAddr, p2p: P) -> anyhow::Result<()> {
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
        #[cfg(all(feature = "grpc", unix))]
        Addr::GrpcUds(path) => {
            use tokio::net::UnixListener;
            use tokio_stream::wrappers::UnixListenerStream;

            let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
            health_reporter
                .set_serving::<p2p_server::P2pServer<P>>()
                .await;

            let uds = UnixListener::bind(path)?;
            let uds_stream = UnixListenerStream::new(uds);

            tonic::transport::Server::builder()
                .add_service(health_service)
                .add_service(p2p_server::P2pServer::new(p2p))
                .serve_with_incoming(uds_stream)
                .await?;

            Ok(())
        }
        #[cfg(feature = "mem")]
        Addr::Mem(sender, receiver) => {
            p2p.serve_mem(sender, receiver).await?;
            Ok(())
        }
    }
}

macro_rules! proxy {
    ($($name:ident: $req:ty => $res:ty),+) => {
        pub type P2pServerAddr = Addr<P2pRequest, P2pResponse>;
        pub type P2pClientAddr = Addr<P2pResponse, P2pRequest>;

        #[derive(Debug, Clone)]
        pub enum P2pClientBackend {
            #[cfg(feature = "grpc")]
            Grpc {
                client: p2p_client::P2pClient<tonic::transport::Channel>,
                health: tonic_health::proto::health_client::HealthClient<tonic::transport::Channel>,
            },
            #[cfg(feature = "mem")]
            Mem(async_channel::Sender<P2pRequest>, async_channel::Receiver<P2pResponse>),
        }

        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone)]
        pub enum P2pRequest {
            $(
                $name($req),
            )+
        }

        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone)]
        pub enum P2pResponse {
            $(
                $name(Result<$res, String>),
            )+
        }

        #[async_trait]
        pub trait P2p: Send + Sync + 'static {
            $(
                async fn $name(&self, request: $req) -> anyhow::Result<$res>;
            )+

            async fn serve_mem(
                &self,
                sender: async_channel::Sender<P2pResponse>,
                receiver: async_channel::Receiver<P2pRequest>
            ) -> anyhow::Result<()> {
                while let Ok(msg) = receiver.recv().await {
                    match msg {
                        $(
                            P2pRequest::$name(req) => {
                                let res = self.$name(req).await.map_err(|e| e.to_string());
                                sender.send(P2pResponse::$name(res)).await.ok();
                            }
                        )+
                    }
                }

                Ok(())
            }
        }

        #[async_trait]
        impl P2p for P2pClientBackend {
            $(
                async fn $name(&self, req: $req) -> anyhow::Result<$res> {
                    match self {
                        #[cfg(feature = "grpc")]
                        Self::Grpc { client, .. } => {
                            let req = iroh_metrics::req::trace_tonic_req(req);
                            let mut c = client.clone();
                            let res = p2p_client::P2pClient::$name(&mut c, req).await?;

                            Ok(res.into_inner())
                        }
                        #[cfg(feature = "mem")]
                        Self::Mem(s, r) => {
                            s.send(P2pRequest::$name(req)).await?;
                            let res = r.recv().await?;
                            if let P2pResponse::$name(res) = res {
                                res.map_err(|e| anyhow::anyhow!(e))
                            } else {
                                anyhow::bail!("invalid response {:?}, expected {}", res, stringify!($name));
                            }
                        }
                    }
                }
            )+
        }


        #[cfg(feature = "grpc")]
        mod grpc {
            use super::*;
            use tonic::{Request, Response, Status};

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
