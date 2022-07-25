use async_trait::async_trait;

use crate::Addr;

include_proto!("store");

pub async fn serve<S: Store>(addr: StoreServerAddr, store: S) -> anyhow::Result<()> {
    match addr {
        #[cfg(feature = "grpc")]
        Addr::GrpcHttp2(addr) => {
            let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
            health_reporter
                .set_serving::<store_server::StoreServer<S>>()
                .await;

            tonic::transport::Server::builder()
                .add_service(health_service)
                .add_service(store_server::StoreServer::new(store))
                .serve(addr)
                .await?;

            Ok(())
        }
        #[cfg(feature = "grpc")]
        Addr::GrpcUds(_) => unimplemented!(),
        #[cfg(feature = "mem")]
        Addr::Mem(sender, receiver) => {
            store.serve_mem(sender, receiver).await?;
            Ok(())
        }
    }
}

macro_rules! proxy {
    ($($name:ident: $req:ty => $res:ty),+) => {
        pub type StoreServerAddr = Addr<StoreRequest, StoreResponse>;
        pub type StoreClientAddr = Addr<StoreResponse, StoreRequest>;

        #[derive(Debug, Clone)]
        pub enum StoreClientBackend {
            #[cfg(feature = "grpc")]
            Grpc {
                client: store_client::StoreClient<tonic::transport::Channel>,
                health: tonic_health::proto::health_client::HealthClient<tonic::transport::Channel>,
            },
            #[cfg(feature = "mem")]
            Mem(async_channel::Sender<StoreRequest>, async_channel::Receiver<StoreResponse>),
        }

        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone)]
        pub enum StoreRequest {
            $(
                $name($req),
            )+
        }

        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone)]
        pub enum StoreResponse {
            $(
                $name(Result<$res, String>),
            )+
        }

        #[async_trait]
        pub trait Store: Send + Sync + 'static {
            $(
                async fn $name(&self, request: $req) -> anyhow::Result<$res>;
            )+

            async fn serve_mem(
                &self,
                sender: async_channel::Sender<StoreResponse>,
                receiver: async_channel::Receiver<StoreRequest>
            ) -> anyhow::Result<()> {
                while let Ok(msg) = receiver.recv().await {
                    match msg {
                        $(
                            StoreRequest::$name(req) => {
                                let res = self.$name(req).await.map_err(|e| e.to_string());
                                sender.send(StoreResponse::$name(res)).await.ok();
                            }
                        )+
                    }
                }

                Ok(())
            }
        }

        #[async_trait]
        impl Store for StoreClientBackend {
            $(
                async fn $name(&self, req: $req) -> anyhow::Result<$res> {
                    match self {
                        #[cfg(feature = "grpc")]
                        Self::Grpc { client, .. } => {
                            let req = iroh_metrics::req::trace_tonic_req(req);
                            let mut c = client.clone();
                            let res = store_client::StoreClient::$name(&mut c, req).await?;

                            Ok(res.into_inner())
                        }
                        #[cfg(feature = "mem")]
                        Self::Mem(s, r) => {
                            s.send(StoreRequest::$name(req)).await?;
                            let res = r.recv().await?;
                            if let StoreResponse::$name(res) = res {
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
            impl<P: Store> store_server::Store for P {
                $(
                    async fn $name(
                        &self,
                        req: Request<$req>,
                    ) -> Result<Response<$res>, Status> {
                        let req = req.into_inner();
                        let res = Store::$name(self, req).await.map_err(|err| Status::internal(err.to_string()))?;
                        Ok(Response::new(res))
                    }
                )+
            }
        }
    }
}

proxy!(
    version: () => VersionResponse,
    put: PutRequest => (),
    get: GetRequest => GetResponse,
    has: HasRequest => HasResponse,
    get_links: GetLinksRequest => GetLinksResponse
);
