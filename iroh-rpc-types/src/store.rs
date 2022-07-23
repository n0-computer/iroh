use async_trait::async_trait;

use crate::Addr;

include_proto!("store");

pub async fn serve<S: Store>(addr: Addr, store: S) -> anyhow::Result<()> {
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
        Addr::Mem => unimplemented!(),
    }
}

macro_rules! proxy {
    ($($name:ident: $req:ty => $res:ty),+) => {
        #[async_trait]
        pub trait Store: Send + Sync + 'static {
            $(
                async fn $name(&self, request: $req) -> anyhow::Result<$res>;
            )+
        }

        #[cfg(feature = "grpc")]
        mod grpc {
            use super::*;
            use store_client::StoreClient;
            use tonic::{transport::Channel, Request, Response, Status};

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

            #[async_trait]
            impl Store for StoreClient<Channel> {
                $(
                    async fn $name(&self, req: $req) -> anyhow::Result<$res> {
                        let req = iroh_metrics::req::trace_tonic_req(req);
                        let mut c = self.clone();
                        let res = StoreClient::$name(&mut c, req).await?;

                        Ok(res.into_inner())
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
