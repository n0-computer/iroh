use async_trait::async_trait;

use crate::Addr;

include_proto!("gateway");

pub async fn serve<G: Gateway>(addr: Addr, gateway: G) -> anyhow::Result<()> {
    match addr {
        #[cfg(feature = "grpc")]
        Addr::GrpcHttp2(addr) => {
            let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
            health_reporter
                .set_serving::<gateway_server::GatewayServer<G>>()
                .await;

            tonic::transport::Server::builder()
                .add_service(health_service)
                .add_service(gateway_server::GatewayServer::new(gateway))
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
        pub trait Gateway: Send + Sync + 'static {
            $(
                async fn $name(&self, request: $req) -> anyhow::Result<$res>;
            )+
        }

        #[cfg(feature = "grpc")]
        mod grpc {
            use super::*;
            use gateway_client::GatewayClient;
            use tonic::{transport::Channel, Request, Response, Status};


            #[async_trait]
            impl<P: Gateway> gateway_server::Gateway for P {
                $(
                    async fn $name(
                        &self,
                        req: Request<$req>,
                    ) -> Result<Response<$res>, Status> {
                        let req = req.into_inner();
                        let res = Gateway::$name(self, req).await.map_err(|err| Status::internal(err.to_string()))?;
                        Ok(Response::new(res))
                    }
                )+
            }

            #[async_trait]
            impl Gateway for GatewayClient<Channel> {
                $(
                    async fn $name(&self, req: $req) -> anyhow::Result<$res> {
                        let req = iroh_metrics::req::trace_tonic_req(req);
                        let mut c = self.clone();
                        let res = GatewayClient::$name(&mut c, req).await?;

                        Ok(res.into_inner())
                    }
                )+
            }
        }
    }
}

proxy!(
    version: () => VersionResponse
);
