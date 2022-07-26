use anyhow::Context;
use async_trait::async_trait;

use crate::Addr;

include_proto!("gateway");

pub async fn serve<G: Gateway>(addr: GatewayServerAddr, gateway: G) -> anyhow::Result<()> {
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
        #[cfg(all(feature = "grpc", unix))]
        Addr::GrpcUds(path) => {
            use tokio::net::UnixListener;
            use tokio_stream::wrappers::UnixListenerStream;

            let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
            health_reporter
                .set_serving::<gateway_server::GatewayServer<G>>()
                .await;

            if path.exists() {
                if path.is_dir() {
                    anyhow::bail!("cannot bind socket to directory: {}", path.display());
                }
                tokio::fs::remove_file(&path).await?;
            }

            let uds = UnixListener::bind(&path)
                .with_context(|| format!("failed to bind to {}", path.display()))?;
            let uds_stream = UnixListenerStream::new(uds);

            tonic::transport::Server::builder()
                .add_service(health_service)
                .add_service(gateway_server::GatewayServer::new(gateway))
                .serve_with_incoming(uds_stream)
                .await?;

            Ok(())
        }
        #[cfg(feature = "mem")]
        Addr::Mem(sender, receiver) => {
            gateway.serve_mem(sender, receiver).await?;
            Ok(())
        }
    }
}

macro_rules! proxy {
    ($($name:ident: $req:ty => $res:ty),+) => {
        pub type GatewayServerAddr = Addr<GatewayRequest, GatewayResponse>;
        pub type GatewayClientAddr = Addr<GatewayResponse, GatewayRequest>;

        #[derive(Debug, Clone)]
        pub enum GatewayClientBackend {
            #[cfg(feature = "grpc")]
            Grpc {
                client: gateway_client::GatewayClient<tonic::transport::Channel>,
                health: tonic_health::proto::health_client::HealthClient<tonic::transport::Channel>,
            },
            #[cfg(feature = "mem")]
            Mem(async_channel::Sender<GatewayRequest>, async_channel::Receiver<GatewayResponse>),
        }

        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone)]
        pub enum GatewayRequest {
            $(
                $name($req),
            )+
        }

        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone)]
        pub enum GatewayResponse {
            $(
                $name(Result<$res, String>),
            )+
        }

        #[async_trait]
        pub trait Gateway: Send + Sync + 'static {
            $(
                async fn $name(&self, request: $req) -> anyhow::Result<$res>;
            )+

            async fn serve_mem(
                &self,
                sender: async_channel::Sender<GatewayResponse>,
                receiver: async_channel::Receiver<GatewayRequest>
            ) -> anyhow::Result<()> {
                while let Ok(msg) = receiver.recv().await {
                    match msg {
                        $(
                            GatewayRequest::$name(req) => {
                                let res = self.$name(req).await.map_err(|e| e.to_string());
                                sender.send(GatewayResponse::$name(res)).await.ok();
                            }
                        )+
                    }
                }

                Ok(())
            }
        }

        #[async_trait]
        impl Gateway for GatewayClientBackend {
            $(
                async fn $name(&self, req: $req) -> anyhow::Result<$res> {
                    match self {
                        #[cfg(feature = "grpc")]
                        Self::Grpc { client, .. } => {
                            let req = iroh_metrics::req::trace_tonic_req(req);
                            let mut c = client.clone();
                            let res = gateway_client::GatewayClient::$name(&mut c, req).await?;

                            Ok(res.into_inner())
                        }
                        #[cfg(feature = "mem")]
                        Self::Mem(s, r) => {
                            s.send(GatewayRequest::$name(req)).await?;
                            let res = r.recv().await?;
                            #[allow(irrefutable_let_patterns)]
                            if let GatewayResponse::$name(res) = res {
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
        }
    }
}

proxy!(
    version: () => VersionResponse
);
