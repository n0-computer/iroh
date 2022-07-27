#[macro_export]
macro_rules! proxy {
    ($label:ident, $($name:ident: $req:ty => $res:ty),+) => {
        paste::paste! {
            pub async fn serve<T: $label>(addr: [<$label ServerAddr>], source: T) -> anyhow::Result<()> {
                match addr {
                    #[cfg(feature = "grpc")]
                    $crate::Addr::GrpcHttp2(addr) => {
                        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
                        health_reporter
                            .set_serving::<[<$label:lower _server>]::[<$label Server>]<T>>()
                            .await;

                        tonic::transport::Server::builder()
                            .add_service(health_service)
                            .add_service([<$label:lower _server>]::[<$label Server>]::new(source))
                            .serve(addr)
                            .await?;

                        Ok(())
                    }
                    #[cfg(all(feature = "grpc", unix))]
                    $crate::Addr::GrpcUds(path) => {
                        use anyhow::Context;
                        use tokio::net::UnixListener;
                        use tokio_stream::wrappers::UnixListenerStream;

                        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
                        health_reporter
                            .set_serving::<[<$label:lower _server>]::[<$label Server>]<T>>()
                            .await;

                        if path.exists() {
                            if path.is_dir() {
                                anyhow::bail!("cannot bind socket to directory: {}", path.display());
                            } else {
                                anyhow::bail!("cannot bind socket: already exists: {}", path.display());
                            }
                        }
                        // Delete file on close
                        struct UdsGuard(std::path::PathBuf);
                        impl Drop for UdsGuard {
                            fn drop(&mut self) {
                                let _ = std::fs::remove_file(&self.0);
                            }
                        }

                        let uds = UnixListener::bind(&path)
                            .with_context(|| format!("failed to bind to {}", path.display()))?;
                        let _guard = UdsGuard(path.clone().into());

                        let uds_stream = UnixListenerStream::new(uds);

                        tonic::transport::Server::builder()
                            .add_service(health_service)
                            .add_service([<$label:lower _server>]::[<$label Server>]::new(source))
                            .serve_with_incoming(uds_stream)
                            .await?;

                        Ok(())
                    }
                    #[cfg(feature = "mem")]
                    $crate::Addr::Mem(sender, receiver) => {
                        while let Ok(msg) = receiver.recv().await {
                            match msg {
                                $(
                                    [<$label Request>]::$name(req) => {
                                        let res = source.$name(req).await.map_err(|e| e.to_string());
                                        sender.send([<$label Response>]::$name(res)).await.ok();
                                    }
                                )+
                            }
                        }

                        Ok(())
                    }
                }
            }


            pub type [<$label ServerAddr>] = $crate::Addr<[<$label Request>], [<$label Response>]>;
            pub type [<$label ClientAddr>] = $crate::Addr<[<$label Response>], [<$label Request>]>;

            #[derive(Debug, Clone)]
            pub enum [<$label ClientBackend>] {
                #[cfg(feature = "grpc")]
                Grpc {
                    client: [<$label:lower _client>]::[<$label Client>]<tonic::transport::Channel>,
                    health: tonic_health::proto::health_client::HealthClient<tonic::transport::Channel>,
                },
                #[cfg(feature = "mem")]
                Mem(async_channel::Sender<[<$label Request>]>, async_channel::Receiver<[<$label Response>]>),
            }

            #[allow(non_camel_case_types)]
            #[derive(Debug, Clone)]
            pub enum [<$label Request>] {
                $(
                    $name($req),
                )+
            }

            #[allow(non_camel_case_types)]
            #[derive(Debug, Clone)]
            pub enum [<$label Response>] {
                $(
                    $name(Result<$res, String>),
                )+
            }

            #[async_trait::async_trait]
            pub trait $label: Send + Sync + 'static {
                $(
                    async fn $name(&self, request: $req) -> anyhow::Result<$res>;
                )+
            }

            #[async_trait::async_trait]
            impl $label for [<$label ClientBackend>] {
                $(
                    async fn $name(&self, req: $req) -> anyhow::Result<$res> {
                        match self {
                            #[cfg(feature = "grpc")]
                            Self::Grpc { client, .. } => {
                                let req = iroh_metrics::req::trace_tonic_req(req);
                                let mut c = client.clone();
                                let res = [<$label:lower _client>]::[<$label Client>]::$name(&mut c, req).await?;

                                Ok(res.into_inner())
                            }
                            #[cfg(feature = "mem")]
                            Self::Mem(s, r) => {
                                s.send([<$label Request>]::$name(req)).await?;
                                let res = r.recv().await?;
                                #[allow(irrefutable_let_patterns)]
                                if let [<$label Response>]::$name(res) = res {
                                    res.map_err(|e| anyhow::anyhow!(e))
                                } else {
                                    anyhow::bail!("invalid response {:?}, expected {}", res, stringify!($name));
                                }
                            }
                        }
                    }
                )+
            }
        }

        #[cfg(feature = "grpc")]
        mod grpc {
            use super::*;
            use tonic::{Request, Response, Status};


            paste::paste! {
                #[async_trait::async_trait]
                impl<P: $label> [<$label:lower _server>]::$label for P {
                    $(
                        async fn $name(
                            &self,
                            req: Request<$req>,
                        ) -> Result<Response<$res>, Status> {
                            let req = req.into_inner();
                            let res = $label::$name(self, req).await.map_err(|err| Status::internal(err.to_string()))?;
                            Ok(Response::new(res))
                        }
                    )+
                }
            }
        }
    }
}

// Based on tonic::include_proto
#[macro_export]
macro_rules! include_proto {
    ($package: tt) => {
        #[allow(clippy::all)]
        mod proto {
            include!(concat!(env!("OUT_DIR"), concat!("/", $package, ".rs")));
        }
        pub use proto::*;
    };
}
