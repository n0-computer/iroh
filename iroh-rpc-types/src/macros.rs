/// Create all the scaffolding needed to implement the grpc services for a given package.
#[macro_export]
macro_rules! proxy {
    ($package:ident, $(($service:ident, $($func:ident: $req:ty => $res:ty),+)),+) => {
        paste::paste! {
            pub async fn serve<$([<T $service:lower>]: [<$package:camel $service:camel>],)+>(addr: [<$package:camel ServerAddr>], $([<$service:snake _source>]: [<T $service:lower>],)+) -> anyhow::Result<()> {
                match addr {
                    #[cfg(feature = "grpc")]
                    $crate::Addr::GrpcHttp2(addr) => {
                        $(
                        let (mut health_reporter, [<$service:snake health_service>]) = tonic_health::server::health_reporter();
                        health_reporter
                        .set_serving::<[<$service:snake _server>]::[<$service:camel Server>]<[<T $service:lower>]>>()
                            .await;
                        )+

                        tonic::transport::Server::builder()
                            $(.add_service([<$service:snake health_service>]))+
                            $(.add_service([<$service:snake _server>]::[<$service:camel Server>]::new([<$service:snake _source>])))+
                            .serve(addr)
                            .await?;

                        Ok(())
                    }
                    #[cfg(all(feature = "grpc", unix))]
                    $crate::Addr::GrpcUds(path) => {
                        use anyhow::Context;
                        use tokio::net::UnixListener;
                        use tokio_stream::wrappers::UnixListenerStream;

                        $(
                        let (mut health_reporter, [<$service:snake health_service>]) = tonic_health::server::health_reporter();
                        health_reporter
                            .set_serving::<[<$service:snake _server>]::[<$service:camel Server>]<[<T $service:lower>]>>()
                            .await;
                        )+

                        if path.exists() {
                            if path.is_dir() {
                                anyhow::bail!("cannot bind socket to directory: {}", path.display());
                            } else {
                                anyhow::bail!("cannot bind socket: already exists: {}", path.display());
                            }
                        }

                        // If the parent directory doesn't exist, we'll fail to bind.
                        // Create a more precise error to recognize that case.
                        if let Some(parent) = path.parent() {
                            if !parent.exists() {
                                anyhow::bail!("socket parent directory doesn't exist: {}", parent.display());
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
                            $(.add_service([<$service:snake health_service>]))+
                            $(.add_service([<$service:snake _server>]::[<$service:camel Server>]::new([<$service:snake _source>])))+
                            .serve_with_incoming(uds_stream)
                            .await?;

                        Ok(())
                    }
                    #[cfg(feature = "mem")]
                    $crate::Addr::Mem(mut receiver) => {
                        while let Some((msg, sender)) = receiver.recv().await {
                            match msg {
                                $($(
                                    [<$package:camel Request>]::[<$service:camel $func:camel>](req) => {
                                        let res = [<$service:snake _source>].$func(req).await.map_err(|e| e.to_string());
                                        sender.send([<$package:camel Response>]::[<$service:camel $func:camel>](res)).ok();
                                    }
                                )+)+
                            }
                        }

                        Ok(())
                    }
                }
            }

            pub type [<$package:camel ServerAddr>] = $crate::Addr<
                tokio::sync::mpsc::Receiver<
                  ([<$package:camel Request>], tokio::sync::oneshot::Sender<[<$package:camel Response>]>),
                >
            >;
            pub type [<$package:camel ClientAddr>] = $crate::Addr<
                tokio::sync::mpsc::Sender<
                  ([<$package:camel Request>], tokio::sync::oneshot::Sender<[<$package:camel Response>]>),
                >
            >;

            #[derive(Debug, Clone)]
            #[allow(clippy::large_enum_variant)]
            pub enum [<$package:camel ClientBackend>] {
                #[cfg(feature = "grpc")]
                Grpc {
                    $(
                      [<$service:snake _client>]: [<$service:snake _client>]::[<$service:camel Client>]<tonic::transport::Channel>,
                    )+
                    health: tonic_health::proto::health_client::HealthClient<tonic::transport::Channel>,
                },
                #[cfg(feature = "mem")]
                Mem(
                    tokio::sync::mpsc::Sender<(
                        [<$package:camel Request>],
                        tokio::sync::oneshot::Sender<[<$package:camel Response>]>
                    )>
                ),
            }


            #[derive(Debug, Clone)]
            pub enum [<$package:camel Request>]
            {
                $($([<$service:camel $func:camel>]($req),)+)+
            }

            #[derive(Debug, Clone)]
            pub enum [<$package:camel Response>] {
                $($([<$service:camel $func:camel>](Result<$res, String>),)+)+
            }

            $(
            #[async_trait::async_trait]
            pub trait [<$package:camel $service:camel>]: Send + Sync + 'static {
                $(
                    async fn [<$func:snake>](&self, request: $req) -> anyhow::Result<$res>;
                )+
            }

            #[async_trait::async_trait]
            impl [<$package:camel $service:camel>] for [<$package ClientBackend>] {
                $(
                    async fn $func(&self, req: $req) -> anyhow::Result<$res> {
                        match self {
                            #[cfg(feature = "grpc")]
                            Self::Grpc { [<$service:snake _client>], .. } => {
                                let req = iroh_metrics::req::trace_tonic_req(req);
                                let mut c = [<$service:snake _client>].clone();
                                let res = [<$service:snake _client>]::[<$service:camel Client>]::[<$func:snake>](&mut c, req).await?;

                                Ok(res.into_inner())
                            }
                            #[cfg(feature = "mem")]
                            Self::Mem(s) => {
                                let (s_res, r_res) = tokio::sync::oneshot::channel();
                                s.send(([<$package:camel Request>]::[<$service:camel $func:camel>](req), s_res)).await?;

                                let res = r_res.await?;
                                #[allow(irrefutable_let_patterns)]
                                if let [<$package:camel Response>]::[<$service:camel $func:camel>](res) = res {
                                    return res.map_err(|e| anyhow::anyhow!(e));
                                } else {
                                    anyhow::bail!("invalid response: {:?}", res);
                                }
                            }
                        }
                    }
                )+
            }
        )+
        }

        #[cfg(feature = "grpc")]
        mod grpc {
            use super::*;
            use tonic::{Request, Response, Status};

            $(
                paste::paste! {
                    #[async_trait::async_trait]
                    impl<P: [<$package:camel $service:camel>]> [<$service:snake _server>]::$service for P {
                        $(
                            async fn [<$func:snake>](
                                &self,
                                req: Request<$req>,
                            ) -> Result<Response<$res>, Status> {
                                let req = req.into_inner();
                                let res = self.[<$func:snake>](req).await.map_err(|err| Status::internal(err.to_string()))?;
                                Ok(Response::new(res))
                            }
                        )+
                    }
                }
            )+
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
