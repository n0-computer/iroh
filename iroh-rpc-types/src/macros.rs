macro_rules! proxy_serve {
    ($label:ident, $($name:ident: $req:ty => $res:ty),+) => {
        paste::paste! {
            pub async fn serve<T: $label>(addr: [<$label ServerAddr>], source: T) -> Result<(), $crate::error::Error> {
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
                        use tokio::net::UnixListener;
                        use tokio_stream::wrappers::UnixListenerStream;

                        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
                        health_reporter
                            .set_serving::<[<$label:lower _server>]::[<$label Server>]<T>>()
                            .await;

                        if path.exists() {
                            return if path.is_dir() {
                                Err($crate::error::Error::SocketToDir(path))
                            } else {
                                Err($crate::error::Error::SocketExists(path))
                            }
                        }

                        // If the parent directory doesn't exist, we'll fail to bind.
                        // Create a more precise error to recognize that case.
                        if let Some(parent) = path.parent() {
                            if !parent.exists() {
                                return Err($crate::error::Error::SocketParentDirDoesNotExist(parent.to_path_buf()))
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
                            .map_err(|e| $crate::error::Error::FailedToBind(path.to_path_buf(), e))?;
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
                    $crate::Addr::Mem(mut receiver) => {
                        while let Some((msg, sender)) = receiver.recv().await {
                            match msg {
                                $(
                                    [<$label Request>]::$name(req) => {
                                        let res = source.$name(req).await.map_err(|e| e.to_string());
                                        sender.send([<$label Response>]::$name(res)).ok();
                                    }
                                )+
                            }
                        }

                        Ok(())
                    }
                }
            }
        }
    }
}

macro_rules! proxy_serve_types {
    ($label:ident, $($name:ident: $req:ty => $res:ty),+) => {
        paste::paste! {
            pub type [<$label ServerAddr>] = $crate::Addr<
                    tokio::sync::mpsc::Receiver<
                            ([<$label Request>], tokio::sync::oneshot::Sender<[<$label Response>]>),
                        >
                    >;
            pub type [<$label ClientAddr>] = $crate::Addr<
                    tokio::sync::mpsc::Sender<
                            ([<$label Request>], tokio::sync::oneshot::Sender<[<$label Response>]>),
                        >
                    >;

            #[derive(Debug, Clone)]
            #[allow(clippy::large_enum_variant)]
            pub enum [<$label ClientBackend>] {
                #[cfg(feature = "grpc")]
                Grpc {
                    client: [<$label:lower _client>]::[<$label Client>]<tonic::transport::Channel>,
                    health: tonic_health::proto::health_client::HealthClient<tonic::transport::Channel>,
                },
                #[cfg(feature = "mem")]
                Mem(
                    tokio::sync::mpsc::Sender<(
                        [<$label Request>],
                        tokio::sync::oneshot::Sender<[<$label Response>]>
                    )>
                ),
            }

            #[allow(non_camel_case_types)]
            #[derive(Debug, Clone)]
            pub enum [<$label Request>] {
                $(
                    $name($req),
                )+
            }

            #[allow(non_camel_case_types)]
            pub enum [<$label Response>] {
                $(
                    $name(Result<$res, String>),
                )+
            }
        }
    }
}

macro_rules! proxy_traits {
    ($label:ident, $errty:ty, $($name:ident: $req:ty => $tonic_res:ty => $res:ty $([$stream_type_name:ident])?),+) => {
        paste::paste! {
            #[async_trait::async_trait]
            pub trait $label: Send + Sync + 'static {
                type Error: std::fmt::Display + From<$crate::error::Error>;

                $(
                    async fn $name(&self, request: $req) -> Result<$res, Self::Error>;
                )+
            }

            #[async_trait::async_trait]
            impl $label for [<$label ClientBackend>] {
                type Error = $errty;

                $(
                    async fn $name(&self, req: $req) -> Result<$res, Self::Error> {
                        match self {
                            #[cfg(feature = "grpc")]
                            Self::Grpc { client, .. } => {
                                let req = iroh_metrics::req::trace_tonic_req(req);
                                let mut c = client.clone();
                                let res = [<$label:lower _client>]::[<$label Client>]::$name(&mut c, req)
                                    .await
                                    .map_err(Self::Error::from)?;
                                let res = res.into_inner();
                                $(
                                    let res = {
                                        use futures::StreamExt;
                                        Box::pin(res.map(|p| {
                                            p.map_err(|e| $crate::error::Error::Str(e.to_string()))
                                                .map_err(Self::Error::from)
                                        }))
                                    };
                                    // hack
                                    #[allow(dead_code)]
                                    if false {
                                        let _x = stringify!($stream_type_name);
                                    }
                                )?
                                Ok(res)
                            }
                            #[cfg(feature = "mem")]
                            Self::Mem(s) => {
                                let (s_res, r_res) = tokio::sync::oneshot::channel();
                                s.send(([<$label Request>]::$name(req), s_res)).await.map_err(|_| $crate::error::Error::SendFailed).map_err(Self::Error::from)?;

                                let res = r_res.await?;
                                #[allow(irrefutable_let_patterns)]
                                if let [<$label Response>]::$name(res) = res {
                                    return res.map_err(|e| $crate::error::Error::Str(e))
                                        .map_err(Self::Error::from)
                                } else {
                                    Err($crate::error::Error::InvalidResponse).map_err(Self::Error::from)
                                }
                            }
                        }
                    }
                )+
            }
        }
    }
}

macro_rules! proxy_grpc {
    ($label:ident, $($name:ident: $req:ty => $tonic_res:ty => $res:ty $([$stream_type_name:ident])?),+) => {
        #[cfg(feature = "grpc")]
        mod grpc {
            use super::*;
            use tonic::{Request, Response, Status};

            paste::paste! {
                #[async_trait::async_trait]
                impl<P: $label> [<$label:lower _server>]::$label for P {
                    $(
                        $(type $stream_type_name = $tonic_res;)?

                        async fn $name(
                            &self,
                            req: Request<$req>,
                        ) -> Result<Response<$tonic_res>, Status> {
                            let req = req.into_inner();
                            let res = $label::$name(self, req).await.map_err(|err| Status::internal(err.to_string()))?;

                            $(
                                let res = {
                                    use futures::StreamExt;
                                    Box::pin(res.map(|s| s.map_err(|e| Status::internal(e.to_string()))))
                                };
                                // hack
                                #[allow(dead_code)]
                                if false {
                                    let _x = stringify!($stream_type_name);
                                }
                            )?

                            Ok(Response::new(res))
                        }
                    )+
                }
            }
        }
    }
}

#[macro_export]
macro_rules! proxy {
    ($label:ident, $errty:ty, $(
        $name:ident: $req:ty => $tonic_res:ty => $res:ty $([$stream_type_name:ident])?
    ),+) => {
        proxy_serve!($label, $($name: $req => $res),+);
        proxy_serve_types!($label, $($name: $req => $res),+);
        proxy_traits!($label, $errty, $($name: $req => $tonic_res => $res $([$stream_type_name])?),+);
        proxy_grpc!($label, $($name: $req => $tonic_res => $res $([$stream_type_name])?),+);
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
