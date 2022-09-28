#[macro_export]
macro_rules! impl_client {
    ($package:ident : $($service:ident),+) => {
        paste::paste! {
            /// Name that the health service registers the client,
            /// as this is derived from the protobuf definition.
            #[cfg(feature = "grpc")]
            pub(crate) const SERVICE_NAME: &str = stringify!([<$package:lower>].[<$package>]);

            /// The display name that we expect to see in the StatusTable.
            #[cfg(feature = "grpc")]
            pub(crate) const NAME: &str = stringify!([<$package:lower>]);

            #[derive(Debug, Clone)]
            pub struct [<$package Client>] {
                pub backend: [<$package:camel ClientBackend>],
            }

            impl [<$package Client>] {
                pub async fn new(addr: [<$package ClientAddr>]) -> Result<Self> {
                    match addr {
                        #[cfg(feature = "grpc")]
                        Addr::GrpcHttp2(addr) => {
                            let conn = Endpoint::new(format!("http://{}", addr))?
                                .keep_alive_while_idle(true)
                                .connect_lazy();

                            $(
                              let [<$service:snake _client>] = [<Grpc $package Client>]::new(conn.clone());
                            )+

                            let health = HealthClient::new(conn);

                            Ok([<$package Client>] {
                                backend: [<$package ClientBackend>]::Grpc { $([<$service:snake _client>])+, health },
                            })
                        }
                        #[cfg(all(feature = "grpc", unix))]
                        Addr::GrpcUds(path) => {
                            use tokio::net::UnixStream;
                            use tonic::transport::Uri;

                            let path = std::sync::Arc::new(path);
                            // dummy addr
                            let conn = Endpoint::new("http://[..]:50051")?
                                .keep_alive_while_idle(true)
                                .connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
                                    let path = path.clone();
                                    UnixStream::connect(path.as_ref().clone())
                                }));

                            $(
                                let [<$service:snake _client>] = [<Grpc $package Client>]::new(conn.clone());
                            )+
                            let health = HealthClient::new(conn);

                            Ok([<$package Client>] {
                                backend: [<$package ClientBackend>]::Grpc { $([<$service:snake _client>],)+ health },
                            })
                        }
                        #[cfg(feature = "mem")]
                        Addr::Mem(s) => Ok([<$package Client>] {
                            backend: [<$package ClientBackend>]::Mem(s),
                        }),
                    }
                }

                #[cfg(feature = "grpc")]
                #[tracing::instrument(skip(self))]
                pub async fn check(&self) -> StatusRow {
                    match &self.backend {
                        [<$package ClientBackend>]::Grpc { health, .. } => {
                            status::check(health.clone(), SERVICE_NAME, NAME).await
                        }
                        _ => {
                            todo!()
                        }
                    }
                }

                #[cfg(feature = "grpc")]
                #[tracing::instrument(skip(self))]
                pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
                    match &self.backend {
                        [<$package ClientBackend>]::Grpc { health, .. } => {
                            status::watch(health.clone(), SERVICE_NAME, NAME).await
                        }
                        _ => {
                            todo!()
                        }
                    }
                }
            }
        }
    };
}
