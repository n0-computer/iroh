#[macro_export]
macro_rules! impl_client {
    ($label:ident) => {
        paste::paste! {
            /// Name that the health service registers the client,
            /// as this is derived from the protobuf definition.
            #[cfg(feature = "grpc")]
            pub(crate) const SERVICE_NAME: &str = stringify!([<$label:lower>].[<$label>]);

            /// The display name that we expect to see in the StatusTable.
            #[cfg(feature = "grpc")]
            pub(crate) const NAME: &str = stringify!([<$label:lower>]);

            #[derive(Debug, Clone)]
            pub struct [<$label Client>] {
                backend: [<$label ClientBackend>],
            }

            impl [<$label Client>] {
                pub async fn new(addr: [<$label ClientAddr>]) -> Result<Self> {
                    tracing::info!("connecting to {}", addr);
                    match addr {
                        #[cfg(feature = "grpc")]
                        Addr::GrpcHttp2(addr) => {
                            let conn = Endpoint::new(format!("http://{}", addr))?
                                .keep_alive_while_idle(true)
                                .connect_lazy();

                            let client = [<Grpc $label Client>]::new(conn.clone());
                            let health = HealthClient::new(conn);

                            Ok([<$label Client>] {
                                backend: [<$label ClientBackend>]::Grpc { client, health },
                            })
                        }
                        #[cfg(feature = "grpc")]
                        Addr::GrpcHttp2Lookup(addr) => {
                            let conn = Endpoint::new(format!("http://{}", addr))?
                                .keep_alive_while_idle(true)
                                .connect_lazy();

                            let client = [<Grpc $label Client>]::new(conn.clone());
                            let health = HealthClient::new(conn);

                            Ok([<$label Client>] {
                                backend: [<$label ClientBackend>]::Grpc { client, health },
                            })
                        }
                        #[cfg(feature = "mem")]
                        Addr::Mem(s) => Ok([<$label Client>] {
                            backend: [<$label ClientBackend>]::Mem(s),
                        }),
                    }
                }

                #[cfg(feature = "grpc")]
                #[tracing::instrument(skip(self))]
                pub async fn check(&self) -> StatusRow {
                    match &self.backend {
                        [<$label ClientBackend>]::Grpc { health, .. } => {
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
                        [<$label ClientBackend>]::Grpc { health, .. } => {
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
