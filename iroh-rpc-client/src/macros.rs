#[macro_export]
macro_rules! impl_client {
    ($label:ident) => {
        paste::paste! {
            #[derive(Debug, Clone)]
            pub struct [<$label Client>] {
                backend: std::sync::Arc<tokio::sync::RwLock<[<$label BackendState>]>>,
            }

            #[derive(Debug)]
            enum [<$label BackendState>] {
                Disconnected(std::net::SocketAddr),
                Connected(iroh_rpc_types::[<$label:snake>]::[<$label Client>]),
            }

            impl [<$label Client>] {
                async fn backend(&self) -> anyhow::Result<iroh_rpc_types::[<$label:snake>]::[<$label Client>]> {
                    if let [<$label BackendState>]::Connected(backend) = &*self.backend.read().await {
                        return Ok(backend.clone());
                    }

                    let backend = &mut *self.backend.write().await;
                    match backend {
                        [<$label BackendState>]::Disconnected(server_addr) => {
                            let transport = tarpc::serde_transport::tcp::connect(
                                *server_addr,
                                tarpc::tokio_serde::formats::Bincode::default,
                            ).await?;

                            let client = iroh_rpc_types::[<$label:snake>]::[<$label Client>]::new(
                                tarpc::client::Config::default(),
                                transport,
                            ).spawn();
                            *backend = [<$label BackendState>]::Connected(client.clone());
                            Ok(client)
                        }
                        [<$label BackendState>]::Connected(backend) => {
                            // connected in the meantime
                            Ok(backend.clone())
                        }
                    }
                }
            }

            pub type [<$label ClientAddr>] = iroh_rpc_types::Addr<
                    tarpc::Response<iroh_rpc_types::[<$label:snake>]::[<$label Response>]>,
                    tarpc::ClientMessage<iroh_rpc_types::[<$label:snake>]::[<$label Request>]>,
           >;


            impl [<$label Client>] {
                pub async fn new(addr: [<$label ClientAddr>]) -> Result<Self> {
                    // tracing::info!("connecting to {}", addr);
                    match addr {
                        iroh_rpc_types::Addr::Tcp(server_addr) => {

                            Ok([<$label Client>] {
                                backend: std::sync::Arc::new(tokio::sync::RwLock::new([<$label BackendState>]::Disconnected(server_addr))),
                            })
                        }
                        #[cfg(unix)]
                        iroh_rpc_types::Addr::Uds(_path) => {
                            todo!()
                        }
                        iroh_rpc_types::Addr::Mem(client_transport) => {
                            let client = iroh_rpc_types::[<$label:snake>]::[<$label Client>]::new(
                                tarpc::client::Config::default(),
                                client_transport,
                            ).spawn();

                            // No lazy mode for channels
                            Ok([<$label Client>] {
                                backend: std::sync::Arc::new(tokio::sync::RwLock::new([<$label BackendState>]::Connected(client))),
                            })
                        },
                    }
                }
            }
        }
    };
}
