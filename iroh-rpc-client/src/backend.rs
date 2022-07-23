#[cfg(feature = "grpc")]
pub use grpc::*;

#[cfg(feature = "grpc")]
mod grpc {
    use anyhow::Result;
    use std::{net::SocketAddr, ops::Deref};
    use tonic::transport::{Channel, Endpoint};
    use tonic_health::proto::health_client::HealthClient;

    pub type StoreBackend = Backend<iroh_rpc_types::store::store_client::StoreClient<Channel>>;
    pub type GatewayBackend =
        Backend<iroh_rpc_types::gateway::gateway_client::GatewayClient<Channel>>;
    pub type P2pBackend = Backend<iroh_rpc_types::p2p::p2p_client::P2pClient<Channel>>;

    #[derive(Debug, Clone)]
    pub struct Backend<C: ClientImpl> {
        client: C,
        health: HealthClient<Channel>,
    }

    impl<C: ClientImpl> Backend<C> {
        pub fn new(addr: SocketAddr) -> Result<Self> {
            let conn = Endpoint::new(format!("http://{}", addr))?
                .keep_alive_while_idle(true)
                .connect_lazy();

            let client = C::new(conn.clone());
            let health = HealthClient::new(conn);

            Ok(Self { client, health })
        }

        pub fn client(&self) -> &C {
            &self.client
        }

        pub fn health(&self) -> &HealthClient<Channel> {
            &self.health
        }
    }

    impl<C: ClientImpl> Deref for Backend<C> {
        type Target = C;

        fn deref(&self) -> &Self::Target {
            &self.client
        }
    }

    pub trait ClientImpl {
        fn new(inner: Channel) -> Self;
    }

    impl ClientImpl for iroh_rpc_types::store::store_client::StoreClient<Channel> {
        fn new(inner: Channel) -> Self {
            iroh_rpc_types::store::store_client::StoreClient::new(inner)
        }
    }

    impl ClientImpl for iroh_rpc_types::gateway::gateway_client::GatewayClient<Channel> {
        fn new(inner: Channel) -> Self {
            iroh_rpc_types::gateway::gateway_client::GatewayClient::new(inner)
        }
    }

    impl ClientImpl for iroh_rpc_types::p2p::p2p_client::P2pClient<Channel> {
        fn new(inner: Channel) -> Self {
            iroh_rpc_types::p2p::p2p_client::P2pClient::new(inner)
        }
    }
}
