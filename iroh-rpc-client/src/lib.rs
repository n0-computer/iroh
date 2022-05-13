use std::sync::Arc;

use iroh_rpc::{new_mem_swarm, Client as RpcClient, RpcBuilder, RpcError, State};
use libp2p::{identity::Keypair, Multiaddr, PeerId};

mod network;

use crate::network::P2pClient;

#[derive(Debug, Clone)]
pub struct Client {
    client: Arc<RpcClient>,
    pub network: P2pClient,
}

impl Client {
    pub fn new(client: RpcClient) -> Self {
        let client = Arc::new(client);
        Client {
            client: client.clone(),
            network: P2pClient::new(client),
        }
    }

    /// Dummy client for testing purposes
    pub fn dummy() -> Self {
        let keypair = Keypair::generate_ed25519();
        let (client, _server) = RpcBuilder::new("dummy")
            .with_swarm(new_mem_swarm(keypair))
            .with_state(State::new(()))
            .build()
            .unwrap();

        Self::new(client)
    }

    pub async fn dial<I: Into<String>>(
        &self,
        namespace: I,
        addr: Multiaddr,
        peer_id: PeerId,
    ) -> Result<(), RpcError> {
        self.client.dial(namespace, addr, peer_id).await
    }

    pub async fn listen(&self, addr: &Multiaddr) -> Result<Multiaddr, RpcError> {
        self.client.listen(addr).await
    }

    pub async fn send_address_book<I: Into<String>>(&self, namespace: I) -> Result<(), RpcError> {
        self.client.send_address_book(namespace).await
    }
}
