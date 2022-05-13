use std::sync::Arc;

use iroh_rpc::{Client as RpcClient, RpcError};
use libp2p::{Multiaddr, PeerId};
use tokio::sync::Mutex;

mod network;

use crate::network::P2pClient;

#[derive(Debug, Clone)]
pub struct Client {
    // TODO: this is wrong
    client: Arc<Mutex<RpcClient>>,
    pub network: P2pClient,
}

impl Client {
    pub fn new(client: RpcClient) -> Self {
        let client = Arc::new(Mutex::new(client));
        Client {
            client: Arc::clone(&client),
            network: P2pClient::new(client),
        }
    }

    pub async fn dial<I: Into<String>>(
        &self,
        namespace: I,
        addr: Multiaddr,
        peer_id: PeerId,
    ) -> Result<(), RpcError> {
        self.client
            .lock()
            .await
            .dial(namespace, addr, peer_id)
            .await
    }

    pub async fn listen(&self, addr: &Multiaddr) -> Result<Multiaddr, RpcError> {
        self.client.lock().await.listen(addr).await
    }

    pub async fn send_address_book<I: Into<String>>(&self, namespace: I) -> Result<(), RpcError> {
        self.client.lock().await.send_address_book(namespace).await
    }
}
