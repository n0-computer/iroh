use std::sync::{Arc, Mutex};

use iroh_rpc::{Client as RpcClient, RpcError};
use libp2p::{Multiaddr, PeerId};

mod network;

use crate::network::P2pClient;

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
        &mut self,
        namespace: I,
        addr: Multiaddr,
        peer_id: PeerId,
    ) -> Result<(), RpcError> {
        self.client
            .lock()
            .unwrap()
            .dial(namespace, addr, peer_id)
            .await
    }

    pub async fn listen(&mut self, addr: Multiaddr) -> Result<Multiaddr, RpcError> {
        self.client.lock().unwrap().listen(addr).await
    }

    pub async fn send_address_book<I: Into<String>>(
        &mut self,
        namespace: I,
    ) -> Result<(), RpcError> {
        self.client
            .lock()
            .unwrap()
            .send_address_book(namespace)
            .await
    }
}
