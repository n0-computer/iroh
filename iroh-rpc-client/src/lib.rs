mod network;

use std::sync::{Arc, Mutex};

use libp2p::{Multiaddr, PeerId};

use iroh_rpc::{Client as RpcClient, RpcError};

use crate::network::P2pClient;

pub struct Client {
    // TODO: this is wrong
    client: Arc<Mutex<RpcClient>>,
    pub network: P2pClient,
}

impl Client {
    pub fn new(client: Arc<Mutex<RpcClient>>) -> Self {
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

    pub async fn shutdown(self) {
        self.client.lock().unwrap().shutdown().await
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
