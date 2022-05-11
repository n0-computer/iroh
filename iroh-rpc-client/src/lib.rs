use cid::Cid;
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};

use iroh_rpc::{
    new_mem_swarm, new_swarm, Behaviour, Client, RpcBuilder, RpcError, Server, State,
    DEFAULT_RPC_CAPACITY,
};

pub fn rpc(keypair: Keypair) -> Result<(RpcClient, Server<()>), RpcError> {
    let (client, server) = RpcBuilder::new()
        .with_swarm(new_mem_swarm(keypair))
        .with_state(State::new(()))
        .with_capacity(DEFAULT_RPC_CAPACITY)
        .build()?;
    Ok((RpcClient(client), server))
}

pub struct RpcClient(Client);

impl RpcClient {
    pub async fn dial_all(&mut self) -> Result<(), RpcError> {
        self.0.dial_all().await
    }

    pub async fn listen(&mut self, addr: Multiaddr) -> Result<Multiaddr, RpcError> {
        self.0.listen(addr).await
    }

    pub async fn shutdown(self) {
        self.0.shutdown().await
    }

    pub async fn with_connection_to<I: Into<String>>(
        mut self,
        namespace: I,
        address: Multiaddr,
        peer_id: PeerId,
    ) -> RpcClient {
        self.0 = self.0.with_connection_to(namespace, address, peer_id);
        self
    }

    // TODO: what should this return?
    pub async fn fetch(cid: Cid) {
        self.0.streaming_call()
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
