use iroh_rpc::{
    new_mem_swarm, new_swarm, Behaviour, Client, RpcBuilder, RpcError, Server, DEFAULT_RPC_CAPACITY,
};
use libp2p::identity::Keypair;

pub fn gateway_rpc(keypair: Keypair) -> Result<(Client, Server<()>), RpcError> {
    RpcBuilder::new()
        .with_swarm(new_mem_swarm(keypair))
        .with_state(())
        .with_capacity(DEFAULT_RPC_CAPACITY)
        .build()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
