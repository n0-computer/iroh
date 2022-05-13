use libp2p::identity::Keypair;
use libp2p::Swarm;

use iroh_rpc::{new_mem_swarm, new_tcp_swarm, Behaviour, RpcBuilder, RpcError, Server, State};
use iroh_rpc_client::Client;

pub async fn tcp_rpc(keys: Keypair) -> Result<(Client, Server<()>), RpcError> {
    let swarm = new_tcp_swarm(keys).await?;
    new_gateway_rpc(swarm)
}

pub async fn mem_rpc(keys: Keypair) -> Result<(Client, Server<()>), RpcError> {
    new_gateway_rpc(new_mem_swarm(keys))
}

fn new_gateway_rpc(swarm: Swarm<Behaviour>) -> Result<(Client, Server<()>), RpcError> {
    let (client, server) = RpcBuilder::new("gateway")
        .with_swarm(swarm)
        .with_state(State::new(()))
        .build()?;
    Ok((Client::new(client), server))
}
