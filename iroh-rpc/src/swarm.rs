use crate::behaviour::Behaviour;

use libp2p::core::{
    muxing, transport,
    transport::{MemoryTransport, Transport},
    upgrade,
};
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmBuilder;
use libp2p::PeerId;
use libp2p::Swarm;
use libp2p::{mplex, yamux};
use std::error::Error;

/// Build a swarm with an in memory transport.
// TODO: eventually generalize, pass in config etc
pub fn new_mem_swarm(id_keys: Keypair) -> Swarm<Behaviour> {
    let peer_id = id_keys.public().to_peer_id();
    SwarmBuilder::new(mem_transport(id_keys), Behaviour::new(), peer_id)
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build()
}

/// Build a swarm with a TCP transport
// TODO: eventually generalize, pass in config etc
pub async fn new_swarm(id_keys: Keypair) -> Result<Swarm<Behaviour>, Box<dyn Error>> {
    let peer_id = id_keys.public().to_peer_id();
    Ok(SwarmBuilder::new(
        libp2p::development_transport(id_keys).await?,
        Behaviour::new(),
        peer_id,
    )
    .executor(Box::new(|fut| {
        tokio::spawn(fut);
    }))
    .build())
}

/// Build a mem transport
pub fn mem_transport(keypair: Keypair) -> transport::Boxed<(PeerId, muxing::StreamMuxerBox)> {
    MemoryTransport::default()
        .upgrade(upgrade::Version::V1)
        .authenticate(libp2p::plaintext::PlainText2Config {
            local_public_key: keypair.public(),
        })
        .multiplex(upgrade::SelectUpgrade::new(
            yamux::YamuxConfig::default(),
            mplex::MplexConfig::default(),
        ))
        .timeout(std::time::Duration::from_secs(20))
        .boxed()
}
