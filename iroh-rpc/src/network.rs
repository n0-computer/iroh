use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::core::PeerId;
use libp2p::{identity, identity::ed25519};
use std::error::Error;

pub fn generate_keys(secret_key_seed: Option<u8>) -> identity::Keypair {
    match secret_key_seed {
        Some(seed) => {
            let mut bytes = [0u8; 32];
            bytes[0] = seed;
            let secret_key = ed25519::SecretKey::from_bytes(&mut bytes).unwrap(); // will only ever error if the byte length is incorrect
            identity::Keypair::Ed25519(secret_key.into())
        }
        None => identity::Keypair::generate_ed25519(),
    }
}

/// Creates the network components:
///     1) A client to communicate outbound requests to the network
///     2) A Stream for inbound requests from the network
///     3) A Server that listens for and coordinates inbound and outbound requests
pub async fn new(_: PeerId) -> Result<(Client, impl Stream<Item = Event>, Server), Box<dyn Error>> {
    let (_, event_receiver) = mpsc::channel(0);
    Ok((Client {}, event_receiver, Server {}))
}

/// Events that get routed from the network to the Client, indicating that the client needs to take
/// some action to fulfill a request from the network
pub struct Event;

/// Server listens for inbound NetworkBehavior requests from over the network, and outbound Commands that come in from the client requesting something off the network
pub struct Server;

/// Client allows the user to make outbound requests from the network
pub struct Client;
