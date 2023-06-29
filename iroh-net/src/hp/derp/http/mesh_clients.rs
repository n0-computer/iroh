use reqwest::Url;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::hp::{
    derp::{http::ClientBuilder, DerpMap, MeshKey, PacketForwarderHandler},
    key::node::SecretKey,
};

use super::Client;

/// Spawns, connects, and manages special `derp::http::Clients`.
///
/// These clients handled incoming network update notifications from remote
/// `derp::http::Server`s. These servers are used as `PacketForwarder`s for
/// peers to which we are not directly connected.
/// A `mesh_key` is used to ensure the remote server belongs to the same mesh network.
#[derive(Debug)]
pub(crate) struct MeshClients {
    tasks: JoinSet<()>,
    mesh_key: MeshKey,
    server_key: SecretKey,
    mesh_addrs: MeshAddrs,
    packet_fwd: PacketForwarderHandler<Client>,
    cancel: CancellationToken,
}

impl MeshClients {
    pub(crate) fn new(
        mesh_key: MeshKey,
        server_key: SecretKey,
        mesh_addrs: MeshAddrs,
        packet_fwd: PacketForwarderHandler<Client>,
    ) -> Self {
        Self {
            tasks: JoinSet::new(),
            cancel: CancellationToken::new(),
            mesh_key,
            server_key,
            mesh_addrs,
            packet_fwd,
        }
    }

    pub(crate) async fn mesh(&mut self) {
        let addrs = match &self.mesh_addrs {
            MeshAddrs::Addrs(urls) => urls.to_owned(),
            MeshAddrs::DerpMap(derp_map) => {
                let mut urls = Vec::new();
                for (_, region) in derp_map.regions.iter() {
                    for node in region.nodes.iter() {
                        // note: `node.host_name` is expected to include the scheme
                        let url: Url = format!("{}/derp", node.host_name).parse().unwrap();
                        urls.push(url);
                    }
                }
                urls
            }
        };
        for addr in addrs {
            let client = ClientBuilder::new()
                .mesh_key(Some(self.mesh_key))
                .build_with_server_url(self.server_key.clone(), addr);

            let packet_forwarder_handler = self.packet_fwd.clone();
            self.tasks.spawn(async move {
                if let Err(e) = client.run_mesh_client(packet_forwarder_handler).await {
                    tracing::warn!("{e:?}");
                }
            });
        }
    }

    pub(crate) async fn shutdown(mut self) {
        self.cancel.cancel();
        self.tasks.shutdown().await
    }
}

#[derive(Debug, Clone)]
pub enum MeshAddrs {
    DerpMap(DerpMap),
    Addrs(Vec<Url>),
}

#[cfg(test)]
mod tests {
    use crate::hp::derp::{http::ServerBuilder, ReceivedMessage};
    use anyhow::{bail, Result};

    use super::*;

    #[tokio::test]
    async fn test_mesh_network() -> Result<()> {
        let mesh_key: MeshKey = [1; 32];
        let a_key = SecretKey::generate();
        let mut derp_server_a = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(a_key))
            .mesh_key(Some(mesh_key))
            .spawn()
            .await?;

        let b_key = SecretKey::generate();
        let mut derp_server_b = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(b_key))
            .mesh_key(Some(mesh_key))
            .spawn()
            .await?;

        let a_url: Url = format!("http://{}/derp", derp_server_a.addr())
            .parse()
            .unwrap();
        let b_url: Url = format!("http://{}/derp", derp_server_b.addr())
            .parse()
            .unwrap();

        derp_server_a
            .re_mesh(MeshAddrs::Addrs(vec![b_url.clone()]))
            .await?;
        derp_server_b
            .re_mesh(MeshAddrs::Addrs(vec![a_url.clone()]))
            .await?;

        let alice_key = SecretKey::generate();
        let alice = ClientBuilder::new().build_with_server_url(alice_key.clone(), a_url);
        let _ = alice.connect().await?;

        let bob_key = SecretKey::generate();
        let bob = ClientBuilder::new().build_with_server_url(bob_key.clone(), b_url);
        let _ = bob.connect().await?;

        // send bob a message from alice
        let msg = "howdy, bob!";
        alice.send(bob_key.public_key(), msg.into()).await?;

        let (recv, _) = bob.recv_detail().await?;
        if let ReceivedMessage::ReceivedPacket { source, data } = recv {
            assert_eq!(alice_key.public_key(), source);
            assert_eq!(msg, data);
        } else {
            bail!("unexpected ReceivedMessage {recv:?}");
        }

        // send alice a message from bob
        let msg = "why hello, alice!";
        bob.send(alice_key.public_key(), msg.into()).await?;

        let (recv, _) = alice.recv_detail().await?;
        if let ReceivedMessage::ReceivedPacket { source, data } = recv {
            assert_eq!(bob_key.public_key(), source);
            assert_eq!(msg, data);
        } else {
            bail!("unexpected ReceivedMessage {recv:?}");
        }

        // shutdown the servers
        derp_server_a.shutdown().await;
        derp_server_b.shutdown().await;
        Ok(())
    }
}
