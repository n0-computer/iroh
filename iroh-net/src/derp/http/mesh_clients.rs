use reqwest::Url;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info_span, Instrument};

use crate::{
    derp::{http::ClientBuilder, DerpMap, MeshKey, PacketForwarderHandler},
    tls::Keypair,
};

use super::Client;

/// Spawns, connects, and manages special [`crate::derp::http::Client`].
///
/// These clients handled incoming network update notifications from remote
/// [`super::Server`]s. These servers are used as [`crate::derp::PacketForwarder`]s for
/// peers to which we are not directly connected.
/// A [`crate::derp::MeshKey`] is used to ensure the remote server belongs to the same mesh network.
#[derive(Debug)]
pub(crate) struct MeshClients {
    tasks: JoinSet<()>,
    mesh_key: MeshKey,
    server_key: Keypair,
    mesh_addrs: MeshAddrs,
    packet_fwd: PacketForwarderHandler<Client>,
    cancel: CancellationToken,
}

impl MeshClients {
    pub(crate) fn new(
        mesh_key: MeshKey,
        server_key: Keypair,
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

    pub(crate) async fn mesh(&mut self) -> anyhow::Result<Vec<tokio::sync::oneshot::Receiver<()>>> {
        let addrs = match &self.mesh_addrs {
            MeshAddrs::Addrs(urls) => urls.to_owned(),
            MeshAddrs::DerpMap(derp_map) => {
                let mut urls = Vec::new();
                for region in derp_map.regions() {
                    for node in region.nodes.iter() {
                        // note: `node.host_name` is expected to include the scheme
                        let mut url = node.url.clone();
                        url.set_path("/derp");
                        urls.push(url);
                    }
                }
                urls
            }
        };
        let mut meshed_once_recvs = Vec::new();
        for addr in addrs {
            let client = ClientBuilder::new()
                .mesh_key(Some(self.mesh_key))
                .server_url(addr)
                .build(self.server_key.clone())
                .expect("will only fail if no `server_url` is present");

            let packet_forwarder_handler = self.packet_fwd.clone();
            let (sender, recv) = tokio::sync::oneshot::channel();
            self.tasks.spawn(
                async move {
                    if let Err(e) = client
                        .run_mesh_client(packet_forwarder_handler, Some(sender))
                        .await
                    {
                        tracing::warn!("{e:?}");
                    }
                }
                .instrument(info_span!("mesh-client")),
            );
            meshed_once_recvs.push(recv);
        }
        Ok(meshed_once_recvs)
    }

    pub(crate) async fn shutdown(mut self) {
        self.cancel.cancel();
        self.tasks.shutdown().await
    }
}

/// The different ways to express the mesh network you want to join.
#[derive(Debug, Clone)]
pub enum MeshAddrs {
    /// Supply a [`DerpMap`] of all the derp servers you want to mesh with.
    DerpMap(DerpMap),
    /// Supply a list of [`Url`]s of all the derp server you want to mesh with.
    Addrs(Vec<Url>),
}

#[cfg(test)]
mod tests {
    use crate::derp::{http::ServerBuilder, ReceivedMessage};
    use anyhow::Result;
    use tracing_subscriber::{prelude::*, EnvFilter};

    use super::*;

    #[tokio::test]
    async fn test_mesh_network() -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();

        // TODO(ramfox): figure out why this fails on later rounds
        // for i in 0..10 {
        // println!("TEST_MESH_NETWORK: round {i}");
        test_mesh_network_once().await?;
        // }
        Ok(())
    }

    async fn test_mesh_network_once() -> Result<()> {
        let mesh_key: MeshKey = [1; 32];
        let a_key = Keypair::generate();
        println!("derp server a: {:?}", a_key.public());
        let mut derp_server_a = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(a_key))
            .mesh_key(Some(mesh_key))
            .spawn()
            .await?;

        let b_key = Keypair::generate();
        println!("derp server b: {:?}", b_key.public());
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

        let server_a_meshed = derp_server_a
            .re_mesh(MeshAddrs::Addrs(vec![b_url.clone()]))
            .await?;
        let server_b_meshed = derp_server_b
            .re_mesh(MeshAddrs::Addrs(vec![a_url.clone()]))
            .await?;

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            futures::future::try_join_all(server_a_meshed),
        )
        .await??;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            futures::future::try_join_all(server_b_meshed),
        )
        .await??;

        let alice_key = Keypair::generate();
        println!("client alice: {:?}", alice_key.public());
        let alice = ClientBuilder::new()
            .server_url(a_url)
            .build(alice_key.clone())?;
        let _ = alice.connect().await?;

        let bob_key = Keypair::generate();
        println!("client bob: {:?}", bob_key.public());
        let bob = ClientBuilder::new()
            .server_url(b_url)
            .build(bob_key.clone())?;
        let _ = bob.connect().await?;

        let msg = "howdy, bob!";
        println!("send message from alice to bob");
        alice.send(bob_key.public(), msg.into()).await?;

        // ensure we get the message, but allow other chatter between the
        // client and the server
        let b = bob.clone();
        let alice_pub_key = alice_key.public();
        tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            loop {
                let (recv, _) = b.recv_detail().await?;
                if let ReceivedMessage::ReceivedPacket { source, data } = recv {
                    assert_eq!(alice_pub_key, source);
                    assert_eq!(msg, data);
                    println!("bob received packet from alice");
                    return Ok::<(), anyhow::Error>(());
                } else {
                    eprintln!("bob received unexpected message {recv:?}");
                }
            }
        })
        .await??;

        // send alice a message from bob
        let msg = "why hello, alice!";
        println!("send message from bob to alice");
        bob.send(alice_key.public(), msg.into()).await?;

        // ensure alice gets the message, but allow other chatter between the
        // client and the server
        tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            loop {
                let (recv, _) = alice.recv_detail().await?;
                if let ReceivedMessage::ReceivedPacket { source, data } = recv {
                    assert_eq!(bob_key.public(), source);
                    assert_eq!(msg, data);
                    println!("alice received packet from alice");
                    return Ok::<(), anyhow::Error>(());
                } else {
                    eprintln!("alice received unexpected message {recv:?}");
                }
            }
        })
        .await??;

        // shutdown the servers
        derp_server_a.shutdown().await;
        derp_server_b.shutdown().await;
        Ok(())
    }
}
