use reqwest::Url;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info_span, Instrument};

use crate::{
    derp::{http::ClientBuilder, DerpMap, MeshKey, PacketForwarderHandler},
    key::SecretKey,
};

use super::{client::MeshClientEvent, Client};

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

    pub(crate) fn mesh(
        &mut self,
    ) -> anyhow::Result<Vec<tokio::sync::mpsc::Receiver<MeshClientEvent>>> {
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
            let (client, client_receiver) = ClientBuilder::new()
                .mesh_key(Some(self.mesh_key))
                .server_url(addr)
                .build(self.server_key.clone())
                .expect("will only fail if no `server_url` is present");

            let packet_forwarder_handler = self.packet_fwd.clone();
            let (sender, recv) = tokio::sync::mpsc::channel(32);
            self.tasks.spawn(
                async move {
                    if let Err(e) = client
                        .run_mesh_client(packet_forwarder_handler, Some(sender), client_receiver)
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
    use std::time::Duration;

    use crate::derp::{http::ServerBuilder, ReceivedMessage};
    use anyhow::Result;

    use super::*;

    #[tokio::test]
    async fn test_mesh_network() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        for i in 0..10 {
            println!("TEST_MESH_NETWORK: round {i}");
            test_mesh_network_once().await?;
        }
        Ok(())
    }

    async fn test_mesh_network_once() -> Result<()> {
        let mesh_key: MeshKey = [1; 32];
        let a_key = SecretKey::generate();
        println!("derp server a: {:?}", a_key.public());
        let mut derp_server_a = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(a_key))
            .mesh_key(Some(mesh_key))
            .spawn()
            .await?;

        let b_key = SecretKey::generate();
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

        let mut server_a_meshed = derp_server_a
            .re_mesh(MeshAddrs::Addrs(vec![b_url.clone()]))
            .await?;
        let mut server_b_meshed = derp_server_b
            .re_mesh(MeshAddrs::Addrs(vec![a_url.clone()]))
            .await?;

        let server_a_chans = &mut server_a_meshed;
        tokio::time::timeout(Duration::from_secs(5), async move {
            for chan in server_a_chans {
                let msg = chan.recv().await.unwrap();
                assert!(matches!(msg, MeshClientEvent::Meshed));
            }
        })
        .await?;
        let server_b_chans = &mut server_b_meshed;
        tokio::time::timeout(Duration::from_secs(5), async move {
            for chan in server_b_chans {
                let msg = chan.recv().await.unwrap();
                assert!(matches!(msg, MeshClientEvent::Meshed));
            }
        })
        .await?;

        let alice_key = SecretKey::generate();
        println!("client alice: {:?}", alice_key.public());
        let (alice, mut alice_receiver) = ClientBuilder::new()
            .server_url(a_url)
            .build(alice_key.clone())?;
        let _ = alice.connect().await?;

        let bob_key = SecretKey::generate();
        println!("client bob: {:?}", bob_key.public());
        let (bob, mut bob_receiver) = ClientBuilder::new()
            .server_url(b_url)
            .build(bob_key.clone())?;
        let _ = bob.connect().await?;

        // wait for the mesh clients to be present in the servers
        let server_a_chans = &mut server_a_meshed;
        let bob_key_public = bob_key.public();
        tokio::time::timeout(Duration::from_secs(5), async move {
            for chan in server_a_chans {
                let msg = chan.recv().await.unwrap();
                if let MeshClientEvent::PeerPresent { peer } = msg {
                    assert_eq!(peer, bob_key_public);
                } else {
                    panic!("unexpected event: {:?}", msg);
                }
            }
        })
        .await?;

        let server_b_chans = &mut server_b_meshed;
        let alice_key_public = alice_key.public();
        tokio::time::timeout(Duration::from_secs(5), async move {
            for chan in server_b_chans {
                let msg = chan.recv().await.unwrap();
                if let MeshClientEvent::PeerPresent { peer } = msg {
                    assert_eq!(peer, alice_key_public);
                } else {
                    panic!("unexpected event: {:?}", msg);
                }
            }
        })
        .await?;

        let msg = "howdy, bob!";
        println!("send message from alice to bob");
        alice.send(bob_key.public(), msg.into()).await?;

        // ensure we get the message, but allow other chatter between the
        // client and the server
        let alice_pub_key = alice_key.public();
        tokio::time::timeout(Duration::from_secs(5), async move {
            loop {
                let (recv, _) = bob_receiver.recv().await.unwrap()?;
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
        tokio::time::timeout(Duration::from_secs(5), async move {
            loop {
                let (recv, _) = alice_receiver.recv().await.unwrap()?;
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
