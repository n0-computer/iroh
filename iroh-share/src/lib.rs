use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub topic: String,
}

pub mod sender {
    use std::sync::atomic::AtomicU64;

    use super::Ticket;
    use anyhow::{Context, Result};
    use async_channel::{bounded, Receiver};
    use futures::channel::oneshot::{channel as oneshot, Receiver as OneShotReceiver};
    use iroh_p2p::{config, GossipsubEvent, Keychain, MemoryStorage, NetworkEvent, Node};
    use iroh_rpc_client::Client;
    use libp2p::gossipsub::{Sha256Topic, TopicHash};
    use libp2p::PeerId;
    use prometheus_client::registry::Registry;
    use tokio::task::JoinHandle;
    use tracing::error;

    /// The sending part of the data transfer.
    pub struct Sender {
        p2p_task: JoinHandle<()>,
        rpc: Client,
        next_id: AtomicU64,
        gossip_events: Receiver<GossipsubEvent>,
    }

    impl Drop for Sender {
        fn drop(&mut self) {
            self.p2p_task.abort();
        }
    }

    impl Sender {
        pub async fn new(port: u16, rpc_port: u16) -> Result<Self> {
            let mut config = config::Libp2pConfig::default();
            config.listening_multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap();
            config.mdns = true;
            config.rpc_addr = format!("0.0.0.0:{rpc_port}").parse().unwrap();
            config.rpc_client.p2p_addr = config.rpc_addr;

            let rpc = Client::new(&config.rpc_client).await?;

            let mut prom_registry = Registry::default();
            let kc = Keychain::<MemoryStorage>::new();
            let mut p2p = Node::new(config, kc, &mut prom_registry).await?;
            let events = p2p.network_events();
            let (s, r) = bounded(1024);

            tokio::task::spawn(async move {
                while let Ok(event) = events.recv().await {
                    match event {
                        NetworkEvent::Gossipsub(e) => {
                            // drop events if they are not processed
                            s.try_send(e).ok();
                        }
                        _ => {}
                    }
                }
            });

            let p2p_task = tokio::task::spawn(async move {
                if let Err(err) = p2p.run().await {
                    error!("{:?}", err);
                }
            });

            Ok(Sender {
                p2p_task,
                rpc,
                next_id: 0.into(),
                gossip_events: r,
            })
        }

        pub async fn transfer_from_data(
            &self,
            name: impl Into<String>,
            data: &[u8],
        ) -> Result<Transfer<'_>> {
            let id = self.next_id();
            let t = Sha256Topic::new(format!("iroh-share-{}", id));

            let (s, r) = oneshot();

            let gossip_events = self.gossip_events.clone();
            let topic_hash = t.hash();
            let th = topic_hash.clone();
            tokio::task::spawn(async move {
                while let Ok(event) = gossip_events.recv().await {
                    match event {
                        GossipsubEvent::Subscribed { peer_id, topic } => {
                            if topic == th {
                                s.send(peer_id).ok();
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            });

            Ok(Transfer {
                id,
                topic: topic_hash,
                sender: self,
                name: name.into(),
                data: data.to_vec(),
                peer: r,
            })
        }

        fn next_id(&self) -> u64 {
            self.next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        }
    }

    pub struct Transfer<'a> {
        id: u64,
        name: String,
        data: Vec<u8>,
        sender: &'a Sender,
        peer: OneShotReceiver<PeerId>,
        topic: TopicHash,
    }

    impl Transfer<'_> {
        pub async fn ticket(self) -> Result<Ticket> {
            let (peer_id, addrs) = self
                .sender
                .rpc
                .p2p
                .get_listening_addrs()
                .await
                .context("getting p2p info")?;

            let root = self.name.as_bytes().to_vec(); // TODO: actual root hash.
            let peer = self.peer;
            let topic = self.topic;
            let topic_string = topic.to_string();
            let rpc = self.sender.rpc.clone();

            tokio::task::spawn(async move {
                match peer.await {
                    Ok(peer_id) => {
                        println!("S: {:?} subscribed, publishing root", peer_id);
                        rpc.p2p.gossipsub_publish(topic, root.into()).await.unwrap();
                    }
                    Err(e) => {
                        error!("failed to receive root, transfer aborted: {:?}", e);
                    }
                }
            });

            Ok(Ticket {
                peer_id,
                addrs,
                topic: topic_string,
            })
        }
    }
}

pub mod receiver {
    use anyhow::Result;
    use async_channel::{bounded, Receiver as ChannelReceiver};
    use iroh_p2p::{config, Keychain, MemoryStorage, NetworkEvent, Node};
    use iroh_rpc_client::Client;
    use libp2p::gossipsub::{GossipsubMessage, MessageId, TopicHash};
    use libp2p::PeerId;
    use prometheus_client::registry::Registry;
    use tokio::task::JoinHandle;
    use tracing::{error, warn};

    use super::Ticket;

    pub struct Receiver {
        p2p_task: JoinHandle<()>,
        rpc: Client,
        gossip_messages: ChannelReceiver<(MessageId, PeerId, GossipsubMessage)>,
    }

    impl Drop for Receiver {
        fn drop(&mut self) {
            self.p2p_task.abort();
        }
    }

    impl Receiver {
        pub async fn new(port: u16, rpc_port: u16) -> Result<Self> {
            let mut config = config::Libp2pConfig::default();
            config.listening_multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap();
            config.mdns = true;
            config.rpc_addr = format!("0.0.0.0:{rpc_port}").parse().unwrap();
            config.rpc_client.p2p_addr = config.rpc_addr;

            let rpc = Client::new(&config.rpc_client).await?;

            let mut prom_registry = Registry::default();
            let kc = Keychain::<MemoryStorage>::new();
            let mut p2p = Node::new(config, kc, &mut prom_registry).await?;
            let events = p2p.network_events();

            let p2p_task = tokio::task::spawn(async move {
                if let Err(err) = p2p.run().await {
                    error!("{:?}", err);
                }
            });

            let (s, r) = bounded(1024);

            tokio::task::spawn(async move {
                while let Ok(event) = events.recv().await {
                    match event {
                        NetworkEvent::Gossipsub(iroh_p2p::GossipsubEvent::Message {
                            from,
                            id,
                            message,
                        }) => {
                            s.try_send((id, from, message)).ok();
                        }
                        _ => {}
                    }
                }
            });

            Ok(Receiver {
                p2p_task,
                rpc,
                gossip_messages: r,
            })
        }

        pub async fn transfer_from_ticket(&self, ticket: Ticket) -> Result<Transfer<'_>> {
            // Connect to the sender
            self.rpc
                .p2p
                .connect(ticket.peer_id, ticket.addrs.clone())
                .await?;
            self.rpc
                .p2p
                .gossipsub_add_explicit_peer(ticket.peer_id)
                .await?;
            let topic = TopicHash::from_raw(&ticket.topic);
            self.rpc.p2p.gossipsub_subscribe(topic.clone()).await?;
            let gossip_messages = self.gossip_messages.clone();

            let expected_sender = ticket.peer_id;
            tokio::task::spawn(async move {
                while let Ok((_id, from, message)) = gossip_messages.recv().await {
                    if from == expected_sender {
                        println!("R: got message {:?}, from: {:?}", message.data, from);
                    } else {
                        warn!("got message from unexpected sender: {:?}", from);
                    }
                }
            });

            Ok(Transfer {
                receiver: self,
                ticket,
                topic,
            })
        }
    }

    pub struct Transfer<'a> {
        ticket: Ticket,
        receiver: &'a Receiver,
        topic: TopicHash,
    }

    impl Transfer<'_> {
        pub async fn recv(&self) -> Result<Data> {
            todo!()
        }
    }

    pub struct Data {
        name: String,
        bytes: Vec<u8>,
    }

    impl Data {
        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn bytes(&self) -> &[u8] {
            &self.bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use anyhow::{Context, Result};

    use receiver as r;
    use sender as s;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_transfer() -> Result<()> {
        let sender = s::Sender::new(9990, 5550).await.context("s:new")?;
        let bytes = vec![1u8; 5 * 1024];
        let sender_transfer = sender
            .transfer_from_data("foo.jpg", &bytes)
            .await
            .context("s: transfer")?;
        let ticket = sender_transfer.ticket().await.context("s: ticket")?;

        // the ticket is serialized, shared with the receiver and deserialized there

        let receiver = r::Receiver::new(9991, 5551).await.context("r: new")?;

        // tries to discover the sender, and receive the root
        let receiver_transfer = receiver
            .transfer_from_ticket(ticket)
            .await
            .context("r: transfer")?;

        tokio::time::sleep(Duration::from_secs(1)).await;

        let data = receiver_transfer.recv().await.context("r: recv")?;
        assert_eq!(data.name(), "foo.jpg");
        assert_eq!(data.bytes(), &bytes);

        Ok(())
    }
}
