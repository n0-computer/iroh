use anyhow::{anyhow, ensure, Result};
use async_channel::{bounded, Receiver as ChannelReceiver};
use cid::Cid;
use futures::StreamExt;
use iroh_p2p::NetworkEvent;
use iroh_resolver::resolver::Path;
use libp2p::gossipsub::{GossipsubMessage, MessageId, TopicHash};
use libp2p::PeerId;
use tokio::io::AsyncReadExt;
use tracing::warn;

use crate::p2p_node::{P2pNode, Ticket};

pub struct Receiver {
    p2p: P2pNode,
    gossip_messages: ChannelReceiver<(MessageId, PeerId, GossipsubMessage)>,
}

impl Receiver {
    pub async fn new(
        port: u16,
        rpc_p2p_port: u16,
        rpc_store_port: u16,
        db_path: &std::path::Path,
    ) -> Result<Self> {
        let (p2p, events) = P2pNode::new(port, rpc_p2p_port, rpc_store_port, db_path).await?;
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
            p2p,
            gossip_messages: r,
        })
    }

    pub async fn transfer_from_ticket(&self, ticket: Ticket) -> Result<Transfer<'_>> {
        // Connect to the sender
        self.p2p
            .rpc()
            .p2p
            .connect(ticket.peer_id, ticket.addrs.clone())
            .await?;
        self.p2p
            .rpc()
            .p2p
            .gossipsub_add_explicit_peer(ticket.peer_id)
            .await?;
        let topic = TopicHash::from_raw(&ticket.topic);
        self.p2p
            .rpc()
            .p2p
            .gossipsub_subscribe(topic.clone())
            .await?;
        let gossip_messages = self.gossip_messages.clone();
        let expected_sender = ticket.peer_id;
        let resolver = self.p2p.resolver().clone();
        let (s, r) = bounded(1024);

        // add provider
        resolver
            .loader()
            .providers()
            .lock()
            .await
            .insert(expected_sender);

        tokio::task::spawn(async move {
            while let Ok((_id, from, message)) = gossip_messages.recv().await {
                if from == expected_sender {
                    match Cid::try_from(message.data) {
                        Ok(root) => {
                            let results = resolver
                                .resolve_recursive(iroh_resolver::resolver::Path::from_cid(root));
                            tokio::pin!(results);
                            while let Some(res) = results.next().await {
                                s.send(res).await.unwrap();
                            }
                            s.close();
                        }
                        Err(err) => {
                            warn!("got unexpected message from {}: {:?}", from, err);
                        }
                    }
                } else {
                    warn!("got message from unexpected sender: {:?}", from);
                }
            }
        });

        Ok(Transfer {
            receiver: self,
            ticket,
            topic,
            data_receiver: r,
        })
    }
}

pub struct Transfer<'a> {
    ticket: Ticket,
    receiver: &'a Receiver,
    topic: TopicHash,
    data_receiver: ChannelReceiver<Result<iroh_resolver::resolver::Out>>,
}

impl Transfer<'_> {
    pub async fn recv(&self) -> Result<Data> {
        // TODO: load not just the root
        let mut res = Vec::new();
        while let Ok(part) = self.data_receiver.recv().await {
            res.push(part?);
        }

        // TODO: notification
        // we expect unixfs
        // root is the first value
        let files: Vec<_> = res[0]
            .unixfs_read_dir()
            .ok_or_else(|| anyhow!("unexpected data format"))?
            .collect::<Result<_>>()?;
        ensure!(files.len() == 1, "expected only one file to be sent");
        let file = &files[0];
        let name = file.name.map(Into::into).unwrap_or_default();

        // grab the actual file
        let file_res = self
            .receiver
            .p2p
            .resolver()
            .resolve(Path::from_cid(file.cid))
            .await?;

        let mut reader = file_res.pretty(self.receiver.p2p.rpc().clone(), Default::default());
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await?;

        Ok(Data { name, bytes })
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
