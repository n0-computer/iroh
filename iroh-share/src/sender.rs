use std::path::Path;

use anyhow::{anyhow, Context, Result};
use async_channel::{bounded, Receiver};
use bytes::Bytes;
use futures::channel::oneshot::{channel as oneshot, Receiver as OneShotReceiver};
use futures::StreamExt;
use iroh_p2p::{GossipsubEvent, NetworkEvent};
use iroh_resolver::unixfs_builder::DirectoryBuilder;
use libp2p::gossipsub::Sha256Topic;
use rand::Rng;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::{
    p2p_node::{P2pNode, Ticket},
    ReceiverMessage, SenderMessage,
};

/// The sending part of the data transfer.
pub struct Sender {
    p2p: P2pNode,
    gossip_events: Receiver<GossipsubEvent>,
}

impl Sender {
    pub async fn new(
        port: u16,
        rpc_p2p_port: u16,
        rpc_store_port: u16,
        db_path: &Path,
    ) -> Result<Self> {
        let (p2p, events) = P2pNode::new(port, rpc_p2p_port, rpc_store_port, db_path).await?;
        let (s, r) = bounded(1024);

        tokio::task::spawn(async move {
            while let Ok(event) = events.recv().await {
                if let NetworkEvent::Gossipsub(e) = event {
                    // drop events if they are not processed
                    s.try_send(e).ok();
                }
            }
        });

        Ok(Sender {
            p2p,
            gossip_events: r,
        })
    }

    pub async fn close(self) -> Result<()> {
        self.p2p.close().await?;
        Ok(())
    }

    pub async fn transfer_from_dir_builder(
        &self,
        dir_builder: DirectoryBuilder,
    ) -> Result<Transfer> {
        let id = self.next_id();
        let t = Sha256Topic::new(format!("iroh-share-{}", id));
        let root_dir = dir_builder.build().await?;

        let (done_sender, done_receiver) = oneshot();

        let (root, num_parts) = {
            let parts = root_dir.encode();
            tokio::pin!(parts);
            let mut num_parts = 0;
            let mut root_cid = None;
            while let Some(part) = parts.next().await {
                // TODO: store links in the store
                let (cid, bytes) = part?;
                num_parts += 1;
                root_cid = Some(cid);
                self.p2p.rpc().store.put(cid, bytes, vec![]).await?;
            }
            (root_cid.unwrap(), num_parts)
        };

        let gossip_events = self.gossip_events.clone();
        let topic_hash = t.hash();
        let th = topic_hash.clone();
        let rpc = self.p2p.rpc().clone();

        // subscribe to the topic, to receive responses
        self.p2p
            .rpc()
            .p2p
            .gossipsub_subscribe(topic_hash.clone())
            .await?;

        let gossip_task = tokio::task::spawn(async move {
            let mut current_peer = None;
            while let Ok(event) = gossip_events.recv().await {
                match event {
                    GossipsubEvent::Subscribed { peer_id, topic } => {
                        if topic == th && current_peer.is_none() {
                            info!("connected to {}", peer_id);
                            current_peer = Some(peer_id);

                            let start =
                                bincode::serialize(&SenderMessage::Start { root, num_parts })
                                    .expect("serialize failure");
                            rpc.p2p
                                .gossipsub_publish(topic.clone(), start.into())
                                .await
                                .unwrap();
                        }
                    }
                    GossipsubEvent::Message { from, message, .. } => {
                        debug!("received message from {}", from);
                        if let Some(current_peer) = current_peer {
                            if from == current_peer {
                                match bincode::deserialize(&message.data) {
                                    Ok(ReceiverMessage::FinishOk) => {
                                        info!("finished transfer");
                                        done_sender.send(Ok(())).ok();
                                        break;
                                    }
                                    Ok(ReceiverMessage::FinishError(err)) => {
                                        info!("transfer failed: {}", err);
                                        done_sender.send(Err(anyhow!("{}", err))).ok();
                                        break;
                                    }
                                    Err(err) => {
                                        warn!("unexpected message: {:?}", err);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        let (peer_id, addrs) = self
            .p2p
            .rpc()
            .p2p
            .get_listening_addrs()
            .await
            .context("getting p2p info")?;
        info!("Available addrs: {:?}", addrs);
        let topic_string = topic_hash.to_string();

        let ticket = Ticket {
            peer_id,
            addrs,
            topic: topic_string,
        };

        Ok(Transfer {
            ticket,
            done_receiver,
            gossip_task,
        })
    }

    pub async fn transfer_from_data(
        &self,
        name: impl Into<String>,
        data: Bytes,
    ) -> Result<Transfer> {
        let name = name.into();
        // wrap in directory to preserve the name
        let mut root_dir = iroh_resolver::unixfs_builder::DirectoryBuilder::new();
        let mut file = iroh_resolver::unixfs_builder::FileBuilder::new();
        file.name(&name).content_bytes(data);
        let file = file.build().await?;
        root_dir.add_file(file);

        self.transfer_from_dir_builder(root_dir).await
    }

    fn next_id(&self) -> u64 {
        rand::thread_rng().gen()
    }
}

pub struct Transfer {
    ticket: Ticket,
    done_receiver: OneShotReceiver<Result<()>>,
    gossip_task: JoinHandle<()>,
}

impl Transfer {
    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }

    /// Waits until the transfer is done.
    pub async fn done(self) -> Result<()> {
        self.done_receiver.await??;
        self.gossip_task.await?;
        Ok(())
    }
}
