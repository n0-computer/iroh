use std::path::Path;
use std::sync::atomic::AtomicU64;

use anyhow::{Context, Result};
use async_channel::{bounded, Receiver};
use bytes::Bytes;
use cid::Cid;
use futures::channel::oneshot::{channel as oneshot, Receiver as OneShotReceiver};
use futures::StreamExt;
use iroh_p2p::{GossipsubEvent, NetworkEvent};
use libp2p::gossipsub::{Sha256Topic, TopicHash};
use libp2p::PeerId;
use tracing::{error, info};

use crate::p2p_node::{P2pNode, Ticket};

/// The sending part of the data transfer.
pub struct Sender {
    p2p: P2pNode,
    next_id: AtomicU64,
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
                match event {
                    NetworkEvent::Gossipsub(e) => {
                        // drop events if they are not processed
                        s.try_send(e).ok();
                    }
                    _ => {}
                }
            }
        });

        Ok(Sender {
            p2p,
            next_id: 0.into(),
            gossip_events: r,
        })
    }

    pub async fn transfer_from_data(
        &self,
        name: impl Into<String>,
        data: Bytes,
    ) -> Result<Transfer<'_>> {
        let id = self.next_id();
        let t = Sha256Topic::new(format!("iroh-share-{}", id));
        let name = name.into();

        let (s, r) = oneshot();

        let root = {
            // wrap in directory to preserve t
            let mut root_dir = iroh_resolver::unixfs_builder::DirectoryBuilder::new();
            let mut file = iroh_resolver::unixfs_builder::FileBuilder::new();
            file.name(&name).content_bytes(data);
            let file = file.build().await?;
            root_dir.add_file(file);
            let root_dir = root_dir.build().await?;
            let parts = root_dir.encode();
            tokio::pin!(parts);
            let mut root_cid = None;
            while let Some(part) = parts.next().await {
                // TODO: store links in the store
                let (cid, bytes) = part?;
                root_cid = Some(cid);
                info!("storing {:?}", cid);
                self.p2p.rpc().store.put(cid, bytes, vec![]).await?;
            }
            root_cid.unwrap()
        };

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
            name,
            root,
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
    root: Cid,
    sender: &'a Sender,
    peer: OneShotReceiver<PeerId>,
    topic: TopicHash,
}

impl Transfer<'_> {
    pub async fn ticket(self) -> Result<Ticket> {
        let (peer_id, addrs) = self
            .sender
            .p2p
            .rpc()
            .p2p
            .get_listening_addrs()
            .await
            .context("getting p2p info")?;
        info!("Available addrs: {:?}", addrs);

        let root = self.root.to_bytes().to_vec(); // TODO: actual root hash.
        let peer = self.peer;
        let topic = self.topic;
        let topic_string = topic.to_string();
        let rpc = self.sender.p2p.rpc().clone();

        tokio::task::spawn(async move {
            match peer.await {
                Ok(peer_id) => {
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
