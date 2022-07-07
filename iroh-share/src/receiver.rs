use anyhow::{ensure, Context, Result};
use async_channel::{bounded, Receiver as ChannelReceiver};
use cid::Cid;
use futures::StreamExt;
use iroh_p2p::NetworkEvent;
use iroh_resolver::resolver::{Out, OutPrettyReader, OutType, Path, Resolver, UnixfsType};
use iroh_resolver::unixfs::LinkRef;
use libp2p::gossipsub::{GossipsubMessage, MessageId, TopicHash};
use libp2p::PeerId;
use tracing::{info, warn};

use crate::p2p_node::{Loader, P2pNode, Ticket};

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

    pub async fn transfer_from_ticket(&self, ticket: &Ticket) -> Result<Transfer<'_>> {
        // Connect to the sender
        info!("connecting");
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
                            // root is the first
                            // let the rest be resolved, but not keep in mem
                            let mut first = true;
                            while let Some(res) = results.next().await {
                                if first {
                                    s.send(res).await.unwrap();
                                    first = false;
                                }
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
            data_receiver: r,
        })
    }

    pub async fn close(self) -> Result<()> {
        self.p2p.close().await?;
        Ok(())
    }
}

pub struct Transfer<'a> {
    receiver: &'a Receiver,
    data_receiver: ChannelReceiver<Result<iroh_resolver::resolver::Out>>,
}

impl Transfer<'_> {
    pub async fn recv(&self) -> Result<Data> {
        let root = self.data_receiver.recv().await??;
        ensure!(
            root.metadata().typ == OutType::Unixfs,
            "expected unixfs data"
        );

        Ok(Data {
            resolver: self.receiver.p2p.resolver().clone(),
            root,
        })
    }
}

pub struct Data {
    resolver: Resolver<Loader>,
    root: Out,
}

impl Data {
    pub fn typ(&self) -> UnixfsType {
        self.root.metadata().unixfs_type.unwrap()
    }

    pub fn is_file(&self) -> bool {
        self.typ() == UnixfsType::File
    }

    pub fn is_dir(&self) -> bool {
        self.typ() == UnixfsType::Dir
    }

    pub fn read_dir(&self) -> Option<impl Iterator<Item = Result<LinkRef<'_>>>> {
        self.root.unixfs_read_dir()
    }

    pub fn pretty(self) -> OutPrettyReader<Loader> {
        self.root
            .pretty(self.resolver.loader().clone(), Default::default())
    }

    pub async fn read_file(&self, link: &LinkRef<'_>) -> Result<Data> {
        let root = self
            .resolver
            .resolve(Path::from_cid(link.cid))
            .await
            .context("resolve")?;

        Ok(Data {
            resolver: self.resolver.clone(),
            root,
        })
    }
}
