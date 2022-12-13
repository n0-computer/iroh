use anyhow::{anyhow, ensure, Context, Result};
use futures::{
    channel::{oneshot::channel as oneshot, oneshot::Receiver as OneShotReceiver},
    Stream, StreamExt,
};
use iroh_p2p::NetworkEvent;
use iroh_resolver::resolver::{Out, OutPrettyReader, OutType, Path, Resolver, UnixfsType};
use iroh_unixfs::{Link, ResponseClip};
use libp2p::gossipsub::{GossipsubMessage, MessageId, TopicHash};
use libp2p::PeerId;
use tokio::sync::mpsc::{channel, Receiver as ChannelReceiver};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

use crate::SenderMessage;
use crate::{
    p2p_node::{Loader, P2pNode, Ticket},
    ReceiverMessage,
};

#[derive(Debug)]
pub struct Receiver {
    p2p: P2pNode,
    gossip_messages: ChannelReceiver<(MessageId, PeerId, GossipsubMessage)>,
    gossip_task: JoinHandle<()>,
}

impl Receiver {
    pub async fn new(port: u16, db_path: &std::path::Path) -> Result<Self> {
        let (p2p, mut events) = P2pNode::new(port, db_path).await?;
        let (s, r) = channel(1024);

        let gossip_task = tokio::task::spawn(async move {
            while let Some(event) = events.recv().await {
                if let NetworkEvent::Gossipsub(iroh_p2p::GossipsubEvent::Message {
                    from,
                    id,
                    message,
                }) = event
                {
                    s.try_send((id, from, message)).ok();
                }
            }
        });

        Ok(Receiver {
            p2p,
            gossip_messages: r,
            gossip_task,
        })
    }

    pub async fn transfer_from_ticket(self, ticket: &Ticket) -> Result<Transfer> {
        // Connect to the sender
        info!("connecting");
        let Receiver {
            p2p,
            mut gossip_messages,
            gossip_task,
        } = self;
        let p2p_rpc = p2p.rpc().try_p2p()?;
        p2p_rpc
            .connect(ticket.peer_id, ticket.addrs.clone())
            .await?;
        p2p_rpc.gossipsub_add_explicit_peer(ticket.peer_id).await?;
        let topic = TopicHash::from_raw(&ticket.topic);
        p2p_rpc.gossipsub_subscribe(topic.clone()).await?;

        let expected_sender = ticket.peer_id;
        let resolver = p2p.resolver().clone();
        let (progress_sender, progress_receiver) = channel(1024);
        let (data_sender, data_receiver) = oneshot();

        // add provider
        resolver
            .loader()
            .providers()
            .lock()
            .await
            .insert(expected_sender);

        let rpc = p2p.rpc().clone();

        let gossip_task_source = tokio::task::spawn(async move {
            let mut data_sender = Some(data_sender);

            while let Some((_id, from, message)) = gossip_messages.recv().await {
                if from == expected_sender {
                    match bincode::deserialize(&message.data) {
                        Ok(SenderMessage::Start { root, num_parts }) => {
                            let results = resolver.resolve_recursive(Path::from_cid(root));
                            tokio::pin!(results);
                            // root is the first
                            let mut index = 1;
                            let mut has_err = None;
                            while let Some(res) = results.next().await {
                                let msg = match &res {
                                    Ok(_out) => Ok(ProgressEvent::Piece {
                                        index,
                                        total: num_parts,
                                    }),
                                    Err(err) => {
                                        has_err = Some(err.to_string());
                                        Err(err.to_string())
                                    }
                                };
                                debug!("progress {}/{}", index, num_parts);
                                progress_sender.send(msg).await.unwrap();

                                if let Some(data_sender) = data_sender.take() {
                                    data_sender.send(res).ok();
                                }

                                // If there was an error abort.
                                if has_err.is_some() {
                                    break;
                                }
                                index += 1;
                            }
                            info!("transfer completed");
                            drop(progress_sender);

                            // TODO: send finish message or error
                            let msg = if let Some(error) = has_err.take() {
                                ReceiverMessage::FinishError(error)
                            } else {
                                ReceiverMessage::FinishOk
                            };
                            rpc.try_p2p()
                                .expect("missing p2p rpc")
                                .gossipsub_publish(
                                    topic,
                                    bincode::serialize(&msg)
                                        .expect("failed to serialize")
                                        .into(),
                                )
                                .await
                                .ok();
                        }
                        Err(err) => {
                            warn!("got unexpected message from {}: {:?}", from, err);
                        }
                    }
                    // we only receive a single iteration
                    break;
                } else {
                    warn!("got message from unexpected sender: {:?}", from);
                }
            }
        });

        Ok(Transfer {
            gossip_task,
            gossip_task_source,
            p2p,
            data_receiver: Some(data_receiver),
            progress_receiver: Some(progress_receiver),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEvent {
    Piece { index: usize, total: usize },
}

#[derive(Debug)]
pub struct Transfer {
    p2p: P2pNode,
    gossip_task: JoinHandle<()>,
    gossip_task_source: JoinHandle<()>,
    data_receiver: Option<OneShotReceiver<Result<Out>>>,
    progress_receiver: Option<ChannelReceiver<std::result::Result<ProgressEvent, String>>>,
}

impl Transfer {
    pub async fn recv(&mut self) -> Result<Data> {
        let data_receiver = self
            .data_receiver
            .take()
            .ok_or_else(|| anyhow!("recv must only be called once"))?;
        let root = data_receiver.await??;

        ensure!(
            root.metadata().typ == OutType::Unixfs,
            "expected unixfs data"
        );

        Ok(Data {
            resolver: self.p2p.resolver().clone(),
            root,
        })
    }

    pub fn progress(
        &mut self,
    ) -> Result<ReceiverStream<std::result::Result<ProgressEvent, String>>> {
        let progress = self
            .progress_receiver
            .take()
            .ok_or_else(|| anyhow!("progerss must only be called once"))?;
        Ok(ReceiverStream::new(progress))
    }

    /// Finish and finalize the transfer.
    pub async fn finish(self) -> Result<()> {
        self.p2p.close().await?;
        self.gossip_task.await?;
        self.gossip_task_source.await?;

        Ok(())
    }
}

#[derive(Debug)]
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

    pub fn read_dir(&self) -> Result<Option<impl Stream<Item = Result<Link>> + '_>> {
        self.root
            .unixfs_read_dir(&self.resolver, Default::default())
    }

    pub fn pretty(self) -> Result<OutPrettyReader<Loader>> {
        self.root
            .pretty(self.resolver, Default::default(), ResponseClip::NoClip)
    }

    pub async fn read_file(&self, link: &Link) -> Result<Data> {
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
