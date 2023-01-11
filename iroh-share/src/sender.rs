use std::path::Path;

use anyhow::{anyhow, Result};
use futures::{channel::oneshot, stream::BoxStream, StreamExt};
use iroh_api::{Cid, UnixfsEntry};
use iroh_api::{GossipsubEvent, P2pApi};
use iroh_embed::Iroh;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::{iroh::build as build_iroh, ReceiverMessage, SenderMessage, Ticket};

pub struct Sender {
    iroh: Iroh,
}

type EventStream = BoxStream<'static, Result<GossipsubEvent>>;
type ProgressStream = BoxStream<'static, Result<(Cid, u64)>>;

impl Sender {
    pub async fn new(database_path: &Path) -> Result<Self> {
        let iroh = build_iroh(9990, database_path).await?;
        Ok(Self { iroh })
    }

    pub async fn make_available(&self, entry: UnixfsEntry) -> Result<ProgressStream> {
        self.iroh.api().add_stream(entry).await
    }

    pub async fn transfer(&self, root: Cid, num_parts: usize) -> Result<Transfer> {
        Transfer::new(self.iroh.api().p2p()?.clone(), root, num_parts).await
    }
}

struct Transfer {
    api: P2pApi,
    ticket: Ticket,
    // progress: TODO
    event_task: JoinHandle<()>,
    done: oneshot::Receiver<Result<()>>,
}

// make available progress
// transfer started
// transfer succeeded
// transfer failed

impl Transfer {
    pub async fn new(api: P2pApi, root: Cid, num_parts: usize) -> Result<Self> {
        let peer_id = api.peer_id().await?;
        let addrs = api.addrs().await?;
        let ticket = Ticket::new(peer_id, addrs);
        let mut events = api.subscribe(ticket.topic.clone()).await?;
        let th = ticket.topic_hash();
        let (done_sender, done_receiver) = futures::channel::oneshot::channel();
        let p2p = api.clone();
        let event_task = tokio::task::spawn(async move {
            let mut current_peer = None;
            while let Some(Ok(e)) = events.next().await {
                match e {
                    GossipsubEvent::Subscribed { peer_id, topic } => {
                        if topic == th && current_peer.is_none() {
                            info!("connected to {}", peer_id);
                            current_peer = Some(peer_id);

                            let start =
                                bincode::serialize(&SenderMessage::Start { root, num_parts })
                                    .expect("serialize failure");
                            p2p.publish(topic.to_string(), start.into()).await.unwrap();
                        }
                    }
                    GossipsubEvent::Message { from, message, .. } => {
                        println!("received message from {}", from);
                        debug!("received message from {}", from);
                        if let Some(current_peer) = current_peer {
                            if from == current_peer {
                                match bincode::deserialize(&message.data) {
                                    Ok(ReceiverMessage::FinishOk) => {
                                        println!("finished transfer");
                                        info!("finished transfer");
                                        done_sender.send(Ok(())).ok();
                                        break;
                                    }
                                    Ok(ReceiverMessage::FinishError(err)) => {
                                        println!("transfer failed: {}", err);
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

        Ok(Self {
            api,
            ticket,
            event_task,
            done: done_receiver,
        })
    }

    pub async fn done(self) -> Result<()> {
        self.done.await??;
        self.event_task.await?;
        Ok(())
    }
}
