use std::collections::HashSet;

use anyhow::{anyhow, Context, Result};
use futures::{stream::StreamExt, FutureExt};
use iroh_gossip::{
    net::{Event, Gossip},
    proto::TopicId,
};
use iroh_net::key::PublicKey;
use iroh_sync::{actor::SyncHandle, ContentStatus, NamespaceId};
use tokio::{
    sync::{broadcast::error::RecvError, mpsc},
    task::JoinSet,
};
use tracing::{debug, error, trace};

use super::live::{Op, ToLiveActor};
use iroh_bytes::downloader::Downloader;

#[derive(strum::Display, Debug)]
pub enum ToGossipActor {
    Shutdown,
    Join {
        namespace: NamespaceId,
        peers: Vec<PublicKey>,
    },
    Leave {
        namespace: NamespaceId,
    },
}

/// This actor subscribes to all gossip events. When receiving entries, they are inserted in the
/// replica (if open). Other events are forwarded to the main actor to be handled there.
pub struct GossipActor {
    inbox: mpsc::Receiver<ToGossipActor>,
    sync: SyncHandle,
    gossip: Gossip,
    downloader: Downloader,
    to_sync_actor: mpsc::Sender<ToLiveActor>,
    joined: HashSet<NamespaceId>,
    want_join: HashSet<NamespaceId>,
    pending_joins: JoinSet<(NamespaceId, Result<TopicId>)>,
}

impl GossipActor {
    pub fn new(
        inbox: mpsc::Receiver<ToGossipActor>,
        sync: SyncHandle,
        gossip: Gossip,
        downloader: Downloader,
        to_sync_actor: mpsc::Sender<ToLiveActor>,
    ) -> Self {
        Self {
            inbox,
            sync,
            gossip,
            downloader,
            to_sync_actor,
            joined: Default::default(),
            want_join: Default::default(),
            pending_joins: Default::default(),
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut gossip_events = self.gossip.clone().subscribe_all();
        let mut i = 0;
        loop {
            i += 1;
            trace!(?i, "tick wait");
            tokio::select! {
                next = gossip_events.next() => {
                    trace!(?i, "tick: gossip_event");
                    if let Err(err) = self.on_gossip_event(next).await {
                        error!("gossip actor died: {err:?}");
                        return Err(err);
                    }
                },
                msg = self.inbox.recv() => {
                    let msg = msg.context("to_actor closed")?;
                    trace!(%msg, ?i, "tick: to_actor");
                    if !self.on_actor_message(msg).await.context("on_actor_message")? {
                        break;
                    }
                }
                Some(res) = self.pending_joins.join_next(), if !self.pending_joins.is_empty() => {
                    trace!(?i, "tick: pending_joins");
                    let (namespace, res) = res.context("pending_joins closed")?;
                    match res {
                        Ok(_topic) => {
                            debug!(namespace = %namespace.fmt_short(), "joined gossip");
                            self.joined.insert(namespace);
                        },
                        Err(err) => {
                            if self.want_join.contains(&namespace) {
                                error!(?namespace, ?err, "failed to join gossip");
                            }
                        }
                    }
                }

            }
        }
        Ok(())
    }

    async fn on_actor_message(&mut self, msg: ToGossipActor) -> anyhow::Result<bool> {
        match msg {
            ToGossipActor::Shutdown => {
                for namespace in self.joined.iter() {
                    self.gossip.quit((*namespace).into()).await.ok();
                }
                return Ok(false);
            }
            ToGossipActor::Join { namespace, peers } => {
                // join gossip for the topic to receive and send message
                let fut = self
                    .gossip
                    .join(namespace.into(), peers)
                    .await?
                    .map(move |res| (namespace, res));
                self.want_join.insert(namespace);
                self.pending_joins.spawn(fut);
            }
            ToGossipActor::Leave { namespace } => {
                self.gossip.quit(namespace.into()).await?;
                self.joined.remove(&namespace);
                self.want_join.remove(&namespace);
            }
        }
        Ok(true)
    }
    async fn on_gossip_event(
        &mut self,
        event: Option<Result<(TopicId, Event), RecvError>>,
    ) -> Result<()> {
        let (topic, event) = match event {
            Some(Ok(event)) => event,
            None => return Err(anyhow!("Gossip event channel closed")),
            Some(Err(err)) => match err {
                RecvError::Lagged(n) => {
                    error!("GossipActor too slow (lagged by {n}) - dropping gossip event");
                    return Ok(());
                }
                RecvError::Closed => {
                    return Err(anyhow!("Gossip event channel closed"));
                }
            },
        };
        let namespace: NamespaceId = topic.as_bytes().into();
        if let Err(err) = self.on_gossip_event_inner(namespace, event).await {
            error!(namespace = %namespace.fmt_short(), ?err, "Failed to process gossip event");
        }
        Ok(())
    }

    async fn on_gossip_event_inner(&mut self, namespace: NamespaceId, event: Event) -> Result<()> {
        match event {
            Event::Received(msg) => {
                let op: Op = postcard::from_bytes(&msg.content)?;
                match op {
                    Op::Put(entry) => {
                        debug!(peer = %msg.delivered_from.fmt_short(), namespace = %namespace.fmt_short(), "received entry via gossip");
                        // Insert the entry into our replica.
                        // If the message was broadcast with neighbor scope, or is received
                        // directly from the author, we assume that the content is available at
                        // that peer. Otherwise we don't.
                        // The download is not triggered here, but in the `on_replica_event`
                        // handler for the `InsertRemote` event.
                        let content_status = match msg.scope.is_direct() {
                            true => ContentStatus::Complete,
                            false => ContentStatus::Missing,
                        };
                        let from = *msg.delivered_from.as_bytes();
                        self.sync
                            .insert_remote(namespace, entry, from, content_status)
                            .await?;
                    }
                    Op::ContentReady(hash) => {
                        // Inform the downloader that we now know that this peer has the content
                        // for this hash.
                        self.downloader
                            .nodes_have(hash, vec![msg.delivered_from])
                            .await;
                    }
                    Op::SyncReport(report) => {
                        self.to_sync_actor
                            .send(ToLiveActor::IncomingSyncReport {
                                from: msg.delivered_from,
                                report,
                            })
                            .await?;
                    }
                }
            }
            // A new neighbor appeared in the gossip swarm. Try to sync with it directly.
            // [Self::sync_with_peer] will check to not resync with peers synced previously in the
            // same session. TODO: Maybe this is too broad and leads to too many sync requests.
            Event::NeighborUp(peer) => {
                self.to_sync_actor
                    .send(ToLiveActor::NeighborUp { namespace, peer })
                    .await?;
            }
            Event::NeighborDown(peer) => {
                self.to_sync_actor
                    .send(ToLiveActor::NeighborDown { namespace, peer })
                    .await?;
            }
        }
        Ok(())
    }
}
