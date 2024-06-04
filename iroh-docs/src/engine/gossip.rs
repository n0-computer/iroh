use std::collections::HashSet;

use anyhow::{Context, Result};
use futures_lite::StreamExt;
use futures_util::FutureExt;
use iroh_gossip::net::{Event, Gossip};
use iroh_net::key::PublicKey;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};
use tokio_stream::{
    wrappers::{errors::BroadcastStreamRecvError, BroadcastStream},
    StreamMap,
};
use tracing::{debug, error, trace, warn};

use crate::{actor::SyncHandle, ContentStatus, NamespaceId};

use super::live::{Op, ToLiveActor};

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
    to_sync_actor: mpsc::Sender<ToLiveActor>,
    joined: HashSet<NamespaceId>,
    want_join: HashSet<NamespaceId>,
    pending_joins: JoinSet<(NamespaceId, Result<broadcast::Receiver<Event>>)>,
    gossip_events: StreamMap<NamespaceId, BroadcastStream<Event>>,
}

impl GossipActor {
    pub fn new(
        inbox: mpsc::Receiver<ToGossipActor>,
        sync: SyncHandle,
        gossip: Gossip,
        to_sync_actor: mpsc::Sender<ToLiveActor>,
    ) -> Self {
        Self {
            inbox,
            sync,
            gossip,
            to_sync_actor,
            joined: Default::default(),
            want_join: Default::default(),
            pending_joins: Default::default(),
            gossip_events: Default::default(),
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut i = 0;
        loop {
            i += 1;
            trace!(?i, "tick wait");
            tokio::select! {
                next = self.gossip_events.next(), if !self.gossip_events.is_empty() => {
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
                        Ok(stream) => {
                            debug!(namespace = %namespace.fmt_short(), "joined gossip");
                            self.joined.insert(namespace);
                            let stream = BroadcastStream::new(stream);
                            self.gossip_events.insert(namespace, stream);
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
                debug!(?namespace, peers = peers.len(), "join gossip");
                let gossip = self.gossip.clone();
                // join gossip for the topic to receive and send message
                let fut = async move {
                    let stream = gossip.subscribe(namespace.into()).await?;
                    let _topic = gossip.join(namespace.into(), peers).await?.await?;
                    Ok(stream)
                };
                let fut = fut.map(move |res| (namespace, res));
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
        event: Option<(NamespaceId, Result<Event, BroadcastStreamRecvError>)>,
    ) -> Result<()> {
        let (namespace, event) = event.context("Gossip event channel closed")?;
        let event = match event {
            Ok(event) => event,
            Err(BroadcastStreamRecvError::Lagged(n)) => {
                warn!("GossipActor too slow (lagged by {n}) - dropping gossip event");
                return Ok(());
            }
        };
        if !self.joined.contains(&namespace) && !self.want_join.contains(&namespace) {
            error!(namespace = %namespace.fmt_short(), "received gossip event for unknown topic");
            return Ok(());
        }
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
                        self.to_sync_actor
                            .send(ToLiveActor::NeighborContentReady {
                                namespace,
                                node: msg.delivered_from,
                                hash,
                            })
                            .await?;
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
