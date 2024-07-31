use std::collections::HashMap;

use anyhow::Result;
use bytes::Bytes;
use futures_lite::StreamExt;
use iroh_gossip::net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender};
use iroh_net::NodeId;
use tokio::{
    sync::mpsc,
    task::{AbortHandle, JoinSet},
};
use tracing::{debug, instrument, warn};

use crate::{actor::SyncHandle, ContentStatus, NamespaceId};

use super::live::{Op, ToLiveActor};

#[derive(Debug)]
struct ActiveState {
    sender: GossipSender,
    abort_handle: AbortHandle,
}

#[derive(Debug)]
pub struct GossipState {
    gossip: Gossip,
    sync: SyncHandle,
    to_live_actor: mpsc::Sender<ToLiveActor>,
    active: HashMap<NamespaceId, ActiveState>,
    active_tasks: JoinSet<()>,
}

impl GossipState {
    pub fn new(gossip: Gossip, sync: SyncHandle, to_live_actor: mpsc::Sender<ToLiveActor>) -> Self {
        Self {
            gossip,
            sync,
            to_live_actor,
            active: Default::default(),
            active_tasks: Default::default(),
        }
    }

    pub fn join(&mut self, namespace: NamespaceId, bootstrap: Vec<NodeId>) {
        let (sender, stream) = self
            .gossip
            .join_pending(namespace.into(), bootstrap)
            .split();
        let to_live_actor = self.to_live_actor.clone();
        let sync_handle = self.sync.clone();
        let abort_handle = self.active_tasks.spawn(async move {
            if let Err(err) = receive_loop(namespace, stream, to_live_actor, sync_handle).await {
                warn!(?err, ?namespace, "gossip subscribe loop failed");
            }
        });
        self.active.insert(
            namespace,
            ActiveState {
                sender,
                abort_handle,
            },
        );
    }

    pub fn quit(&mut self, topic: &NamespaceId) {
        if let Some(state) = self.active.remove(topic) {
            state.abort_handle.abort();
        }
    }

    pub async fn broadcast(&self, namespace: &NamespaceId, message: Bytes) {
        if let Some(state) = self.active.get(namespace) {
            state.sender.broadcast(message).await.ok();
        }
    }

    pub async fn broadcast_neighbors(&self, namespace: &NamespaceId, message: Bytes) {
        if let Some(state) = self.active.get(namespace) {
            state.sender.broadcast_neighbors(message).await.ok();
        }
    }

    pub fn max_message_size(&self) -> usize {
        self.gossip.max_message_size()
    }

    /// Progress the internal task queues.
    ///
    /// This future is cancel-safe, so it may be dropped and recreated at any time.
    /// If there are no running tasks, the returned future is pending infinitely. To resume after
    /// adding tasks recreate the future.
    pub async fn progress(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                Some(res) = self.active_tasks.join_next(), if !self.active_tasks.is_empty() => {
                    match res {
                        Err(err) if err.is_cancelled() => continue,
                        Err(err) => break Err(err.into()),
                        Ok(()) => continue,
                    }
                }
                else => std::future::pending().await
            }
        }
    }
}

#[instrument("gossip-recv", skip_all, fields(namespace=%namespace.fmt_short()))]
async fn receive_loop(
    namespace: NamespaceId,
    mut recv: GossipReceiver,
    to_sync_actor: mpsc::Sender<ToLiveActor>,
    sync: SyncHandle,
) -> Result<()> {
    for peer in recv.neighbors() {
        to_sync_actor
            .send(ToLiveActor::NeighborUp { namespace, peer })
            .await?;
    }
    while let Some(event) = recv.try_next().await? {
        warn!(?event, "event");
        let event = match event {
            Event::Gossip(event) => event,
            Event::Lagged => {
                warn!("gossip loop lagged - dropping gossip event");
                continue;
            }
        };
        match event {
            GossipEvent::Received(msg) => {
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
                        sync.insert_remote(namespace, entry, from, content_status)
                            .await?;
                    }
                    Op::ContentReady(hash) => {
                        to_sync_actor
                            .send(ToLiveActor::NeighborContentReady {
                                namespace,
                                node: msg.delivered_from,
                                hash,
                            })
                            .await?;
                    }
                    Op::SyncReport(report) => {
                        to_sync_actor
                            .send(ToLiveActor::IncomingSyncReport {
                                from: msg.delivered_from,
                                report,
                            })
                            .await?;
                    }
                }
            }
            GossipEvent::NeighborUp(peer) => {
                to_sync_actor
                    .send(ToLiveActor::NeighborUp { namespace, peer })
                    .await?;
            }
            GossipEvent::NeighborDown(peer) => {
                to_sync_actor
                    .send(ToLiveActor::NeighborDown { namespace, peer })
                    .await?;
            }
            GossipEvent::Joined(peers) => {
                for peer in peers {
                    to_sync_actor
                        .send(ToLiveActor::NeighborUp { namespace, peer })
                        .await?;
                }
            }
        }
    }
    Ok(())
}
