use std::collections::{hash_map, HashMap};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_lite::StreamExt;
use futures_util::FutureExt;
use iroh_gossip::net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender, JoinOptions};
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
    active_tasks: JoinSet<(NamespaceId, Result<()>)>,
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

    pub async fn join(&mut self, namespace: NamespaceId, bootstrap: Vec<NodeId>) -> Result<()> {
        match self.active.entry(namespace) {
            hash_map::Entry::Occupied(entry) => {
                if !bootstrap.is_empty() {
                    entry.get().sender.join_peers(bootstrap).await?;
                }
            }
            hash_map::Entry::Vacant(entry) => {
                let sub = self
                    .gossip
                    .join_with_opts(namespace.into(), JoinOptions::with_bootstrap(bootstrap));
                let (sender, stream) = sub.split();
                let abort_handle = self.active_tasks.spawn(
                    receive_loop(
                        namespace,
                        stream,
                        self.to_live_actor.clone(),
                        self.sync.clone(),
                    )
                    .map(move |res| (namespace, res)),
                );
                entry.insert(ActiveState {
                    sender,
                    abort_handle,
                });
            }
        }
        Ok(())
    }

    pub fn quit(&mut self, topic: &NamespaceId) {
        if let Some(state) = self.active.remove(topic) {
            state.abort_handle.abort();
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        for (_, state) in self.active.drain() {
            state.abort_handle.abort();
        }
        self.progress().await
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

    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    /// Progress the internal task queues.
    ///
    /// Returns an error if any of the active tasks panic.
    ///
    /// ## Cancel safety
    ///
    /// This function is fully cancel-safe.
    pub async fn progress(&mut self) -> Result<()> {
        while let Some(res) = self.active_tasks.join_next().await {
            match res {
                Err(err) if err.is_cancelled() => continue,
                Err(err) => return Err(err).context("gossip receive loop panicked"),
                Ok((namespace, res)) => {
                    self.active.remove(&namespace);
                    if let Err(err) = res {
                        warn!(?err, ?namespace, "gossip receive loop failed")
                    }
                }
            }
        }
        Ok(())
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
        let event = match event {
            Event::Gossip(event) => event,
            Event::Lagged => {
                debug!("gossip loop lagged - dropping gossip event");
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
                        if let Err(err) = sync
                            .insert_remote(namespace, entry, from, content_status)
                            .await
                        {
                            debug!("ignoring entry received via gossip: {err}");
                        }
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
