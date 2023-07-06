use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::sync::connect_and_sync;
use anyhow::{anyhow, Context};
use futures::{
    future::{BoxFuture, Shared},
    stream::FuturesUnordered,
    FutureExt, TryFutureExt,
};
use iroh_gossip::{
    net::{Event, GossipHandle},
    proto::TopicId,
};
use iroh_net::{tls::PeerId, MagicEndpoint};
use iroh_sync::sync::{InsertOrigin, Replica, SignedEntry};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinError,
};
use tokio_stream::StreamExt;
use tracing::error;

const CHANNEL_CAP: usize = 8;

/// The address to connect to a peer
/// TODO: Move into iroh-net
/// TODO: Make an enum and support DNS resolution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerSource {
    pub peer_id: PeerId,
    pub addrs: Vec<SocketAddr>,
    pub derp_region: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    Put(SignedEntry),
}

#[derive(Debug)]
enum SyncState {
    Running,
    Finished,
    Failed(anyhow::Error),
}

#[derive(Debug)]
pub enum ToActor {
    Shutdown,
}

/// Handle to a running live sync actor
#[derive(Debug, Clone)]
pub struct LiveSync {
    to_actor_tx: mpsc::Sender<ToActor>,
    task: Shared<BoxFuture<'static, Result<(), Arc<JoinError>>>>,
}

impl LiveSync {
    pub fn spawn(
        endpoint: MagicEndpoint,
        gossip: GossipHandle,
        doc: Replica,
        initial_peers: Vec<PeerSource>,
    ) -> Self {
        let (to_actor_tx, to_actor_rx) = mpsc::channel(CHANNEL_CAP);
        let mut actor = Actor::new(endpoint, gossip, doc, initial_peers, to_actor_rx);
        let task = tokio::spawn(async move { actor.run().await });
        let handle = LiveSync {
            to_actor_tx,
            task: task.map_err(Arc::new).boxed().shared(),
        };
        handle
    }

    /// Cancel the live sync.
    pub async fn cancel(&mut self) -> anyhow::Result<()> {
        self.to_actor_tx.send(ToActor::Shutdown).await?;
        self.task.clone().await?;
        Ok(())
    }
}

// TODO: Right now works with a single doc. Can quite easily be extended to work on a set of
// replicas. Then the handle above could have a
// `join_doc(doc: Replica, initial_peers: Vec<PeerSource)`
// method to send new replicas to the actor. Will be more efficient than spawning an actor per
// document likely.
// TODO: Also add `handle_connection` to the replica and track incoming sync requests here too.
// Currently peers might double-sync in both directions.
#[derive(Debug)]
struct Actor {
    replica: Replica,
    endpoint: MagicEndpoint,
    initial_peers: Vec<PeerSource>,
    gossip_stream: GossipStream,
    to_actor_rx: mpsc::Receiver<ToActor>,
    insert_entry_rx: mpsc::UnboundedReceiver<SignedEntry>,
    sync_state: HashMap<PeerId, SyncState>,
    gossip: GossipHandle,
    running_sync_tasks: FuturesUnordered<tokio::task::JoinHandle<(PeerId, anyhow::Result<()>)>>,
}

impl Actor {
    pub fn new(
        endpoint: MagicEndpoint,
        gossip: GossipHandle,
        replica: Replica,
        initial_peers: Vec<PeerSource>,
        to_actor_rx: mpsc::Receiver<ToActor>,
    ) -> Self {
        // TODO: instead of an unbounded channel, we'd want a FIFO ring buffer likely
        // (we have to send from the blocking Replica::on_insert callback, so we need a channel
        // with nonblocking sending, so either unbounded or ringbuffer like)
        let (insert_tx, insert_rx) = mpsc::unbounded_channel();
        // let (to_actor_tx, to_actor_rx) = mpsc::channel(CHANNEL_CAP);
        // setup replica insert notifications.
        replica.on_insert(Box::new(move |origin, entry| {
            // only care for local inserts, otherwise we'd do endless gossip loops
            if let InsertOrigin::Local = origin {
                insert_tx.send(entry.clone()).ok();
            }
        }));

        // setup a gossip subscripion
        let peer_ids: Vec<PeerId> = initial_peers.iter().map(|p| p.peer_id.clone()).collect();
        let topic: TopicId = replica.namespace().as_bytes().into();
        let gossip_subscription = GossipStream::new(gossip.clone(), topic, peer_ids);

        Self {
            gossip,
            replica,
            endpoint,
            gossip_stream: gossip_subscription,
            insert_entry_rx: insert_rx,
            to_actor_rx,
            sync_state: Default::default(),
            running_sync_tasks: Default::default(),
            initial_peers,
        }
    }
    pub async fn run(&mut self) {
        if let Err(err) = self.run_inner().await {
            error!("live sync failed: {err:?}");
        }
    }

    async fn run_inner(&mut self) -> anyhow::Result<()> {
        // add addresses of initial peers to our endpoint address book
        for peer in &self.initial_peers {
            self.endpoint
                .add_known_addrs(peer.peer_id, peer.derp_region, &peer.addrs)
                .await?;
        }
        // trigger initial sync with initial peers
        for peer in self.initial_peers.clone().iter().map(|p| p.peer_id) {
            self.sync_with_peer(peer);
        }
        loop {
            tokio::select! {
                biased;
                msg = self.to_actor_rx.recv() => {
                    match msg {
                        // received shutdown signal, or livesync handle was dropped: break loop and
                        // exit
                        Some(ToActor::Shutdown) | None => break,
                    }
                }
                // new gossip message
                event = self.gossip_stream.next() => {
                    if let Err(err) = self.on_gossip_event(event?) {
                        error!("Failed to process gossip event: {err:?}");
                    }
                },
                entry = self.insert_entry_rx.recv() => {
                    let entry = entry.ok_or_else(|| anyhow!("insert_rx returned None"))?;
                    self.on_insert_entry(entry).await?;
                }
                Some(res) = self.running_sync_tasks.next() => {
                    let (peer, res) = res.context("task sync_with_peer paniced")?;
                    self.on_sync_finished(peer, res);

                }
            }
        }
        Ok(())
    }

    fn sync_with_peer(&mut self, peer: PeerId) {
        // Check if we synced and only start sync if not yet synced
        // sync_with_peer is triggered on NeighborUp events, so might trigger repeatedly for the
        // same peers.
        // TODO: Track finished time and potentially re-run sync
        if let Some(_state) = self.sync_state.get(&peer) {
            return;
        };
        self.sync_state.insert(peer, SyncState::Running);
        let task = {
            let endpoint = self.endpoint.clone();
            let replica = self.replica.clone();
            tokio::spawn(async move {
                println!("> connect and sync with {peer}");
                // TODO: Make sure that the peer is dialable.
                let res = connect_and_sync(&endpoint, &replica, peer, None, &[]).await;
                println!("> sync with {peer} done: {res:?}");
                (peer, res)
            })
        };
        self.running_sync_tasks.push(task);
    }

    fn on_sync_finished(&mut self, peer: PeerId, res: anyhow::Result<()>) {
        let state = match res {
            Ok(_) => SyncState::Finished,
            Err(err) => SyncState::Failed(err),
        };
        self.sync_state.insert(peer, state);
    }

    fn on_gossip_event(&mut self, event: Event) -> anyhow::Result<()> {
        match event {
            // We received a gossip message. Try to insert it into our replica.
            Event::Received(data) => {
                let op: Op = postcard::from_bytes(&data)?;
                match op {
                    Op::Put(entry) => {
                        self.replica.insert_remote_entry(entry)?;
                    }
                }
            }
            // A new neighbor appeared in the gossip swarm. Try to sync with it directly.
            // [Self::sync_with_peer] will check to not resync with peers synced previously in the
            // same session. TODO: Maybe this is too broad and leads to too many sync requests.
            Event::NeighborUp(peer) => {
                self.sync_with_peer(peer);
            }
            _ => {}
        }
        Ok(())
    }

    /// A new entry was inserted locally. Broadcast a gossip message.
    async fn on_insert_entry(&mut self, entry: SignedEntry) -> anyhow::Result<()> {
        let op = Op::Put(entry);
        let topic: TopicId = self.replica.namespace().as_bytes().into();
        self.gossip
            .broadcast(topic, postcard::to_stdvec(&op)?.into())
            .await?;
        Ok(())
    }
}

// TODO: If this is the API surface we want move to iroh-gossip/src/net and make this be
// GossipHandle::subscribe
#[derive(Debug)]
pub enum GossipStream {
    Joining(GossipHandle, TopicId, Vec<PeerId>),
    Running(broadcast::Receiver<Event>),
}

impl GossipStream {
    pub fn new(gossip: GossipHandle, topic: TopicId, peers: Vec<PeerId>) -> Self {
        Self::Joining(gossip, topic, peers)
    }
    pub async fn next(&mut self) -> anyhow::Result<Event> {
        loop {
            match self {
                Self::Joining(gossip, topic, peers) => {
                    // TODO: avoid the clone
                    gossip.join(*topic, peers.clone()).await?;
                    let sub = gossip.subscribe(*topic).await?;
                    *self = Self::Running(sub);
                }
                Self::Running(sub) => {
                    let ret = sub.recv().await.map_err(|e| e.into());
                    return ret;
                }
            }
        }
    }
}
