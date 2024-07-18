use std::{
    collections::{hash_map, HashMap, HashSet},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use futures_buffered::join_all;
use futures_concurrency::future::future_group;
use futures_concurrency::future::Join;
use futures_lite::StreamExt;
use futures_util::FutureExt;
use iroh_net::{
    dialer::Dialer,
    endpoint::{get_remote_node_id, Connection},
    util::SharedAbortingJoinHandle,
    Endpoint, NodeId,
};
use tokio::{
    io::Interest,
    sync::{mpsc, oneshot},
    task::{AbortHandle, JoinHandle, JoinSet},
};
use tokio_stream::{wrappers::ReceiverStream, StreamMap, StreamNotifyClose};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error_span, Instrument};

use crate::{
    auth::{Auth, InterestMap},
    net::{setup, WillowConn, ALPN},
    proto::{
        grouping::{Area, AreaOfInterest},
        keys::NamespaceId,
        sync::{ReadAuthorisation, ReadCapability},
    },
    session::{
        error::ChannelReceiverDropped,
        intents::{EventKind, Intent, IntentHandle},
        Error, Interests, Role, SessionEvent, SessionHandle, SessionId, SessionInit, SessionMode,
        SessionUpdate,
    },
    store::traits::Storage,
};

use super::actor::ActorHandle;

#[derive(derive_more::Debug)]
pub enum Input {
    SubmitIntent {
        peer: NodeId,
        intent: Intent,
    },
    HandleConnection {
        #[debug("Connection")]
        conn: Connection,
    },
}

#[derive(derive_more::Debug)]
pub struct PeerManager {
    actor: ActorHandle,
    endpoint: Endpoint,
    inbox: mpsc::Receiver<Input>,
    events_rx: StreamMap<NodeId, ReceiverStream<SessionEvent>>,
    tasks: JoinSet<(NodeId, Result<WillowConn>)>,
    peers: HashMap<NodeId, PeerState>,
}

impl PeerManager {
    pub fn new(
        actor_handle: ActorHandle,
        endpoint: Endpoint,
        inbox: mpsc::Receiver<Input>,
    ) -> Self {
        PeerManager {
            endpoint: endpoint.clone(),
            actor: actor_handle,
            inbox,
            events_rx: Default::default(),
            tasks: Default::default(),
            peers: Default::default(),
        }
    }
    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                Some(input) = self.inbox.recv() => {
                    debug!(?input, "tick: inbox");
                    self.handle_input(input).await;
                }
                Some((session_id, event)) = self.events_rx.next(), if !self.events_rx.is_empty() => {
                    debug!(?session_id, ?event, "tick: event");
                    self.handle_event(session_id, event);
                }
                Some(res) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    debug!("tick: task.join_next");
                    match res {
                        Err(err) if err.is_cancelled() => continue,
                        Err(err) => Err(err).context("establish task paniced")?,
                        Ok((_peer, Ok(conn))) => self.on_established(conn).await?,
                        Ok((peer, Err(err))) => self.failed_to_connect(peer, Arc::new(Error::Net(err))).await,
                    }
                }
                else => break,
            }
        }
        Ok(())
    }

    pub async fn handle_input(&mut self, input: Input) {
        match input {
            Input::SubmitIntent { peer, intent } => {
                if let Err(err) = self.submit_intent(peer, intent).await {
                    tracing::warn!("failed to submit intent: {err:?}");
                }
            }
            Input::HandleConnection { conn } => {
                self.handle_connection(conn);
            }
        }
    }

    fn handle_connection(&mut self, conn: Connection) {
        let peer = match get_remote_node_id(&conn) {
            Ok(node_id) => node_id,
            Err(err) => {
                tracing::debug!("ignore incoming connection (QUIC handshake failed: {err})");
                return;
            }
        };
        let me = self.endpoint.node_id();

        match self.peers.get_mut(&peer) {
            None => {
                let abort_handle = self
                    .tasks
                    .spawn(WillowConn::betty(conn, me).map(move |res| (peer, res)));
                let init = SessionInit::new(Interests::All, SessionMode::Live);
                let intent = Intent::new_detached(init);
                self.peers.insert(
                    peer,
                    PeerState::Pending {
                        our_role: Role::Betty,
                        intents: vec![intent],
                        abort_handle,
                    },
                );
            }
            Some(PeerState::Pending {
                our_role: Role::Alfie,
                abort_handle,
                intents,
            }) => {
                if me > peer {
                    tracing::debug!(
                        "ignore incoming connection (already dialing and our dial wins)"
                    );
                    conn.close(0u8.into(), b"duplicate-our-dial-wins");
                } else {
                    // abort our dial attempt
                    abort_handle.abort();
                    // set the new abort handle
                    *abort_handle = self
                        .tasks
                        .spawn(WillowConn::betty(conn, me).map(move |res| (peer, res)));
                    // add catchall interest
                    let init = SessionInit::new(Interests::All, SessionMode::Live);
                    let intent = Intent::new_detached(init);
                    intents.push(intent);
                }
            }
            Some(PeerState::Pending {
                our_role: Role::Betty,
                ..
            }) => {
                tracing::debug!("ignore incoming connection (already accepting)");
                conn.close(0u8.into(), b"duplicate-already-accepting");
            }
            Some(PeerState::Active { .. }) => {
                tracing::debug!("got connection for already active peer");
                conn.close(0u8.into(), b"duplicate-already-accepting");
            }
        }
    }

    async fn failed_to_connect(&mut self, peer: NodeId, error: Arc<Error>) {
        let Some(peer_state) = self.peers.remove(&peer) else {
            tracing::warn!(?peer, "attempted to remove unknown peer");
            return;
        };
        match peer_state {
            PeerState::Pending { intents, .. } => {
                join_all(
                    intents
                        .into_iter()
                        .map(|intent| intent.send_abort(error.clone())),
                )
                .await;
            }
            PeerState::Active { .. } => {
                unreachable!("we don't accept connections for active peers")
            }
        };
    }

    async fn on_established(&mut self, conn: WillowConn) -> anyhow::Result<()> {
        let peer = conn.peer;
        let peer_state = self
            .peers
            .remove(&peer)
            .ok_or_else(|| anyhow!("unreachable: on_established called for unknown peer"))?;

        let PeerState::Pending { intents, .. } = peer_state else {
            anyhow::bail!("unreachable: on_established called for peer in wrong state")
        };

        let session_handle = self.actor.init_session(conn, intents).await?;

        let SessionHandle {
            cancel_token: _,
            update_tx,
            event_rx,
        } = session_handle;
        self.events_rx.insert(peer, ReceiverStream::new(event_rx));
        self.peers.insert(peer, PeerState::Active { update_tx });
        Ok(())
    }

    pub async fn submit_intent(&mut self, peer: NodeId, intent: Intent) -> Result<()> {
        match self.peers.get_mut(&peer) {
            None => {
                let intents = vec![intent];
                let me = self.endpoint.node_id();
                let endpoint = self.endpoint.clone();
                let abort_handle = self.tasks.spawn(
                    async move {
                        let conn = endpoint.connect_by_node_id(&peer, ALPN).await?;
                        let conn = WillowConn::alfie(conn, me).await?;
                        Ok(conn)
                    }
                    .map(move |res| (peer, res)),
                );
                let peer_state = PeerState::Pending {
                    intents,
                    abort_handle,
                    our_role: Role::Alfie,
                };
                self.peers.insert(peer, peer_state);
            }
            Some(state) => match state {
                PeerState::Pending { intents, .. } => {
                    intents.push(intent);
                }
                PeerState::Active { update_tx, .. } => {
                    update_tx.send(SessionUpdate::SubmitIntent(intent)).await?;
                }
            },
        };
        Ok(())
    }

    pub fn handle_event(&mut self, peer: NodeId, event: SessionEvent) {
        tracing::info!(?event, "event");
        match event {
            SessionEvent::Established => {}
            SessionEvent::Complete { .. } => {
                self.peers.remove(&peer);
            }
        }
    }
}

#[derive(Debug)]
enum PeerState {
    Pending {
        our_role: Role,
        intents: Vec<Intent>,
        abort_handle: AbortHandle,
    },
    Active {
        update_tx: mpsc::Sender<SessionUpdate>,
        // cancel_token: CancellationToken,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("receiver dropped")]
pub struct ReceiverDropped;
