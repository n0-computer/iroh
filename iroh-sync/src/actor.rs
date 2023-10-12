//! This contains an actor spawned on a seperate thread to process replica and store operations.

use std::{
    collections::{hash_map, HashMap},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use iroh_bytes::Hash;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing::{debug, error, error_span, trace, warn};

use crate::{
    ranger::Message,
    store::{self, GetFilter},
    Author, AuthorId, ContentStatus, ContentStatusCallback, Event, Namespace, NamespaceId,
    PeerIdBytes, Replica, SignedEntry, SyncOutcome,
};

#[derive(derive_more::Debug, derive_more::Display)]
enum Action {
    #[display("NewAuthor")]
    ImportAuthor {
        author: Author,
        #[debug("reply")]
        reply: oneshot::Sender<Result<AuthorId>>,
    },
    #[display("NewReplica")]
    ImportReplica {
        namespace: Namespace,
        #[debug("reply")]
        reply: oneshot::Sender<Result<NamespaceId>>,
    },
    #[display("ListAuthors")]
    ListAuthors {
        #[debug("reply")]
        reply: flume::Sender<Result<AuthorId>>,
    },
    #[display("ListReplicas")]
    ListReplicas {
        #[debug("reply")]
        reply: flume::Sender<Result<NamespaceId>>,
    },
    #[display("Replica({}, {})", namespace.fmt_short(), action)]
    Replica {
        namespace: NamespaceId,
        action: ReplicaAction,
    },
    #[display("Shutdown")]
    Shutdown,
}

#[derive(derive_more::Debug, strum::Display)]
enum ReplicaAction {
    UpdateState {
        change: StateUpdate,
        #[debug("reply")]
        reply: oneshot::Sender<Result<()>>,
    },
    InsertLocal {
        author: AuthorId,
        key: Bytes,
        hash: Hash,
        len: u64,
        #[debug("reply")]
        reply: oneshot::Sender<Result<()>>,
    },
    DeletePrefix {
        author: AuthorId,
        key: Bytes,
        #[debug("reply")]
        reply: oneshot::Sender<Result<usize>>,
    },
    InsertRemote {
        entry: SignedEntry,
        from: PeerIdBytes,
        content_status: ContentStatus,
        #[debug("reply")]
        reply: oneshot::Sender<Result<()>>,
    },
    SyncInitialMessage {
        #[debug("reply")]
        reply: oneshot::Sender<Result<Message<SignedEntry>>>,
    },
    SyncProcessMessage {
        message: Message<SignedEntry>,
        from: PeerIdBytes,
        state: SyncOutcome,
        #[debug("reply")]
        reply: oneshot::Sender<Result<(Option<Message<SignedEntry>>, SyncOutcome)>>,
    },
    GetSyncPeers {
        #[debug("reply")]
        reply: oneshot::Sender<Result<Option<Vec<PeerIdBytes>>>>,
    },
    RegisterUsefulPeer {
        peer: PeerIdBytes,
        #[debug("reply")]
        reply: oneshot::Sender<Result<()>>,
    },
    GetOne {
        author: AuthorId,
        key: Bytes,
        reply: oneshot::Sender<Result<Option<SignedEntry>>>,
    },
    GetMany {
        filter: GetFilter,
        reply: flume::Sender<Result<SignedEntry>>,
    },
    Drop {
        reply: oneshot::Sender<Result<()>>,
    },
    ExportSecretKey {
        reply: oneshot::Sender<Result<Namespace>>,
    },
}

/// Describes the intended state change for a replica.
///
/// Fields set to `None` mean no change (keep current state).
/// Fields set to `Some` mean change the state to the desired value.
#[derive(Debug, Default, Clone, Copy)]
pub struct StateUpdate {
    /// Whether to emit insert events for this replica.
    pub watch: Option<bool>,
    /// Whether to accept sync requests for this replica.
    pub sync: Option<bool>,
}
impl StateUpdate {
    /// Create a state update with a change for [`Self::watch`].
    pub fn with_watch(watch: bool) -> Self {
        Self::default().watch(watch)
    }
    /// Create a state update with a change for [`Self::sync`].
    pub fn with_sync(sync: bool) -> Self {
        Self::default().sync(sync)
    }
    /// Set [`Self::watch`].
    pub fn watch(mut self, watch: bool) -> Self {
        self.watch = Some(watch);
        self
    }
    /// Set [`Self::sync`].
    pub fn sync(mut self, sync: bool) -> Self {
        self.sync = Some(sync);
        self
    }
}

/// The state for an open replica.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaState {
    /// Whether to emit insert events for this replica.
    pub watch: bool,
    /// Whether to accept sync requests for this replica.
    pub sync: bool,
}

impl ReplicaState {
    /// Create a new state with a [`StateUpdate`] applied.
    pub fn with_update(mut self, update: StateUpdate) -> Self {
        if let Some(watch) = update.watch {
            self.watch = watch;
        }
        if let Some(sync) = update.sync {
            self.sync = sync;
        }
        self
    }

    /// Apply a [`StateUpdate`] to this state.
    pub fn update(&mut self, update: StateUpdate) {
        *self = self.with_update(update)
    }
}

type ActorSender = flume::Sender<Action>;

/// A channel to receive replica events on.
pub type EventReceiver = flume::Receiver<Event>;

/// The [`SyncHandle`] is the handle to a thread that runs replica and store operations.
#[derive(Debug, Clone)]
pub struct SyncHandle {
    tx: ActorSender,
}

#[allow(missing_docs)]
impl SyncHandle {
    /// Spawn a sync actor and return a handle.
    pub fn spawn<S: store::Store>(
        store: S,
        content_status_callback: Option<ContentStatusCallback>,
        me: String,
    ) -> (SyncHandle, EventReceiver) {
        const EVENT_CAP: usize = 1024;
        const ACTION_CAP: usize = 128;
        let (event_tx, event_rx) = flume::bounded(EVENT_CAP);
        let (action_tx, action_rx) = flume::bounded(ACTION_CAP);
        let mut actor = Actor {
            store,
            states: Default::default(),
            event_tx,
            action_rx,
            content_status_callback,
        };
        std::thread::spawn(move || {
            let span = error_span!("sync", %me);
            let _enter = span.enter();

            if let Err(err) = actor.run() {
                error!("Sync actor closed with error: {err:?}");
            }
        });
        let handle = SyncHandle { tx: action_tx };
        (handle, event_rx)
    }

    pub async fn update_state(&self, namespace: NamespaceId, change: StateUpdate) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::UpdateState { change, reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn insert_local(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: Bytes,
        hash: Hash,
        len: u64,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::InsertLocal {
            author,
            key,
            hash,
            len,
            reply,
        };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn delete_prefix(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: Bytes,
    ) -> Result<usize> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::DeletePrefix { author, key, reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn insert_remote(
        &self,
        namespace: NamespaceId,
        entry: SignedEntry,
        from: PeerIdBytes,
        content_status: ContentStatus,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::InsertRemote {
            entry,
            from,
            content_status,
            reply,
        };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn sync_initial_message(
        &self,
        namespace: NamespaceId,
    ) -> Result<Message<SignedEntry>> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::SyncInitialMessage { reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn sync_process_message(
        &self,
        namespace: NamespaceId,
        message: Message<SignedEntry>,
        from: PeerIdBytes,
        state: SyncOutcome,
    ) -> Result<(Option<Message<SignedEntry>>, SyncOutcome)> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::SyncProcessMessage {
            reply,
            message,
            from,
            state,
        };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn get_sync_peers(&self, namespace: NamespaceId) -> Result<Option<Vec<PeerIdBytes>>> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::GetSyncPeers { reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn register_useful_peer(
        &self,
        namespace: NamespaceId,
        peer: PeerIdBytes,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::RegisterUsefulPeer { reply, peer };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    // TODO: it would be great if this could be a sync method...
    pub async fn get_many(
        &self,
        namespace: NamespaceId,
        filter: GetFilter,
        reply: flume::Sender<Result<SignedEntry>>,
    ) -> Result<()> {
        let action = ReplicaAction::GetMany { filter, reply };
        self.send_replica(namespace, action).await?;
        Ok(())
    }

    pub async fn get_one(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: Bytes,
    ) -> Result<Option<SignedEntry>> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::GetOne { author, key, reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn drop_replica(&self, namespace: NamespaceId) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::Drop { reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn export_secret_key(&self, namespace: NamespaceId) -> Result<Namespace> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::ExportSecretKey { reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn shutdown(&self) {
        self.send(Action::Shutdown).await.ok();
    }

    pub async fn list_authors(&self, reply: flume::Sender<Result<AuthorId>>) -> Result<()> {
        self.send(Action::ListAuthors { reply }).await
    }

    pub async fn list_replicas(&self, reply: flume::Sender<Result<NamespaceId>>) -> Result<()> {
        self.send(Action::ListReplicas { reply }).await
    }

    pub async fn import_author(&self, author: Author) -> Result<AuthorId> {
        let (reply, rx) = oneshot::channel();
        self.send(Action::ImportAuthor { author, reply }).await?;
        rx.await?
    }

    pub async fn import_replica(&self, namespace: Namespace) -> Result<NamespaceId> {
        let (reply, rx) = oneshot::channel();
        self.send(Action::ImportReplica { namespace, reply })
            .await?;
        rx.await?
    }

    async fn send(&self, action: Action) -> Result<()> {
        self.tx.send_async(action).await?;
        Ok(())
    }
    async fn send_replica(&self, namespace: NamespaceId, action: ReplicaAction) -> Result<()> {
        self.send(Action::Replica { namespace, action }).await?;
        Ok(())
    }
}

type ReplicaStates<S> =
    HashMap<NamespaceId, (Replica<<S as store::Store>::Instance>, ReplicaState)>;

struct Actor<S: store::Store> {
    store: S,
    states: ReplicaStates<S>,
    event_tx: flume::Sender<Event>,
    action_rx: flume::Receiver<Action>,
    content_status_callback: Option<ContentStatusCallback>,
}

impl<S: store::Store> Actor<S> {
    fn run(&mut self) -> Result<()> {
        loop {
            let Ok(action) = self.action_rx.recv() else {
                break;
            };
            trace!(%action, "tick");
            let is_shutdown = matches!(action, Action::Shutdown);
            if let Err(err) = self.on_action(action) {
                warn!("failed to send reply: {err}");
            }
            if is_shutdown {
                break;
            }
        }
        trace!("shutdown");
        Ok(())
    }

    fn on_action(&mut self, action: Action) -> Result<()> {
        match action {
            Action::Shutdown => {
                for (namespace, _) in self.states.drain() {
                    self.store.close_replica(&namespace);
                }
                Ok(())
            }
            Action::ImportAuthor { author, reply } => {
                let id = author.id();
                send_reply(reply, self.store.import_author(author).map(|_| id))
            }
            Action::ImportReplica { namespace, reply } => {
                let id = namespace.id();
                send_reply(reply, self.store.new_replica(namespace).map(|_| id))
            }
            Action::ListAuthors { reply } => iter_to_channel(
                reply,
                self.store
                    .list_authors()
                    .map(|a| a.map(|a| a.map(|a| a.id()))),
            ),
            Action::ListReplicas { reply } => iter_to_channel(reply, self.store.list_namespaces()),
            Action::Replica { namespace, action } => self.on_replica_action(namespace, action),
        }
    }

    fn on_replica_action(&mut self, namespace: NamespaceId, action: ReplicaAction) -> Result<()> {
        match action {
            ReplicaAction::UpdateState { change, reply } => {
                self.update_state(namespace, change)?;
                send_reply(reply, Ok(()))
            }
            ReplicaAction::InsertLocal {
                author,
                key,
                hash,
                len,
                reply,
            } => send_reply_with(reply, self, |this| {
                let author = this.get_author(&author)?;
                let replica = this.get_or_open(namespace)?;
                replica.insert(&key, &author, hash, len)?;
                Ok(())
            }),
            ReplicaAction::DeletePrefix { author, key, reply } => {
                send_reply_with(reply, self, |this| {
                    let author = this.get_author(&author)?;
                    let replica = this.get_or_open(namespace)?;
                    let res = replica.delete_prefix(&key, &author)?;
                    Ok(res)
                })
            }
            ReplicaAction::InsertRemote {
                entry,
                from,
                content_status,
                reply,
            } => send_reply_with(reply, self, move |this| {
                let replica = this.get_if_syncing(&namespace)?;
                replica.insert_remote_entry(entry, from, content_status)?;
                Ok(())
            }),

            ReplicaAction::SyncInitialMessage { reply } => {
                let res = self
                    .get_if_syncing(&namespace)
                    .and_then(|replica| replica.sync_initial_message());
                send_reply(reply, res)
            }
            ReplicaAction::SyncProcessMessage {
                message,
                from,
                mut state,
                reply,
            } => {
                let res = self.get_if_syncing(&namespace).and_then(|replica| {
                    let res = replica.sync_process_message(message, from, &mut state)?;
                    Ok((res, state))
                });
                send_reply(reply, res)
            }
            ReplicaAction::GetSyncPeers { reply } => {
                let peers = match self.store.get_sync_peers(&namespace) {
                    Err(err) => Err(err),
                    Ok(None) => Ok(None),
                    Ok(Some(iter)) => Ok(Some(iter.collect())),
                };
                send_reply(reply, peers)
            }
            ReplicaAction::RegisterUsefulPeer { peer, reply } => {
                let res = self.store.register_useful_peer(namespace, peer);
                send_reply(reply, res)
            }
            ReplicaAction::GetOne { author, key, reply } => {
                let res = self.store.get_one(namespace, author, key);
                send_reply(reply, res)
            }
            ReplicaAction::GetMany { filter, reply } => {
                iter_to_channel(reply, self.store.get_many(namespace, filter))
            }
            ReplicaAction::Drop { reply } => {
                self.states.remove(&namespace);
                let res = self.store.remove_replica(&namespace);
                send_reply(reply, res)
            }
            ReplicaAction::ExportSecretKey { reply } => {
                let res = self.get_or_open(namespace).map(|r| r.secret_key());
                send_reply(reply, res)
            }
        }
    }

    fn get_or_open(&mut self, namespace: NamespaceId) -> Result<&Replica<S::Instance>> {
        let (replica, _state) = get_or_open(
            &self.store,
            &mut self.states,
            &self.content_status_callback,
            namespace,
        )?;
        Ok(&*replica)
    }

    // TODO: Do we limit operations to replicas opened before?
    // fn get_if_open(&self, namespace: &NamespaceId) -> Result<&Replica<S::Instance>> {
    //     self.states
    //         .get(namespace)
    //         .map(|(replica, _state)| replica)
    //         .context("replica not open")
    // }

    fn get_if_syncing(&self, namespace: &NamespaceId) -> Result<&Replica<S::Instance>> {
        self.states
            .get(namespace)
            .and_then(|(replica, state)| match state.sync {
                false => None,
                true => Some(replica),
            })
            .context("replica not open")
    }

    fn get_author(&self, id: &AuthorId) -> Result<Author> {
        self.store.get_author(id)?.context("author not found")
    }

    fn update_state(&mut self, namespace: NamespaceId, change: StateUpdate) -> Result<()> {
        // open the replica, if it is not yet open.
        let (replica, state) = get_or_open(
            &self.store,
            &mut self.states,
            &self.content_status_callback,
            namespace,
        )?;
        let next_state = state.with_update(change);
        trace!(namespace = %namespace.fmt_short(), ?change, ?next_state, "update state");
        match (state.watch, next_state.watch) {
            (true, false) => {
                replica.unset_event_sender();
            }
            (false, true) => {
                replica.set_event_sender(self.event_tx.clone());
            }
            _ => {}
        };
        *state = next_state;
        Ok(())
    }
}
fn get_or_open<'a, 'b, S: store::Store>(
    store: &'a S,
    states: &'b mut ReplicaStates<S>,
    content_status_callback: &Option<ContentStatusCallback>,
    namespace: NamespaceId,
) -> Result<&'b mut (Replica<S::Instance>, ReplicaState)> {
    match states.entry(namespace) {
        hash_map::Entry::Vacant(e) => {
            let replica = store
                .open_replica(&namespace)?
                .context("replica not found")?;
            if let Some(cb) = &content_status_callback {
                replica.set_content_status_callback(Arc::clone(cb));
            }
            Ok(e.insert((replica, ReplicaState::default())))
        }
        hash_map::Entry::Occupied(e) => Ok(e.into_mut()),
    }
}

fn iter_to_channel<T: Send + 'static>(
    channel: flume::Sender<Result<T>>,
    iter: Result<impl Iterator<Item = Result<T>>>,
) -> Result<()> {
    match iter {
        Err(err) => channel.send(Err(err)).map_err(receiver_dropped)?,
        Ok(iter) => {
            for item in iter {
                channel.send(item).map_err(receiver_dropped)?;
            }
        }
    }
    Ok(())
}

fn send_reply<T>(sender: oneshot::Sender<T>, value: T) -> Result<()> {
    sender.send(value).map_err(receiver_dropped)
}

fn send_reply_with<T, S: store::Store>(
    sender: oneshot::Sender<Result<T>>,
    this: &mut Actor<S>,
    f: impl FnOnce(&mut Actor<S>) -> Result<T>,
) -> Result<()> {
    sender.send(f(this)).map_err(receiver_dropped)
}

fn receiver_dropped<T>(_err: T) -> anyhow::Error {
    anyhow!("receiver dropped")
}
