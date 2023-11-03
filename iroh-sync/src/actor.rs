//! This contains an actor spawned on a seperate thread to process replica and store operations.

use std::{
    collections::{hash_map, HashMap},
    num::NonZeroU64,
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
    store::{self, Query},
    Author, AuthorHeads, AuthorId, ContentStatus, ContentStatusCallback, Event, Namespace,
    NamespaceId, PeerIdBytes, Replica, SignedEntry, SyncOutcome,
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
    ImportNamespace {
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
    #[display("Replica({}, {})", _0.fmt_short(), _1)]
    Replica(NamespaceId, ReplicaAction),
    #[display("Shutdown")]
    Shutdown,
}

#[derive(derive_more::Debug, strum::Display)]
enum ReplicaAction {
    Open {
        #[debug("reply")]
        reply: oneshot::Sender<Result<()>>,
        opts: OpenOpts,
    },
    Close {
        #[debug("reply")]
        reply: oneshot::Sender<Result<bool>>,
    },
    GetState {
        #[debug("reply")]
        reply: oneshot::Sender<Result<OpenState>>,
    },
    SetSync {
        sync: bool,
        #[debug("reply")]
        reply: oneshot::Sender<Result<()>>,
    },
    Subscribe {
        sender: flume::Sender<Event>,
        #[debug("reply")]
        reply: oneshot::Sender<Result<()>>,
    },
    Unsubscribe {
        sender: flume::Sender<Event>,
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
        query: Query,
        reply: flume::Sender<Result<SignedEntry>>,
    },
    DropReplica {
        reply: oneshot::Sender<Result<()>>,
    },
    ExportSecretKey {
        reply: oneshot::Sender<Result<Namespace>>,
    },
    HasNewsForUs {
        heads: AuthorHeads,
        #[debug("reply")]
        reply: oneshot::Sender<Result<Option<NonZeroU64>>>,
    },
}

/// The state for an open replica.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenState {
    /// Whether to accept sync requests for this replica.
    pub sync: bool,
    /// How many event subscriptions are open
    pub subscribers: usize,
    /// By how many handles the replica is currently held open
    pub handles: usize,
}

#[derive(Debug)]
struct OpenReplica<S: store::Store> {
    replica: Replica<S::Instance>,
    handles: usize,
    sync: bool,
}

/// The [`SyncHandle`] is the handle to a thread that runs replica and store operations.
#[derive(Debug, Clone)]
pub struct SyncHandle {
    tx: flume::Sender<Action>,
}

/// Options when opening a replica.
#[derive(Debug, Default)]
pub struct OpenOpts {
    /// Set to true to set sync state to true.
    pub sync: bool,
    /// Optionally subscribe to replica events.
    pub subscribe: Option<flume::Sender<Event>>,
}
impl OpenOpts {
    /// Set sync state to true.
    pub fn sync(mut self) -> Self {
        self.sync = true;
        self
    }
    /// Subscribe to replica events.
    pub fn subscribe(mut self, subscribe: flume::Sender<Event>) -> Self {
        self.subscribe = Some(subscribe);
        self
    }
}

#[allow(missing_docs)]
impl SyncHandle {
    /// Spawn a sync actor and return a handle.
    pub fn spawn<S: store::Store>(
        store: S,
        content_status_callback: Option<ContentStatusCallback>,
        me: String,
    ) -> SyncHandle {
        const ACTION_CAP: usize = 1024;
        let (action_tx, action_rx) = flume::bounded(ACTION_CAP);
        let mut actor = Actor {
            store,
            states: Default::default(),
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
        SyncHandle { tx: action_tx }
    }

    pub async fn open(&self, namespace: NamespaceId, opts: OpenOpts) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::Open { reply, opts };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn close(&self, namespace: NamespaceId) -> Result<bool> {
        let (reply, rx) = oneshot::channel();
        self.send_replica(namespace, ReplicaAction::Close { reply })
            .await?;
        rx.await?
    }

    pub async fn subscribe(
        &self,
        namespace: NamespaceId,
        sender: flume::Sender<Event>,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send_replica(namespace, ReplicaAction::Subscribe { sender, reply })
            .await?;
        rx.await?
    }

    pub async fn unsubscribe(
        &self,
        namespace: NamespaceId,
        sender: flume::Sender<Event>,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send_replica(namespace, ReplicaAction::Unsubscribe { sender, reply })
            .await?;
        rx.await?
    }

    pub async fn set_sync(&self, namespace: NamespaceId, sync: bool) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::SetSync { sync, reply };
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

    pub async fn has_news_for_us(
        &self,
        namespace: NamespaceId,
        heads: AuthorHeads,
    ) -> Result<Option<NonZeroU64>> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::HasNewsForUs { reply, heads };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn get_many(
        &self,
        namespace: NamespaceId,
        query: Query,
        reply: flume::Sender<Result<SignedEntry>>,
    ) -> Result<()> {
        let action = ReplicaAction::GetMany { query, reply };
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
        let author = author.into();
        let key = key.into();
        let action = ReplicaAction::GetOne { author, key, reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn drop_replica(&self, namespace: NamespaceId) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::DropReplica { reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn export_secret_key(&self, namespace: NamespaceId) -> Result<Namespace> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::ExportSecretKey { reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn get_state(&self, namespace: NamespaceId) -> Result<OpenState> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::GetState { reply };
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

    pub async fn import_namespace(&self, namespace: Namespace) -> Result<NamespaceId> {
        let (reply, rx) = oneshot::channel();
        self.send(Action::ImportNamespace { namespace, reply })
            .await?;
        rx.await?
    }

    async fn send(&self, action: Action) -> Result<()> {
        self.tx
            .send_async(action)
            .await
            .context("sending to iroh_sync actor failed")?;
        Ok(())
    }
    async fn send_replica(&self, namespace: NamespaceId, action: ReplicaAction) -> Result<()> {
        self.send(Action::Replica(namespace, action)).await?;
        Ok(())
    }
}

struct Actor<S: store::Store> {
    store: S,
    states: OpenReplicas<S>,
    action_rx: flume::Receiver<Action>,
    content_status_callback: Option<ContentStatusCallback>,
}

impl<S: store::Store> Actor<S> {
    fn run(&mut self) -> Result<()> {
        while let Ok(action) = self.action_rx.recv() {
            trace!(%action, "tick");
            let is_shutdown = matches!(action, Action::Shutdown);
            if self.on_action(action).is_err() {
                warn!("failed to send reply: receiver dropped");
            }
            if is_shutdown {
                break;
            }
        }
        trace!("shutdown");
        Ok(())
    }

    fn on_action(&mut self, action: Action) -> Result<(), SendReplyError> {
        match action {
            Action::Shutdown => {
                self.close_all();
                Ok(())
            }
            Action::ImportAuthor { author, reply } => {
                let id = author.id();
                send_reply(reply, self.store.import_author(author).map(|_| id))
            }
            Action::ImportNamespace { namespace, reply } => {
                let id = namespace.id();
                send_reply(reply, self.store.import_namespace(namespace).map(|_| id))
            }
            Action::ListAuthors { reply } => iter_to_channel(
                reply,
                self.store
                    .list_authors()
                    .map(|a| a.map(|a| a.map(|a| a.id()))),
            ),
            Action::ListReplicas { reply } => iter_to_channel(reply, self.store.list_namespaces()),
            Action::Replica(namespace, action) => self.on_replica_action(namespace, action),
        }
    }

    fn on_replica_action(
        &mut self,
        namespace: NamespaceId,
        action: ReplicaAction,
    ) -> Result<(), SendReplyError> {
        match action {
            ReplicaAction::Open { reply, opts } => {
                let res = self.open(namespace, opts);
                send_reply(reply, res)
            }
            ReplicaAction::Close { reply } => {
                let res = self.close(namespace);
                // ignore errors when no receiver is present for close
                reply.send(Ok(res)).ok();
                Ok(())
            }
            ReplicaAction::Subscribe { sender, reply } => send_reply_with(reply, self, |this| {
                let replica = this.states.replica(&namespace)?;
                replica.subscribe(sender);
                Ok(())
            }),
            ReplicaAction::Unsubscribe { sender, reply } => send_reply_with(reply, self, |this| {
                let replica = this.states.replica(&namespace)?;
                replica.unsubscribe(&sender);
                drop(sender);
                Ok(())
            }),
            ReplicaAction::SetSync { sync, reply } => send_reply_with(reply, self, |this| {
                let state = this.states.get_mut(&namespace)?;
                state.sync = sync;
                Ok(())
            }),
            ReplicaAction::InsertLocal {
                author,
                key,
                hash,
                len,
                reply,
            } => send_reply_with(reply, self, |this| {
                let author = get_author(&this.store, &author)?;
                let replica = this.states.replica(&namespace)?;
                replica.insert(&key, &author, hash, len)?;
                Ok(())
            }),
            ReplicaAction::DeletePrefix { author, key, reply } => {
                send_reply_with(reply, self, |this| {
                    let author = get_author(&this.store, &author)?;
                    let replica = this.states.replica(&namespace)?;
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
                let replica = this.states.replica_if_syncing(&namespace)?;
                replica.insert_remote_entry(entry, from, content_status)?;
                Ok(())
            }),

            ReplicaAction::SyncInitialMessage { reply } => {
                send_reply_with(reply, self, move |this| {
                    let replica = this.states.replica_if_syncing(&namespace)?;
                    let res = replica.sync_initial_message()?;
                    Ok(res)
                })
            }
            ReplicaAction::SyncProcessMessage {
                message,
                from,
                mut state,
                reply,
            } => send_reply_with(reply, self, move |this| {
                let replica = this.states.replica_if_syncing(&namespace)?;
                let res = replica.sync_process_message(message, from, &mut state)?;
                Ok((res, state))
            }),
            ReplicaAction::GetSyncPeers { reply } => send_reply_with(reply, self, move |this| {
                this.states.ensure_open(&namespace)?;
                let peers = this.store.get_sync_peers(&namespace)?;
                Ok(peers.map(|iter| iter.collect()))
            }),
            ReplicaAction::RegisterUsefulPeer { peer, reply } => {
                let res = self.store.register_useful_peer(namespace, peer);
                send_reply(reply, res)
            }
            ReplicaAction::GetOne { author, key, reply } => {
                send_reply_with(reply, self, move |this| {
                    this.states.ensure_open(&namespace)?;
                    this.store.get_one(namespace, author, key)
                })
            }
            ReplicaAction::GetMany { query, reply } => {
                let iter = self
                    .states
                    .ensure_open(&namespace)
                    .and_then(|_| self.store.get_many(namespace, query));
                iter_to_channel(reply, iter)
            }
            ReplicaAction::DropReplica { reply } => send_reply_with(reply, self, |this| {
                this.close(namespace);
                this.store.remove_replica(&namespace)
            }),
            ReplicaAction::ExportSecretKey { reply } => {
                let res = self.states.replica(&namespace).map(|r| r.secret_key());
                send_reply(reply, res)
            }
            ReplicaAction::GetState { reply } => send_reply_with(reply, self, move |this| {
                let state = this.states.get_mut(&namespace)?;
                Ok(OpenState {
                    handles: state.handles,
                    sync: state.sync,
                    subscribers: state.replica.subscribers_count(),
                })
            }),
            ReplicaAction::HasNewsForUs { heads, reply } => {
                let res = self.store.has_news_for_us(namespace, &heads);
                send_reply(reply, res)
            }
        }
    }

    fn close(&mut self, namespace: NamespaceId) -> bool {
        let on_close_cb = |replica| self.store.close_replica(replica);
        self.states.close_with(namespace, on_close_cb)
    }

    fn close_all(&mut self) {
        let on_close_cb = |replica| self.store.close_replica(replica);
        self.states.close_all_with(on_close_cb);
    }

    fn open(&mut self, namespace: NamespaceId, opts: OpenOpts) -> Result<()> {
        let open_cb = || {
            let mut replica = self.store.open_replica(&namespace)?;
            if let Some(cb) = &self.content_status_callback {
                replica.set_content_status_callback(Arc::clone(cb));
            }
            Ok(replica)
        };
        self.states.open_with(namespace, opts, open_cb)
    }
}

struct OpenReplicas<S: store::Store>(HashMap<NamespaceId, OpenReplica<S>>);

// We need a manual impl here because the derive won't work unless we'd restrict to S: Default.
impl<S: store::Store> Default for OpenReplicas<S> {
    fn default() -> Self {
        Self(Default::default())
    }
}
impl<S: store::Store> OpenReplicas<S> {
    fn replica(&mut self, namespace: &NamespaceId) -> Result<&mut Replica<S::Instance>> {
        self.get_mut(namespace).map(|state| &mut state.replica)
    }

    fn get_mut(&mut self, namespace: &NamespaceId) -> Result<&mut OpenReplica<S>> {
        self.0.get_mut(namespace).context("replica not open")
    }

    fn replica_if_syncing(&mut self, namespace: &NamespaceId) -> Result<&mut Replica<S::Instance>> {
        let state = self.get_mut(namespace)?;
        if !state.sync {
            Err(anyhow!("sync is not enabled for replica"))
        } else {
            Ok(&mut state.replica)
        }
    }

    fn is_open(&self, namespace: &NamespaceId) -> bool {
        self.0.contains_key(namespace)
    }

    fn ensure_open(&self, namespace: &NamespaceId) -> Result<()> {
        match self.is_open(namespace) {
            true => Ok(()),
            false => Err(anyhow!("replica not open")),
        }
    }
    fn open_with(
        &mut self,
        namespace: NamespaceId,
        opts: OpenOpts,
        open_cb: impl Fn() -> Result<Replica<S::Instance>>,
    ) -> Result<()> {
        match self.0.entry(namespace) {
            hash_map::Entry::Vacant(e) => {
                let mut replica = open_cb()?;
                if let Some(sender) = opts.subscribe {
                    replica.subscribe(sender);
                }
                debug!(namespace = %namespace.fmt_short(), "open");
                let state = OpenReplica {
                    replica,
                    sync: opts.sync,
                    handles: 1,
                };
                e.insert(state);
            }
            hash_map::Entry::Occupied(mut e) => {
                let state = e.get_mut();
                state.handles += 1;
                state.sync = state.sync || opts.sync;
                if let Some(sender) = opts.subscribe {
                    state.replica.subscribe(sender);
                }
            }
        }
        Ok(())
    }
    fn close_with(
        &mut self,
        namespace: NamespaceId,
        on_close: impl Fn(Replica<S::Instance>),
    ) -> bool {
        match self.0.entry(namespace) {
            hash_map::Entry::Vacant(_e) => {
                warn!(namespace = %namespace.fmt_short(), "received close request for closed replica");
                true
            }
            hash_map::Entry::Occupied(mut e) => {
                let state = e.get_mut();
                state.handles = state.handles.wrapping_sub(1);
                if state.handles == 0 {
                    let (_, state) = e.remove_entry();
                    debug!(namespace = %namespace.fmt_short(), "close");
                    on_close(state.replica);
                    true
                } else {
                    false
                }
            }
        }
    }

    fn close_all_with(&mut self, on_close: impl Fn(Replica<S::Instance>)) {
        for (_namespace, state) in self.0.drain() {
            on_close(state.replica)
        }
    }
}

fn iter_to_channel<T: Send + 'static>(
    channel: flume::Sender<Result<T>>,
    iter: Result<impl Iterator<Item = Result<T>>>,
) -> Result<(), SendReplyError> {
    match iter {
        Err(err) => channel.send(Err(err)).map_err(send_reply_error)?,
        Ok(iter) => {
            for item in iter {
                channel.send(item).map_err(send_reply_error)?;
            }
        }
    }
    Ok(())
}

fn get_author<S: store::Store>(store: &S, id: &AuthorId) -> Result<Author> {
    store.get_author(id)?.context("author not found")
}

#[derive(Debug)]
struct SendReplyError;

fn send_reply<T>(sender: oneshot::Sender<T>, value: T) -> Result<(), SendReplyError> {
    sender.send(value).map_err(send_reply_error)
}

fn send_reply_with<T, S: store::Store>(
    sender: oneshot::Sender<Result<T>>,
    this: &mut Actor<S>,
    f: impl FnOnce(&mut Actor<S>) -> Result<T>,
) -> Result<(), SendReplyError> {
    sender.send(f(this)).map_err(send_reply_error)
}

fn send_reply_error<T>(_err: T) -> SendReplyError {
    SendReplyError
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn open_close() -> anyhow::Result<()> {
        let store = store::memory::Store::default();
        let sync = SyncHandle::spawn(store, None, "foo".into());
        let namespace = Namespace::new(&mut rand::rngs::OsRng {});
        sync.import_namespace(namespace.clone()).await?;
        sync.open(namespace.id(), Default::default()).await?;
        let (tx, rx) = flume::bounded(10);
        sync.subscribe(namespace.id(), tx).await?;
        sync.close(namespace.id()).await?;
        assert!(rx.recv_async().await.is_err());
        Ok(())
    }
}
