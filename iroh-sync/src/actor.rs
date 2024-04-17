//! This contains an actor spawned on a separate thread to process replica and store operations.

use std::{
    collections::{hash_map, HashMap},
    num::NonZeroU64,
    sync::Arc,
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use iroh_base::hash::Hash;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing::{debug, error, error_span, trace, warn};

use crate::{
    ranger::Message,
    store::{
        fs::{ContentHashesIterator, StoreInstance},
        DownloadPolicy, ImportNamespaceOutcome, Query, Store,
    },
    Author, AuthorHeads, AuthorId, Capability, CapabilityKind, Content, ContentStore, Event,
    NamespaceId, NamespaceSecret, PeerIdBytes, Replica, ReplicaInfo, SignedEntry, SyncOutcome,
};

const ACTION_CAP: usize = 1024;
const MAX_COMMIT_DELAY: Duration = Duration::from_millis(500);

#[derive(derive_more::Debug, derive_more::Display)]
enum Action {
    #[display("NewAuthor")]
    ImportAuthor {
        author: Author,
        #[debug("reply")]
        reply: oneshot::Sender<Result<AuthorId>>,
    },
    #[display("ExportAuthor")]
    ExportAuthor {
        author: AuthorId,
        #[debug("reply")]
        reply: oneshot::Sender<Result<Option<Author>>>,
    },
    #[display("DeleteAuthor")]
    DeleteAuthor {
        author: AuthorId,
        #[debug("reply")]
        reply: oneshot::Sender<Result<()>>,
    },
    #[display("NewReplica")]
    ImportNamespace {
        capability: Capability,
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
        reply: flume::Sender<Result<(NamespaceId, CapabilityKind)>>,
    },
    #[display("ContentHashes")]
    ContentHashes {
        #[debug("reply")]
        reply: oneshot::Sender<Result<ContentHashesIterator>>,
    },
    #[display("Replica({}, {})", _0.fmt_short(), _1)]
    Replica(NamespaceId, ReplicaAction),
    #[display("Shutdown")]
    Shutdown {
        #[debug("reply")]
        reply: Option<oneshot::Sender<Store>>,
    },
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
        content: Content,
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
    GetExact {
        author: AuthorId,
        key: Bytes,
        include_empty: bool,
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
        reply: oneshot::Sender<Result<NamespaceSecret>>,
    },
    HasNewsForUs {
        heads: AuthorHeads,
        #[debug("reply")]
        reply: oneshot::Sender<Result<Option<NonZeroU64>>>,
    },
    SetDownloadPolicy {
        policy: DownloadPolicy,
        #[debug("reply")]
        reply: oneshot::Sender<Result<()>>,
    },
    GetDownloadPolicy {
        #[debug("reply")]
        reply: oneshot::Sender<Result<DownloadPolicy>>,
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
struct OpenReplica {
    info: ReplicaInfo,
    sync: bool,
    handles: usize,
}

/// The [`SyncHandle`] controls an actor thread which executes replica and store operations.
///
/// The [`SyncHandle`] exposes async methods which all send messages into the actor thread, usually
/// returning something via a return channel. The actor thread itself is a regular [`std::thread`]
/// which processes incoming messages sequentially.
///
/// The handle is cheaply cloneable. Once the last clone is dropped, the actor thread is joined.
/// The thread will finish processing all messages in the channel queue, and then exit.
/// To prevent this last drop from blocking the calling thread, you can call [`SyncHandle::shutdown`]
/// and await its result before dropping the last [`SyncHandle`]. This ensures that
/// waiting for the actor to finish happens in an async context, and therefore that the final
/// [`SyncHandle::drop`] will not block.
#[derive(Debug, Clone)]
pub struct SyncHandle {
    tx: flume::Sender<Action>,
    join_handle: Arc<Option<JoinHandle<()>>>,
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
    pub fn spawn<C: ContentStore + 'static>(
        store: Store,
        content_store: C,
        me: String,
    ) -> SyncHandle {
        let (action_tx, action_rx) = flume::bounded(ACTION_CAP);
        let actor = Actor {
            store,
            states: Default::default(),
            action_rx,
            content_store,
        };
        let join_handle = std::thread::Builder::new()
            .name("sync-actor".to_string())
            .spawn(move || {
                let span = error_span!("sync", %me);
                let _enter = span.enter();

                if let Err(err) = actor.run() {
                    error!("Sync actor closed with error: {err:?}");
                }
            })
            .expect("failed to spawn thread");
        let join_handle = Arc::new(Some(join_handle));
        SyncHandle {
            tx: action_tx,
            join_handle,
        }
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
        content: Content,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::InsertRemote {
            entry,
            from,
            content,
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

    pub async fn get_exact(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: Bytes,
        include_empty: bool,
    ) -> Result<Option<SignedEntry>> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::GetExact {
            author,
            key,
            include_empty,
            reply,
        };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn drop_replica(&self, namespace: NamespaceId) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::DropReplica { reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn export_secret_key(&self, namespace: NamespaceId) -> Result<NamespaceSecret> {
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

    pub async fn shutdown(&self) -> Result<Store> {
        let (reply, rx) = oneshot::channel();
        let action = Action::Shutdown { reply: Some(reply) };
        self.send(action).await.ok();
        Ok(rx.await?)
    }

    pub async fn list_authors(&self, reply: flume::Sender<Result<AuthorId>>) -> Result<()> {
        self.send(Action::ListAuthors { reply }).await
    }

    pub async fn list_replicas(
        &self,
        reply: flume::Sender<Result<(NamespaceId, CapabilityKind)>>,
    ) -> Result<()> {
        self.send(Action::ListReplicas { reply }).await
    }

    pub async fn import_author(&self, author: Author) -> Result<AuthorId> {
        let (reply, rx) = oneshot::channel();
        self.send(Action::ImportAuthor { author, reply }).await?;
        rx.await?
    }

    pub async fn export_author(&self, author: AuthorId) -> Result<Option<Author>> {
        let (reply, rx) = oneshot::channel();
        self.send(Action::ExportAuthor { author, reply }).await?;
        rx.await?
    }

    pub async fn delete_author(&self, author: AuthorId) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(Action::DeleteAuthor { author, reply }).await?;
        rx.await?
    }

    pub async fn import_namespace(&self, capability: Capability) -> Result<NamespaceId> {
        let (reply, rx) = oneshot::channel();
        self.send(Action::ImportNamespace { capability, reply })
            .await?;
        rx.await?
    }

    pub async fn get_download_policy(&self, namespace: NamespaceId) -> Result<DownloadPolicy> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::GetDownloadPolicy { reply };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn set_download_policy(
        &self,
        namespace: NamespaceId,
        policy: DownloadPolicy,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let action = ReplicaAction::SetDownloadPolicy { reply, policy };
        self.send_replica(namespace, action).await?;
        rx.await?
    }

    pub async fn content_hashes(&self) -> Result<ContentHashesIterator> {
        let (reply, rx) = oneshot::channel();
        self.send(Action::ContentHashes { reply }).await?;
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

impl Drop for SyncHandle {
    fn drop(&mut self) {
        // this means we're dropping the last reference
        if let Some(handle) = Arc::get_mut(&mut self.join_handle) {
            self.tx.send(Action::Shutdown { reply: None }).ok();
            let handle = handle.take().expect("this can only run once");
            if let Err(err) = handle.join() {
                warn!(?err, "Failed to join sync actor");
            }
        }
    }
}

struct Actor<C> {
    store: Store,
    content_store: C,
    states: OpenReplicas,
    action_rx: flume::Receiver<Action>,
}

impl<C: ContentStore> Actor<C> {
    fn run(mut self) -> Result<()> {
        loop {
            let action = match self.action_rx.recv_timeout(MAX_COMMIT_DELAY) {
                Ok(action) => action,
                Err(flume::RecvTimeoutError::Timeout) => {
                    if let Err(cause) = self.store.flush() {
                        error!(?cause, "failed to flush store");
                    }
                    continue;
                }
                Err(flume::RecvTimeoutError::Disconnected) => {
                    debug!("action channel disconnected");
                    break;
                }
            };
            trace!(%action, "tick");
            match action {
                Action::Shutdown { reply } => {
                    if let Err(cause) = self.store.flush() {
                        warn!(?cause, "failed to flush store");
                    }
                    self.close_all();
                    if let Some(reply) = reply {
                        send_reply(reply, self.store).ok();
                    }
                    break;
                }
                action => {
                    if self.on_action(action).is_err() {
                        warn!("failed to send reply: receiver dropped");
                    }
                }
            }
        }
        debug!("shutdown");
        Ok(())
    }

    fn on_action(&mut self, action: Action) -> Result<(), SendReplyError> {
        match action {
            Action::Shutdown { .. } => {
                unreachable!("Shutdown action should be handled in run()")
            }
            Action::ImportAuthor { author, reply } => {
                let id = author.id();
                send_reply(reply, self.store.import_author(author).map(|_| id))
            }
            Action::ExportAuthor { author, reply } => {
                send_reply(reply, self.store.get_author(&author))
            }
            Action::DeleteAuthor { author, reply } => {
                send_reply(reply, self.store.delete_author(author))
            }
            Action::ImportNamespace { capability, reply } => send_reply_with(reply, self, |this| {
                let id = capability.id();
                let outcome = this.store.import_namespace(capability.clone())?;
                if let ImportNamespaceOutcome::Upgraded = outcome {
                    if let Ok(state) = this.states.get_mut(&id) {
                        state.info.merge_capability(capability)?;
                    }
                }
                Ok(id)
            }),
            Action::ListAuthors { reply } => iter_to_channel(
                reply,
                self.store
                    .list_authors()
                    .map(|a| a.map(|a| a.map(|a| a.id()))),
            ),
            Action::ListReplicas { reply } => iter_to_channel(reply, self.store.list_namespaces()),
            Action::ContentHashes { reply } => {
                send_reply_with(reply, self, |this| this.store.content_hashes())
            }
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
                let state = this.states.get_mut(&namespace)?;
                state.info.subscribe(sender);
                Ok(())
            }),
            ReplicaAction::Unsubscribe { sender, reply } => send_reply_with(reply, self, |this| {
                let state = this.states.get_mut(&namespace)?;
                state.info.unsubscribe(&sender);
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
            } => send_reply_with(reply, self, move |this| {
                let author = get_author(&mut this.store, &author)?;
                let mut replica =
                    this.states
                        .replica(namespace, &mut this.store, &this.content_store)?;
                replica.insert(&key, &author, hash, len)?;
                Ok(())
            }),
            ReplicaAction::DeletePrefix { author, key, reply } => {
                send_reply_with(reply, self, |this| {
                    let author = get_author(&mut this.store, &author)?;
                    let mut replica =
                        this.states
                            .replica(namespace, &mut this.store, &this.content_store)?;
                    let res = replica.delete_prefix(&key, &author)?;
                    Ok(res)
                })
            }
            ReplicaAction::InsertRemote {
                entry,
                from,
                content,
                reply,
            } => send_reply_with(reply, self, move |this| {
                let mut replica = this.states.replica_if_syncing(
                    &namespace,
                    &mut this.store,
                    &this.content_store,
                )?;
                replica.insert_remote_entry(entry, from, content)?;
                Ok(())
            }),

            ReplicaAction::SyncInitialMessage { reply } => {
                send_reply_with(reply, self, move |this| {
                    let mut replica = this.states.replica_if_syncing(
                        &namespace,
                        &mut this.store,
                        &this.content_store,
                    )?;
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
                let mut replica = this.states.replica_if_syncing(
                    &namespace,
                    &mut this.store,
                    &this.content_store,
                )?;
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
            ReplicaAction::GetExact {
                author,
                key,
                include_empty,
                reply,
            } => send_reply_with(reply, self, move |this| {
                this.states.ensure_open(&namespace)?;
                this.store.get_exact(namespace, author, key, include_empty)
            }),
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
                let res = self
                    .states
                    .get_mut(&namespace)
                    .and_then(|state| Ok(state.info.capability.secret_key()?.clone()));
                send_reply(reply, res)
            }
            ReplicaAction::GetState { reply } => send_reply_with(reply, self, move |this| {
                let state = this.states.get_mut(&namespace)?;
                let handles = state.handles;
                let sync = state.sync;
                let subscribers = state.info.subscribers_count();
                Ok(OpenState {
                    handles,
                    sync,
                    subscribers,
                })
            }),
            ReplicaAction::HasNewsForUs { heads, reply } => {
                let res = self.store.has_news_for_us(namespace, &heads);
                send_reply(reply, res)
            }
            ReplicaAction::SetDownloadPolicy { policy, reply } => {
                send_reply(reply, self.store.set_download_policy(&namespace, policy))
            }
            ReplicaAction::GetDownloadPolicy { reply } => {
                send_reply(reply, self.store.get_download_policy(&namespace))
            }
        }
    }

    fn close(&mut self, namespace: NamespaceId) -> bool {
        let res = self.states.close(namespace);
        if res {
            self.store.close_replica(namespace);
        }
        res
    }

    fn close_all(&mut self) {
        for id in self.states.close_all() {
            self.store.close_replica(id);
        }
    }

    fn open(&mut self, namespace: NamespaceId, opts: OpenOpts) -> Result<()> {
        let open_cb = || {
            let info = self.store.load_replica_info(&namespace)?;
            Ok(info)
        };
        self.states.open_with(namespace, opts, open_cb)
    }
}

#[derive(Default)]
struct OpenReplicas(HashMap<NamespaceId, OpenReplica>);

impl OpenReplicas {
    fn replica<'a, 'b, C: ContentStore>(
        &'a mut self,
        namespace: NamespaceId,
        store: &'b mut Store,
        content_store: &'b C,
    ) -> Result<Replica<'b, 'b, C, &'a mut ReplicaInfo>> {
        let state = self.get_mut(&namespace)?;
        Ok(Replica::new(
            StoreInstance::new(state.info.capability.id(), store),
            content_store,
            &mut state.info,
        ))
    }

    fn replica_if_syncing<'a, 'b, C: ContentStore>(
        &'a mut self,
        namespace: &NamespaceId,
        store: &'b mut Store,
        content_store: &'b C,
    ) -> Result<Replica<'b, 'b, C, &'a mut ReplicaInfo>> {
        let state = self.get_mut(namespace)?;
        anyhow::ensure!(state.sync, "sync is not enabled for replica");
        Ok(Replica::new(
            StoreInstance::new(state.info.capability.id(), store),
            content_store,
            &mut state.info,
        ))
    }

    fn get_mut(&mut self, namespace: &NamespaceId) -> Result<&mut OpenReplica> {
        self.0.get_mut(namespace).context("replica not open")
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
        mut open_cb: impl FnMut() -> Result<ReplicaInfo>,
    ) -> Result<()> {
        match self.0.entry(namespace) {
            hash_map::Entry::Vacant(e) => {
                let mut info = open_cb()?;
                if let Some(sender) = opts.subscribe {
                    info.subscribe(sender);
                }
                debug!(namespace = %namespace.fmt_short(), "open");
                let state = OpenReplica {
                    info,
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
                    state.info.subscribe(sender);
                }
            }
        }
        Ok(())
    }

    fn close(&mut self, namespace: NamespaceId) -> bool {
        match self.0.entry(namespace) {
            hash_map::Entry::Vacant(_e) => {
                warn!(namespace = %namespace.fmt_short(), "received close request for closed replica");
                true
            }
            hash_map::Entry::Occupied(mut e) => {
                let state = e.get_mut();
                state.handles = state.handles.wrapping_sub(1);
                if state.handles == 0 {
                    let _ = e.remove_entry();
                    debug!(namespace = %namespace.fmt_short(), "close");
                    true
                } else {
                    false
                }
            }
        }
    }

    fn close_all(&mut self) -> impl Iterator<Item = NamespaceId> + '_ {
        self.0.drain().map(|(n, _s)| n)
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

fn get_author(store: &mut Store, id: &AuthorId) -> Result<Author> {
    store.get_author(id)?.context("author not found")
}

#[derive(Debug)]
struct SendReplyError;

fn send_reply<T>(sender: oneshot::Sender<T>, value: T) -> Result<(), SendReplyError> {
    sender.send(value).map_err(send_reply_error)
}

fn send_reply_with<T, C>(
    sender: oneshot::Sender<Result<T>>,
    this: &mut Actor<C>,
    f: impl FnOnce(&mut Actor<C>) -> Result<T>,
) -> Result<(), SendReplyError> {
    sender.send(f(this)).map_err(send_reply_error)
}

fn send_reply_error<T>(_err: T) -> SendReplyError {
    SendReplyError
}

#[cfg(test)]
mod tests {
    use crate::{store, NoopContentStore};

    use super::*;
    #[tokio::test]
    async fn open_close() -> anyhow::Result<()> {
        let store = store::Store::memory();
        let sync = SyncHandle::spawn(store, NoopContentStore, "foo".into());
        let namespace = NamespaceSecret::new(&mut rand::rngs::OsRng {});
        let id = namespace.id();
        sync.import_namespace(namespace.into()).await?;
        sync.open(id, Default::default()).await?;
        let (tx, rx) = flume::bounded(10);
        sync.subscribe(id, tx).await?;
        sync.close(id).await?;
        assert!(rx.recv_async().await.is_err());
        Ok(())
    }
}
