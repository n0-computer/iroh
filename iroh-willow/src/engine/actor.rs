use std::{sync::Arc, thread::JoinHandle};

use anyhow::Result;
use futures_lite::{stream::Stream, StreamExt};
use iroh_base::key::NodeId;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, error_span, trace, warn, Instrument};

use crate::{
    form::{AuthForm, EntryOrForm},
    interest::{CapSelector, CapabilityPack, DelegateTo, InterestMap, Interests},
    net::ConnHandle,
    proto::{
        data_model::{AuthorisedEntry, Path, SubspaceId},
        grouping::{Area, Range3d},
        keys::{NamespaceId, NamespaceKind, UserId, UserSecretKey},
        meadowcap::{self, AccessMode},
    },
    session::{intents::Intent, run_session, Error, EventSender, SessionHandle},
    store::{
        traits::{
            EntryOrigin, EntryReader, EntryStorage, SecretStorage, Storage, StoreEvent,
            SubscribeParams,
        },
        Store,
    },
};

pub const INBOX_CAP: usize = 1024;
pub const SESSION_EVENT_CHANNEL_CAP: usize = 64;
pub const SESSION_UPDATE_CHANNEL_CAP: usize = 64;

/// Handle to a Willow storage thread.
#[derive(Debug, Clone)]
pub struct ActorHandle {
    inbox_tx: tokio::sync::mpsc::Sender<Input>,
    join_handle: Arc<Option<JoinHandle<()>>>,
}

impl ActorHandle {
    pub fn spawn_memory(payloads: iroh_blobs::store::mem::Store, me: NodeId) -> Self {
        Self::spawn(move || crate::store::memory::Store::new(payloads), me)
    }

    pub fn spawn<S: Storage>(
        create_store: impl 'static + Send + FnOnce() -> S,
        me: NodeId,
    ) -> ActorHandle {
        let (inbox_tx, inbox_rx) = tokio::sync::mpsc::channel(INBOX_CAP);
        let join_handle = std::thread::Builder::new()
            .name("willow".to_string())
            .spawn(move || {
                let span = error_span!("willow", me=%me.fmt_short());
                let _guard = span.enter();
                let store = Store::new((create_store)());
                let actor = Actor::new(store, inbox_rx);
                if let Err(error) = actor.run() {
                    error!(?error, "willow actor failed");
                };
            })
            .expect("failed to spawn willow-actor thread");
        let join_handle = Arc::new(Some(join_handle));
        ActorHandle {
            inbox_tx,
            join_handle,
        }
    }

    async fn send(&self, action: Input) -> Result<()> {
        self.inbox_tx.send(action).await?;
        Ok(())
    }

    pub async fn ingest_entry(&self, authorised_entry: AuthorisedEntry) -> Result<bool> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::IngestEntry {
            authorised_entry,
            origin: EntryOrigin::Local,
            reply,
        })
        .await?;
        let inserted = reply_rx.await??;
        Ok(inserted)
    }

    pub async fn insert_entry(
        &self,
        entry: impl Into<EntryOrForm>,
        auth: impl Into<AuthForm>,
    ) -> Result<(AuthorisedEntry, bool)> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::InsertEntry {
            entry: entry.into(),
            auth: auth.into(),
            reply,
        })
        .await?;
        let (entry, inserted) = reply_rx.await??;
        Ok((entry, inserted))
    }

    pub async fn insert_secret(&self, secret: impl Into<meadowcap::SecretKey>) -> Result<()> {
        let secret = secret.into();
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::InsertSecret { secret, reply }).await?;
        reply_rx.await??;
        Ok(())
    }

    pub async fn get_entry(
        &self,
        namespace: NamespaceId,
        subspace: SubspaceId,
        path: Path,
    ) -> Result<Option<AuthorisedEntry>> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::GetEntry {
            namespace,
            subspace,
            path,
            reply,
        })
        .await?;
        reply_rx.await?
    }

    pub async fn get_entries(
        &self,
        namespace: NamespaceId,
        range: Range3d,
    ) -> Result<impl Stream<Item = anyhow::Result<AuthorisedEntry>>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        self.send(Input::GetEntries {
            namespace,
            reply: tx,
            range,
        })
        .await?;
        Ok(ReceiverStream::new(rx))
    }

    pub(crate) async fn init_session(
        &self,
        conn: ConnHandle,
        intents: Vec<Intent>,
    ) -> Result<SessionHandle> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::InitSession {
            conn,
            intents,
            reply,
        })
        .await?;
        reply_rx.await?
    }

    // pub async fn subscribe_namespace(&self, namespace: NamespaceId) -> Result<Subscriber> {}

    pub async fn create_namespace(
        &self,
        kind: NamespaceKind,
        owner: UserId,
    ) -> Result<NamespaceId> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::CreateNamespace { kind, owner, reply })
            .await?;
        reply_rx.await?
    }

    pub async fn create_user(&self) -> Result<UserId> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::CreateUser { reply }).await?;
        reply_rx.await?
    }

    pub async fn delegate_caps(
        &self,
        from: CapSelector,
        access_mode: AccessMode,
        to: DelegateTo,
    ) -> Result<Vec<CapabilityPack>> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::DelegateCaps {
            from,
            access_mode,
            to,
            store: false,
            reply,
        })
        .await?;
        reply_rx.await?
    }

    pub async fn import_caps(&self, caps: Vec<CapabilityPack>) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::ImportCaps { caps, reply }).await?;
        reply_rx.await?
    }

    pub async fn resolve_interests(&self, interests: Interests) -> Result<InterestMap> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::ResolveInterests { interests, reply })
            .await?;
        reply_rx.await?
    }

    pub async fn shutdown(&self) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::Shutdown { reply: Some(reply) }).await?;
        reply_rx.await?;
        Ok(())
    }

    pub async fn subscribe_area(
        &self,
        namespace: NamespaceId,
        area: Area,
        params: SubscribeParams,
        sender: mpsc::Sender<StoreEvent>,
    ) -> Result<()> {
        self.send(Input::SubscribeArea {
            namespace,
            area,
            params,
            sender,
        })
        .await?;
        Ok(())
    }

    pub async fn resume_subscription(
        &self,
        progress_id: u64,
        namespace: NamespaceId,
        area: Area,
        params: SubscribeParams,
        sender: mpsc::Sender<StoreEvent>,
    ) -> Result<()> {
        self.send(Input::ResumeSubscription {
            progress_id,
            namespace,
            area,
            params,
            sender,
        })
        .await?;
        Ok(())
    }
}

impl Drop for ActorHandle {
    fn drop(&mut self) {
        // this means we're dropping the last reference
        if let Some(handle) = Arc::get_mut(&mut self.join_handle) {
            // gain ownership of handle
            let handle = handle.take().expect("can only drop once");

            // gain ownership of inbox_tx
            let (dumb, _) = tokio::sync::mpsc::channel(1);
            let inbox_tx = std::mem::replace(&mut self.inbox_tx, dumb);

            // shutdown
            let shutdown = move || {
                inbox_tx.blocking_send(Input::Shutdown { reply: None }).ok();
                if let Err(err) = handle.join() {
                    warn!(?err, "Failed to join sync actor");
                }
            };

            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    // We shouldn't block the runtime
                    runtime.spawn_blocking(shutdown);
                }
                Err(_) => {
                    // We can do everything sync
                    shutdown();
                }
            }
        }
    }
}

#[derive(derive_more::Debug, strum::Display)]
pub enum Input {
    InitSession {
        conn: ConnHandle,
        intents: Vec<Intent>,
        reply: oneshot::Sender<Result<SessionHandle>>,
    },
    GetEntries {
        namespace: NamespaceId,
        range: Range3d,
        reply: mpsc::Sender<Result<AuthorisedEntry>>,
    },
    GetEntry {
        namespace: NamespaceId,
        subspace: SubspaceId,
        path: Path,
        reply: oneshot::Sender<Result<Option<AuthorisedEntry>>>,
    },
    IngestEntry {
        authorised_entry: AuthorisedEntry,
        origin: EntryOrigin,
        reply: oneshot::Sender<Result<bool>>,
    },
    InsertEntry {
        entry: EntryOrForm,
        auth: AuthForm,
        reply: oneshot::Sender<Result<(AuthorisedEntry, bool), Error>>,
    },
    InsertSecret {
        secret: meadowcap::SecretKey,
        reply: oneshot::Sender<Result<()>>,
    },
    CreateNamespace {
        kind: NamespaceKind,
        owner: UserId,
        reply: oneshot::Sender<Result<NamespaceId>>,
    },
    CreateUser {
        reply: oneshot::Sender<Result<UserId>>,
    },
    ImportCaps {
        caps: Vec<CapabilityPack>,
        reply: oneshot::Sender<Result<()>>,
    },
    ResolveInterests {
        interests: Interests,
        reply: oneshot::Sender<Result<InterestMap>>,
    },
    DelegateCaps {
        from: CapSelector,
        access_mode: AccessMode,
        to: DelegateTo,
        store: bool,
        reply: oneshot::Sender<Result<Vec<CapabilityPack>>>,
    },
    Shutdown {
        #[debug(skip)]
        reply: Option<oneshot::Sender<()>>,
    },
    SubscribeArea {
        namespace: NamespaceId,
        area: Area,
        params: SubscribeParams,
        sender: mpsc::Sender<StoreEvent>,
    },
    ResumeSubscription {
        progress_id: u64,
        namespace: NamespaceId,
        area: Area,
        params: SubscribeParams,
        sender: mpsc::Sender<StoreEvent>,
    },
}

#[derive(Debug)]
struct Actor<S: Storage> {
    inbox_rx: tokio::sync::mpsc::Receiver<Input>,
    store: Store<S>,
    next_session_id: u64,
    tasks: JoinSet<()>,
}

impl<S: Storage> Actor<S> {
    pub fn new(store: Store<S>, inbox_rx: tokio::sync::mpsc::Receiver<Input>) -> Self {
        Self {
            store,
            inbox_rx,
            next_session_id: 0,
            tasks: Default::default(),
        }
    }

    pub fn run(self) -> Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to start current-thread runtime for willow actor");
        let local_set = tokio::task::LocalSet::new();
        local_set.block_on(&rt, async move { self.run_async().await })
    }

    async fn run_async(mut self) -> Result<()> {
        loop {
            tokio::select! {
                msg = self.inbox_rx.recv() => match msg {
                    None => break,
                    Some(Input::Shutdown { reply }) => {
                        self.tasks.shutdown().await;
                        drop(self);
                        if let Some(reply) = reply {
                            reply.send(()).ok();
                        }
                        break;
                    }
                    Some(msg) => {
                        if self.handle_message(msg).await.is_err() {
                            warn!("failed to send reply: receiver dropped");
                        }
                    }
                },
            };
        }
        Ok(())
    }

    fn next_session_id(&mut self) -> u64 {
        let id = self.next_session_id;
        self.next_session_id += 1;
        id
    }

    async fn handle_message(&mut self, message: Input) -> Result<(), SendReplyError> {
        trace!(%message, "tick: handle_message");
        match message {
            Input::Shutdown { .. } => unreachable!("handled in run"),
            Input::InitSession {
                conn,
                intents,
                reply,
            } => {
                let session_id = self.next_session_id();
                let store = self.store.clone();

                let (update_tx, update_rx) = mpsc::channel(SESSION_UPDATE_CHANNEL_CAP);
                let (event_tx, event_rx) = mpsc::channel(SESSION_EVENT_CHANNEL_CAP);
                let update_rx = tokio_stream::wrappers::ReceiverStream::new(update_rx);

                let peer = conn.peer;
                let future = run_session(
                    store,
                    conn,
                    intents,
                    session_id,
                    EventSender(event_tx),
                    update_rx,
                )
                .instrument(error_span!("session", peer = %peer.fmt_short()));

                self.tasks.spawn_local(async move {
                    if let Err(err) = future.await {
                        debug!(?peer, ?session_id, ?err, "session failed");
                    }
                });

                let handle = SessionHandle {
                    update_tx,
                    event_rx,
                };
                send_reply(reply, Ok(handle))
            }
            Input::GetEntries {
                namespace,
                range,
                reply,
            } => {
                let snapshot = self.store.entries().snapshot();
                match snapshot {
                    Err(err) => reply.send(Err(err)).await.map_err(send_reply_error),
                    Ok(snapshot) => {
                        self.tasks.spawn_local(async move {
                            match snapshot.get_authorised_entries(namespace, &range) {
                                Ok(iter) => {
                                    for entry in iter {
                                        if reply.send(entry).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                                Err(err) => {
                                    let _ = reply.send(Err(err)).await;
                                }
                            }
                        });
                        Ok(())
                    }
                }
            }
            Input::GetEntry {
                namespace,
                subspace,
                path,
                reply,
            } => {
                let res = self
                    .store
                    .entries()
                    .reader()
                    .get_entry(namespace, subspace, &path);
                send_reply(reply, res)
            }
            Input::IngestEntry {
                authorised_entry,
                origin,
                reply,
            } => {
                let res = self.store.entries().ingest_entry(&authorised_entry, origin);
                send_reply(reply, res)
            }
            Input::InsertEntry { entry, auth, reply } => {
                let res = self.store.insert_entry(entry, auth).await;
                let res = res.map_err(Into::into);
                send_reply(reply, res)
            }
            Input::InsertSecret { secret, reply } => {
                let res = self.store.secrets().insert(secret);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            Input::CreateNamespace { kind, owner, reply } => {
                let res = self
                    .store
                    .create_namespace(&mut rand::thread_rng(), kind, owner);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            Input::CreateUser { reply } => {
                let secret = UserSecretKey::generate(&mut rand::thread_rng());
                let res = self.store.secrets().insert_user(secret);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            Input::ImportCaps { caps, reply } => {
                let res = self.store.auth().import_caps(caps);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            Input::DelegateCaps {
                from,
                access_mode,
                to,
                store,
                reply,
            } => {
                let res = self
                    .store
                    .auth()
                    .delegate_full_caps(from, access_mode, to, store);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            Input::ResolveInterests { interests, reply } => {
                let res = self.store.auth().resolve_interests(interests);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            Input::SubscribeArea {
                namespace,
                area,
                params,
                sender,
            } => {
                let store = self.store.clone();
                self.tasks.spawn_local(async move {
                    // TODO: We wouldn't need to manually forward in a loop here if subscribe_area took a sender
                    // instead of returning a stream.
                    let mut stream = store.entries().subscribe_area(namespace, area, params);
                    while let Some(event) = stream.next().await {
                        if sender.send(event).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(())
            }
            Input::ResumeSubscription {
                progress_id,
                namespace,
                area,
                params,
                sender,
            } => {
                let store = self.store.clone();
                self.tasks.spawn_local(async move {
                    let mut stream =
                        store
                            .entries()
                            .resume_subscription(progress_id, namespace, area, params);
                    while let Some(event) = stream.next().await {
                        if sender.send(event).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
struct SendReplyError;

fn send_reply<T>(sender: oneshot::Sender<T>, value: T) -> Result<(), SendReplyError> {
    sender.send(value).map_err(send_reply_error)
}

fn send_reply_error<T>(_err: T) -> SendReplyError {
    SendReplyError
}
