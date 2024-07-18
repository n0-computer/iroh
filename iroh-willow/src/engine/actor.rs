use std::{sync::Arc, thread::JoinHandle};

use anyhow::Result;
use futures_lite::stream::Stream;
use iroh_base::key::NodeId;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, error_span, trace, warn, Instrument};

use crate::{
    auth::{CapSelector, CapabilityPack, DelegateTo, InterestMap},
    form::{AuthForm, EntryForm, EntryOrForm},
    net::WillowConn,
    proto::{
        grouping::ThreeDRange,
        keys::{NamespaceId, NamespaceKind, UserId, UserSecretKey},
        meadowcap::{self, AccessMode},
        willow::{AuthorisedEntry, Entry},
    },
    session::{intents::Intent, run_session, Error, EventSender, Interests, SessionHandle},
    store::{
        entry::EntryOrigin,
        traits::{EntryReader, SecretStorage, Storage},
        Store,
    },
};

pub const INBOX_CAP: usize = 1024;
pub const SESSION_EVENT_CHANNEL_CAP: usize = 64;
pub const SESSION_UPDATE_CHANNEL_CAP: usize = 64;

#[derive(Debug, Clone)]
pub struct ActorHandle {
    inbox_tx: flume::Sender<Input>,
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
        let (inbox_tx, inbox_rx) = flume::bounded(INBOX_CAP);
        let join_handle = std::thread::Builder::new()
            .name("willow-actor".to_string())
            .spawn(move || {
                let span = error_span!("willow-actor", me=%me.fmt_short());
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
        self.inbox_tx.send_async(action).await?;
        Ok(())
    }

    pub async fn ingest_entry(&self, authorised_entry: AuthorisedEntry) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::IngestEntry {
            authorised_entry,
            origin: EntryOrigin::Local,
            reply,
        })
        .await?;
        reply_rx.await??;
        Ok(())
    }

    pub async fn insert_entry(&self, entry: Entry, auth: impl Into<AuthForm>) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::InsertEntry {
            entry: EntryOrForm::Entry(entry),
            auth: auth.into(),
            reply,
        })
        .await?;
        reply_rx.await??;
        Ok(())
    }

    pub async fn insert(
        &self,
        form: EntryForm,
        authorisation: impl Into<AuthForm>,
    ) -> Result<(Entry, bool)> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::InsertEntry {
            entry: EntryOrForm::Form(form),
            auth: authorisation.into(),
            reply,
        })
        .await?;
        let inserted = reply_rx.await??;
        Ok(inserted)
    }

    pub async fn insert_secret(&self, secret: impl Into<meadowcap::SecretKey>) -> Result<()> {
        let secret = secret.into();
        let (reply, reply_rx) = oneshot::channel();
        self.send(Input::InsertSecret { secret, reply }).await?;
        reply_rx.await??;
        Ok(())
    }

    pub async fn get_entries(
        &self,
        namespace: NamespaceId,
        range: ThreeDRange,
    ) -> Result<impl Stream<Item = anyhow::Result<Entry>>> {
        let (tx, rx) = flume::bounded(1024);
        self.send(Input::GetEntries {
            namespace,
            reply: tx,
            range,
        })
        .await?;
        Ok(rx.into_stream())
    }

    pub async fn init_session(
        &self,
        conn: WillowConn,
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
}

impl Drop for ActorHandle {
    fn drop(&mut self) {
        // this means we're dropping the last reference
        if let Some(handle) = Arc::get_mut(&mut self.join_handle) {
            let handle = handle.take().expect("can only drop once");
            self.inbox_tx.send(Input::Shutdown { reply: None }).ok();
            if let Err(err) = handle.join() {
                warn!(?err, "Failed to join sync actor");
            }
        }
    }
}

#[derive(derive_more::Debug, strum::Display)]
pub enum Input {
    InitSession {
        conn: WillowConn,
        intents: Vec<Intent>,
        reply: oneshot::Sender<Result<SessionHandle>>,
    },
    GetEntries {
        namespace: NamespaceId,
        range: ThreeDRange,
        #[debug(skip)]
        reply: flume::Sender<Result<Entry>>,
    },
    IngestEntry {
        authorised_entry: AuthorisedEntry,
        origin: EntryOrigin,
        reply: oneshot::Sender<Result<bool>>,
    },
    InsertEntry {
        entry: EntryOrForm,
        auth: AuthForm,
        reply: oneshot::Sender<Result<(Entry, bool), Error>>,
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
}

#[derive(Debug)]
struct Actor<S: Storage> {
    inbox_rx: flume::Receiver<Input>,
    store: Store<S>,
    next_session_id: u64,
    tasks: JoinSet<()>,
}

impl<S: Storage> Actor<S> {
    pub fn new(store: Store<S>, inbox_rx: flume::Receiver<Input>) -> Self {
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
                msg = self.inbox_rx.recv_async() => match msg {
                    Err(_) => break,
                    Ok(Input::Shutdown { reply }) => {
                        self.tasks.shutdown().await;
                        drop(self);
                        if let Some(reply) = reply {
                            reply.send(()).ok();
                        }
                        break;
                    }
                    Ok(msg) => {
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
                let cancel_token = CancellationToken::new();

                let (update_tx, update_rx) = mpsc::channel(SESSION_UPDATE_CHANNEL_CAP);
                let (event_tx, event_rx) = mpsc::channel(SESSION_EVENT_CHANNEL_CAP);
                let update_rx = tokio_stream::wrappers::ReceiverStream::new(update_rx);

                let peer = conn.peer;
                let future = run_session(
                    store,
                    conn,
                    intents,
                    cancel_token.clone(),
                    session_id,
                    EventSender(event_tx.clone()),
                    update_rx,
                )
                .instrument(error_span!("session", peer = %peer.fmt_short()));

                self.tasks.spawn_local(async move {
                    if let Err(err) = future.await {
                        tracing::debug!(?peer, ?session_id, ?err, "session failed");
                    }
                });

                let handle = SessionHandle {
                    cancel_token,
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
                    Err(err) => reply.send(Err(err)).map_err(send_reply_error),
                    Ok(snapshot) => {
                        self.tasks.spawn_local(async move {
                            let iter = snapshot.get_entries(namespace, &range);
                            for entry in iter {
                                if reply.send_async(entry).await.is_err() {
                                    break;
                                }
                            }
                        });
                        Ok(())
                    }
                }
            }
            Input::IngestEntry {
                authorised_entry,
                origin,
                reply,
            } => {
                let res = self.store.entries().ingest(&authorised_entry, origin);
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
