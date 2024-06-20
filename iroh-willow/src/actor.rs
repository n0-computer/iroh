use std::{collections::HashMap, sync::Arc, thread::JoinHandle};

use anyhow::Result;
use futures_lite::{future::Boxed as BoxFuture, stream::Stream, StreamExt};
use futures_util::future::{self, FutureExt};
use iroh_base::key::NodeId;
use tokio::{sync::oneshot, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, error_span, trace, warn, Instrument};

use crate::{
    form::{AuthForm, EntryForm, EntryOrForm},
    proto::{
        grouping::ThreeDRange,
        keys::{NamespaceId, NamespaceKind, UserId, UserSecretKey},
        meadowcap::{self, AccessMode},
        willow::{AuthorisedEntry, Entry},
    },
    session::{Channels, Error, InitialTransmission, Role, Session, SessionId, SessionInit},
    store::{
        auth::{CapSelector, CapabilityPack, DelegateTo},
        traits::{EntryReader, SecretStorage, Storage},
        Origin, Store,
    },
    util::task::{JoinMap, TaskKey},
};

pub const INBOX_CAP: usize = 1024;

#[derive(Debug, Clone)]
pub struct ActorHandle {
    tx: flume::Sender<ToActor>,
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
        let (tx, rx) = flume::bounded(INBOX_CAP);
        let join_handle = std::thread::Builder::new()
            .name("willow-actor".to_string())
            .spawn(move || {
                let span = error_span!("willow_thread", me=%me.fmt_short());
                let _guard = span.enter();

                let store = (create_store)();
                let store = Store::new(store);
                let actor = Actor {
                    store,
                    sessions: Default::default(),
                    inbox_rx: rx,
                    next_session_id: 0,
                    session_tasks: Default::default(),
                    tasks: Default::default(),
                };
                if let Err(error) = actor.run() {
                    error!(?error, "storage thread failed");
                };
            })
            .expect("failed to spawn thread");
        let join_handle = Arc::new(Some(join_handle));
        ActorHandle { tx, join_handle }
    }
    pub async fn send(&self, action: ToActor) -> Result<()> {
        self.tx.send_async(action).await?;
        Ok(())
    }
    pub fn send_blocking(&self, action: ToActor) -> Result<()> {
        self.tx.send(action)?;
        Ok(())
    }
    pub async fn ingest_entry(&self, authorised_entry: AuthorisedEntry) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::IngestEntry {
            authorised_entry,
            origin: Origin::Local,
            reply,
        })
        .await?;
        reply_rx.await??;
        Ok(())
    }
    pub async fn insert_entry(&self, entry: Entry, auth: impl Into<AuthForm>) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::InsertEntry {
            entry: EntryOrForm::Entry(entry),
            auth: auth.into(),
            reply,
        })
        .await?;
        reply_rx.await??;
        Ok(())
    }

    pub async fn insert_form(
        &self,
        form: EntryForm,
        authorisation: impl Into<AuthForm>,
    ) -> Result<(Entry, bool)> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::InsertEntry {
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
        self.send(ToActor::InsertSecret { secret, reply }).await?;
        reply_rx.await??;
        Ok(())
    }

    pub async fn get_entries(
        &self,
        namespace: NamespaceId,
        range: ThreeDRange,
    ) -> Result<impl Stream<Item = anyhow::Result<Entry>>> {
        let (tx, rx) = flume::bounded(1024);
        self.send(ToActor::GetEntries {
            namespace,
            reply: tx,
            range,
        })
        .await?;
        Ok(rx.into_stream())
    }

    pub async fn init_session(
        &self,
        peer: NodeId,
        our_role: Role,
        initial_transmission: InitialTransmission,
        channels: Channels,
        init: SessionInit,
    ) -> Result<SessionHandle> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::InitSession {
            our_role,
            initial_transmission,
            peer,
            channels,
            init,
            reply,
        })
        .await?;
        reply_rx.await?
    }
    pub async fn create_namespace(
        &self,
        kind: NamespaceKind,
        owner: UserId,
    ) -> Result<NamespaceId> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::CreateNamespace { kind, owner, reply })
            .await?;
        reply_rx.await?
    }

    pub async fn create_user(&self) -> Result<UserId> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::CreateUser { reply }).await?;
        reply_rx.await?
    }

    pub async fn delegate_caps(
        &self,
        from: CapSelector,
        access_mode: AccessMode,
        to: DelegateTo,
    ) -> Result<Vec<CapabilityPack>> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::DelegateCaps {
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
        self.send(ToActor::ImportCaps { caps, reply }).await?;
        reply_rx.await?
    }
}

impl Drop for ActorHandle {
    fn drop(&mut self) {
        // this means we're dropping the last reference
        if let Some(handle) = Arc::get_mut(&mut self.join_handle) {
            self.tx.send(ToActor::Shutdown { reply: None }).ok();
            let handle = handle.take().expect("may only run once");
            if let Err(err) = handle.join() {
                warn!(?err, "Failed to join sync actor");
            }
        }
    }
}

#[derive(Debug)]
pub struct SessionHandle {
    on_finish: future::Shared<BoxFuture<Result<(), Arc<Error>>>>,
    cancel_token: CancellationToken,
}

impl SessionHandle {
    fn new(
        cancel_token: CancellationToken,
        on_finish: oneshot::Receiver<Result<(), Error>>,
    ) -> Self {
        let on_finish = on_finish
            .map(|r| match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(err)) => Err(Arc::new(err)),
                Err(_) => Err(Arc::new(Error::ActorFailed)),
            })
            .boxed()
            .shared();
        SessionHandle {
            on_finish,
            cancel_token,
        }
    }
    /// Wait for the session to finish.
    ///
    /// Returns an error if the session failed to complete.
    pub async fn on_finish(&self) -> Result<(), Arc<Error>> {
        self.on_finish.clone().await
    }

    /// Finish the session gracefully.
    ///
    /// After calling this, no further protocol messages will be sent from this node.
    /// Previously queued messages will still be sent out. The session will only be closed
    /// once the other peer closes their senders as well.
    pub fn close(&self) {
        self.cancel_token.cancel();
    }
}

#[derive(derive_more::Debug, strum::Display)]
pub enum ToActor {
    InitSession {
        our_role: Role,
        peer: NodeId,
        initial_transmission: InitialTransmission,
        #[debug(skip)]
        channels: Channels,
        init: SessionInit,
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
        origin: Origin,
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
struct ActiveSession {
    #[allow(unused)]
    peer: NodeId,
    on_finish: oneshot::Sender<Result<(), Error>>,
    task_key: TaskKey, // state: SharedSessionState<S>
}

#[derive(Debug)]
pub struct Actor<S: Storage> {
    inbox_rx: flume::Receiver<ToActor>,
    store: Store<S>,
    next_session_id: u64,
    sessions: HashMap<SessionId, ActiveSession>,
    session_tasks: JoinMap<SessionId, Result<(), Error>>,
    tasks: JoinSet<()>,
}

impl<S: Storage> Actor<S> {
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
                    Ok(ToActor::Shutdown { reply }) => {
                        tokio::join!(
                            self.tasks.shutdown(),
                            self.session_tasks.shutdown()
                        );
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
                Some((id, res)) = self.session_tasks.next(), if !self.session_tasks.is_empty() => {
                    let res = match res {
                        Ok(res) => res,
                        Err(err) => Err(err.into())
                    };
                    self.complete_session(&id, res);
                }
            };
        }
        Ok(())
    }

    fn next_session_id(&mut self) -> u64 {
        let id = self.next_session_id;
        self.next_session_id += 1;
        id
    }

    async fn handle_message(&mut self, message: ToActor) -> Result<(), SendReplyError> {
        trace!(%message, "tick: handle_message");
        match message {
            ToActor::Shutdown { .. } => unreachable!("handled in run"),
            ToActor::InitSession {
                peer,
                channels,
                our_role,
                initial_transmission,
                init,
                reply,
            } => {
                let Channels { send, recv } = channels;
                let id = self.next_session_id();
                let session = Session::new(id, init.mode, our_role, send, initial_transmission);

                let store = self.store.clone();
                let cancel_token = CancellationToken::new();

                let future = session
                    .run(store, recv, init, cancel_token.clone())
                    .instrument(error_span!("session", peer = %peer.fmt_short()));
                let task_key = self.session_tasks.spawn_local(id, future);

                let (on_finish_tx, on_finish_rx) = oneshot::channel();
                let active_session = ActiveSession {
                    on_finish: on_finish_tx,
                    task_key,
                    peer,
                };
                self.sessions.insert(id, active_session);
                let handle = SessionHandle::new(cancel_token, on_finish_rx);
                send_reply(reply, Ok(handle))
            }
            ToActor::GetEntries {
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
            ToActor::IngestEntry {
                authorised_entry,
                origin,
                reply,
            } => {
                let res = self.store.entries().ingest(&authorised_entry, origin);
                send_reply(reply, res)
            }
            ToActor::InsertEntry { entry, auth, reply } => {
                let res = self.store.insert_entry(entry, auth).await;
                let res = res.map_err(Into::into);
                send_reply(reply, res)
            }
            ToActor::InsertSecret { secret, reply } => {
                let res = self.store.secrets().insert(secret);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            ToActor::CreateNamespace { kind, owner, reply } => {
                let res = self
                    .store
                    .create_namespace(&mut rand::thread_rng(), kind, owner);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            ToActor::CreateUser { reply } => {
                let secret = UserSecretKey::generate(&mut rand::thread_rng());
                let res = self.store.secrets().insert_user(secret);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            ToActor::ImportCaps { caps, reply } => {
                let res = self.store.import_caps(caps);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
            ToActor::DelegateCaps {
                from,
                access_mode,
                to,
                store,
                reply,
            } => {
                let res = self.store.delegate_cap(from, access_mode, to, store);
                send_reply(reply, res.map_err(anyhow::Error::from))
            }
        }
    }

    fn complete_session(&mut self, session_id: &SessionId, result: Result<(), Error>) {
        let session = self.sessions.remove(session_id);
        if let Some(session) = session {
            session.on_finish.send(result).ok();
            self.session_tasks.remove(&session.task_key);
        } else {
            warn!("remove_session called for unknown session");
        }
    }
}

#[derive(Debug)]
struct SendReplyError;

fn send_reply<T>(sender: oneshot::Sender<T>, value: T) -> Result<(), SendReplyError> {
    sender.send(value).map_err(send_reply_error)
}

// fn send_reply_with<T, S: Storage>(
//     sender: oneshot::Sender<Result<T, Error>>,
//     this: &mut Actor<S>,
//     f: impl FnOnce(&mut Actor<S>) -> Result<T, Error>,
// ) -> Result<(), SendReplyError> {
//     sender.send(f(this)).map_err(send_reply_error)
// }

fn send_reply_error<T>(_err: T) -> SendReplyError {
    SendReplyError
}
