use std::{collections::HashMap, sync::Arc, thread::JoinHandle};

use futures_lite::{future::Boxed as BoxFuture, stream::Stream, StreamExt};
use futures_util::future::{self, FutureExt};
use iroh_base::key::NodeId;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, error_span, trace, warn, Instrument};

use crate::{
    net::InitialTransmission,
    proto::{
        grouping::ThreeDRange,
        keys::NamespaceId,
        meadowcap,
        willow::{AuthorisedEntry, Entry, WriteCapability},
    },
    session::{Channels, Error, Role, Session, SessionId, SessionInit},
    store::{
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
                };
                if let Err(error) = actor.run() {
                    error!(?error, "storage thread failed");
                };
            })
            .expect("failed to spawn thread");
        let join_handle = Arc::new(Some(join_handle));
        ActorHandle { tx, join_handle }
    }
    pub async fn send(&self, action: ToActor) -> anyhow::Result<()> {
        self.tx.send_async(action).await?;
        Ok(())
    }
    pub fn send_blocking(&self, action: ToActor) -> anyhow::Result<()> {
        self.tx.send(action)?;
        Ok(())
    }
    pub async fn ingest_entry(&self, entry: AuthorisedEntry) -> anyhow::Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::IngestEntry { entry, reply }).await?;
        reply_rx.await??;
        Ok(())
    }
    pub async fn insert_entry(
        &self,
        entry: Entry,
        capability: WriteCapability,
    ) -> anyhow::Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.send(ToActor::InsertEntry {
            entry,
            capability,
            reply,
        })
        .await?;
        reply_rx.await??;
        Ok(())
    }

    pub async fn insert_secret(
        &self,
        secret: impl Into<meadowcap::SecretKey>,
    ) -> anyhow::Result<()> {
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
    ) -> anyhow::Result<impl Stream<Item = anyhow::Result<Entry>>> {
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
    ) -> anyhow::Result<SessionHandle> {
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
}

impl Drop for ActorHandle {
    fn drop(&mut self) {
        // this means we're dropping the last reference
        if let Some(handle) = Arc::get_mut(&mut self.join_handle) {
            self.tx.send(ToActor::Shutdown { reply: None }).ok();
            let handle = handle.take().expect("this can only run once");
            if let Err(err) = handle.join() {
                warn!(?err, "Failed to join sync actor");
            }
        }
    }
}

#[derive(Debug)]
pub struct SessionHandle {
    on_finish: future::Shared<BoxFuture<Result<(), Arc<Error>>>>,
    finish: CancellationToken,
}

impl SessionHandle {
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
    pub fn finish(&self) {
        self.finish.cancel();
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
        // on_finish: oneshot::Sender<Result<(), Error>>,
        reply: oneshot::Sender<anyhow::Result<SessionHandle>>,
    },
    GetEntries {
        namespace: NamespaceId,
        range: ThreeDRange,
        #[debug(skip)]
        reply: flume::Sender<anyhow::Result<Entry>>,
    },
    IngestEntry {
        entry: AuthorisedEntry,
        reply: oneshot::Sender<anyhow::Result<bool>>,
    },
    InsertEntry {
        entry: Entry,
        capability: WriteCapability,
        reply: oneshot::Sender<Result<bool, Error>>,
    },
    InsertSecret {
        secret: meadowcap::SecretKey,
        reply: oneshot::Sender<anyhow::Result<()>>,
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
}

impl<S: Storage> Actor<S> {
    pub fn run(self) -> anyhow::Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to start current-thread runtime for willow actor");
        let local_set = tokio::task::LocalSet::new();
        local_set.block_on(&rt, async move { self.run_async().await })
    }
    async fn run_async(mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                msg = self.inbox_rx.recv_async() => match msg {
                    Err(_) => break,
                    Ok(ToActor::Shutdown { reply }) => {
                        if let Some(reply) = reply {
                            reply.send(()).ok();
                        }
                        break;
                    }
                    Ok(msg) => {
                        if self.handle_message(msg).is_err() {
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

    fn handle_message(&mut self, message: ToActor) -> Result<(), SendReplyError> {
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
                let finish = CancellationToken::new();

                let future = session
                    .run(store, recv, init, finish.clone())
                    .instrument(error_span!("session", peer = %peer.fmt_short()));
                let task_key = self.session_tasks.spawn_local(id, future);

                let (on_finish_tx, on_finish_rx) = oneshot::channel();

                let active_session = ActiveSession {
                    on_finish: on_finish_tx,
                    task_key,
                    peer,
                };
                self.sessions.insert(id, active_session);
                let on_finish = on_finish_rx
                    .map(|r| match r {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(err)) => Err(Arc::new(err)),
                        Err(_) => Err(Arc::new(Error::ActorFailed)),
                    })
                    .boxed()
                    .shared();
                let handle = SessionHandle { on_finish, finish };
                send_reply(reply, Ok(handle))
            }
            ToActor::GetEntries {
                namespace,
                range,
                reply,
            } => {
                let snapshot = self.store.entries().snapshot();
                match snapshot {
                    Ok(snapshot) => {
                        iter_to_channel(reply, Ok(snapshot.get_entries(namespace, &range)))
                    }
                    Err(err) => reply.send(Err(err)).map_err(send_reply_error),
                }
            }
            ToActor::IngestEntry { entry, reply } => {
                let res = self.store.entries().ingest(&entry, Origin::Local);
                send_reply(reply, res)
            }
            ToActor::InsertEntry {
                entry,
                capability,
                reply,
            } => send_reply_with(reply, self, |slf| {
                let user_id = capability.receiver().id();
                let user_secret = slf
                    .store
                    .secrets()
                    .get_user(&user_id)
                    .ok_or(Error::MissingUserKey(user_id))?;
                let authorised_entry = entry.attach_authorisation(capability, &user_secret)?;
                slf.store
                    .entries()
                    .ingest(&authorised_entry, Origin::Local)
                    .map_err(Error::Store)
            }),
            ToActor::InsertSecret { secret, reply } => {
                let res = self.store.secrets().insert(secret);
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

fn send_reply_with<T, S: Storage>(
    sender: oneshot::Sender<Result<T, Error>>,
    this: &mut Actor<S>,
    f: impl FnOnce(&mut Actor<S>) -> Result<T, Error>,
) -> Result<(), SendReplyError> {
    sender.send(f(this)).map_err(send_reply_error)
}

fn send_reply_error<T>(_err: T) -> SendReplyError {
    SendReplyError
}
fn iter_to_channel<T: Send + 'static>(
    channel: flume::Sender<anyhow::Result<T>>,
    iter: anyhow::Result<impl Iterator<Item = anyhow::Result<T>>>,
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
