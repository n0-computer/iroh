use std::{collections::HashMap, sync::Arc, thread::JoinHandle};

use futures_lite::{future::Boxed as BoxFuture, stream::Stream, StreamExt};
use futures_util::future::{self, FutureExt};
use iroh_base::key::NodeId;
use tokio::sync::oneshot;
use tracing::{debug, error, error_span, trace, warn, Instrument};

use crate::{
    net::InitialTransmission,
    proto::{
        grouping::ThreeDRange,
        keys::NamespaceId,
        meadowcap,
        willow::{AuthorisedEntry, Entry},
    },
    session::{Channels, Error, Role, Session, SessionInit},
    store::{KeyStore, ReadonlyStore, Shared, Store},
    util::task::{JoinMap, TaskKey},
};

pub const INBOX_CAP: usize = 1024;

pub type SessionId = u64;

#[derive(Debug, Clone)]
pub struct ActorHandle {
    tx: flume::Sender<ToActor>,
    join_handle: Arc<Option<JoinHandle<()>>>,
}

impl ActorHandle {
    pub fn spawn<S: Store, K: KeyStore>(store: S, key_store: K, me: NodeId) -> ActorHandle {
        let (tx, rx) = flume::bounded(INBOX_CAP);
        let join_handle = std::thread::Builder::new()
            .name("willow-actor".to_string())
            .spawn(move || {
                let span = error_span!("willow_thread", me=%me.fmt_short());
                let _guard = span.enter();

                let actor = StorageThread {
                    store: Shared::new(store),
                    key_store: Shared::new(key_store),
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
    ) -> anyhow::Result<impl Stream<Item = Entry>> {
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
        let (on_finish_tx, on_finish_rx) = oneshot::channel();
        self.send(ToActor::InitSession {
            our_role,
            initial_transmission,
            peer,
            channels,
            init,
            on_finish: on_finish_tx,
        })
        .await?;

        let on_finish = on_finish_rx
            .map(|r| match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(err)) => Err(Arc::new(err.into())),
                Err(_) => Err(Arc::new(Error::ActorFailed)),
            })
            .boxed();
        let on_finish = on_finish.shared();
        let handle = SessionHandle { on_finish };
        Ok(handle)
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
}

impl SessionHandle {
    /// Wait for the session to finish.
    ///
    /// Returns an error if the session failed to complete.
    pub async fn on_finish(self) -> Result<(), Arc<Error>> {
        self.on_finish.await
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
        on_finish: oneshot::Sender<Result<(), Error>>,
    },
    GetEntries {
        namespace: NamespaceId,
        range: ThreeDRange,
        #[debug(skip)]
        reply: flume::Sender<Entry>,
    },
    IngestEntry {
        entry: AuthorisedEntry,
        reply: oneshot::Sender<anyhow::Result<bool>>,
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
pub struct StorageThread<S, K> {
    inbox_rx: flume::Receiver<ToActor>,
    store: Shared<S>,
    key_store: Shared<K>,
    next_session_id: u64,
    sessions: HashMap<SessionId, ActiveSession>,
    session_tasks: JoinMap<SessionId, Result<(), Error>>,
}

impl<S: Store, K: KeyStore> StorageThread<S, K> {
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
                    Ok(msg) => self.handle_message(msg)?,
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

    fn handle_message(&mut self, message: ToActor) -> Result<(), Error> {
        trace!(%message, "tick: handle_message");
        match message {
            ToActor::Shutdown { .. } => unreachable!("handled in run"),
            ToActor::InitSession {
                peer,
                channels,
                our_role,
                initial_transmission,
                init,
                on_finish,
            } => {
                let Channels { send, recv } = channels;
                let session = Session::new(send, our_role, initial_transmission);

                let id = self.next_session_id();
                let store = self.store.clone();
                let key_store = self.key_store.clone();

                let future = session
                    .run(store, key_store, recv, init)
                    .instrument(error_span!("session", peer = %peer.fmt_short()));
                let task_key = self.session_tasks.spawn_local(id, future);

                let active_session = ActiveSession {
                    on_finish,
                    task_key,
                    peer,
                };
                self.sessions.insert(id, active_session);
            }
            ToActor::GetEntries {
                namespace,
                range,
                reply,
            } => {
                // TODO: We don't want to use a snapshot here.
                let snapshot = self.store.snapshot()?;
                let entries = snapshot
                    .get_entries(namespace, &range)
                    .filter_map(|r| r.ok());
                for entry in entries {
                    reply.send(entry).ok();
                }
            }
            ToActor::IngestEntry { entry, reply } => {
                let res = self.store.ingest_entry(&entry);
                reply.send(res).ok();
            }
            ToActor::InsertSecret { secret, reply } => {
                let res = self.key_store.insert(secret);
                reply.send(res.map_err(anyhow::Error::from)).ok();
            }
        }
        Ok(())
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
