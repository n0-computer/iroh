use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::Arc, thread::JoinHandle};

use futures_lite::{future::Boxed as BoxFuture, stream::Stream, StreamExt};
use futures_util::future::{FutureExt, Shared};
use iroh_base::key::NodeId;
use tokio::sync::oneshot;
use tracing::{debug, error, error_span, trace, warn, Instrument};

use crate::{
    net::InitialTransmission,
    proto::{
        grouping::ThreeDRange,
        keys::NamespaceId,
        wgps::AreaOfInterestHandle,
        willow::{AuthorisedEntry, Entry},
    },
    session::{
        coroutine::ControlRoutine, Channels, Error, Role, SessionInit, SessionState,
        SharedSessionState,
    },
    store::Store,
    util::task_set::{TaskKey, TaskSet},
};

pub const INBOX_CAP: usize = 1024;

pub type SessionId = NodeId;

#[derive(Debug, Clone)]
pub struct ActorHandle {
    tx: flume::Sender<ToActor>,
    join_handle: Arc<Option<JoinHandle<()>>>,
}

impl ActorHandle {
    pub fn spawn<S: Store>(store: S, me: NodeId) -> ActorHandle {
        let (tx, rx) = flume::bounded(INBOX_CAP);
        let join_handle = std::thread::Builder::new()
            .name("sync-actor".to_string())
            .spawn(move || {
                let span = error_span!("willow_thread", me=%me.fmt_short());
                let _guard = span.enter();

                let actor = StorageThread {
                    store: Rc::new(RefCell::new(store)),
                    sessions: Default::default(),
                    inbox_rx: rx,
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
        let state = SessionState::new(our_role, initial_transmission);

        let (on_finish_tx, on_finish_rx) = oneshot::channel();
        self.send(ToActor::InitSession {
            peer,
            state,
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
    on_finish: Shared<BoxFuture<Result<(), Arc<Error>>>>,
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
        peer: NodeId,
        #[debug(skip)]
        state: SessionState,
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
    Shutdown {
        #[debug(skip)]
        reply: Option<oneshot::Sender<()>>,
    },
}

#[derive(Debug)]
struct ActiveSession {
    on_done: oneshot::Sender<Result<(), Error>>,
    task_key: TaskKey,
    // state: SharedSessionState<S>
}

#[derive(Debug)]
pub struct StorageThread<S> {
    inbox_rx: flume::Receiver<ToActor>,
    store: Rc<RefCell<S>>,
    sessions: HashMap<SessionId, ActiveSession>,
    tasks: TaskSet<(SessionId, Result<(), Error>)>,
}

impl<S: Store> StorageThread<S> {
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
                Some((_key, res)) = self.tasks.next(), if !self.tasks.is_empty() => match res {
                    Ok((id, res)) => {
                        self.complete_session(&id, res);
                    }
                    Err(err) => {
                        warn!("task failed to join: {err}");
                        return Err(err.into());
                    }
                }
            };
        }
        Ok(())
    }

    fn handle_message(&mut self, message: ToActor) -> Result<(), Error> {
        trace!(%message, "tick: handle_message");
        match message {
            ToActor::Shutdown { .. } => unreachable!("handled in run"),
            ToActor::InitSession {
                peer,
                state,
                channels,
                init,
                on_finish: on_done,
            } => {
                // self.init_session(peer, state, channels, init, on_finish);
                let span = error_span!("session", peer=%peer.fmt_short());
                let session_id = peer;

                // let Channels { send, recv } = channels;
                // let store = self.store.clone();
                // let state = SharedSessionState::new(state, send, store, reconcile_state);

                let fut = ControlRoutine::run(channels, state, self.store.clone(), init);
                let fut = fut.instrument(span.clone());
                let task_key = self
                    .tasks
                    .spawn_local(async move { (session_id, fut.await) });
                let session = ActiveSession { on_done, task_key };
                self.sessions.insert(peer, session);
            }
            ToActor::GetEntries {
                namespace,
                range,
                reply,
            } => {
                let store = self.store.borrow();
                let entries = store.get_entries(namespace, &range).filter_map(|r| r.ok());
                for entry in entries {
                    reply.send(entry).ok();
                }
            }
            ToActor::IngestEntry { entry, reply } => {
                let res = self.store.borrow_mut().ingest_entry(&entry);
                reply.send(res).ok();
            }
        }
        Ok(())
    }

    fn complete_session(&mut self, peer: &NodeId, result: Result<(), Error>) {
        let session = self.sessions.remove(peer);
        if let Some(session) = session {
            self.tasks.remove(session.task_key);
            session.on_done.send(result).ok();
        } else {
            warn!("remove_session called for unknown session");
        }
    }
}

pub type AreaOfInterestHandlePair = (AreaOfInterestHandle, AreaOfInterestHandle);
