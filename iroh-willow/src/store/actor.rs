use std::{
    collections::{hash_map, HashMap, VecDeque},
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use futures::{
    future::{BoxFuture, LocalBoxFuture},
    FutureExt,
};
use genawaiter::{
    sync::{Co, Gen},
    GeneratorState,
};
use tokio::sync::oneshot;
use tracing::{debug, error, error_span, info, instrument, warn};
// use iroh_net::NodeId;

use super::Store;
use crate::{
    proto::{
        grouping::{NamespacedRange, ThreeDRange},
        keys::NamespaceId,
        wgps::{AreaOfInterestHandle, LogicalChannel, Message, ReconciliationSendEntry},
        willow::{AuthorisedEntry, Entry},
    },
    session::{
        coroutine::{Channels, Coroutine, SessionState, Yield},
        Error,
    },
    util::channel::{self, ReadOutcome, Receiver},
};
use iroh_base::key::NodeId;

pub const CHANNEL_CAP: usize = 1024;

// #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
// pub struct SessionId(u64);
// pub type NodeId = SessionId;

#[derive(Debug, Clone)]
pub struct StoreHandle {
    tx: flume::Sender<ToActor>,
    join_handle: Arc<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone)]
pub enum Interest {
    Send,
    Recv,
}

#[derive(Debug, Clone)]
pub struct Notifier {
    store: StoreHandle,
    peer: NodeId,
    channel: LogicalChannel,
    direction: Interest,
}

impl Notifier {
    pub fn channel(&self) -> LogicalChannel {
        self.channel
    }
    pub async fn notify(&self) -> anyhow::Result<()> {
        let msg = match self.direction {
            Interest::Send => ToActor::ResumeSend {
                peer: self.peer,
                channel: self.channel,
            },
            Interest::Recv => ToActor::ResumeRecv {
                peer: self.peer,
                channel: self.channel,
            },
        };
        self.store.send(msg).await?;
        Ok(())
    }
}

impl StoreHandle {
    pub fn spawn<S: Store>(store: S, me: NodeId) -> StoreHandle {
        let (tx, rx) = flume::bounded(CHANNEL_CAP);
        let join_handle = std::thread::Builder::new()
            .name("sync-actor".to_string())
            .spawn(move || {
                let span = error_span!("store", me=%me.fmt_short());
                let _enter = span.enter();

                let mut actor = StorageThread {
                    store,
                    sessions: Default::default(),
                    actor_rx: rx,
                };
                if let Err(error) = actor.run() {
                    error!(?error, "storage thread failed");
                };
            })
            .expect("failed to spawn thread");
        let join_handle = Arc::new(Some(join_handle));
        StoreHandle { tx, join_handle }
    }
    pub async fn send(&self, action: ToActor) -> anyhow::Result<()> {
        self.tx.send_async(action).await?;
        Ok(())
    }
    pub fn notifier(
        &self,
        channel: LogicalChannel,
        direction: Interest,
        peer: NodeId,
    ) -> Notifier {
        Notifier {
            store: self.clone(),
            peer,
            channel,
            direction,
        }
    }
}

impl Drop for StoreHandle {
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
#[derive(derive_more::Debug)]
pub enum ToActor {
    InitSession {
        peer: NodeId,
        #[debug(skip)]
        state: SessionState,
        #[debug(skip)]
        channels: Arc<Channels>,
        start: Option<(AreaOfInterestHandle, AreaOfInterestHandle)>,
    },
    DropSession {
        peer: NodeId,
    },
    ResumeSend {
        peer: NodeId,
        channel: LogicalChannel,
    },
    ResumeRecv {
        peer: NodeId,
        channel: LogicalChannel,
    },
    GetEntries {
        namespace: NamespaceId,
        #[debug(skip)]
        reply: flume::Sender<Entry>,
    },
    Shutdown {
        #[debug(skip)]
        reply: Option<oneshot::Sender<()>>,
    },
}

#[derive(Debug)]
struct StorageSession {
    state: SessionState,
    channels: Arc<Channels>,
    pending: PendingCoroutines,
}

#[derive(derive_more::Debug, Default)]
struct PendingCoroutines {
    #[debug("{}", "on_control.len()")]
    on_control: VecDeque<ReconcileGen>,
    #[debug("{}", "on_reconciliation.len()")]
    on_reconciliation: VecDeque<ReconcileGen>,
}

impl PendingCoroutines {
    fn get_mut(&mut self, channel: LogicalChannel) -> &mut VecDeque<ReconcileGen> {
        match channel {
            LogicalChannel::Control => &mut self.on_control,
            LogicalChannel::Reconciliation => &mut self.on_reconciliation,
        }
    }
    fn get(&self, channel: LogicalChannel) -> &VecDeque<ReconcileGen> {
        match channel {
            LogicalChannel::Control => &self.on_control,
            LogicalChannel::Reconciliation => &self.on_reconciliation,
        }
    }
    fn push_back(&mut self, channel: LogicalChannel, generator: ReconcileGen) {
        self.get_mut(channel).push_back(generator);
    }
    fn push_front(&mut self, channel: LogicalChannel, generator: ReconcileGen) {
        self.get_mut(channel).push_front(generator);
    }
    fn pop_front(&mut self, channel: LogicalChannel) -> Option<ReconcileGen> {
        self.get_mut(channel).pop_front()
    }
    fn len(&self, channel: LogicalChannel) -> usize {
        self.get(channel).len()
    }

    fn is_empty(&self) -> bool {
        self.on_control.is_empty() && self.on_reconciliation.is_empty()
    }
}

#[derive(Debug)]
pub struct StorageThread<S> {
    store: S,
    sessions: HashMap<NodeId, StorageSession>,
    actor_rx: flume::Receiver<ToActor>,
}

type ReconcileFut = LocalBoxFuture<'static, Result<(), Error>>;
type ReconcileGen = Gen<Yield, (), ReconcileFut>;

impl<S: Store> StorageThread<S> {
    pub fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let message = match self.actor_rx.recv() {
                Err(_) => break,
                Ok(message) => message,
            };
            match message {
                ToActor::Shutdown { reply } => {
                    if let Some(reply) = reply {
                        reply.send(()).ok();
                    }
                    break;
                }
                message => self.handle_message(message)?,
            }
        }
        Ok(())
    }

    fn handle_message(&mut self, message: ToActor) -> Result<(), Error> {
        debug!(?message, "tick: handle_message");
        match message {
            ToActor::Shutdown { .. } => unreachable!("handled in run"),
            ToActor::InitSession {
                peer,
                state,
                channels,
                start,
            } => {
                let session = StorageSession {
                    state,
                    channels,
                    pending: Default::default(),
                };
                self.sessions.insert(peer, session);
                if let Some((our_handle, their_handle)) = start {
                    self.start_coroutine(peer, |routine| {
                        routine
                            .init_reconciliation(our_handle, their_handle)
                            .boxed_local()
                    })?;
                }
                self.resume_recv(peer, LogicalChannel::Reconciliation)?;
                self.resume_send(peer, LogicalChannel::Reconciliation)?;
                self.resume_send(peer, LogicalChannel::Control)?;
            }
            ToActor::DropSession { peer } => {
                self.sessions.remove(&peer);
            }
            ToActor::ResumeSend { peer, channel } => {
                self.resume_send(peer, channel)?;
            }
            ToActor::ResumeRecv { peer, channel } => {
                self.resume_recv(peer, channel)?;
            }
            ToActor::GetEntries { namespace, reply } => {
                let entries = self
                    .store
                    .get_entries(namespace, &ThreeDRange::full())
                    .filter_map(|r| r.ok());
                for entry in entries {
                    reply.send(entry).ok();
                }
            }
        }
        Ok(())
    }
    fn session_mut(&mut self, peer: &NodeId) -> Result<&mut StorageSession, Error> {
        self.sessions.get_mut(peer).ok_or(Error::SessionNotFound)
    }

    fn session(&mut self, peer: &NodeId) -> Result<&StorageSession, Error> {
        self.sessions.get(peer).ok_or(Error::SessionNotFound)
    }
    fn on_message(&mut self, peer: NodeId, message: Message) -> Result<(), Error> {
        info!(msg=%message, "recv");
        match message {
            Message::ReconciliationSendFingerprint(message) => {
                self.start_coroutine(peer, |routine| {
                    routine.on_send_fingerprint(message).boxed_local()
                })?;
            }
            Message::ReconciliationAnnounceEntries(message) => {
                self.start_coroutine(peer, |routine| {
                    routine.on_announce_entries(message).boxed_local()
                })?;
            }
            Message::ReconciliationSendEntry(message) => {
                let session = self.session_mut(&peer)?;
                let authorised_entry = {
                    let mut state = session.state.lock().unwrap();
                    let authorised_entry = state.authorize_send_entry(message)?;
                    state.trigger_notify_if_complete();
                    authorised_entry
                };
                self.store.ingest_entry(&authorised_entry)?;
                debug!("ingested entry");
            }
            _ => return Err(Error::UnsupportedMessage),
        }
        let session = self.session(&peer)?;
        let state = session.state.lock().unwrap();
        let started = state.reconciliation_started;
        let pending_ranges = &state.pending_ranges;
        let pending_entries = &state.pending_entries;
        let is_complete = state.is_complete();
        info!(
            is_complete,
            started,
            ?pending_entries,
            ?pending_ranges,
            "handled"
        );

        Ok(())
    }

    fn start_coroutine(
        &mut self,
        peer: NodeId,
        producer: impl FnOnce(Coroutine<S::Snapshot>) -> ReconcileFut,
    ) -> Result<(), Error> {
        let session = self.sessions.get_mut(&peer).ok_or(Error::SessionNotFound)?;
        let snapshot = Arc::new(self.store.snapshot()?);

        let channels = session.channels.clone();
        let state = session.state.clone();

        let generator = Gen::new(move |co| {
            let routine = Coroutine {
                store: snapshot,
                channels,
                state,
                co,
            };
            (producer)(routine)
        });
        self.resume_coroutine(peer, generator)
    }

    #[instrument(skip_all, fields(session=%peer.fmt_short(),ch=%channel.fmt_short()))]
    fn resume_recv(&mut self, peer: NodeId, channel: LogicalChannel) -> Result<(), Error> {
        let session = self.session(&peer)?;
        debug!("resume");
        let channel = session.channels.receiver(channel).clone();
        loop {
            match channel.read_message_or_set_notify()? {
                ReadOutcome::Closed => {
                    debug!("yield: Closed");
                    break;
                }
                ReadOutcome::ReadBufferEmpty => {
                    debug!("yield: ReadBufferEmpty");
                    break;
                }
                ReadOutcome::Item(message) => {
                    debug!(?message, "recv");
                    self.on_message(peer, message)?;
                }
            }
        }
        Ok(())
    }

    #[instrument(skip_all, fields(session=%peer.fmt_short(), ch=%channel.fmt_short()))]
    fn resume_send(&mut self, peer: NodeId, channel: LogicalChannel) -> Result<(), Error> {
        let session = self.session_mut(&peer)?;
        debug!(pending = session.pending.len(channel), "resume");
        let generator = session.pending.pop_front(channel);
        match generator {
            Some(generator) => self.resume_coroutine(peer, generator),
            None => {
                debug!("nothing to resume");
                Ok(())
            }
        }
    }

    fn resume_coroutine(&mut self, peer: NodeId, mut generator: ReconcileGen) -> Result<(), Error> {
        debug!(session = peer.fmt_short(), "resume");
        let session = self.session_mut(&peer)?;
        match generator.resume() {
            GeneratorState::Yielded(why) => match why {
                Yield::SendBufferFull(channel) => {
                    debug!("yield: SendBufferFull");
                    session.pending.push_back(channel, generator);
                    Ok(())
                }
            },
            GeneratorState::Complete(res) => {
                debug!(?res, "done");
                session.state.lock().unwrap().trigger_notify_if_complete();
                res
            }
        }
    }
}
