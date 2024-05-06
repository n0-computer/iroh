use std::{
    collections::{hash_map, HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use futures::{
    future::{BoxFuture, LocalBoxFuture},
    FutureExt,
};
use genawaiter::{
    sync::{Co, Gen},
    GeneratorState,
};
use tracing::error;
// use iroh_net::NodeId;

use super::Store;
use crate::{
    proto::wgps::{LogicalChannel, Message, ReconciliationSendEntry},
    session::{
        coroutine::{Channels, ReconcileRoutine, SessionState, Yield},
        Error,
    },
    util::channel::{self, ReadOutcome, Receiver},
};

pub const CHANNEL_CAP: usize = 1024;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct SessionId(u64);
pub type NodeId = SessionId;

pub struct StoreHandle {
    tx: flume::Sender<ToActor>,
}
impl StoreHandle {
    pub fn spawn<S: Store>(store: S) -> StoreHandle {
        let (tx, rx) = flume::bounded(CHANNEL_CAP);
        let _join_handle = std::thread::spawn(move || {
            let actor = StorageThread {
                store,
                sessions: Default::default(),
                actor_rx: rx,
            };
            if let Err(error) = actor.run() {
                error!(?error, "storage thread failed");
            };
        });
        StoreHandle { tx }
    }
    pub async fn send(&self, action: ToActor) -> anyhow::Result<()> {
        self.tx.send_async(action).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ToActor {
    InitSession {
        peer: NodeId,
        state: SessionState,
        channels: Arc<Channels>,
    },
    DropSession {
        peer: NodeId,
    },
    ResumeWrite {
        peer: NodeId,
        channel: LogicalChannel,
    },
    ResumeRead {
        peer: NodeId,
        channel: LogicalChannel,
    },
}

#[derive(Debug)]
struct StorageSession {
    state: SessionState,
    channels: Arc<Channels>,
    waiting: WaitingCoroutines,
}

#[derive(derive_more::Debug, Default)]
struct WaitingCoroutines {
    #[debug("{}", "on_control.len()")]
    on_control: VecDeque<ReconcileGen>,
    #[debug("{}", "on_reconciliation.len()")]
    on_reconciliation: VecDeque<ReconcileGen>,
}

impl WaitingCoroutines {
    fn get_mut(&mut self, channel: LogicalChannel) -> &mut VecDeque<ReconcileGen> {
        match channel {
            LogicalChannel::ControlChannel => &mut self.on_control,
            LogicalChannel::ReconciliationChannel => &mut self.on_reconciliation,
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
    pub fn run(mut self) -> anyhow::Result<()> {
        loop {
            match self.actor_rx.recv() {
                Err(_) => break,
                Ok(message) => self.handle_message(message)?,
            }
        }
        Ok(())
    }

    fn handle_message(&mut self, message: ToActor) -> Result<(), Error> {
        match message {
            ToActor::InitSession {
                peer,
                state,
                channels,
            } => {
                let session = StorageSession {
                    state,
                    channels,
                    waiting: Default::default(),
                };
                self.sessions.insert(peer, session);
                self.resume_read(peer, LogicalChannel::ReconciliationChannel)?;
            }
            ToActor::DropSession { peer } => {
                self.sessions.remove(&peer);
            }
            ToActor::ResumeWrite { peer, channel } => {
                self.resume_write(peer, channel)?;
            }
            ToActor::ResumeRead { peer, channel } => {
                self.resume_read(peer, channel)?;
            }
        }
        Ok(())
    }
    fn resume_read(&mut self, peer: NodeId, channel: LogicalChannel) -> Result<(), Error> {
        let channel = self.session(&peer)?.channels.receiver(channel).clone();
        loop {
            match channel.read_message()? {
                ReadOutcome::NeedMoreData => {
                    channel.need_notify();
                    break;
                }
                ReadOutcome::Item(message) => {
                    self.on_message(peer, message)?;
                }
            }
        }
        Ok(())
    }

    fn session_mut(&mut self, peer: &NodeId) -> Result<&mut StorageSession, Error> {
        self.sessions
            .get_mut(peer)
            .ok_or(Error::InvalidMessageInCurrentState)
    }

    fn session(&mut self, peer: &NodeId) -> Result<&StorageSession, Error> {
        self.sessions
            .get(peer)
            .ok_or(Error::InvalidMessageInCurrentState)
    }
    fn on_message(&mut self, peer: NodeId, message: Message) -> Result<(), Error> {
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
                let authorised_entry = session
                    .state
                    .lock()
                    .unwrap()
                    .authorize_send_entry(message)?;
                self.store.ingest_entry(&authorised_entry)?;
            }
            _ => return Err(Error::UnsupportedMessage),
        }
        Ok(())
    }

    fn start_coroutine(
        &mut self,
        peer: NodeId,
        producer: impl FnOnce(ReconcileRoutine<S::Snapshot>) -> ReconcileFut,
    ) -> Result<(), Error> {
        let session = self.sessions.get_mut(&peer).ok_or(Error::SessionLost)?;
        let snapshot = Arc::new(self.store.snapshot()?);

        let channels = session.channels.clone();
        let state = session.state.clone();

        let mut generator = Gen::new(move |co| {
            let routine = ReconcileRoutine {
                store: snapshot,
                channels,
                state,
                co,
            };
            (producer)(routine)
        });
        match generator.resume() {
            GeneratorState::Yielded(Yield::SendBufferFull(channel)) => {
                session.waiting.push_back(channel, generator);
                Ok(())
            }
            GeneratorState::Complete(res) => res,
        }
    }

    fn resume_write(&mut self, peer: NodeId, channel: LogicalChannel) -> Result<(), Error> {
        let session = self.session_mut(&peer)?;
        let Some(mut generator) = session.waiting.pop_front(channel) else {
            // debug_assert!(false, "resume_coroutine called but no generator");
            // TODO: error?
            return Ok(());
        };
        match generator.resume() {
            GeneratorState::Yielded(why) => match why {
                Yield::SendBufferFull(channel) => {
                    session.waiting.push_front(channel, generator);
                    Ok(())
                }
            },
            GeneratorState::Complete(res) => res,
        }
    }
}
