use std::collections::VecDeque;

use super::Error;
use genawaiter::{
    sync::{Co, Gen},
    GeneratorState,
};
use tracing::info;

#[derive(Debug)]
pub enum Yield {
    Init,
    OutboxFull,
    InboxEmpty,
    AllDone(usize),
}

// pub type Coroutine = genawaiter::Coroutine

#[derive(Debug)]
pub struct Reconciler {
    // gen: Option<Gen<Yield, ()>>, // co: genawaiter::sync::Co<Result<Yield, Error>>,
    state: State,
}

#[derive(Debug)]
pub struct State {
    outbox: VecDeque<i32>,
    inbox: VecDeque<i32>,
    count: usize,
}

pub struct WorkerState {
    inbox: flume::Receiver<i32>,
    outbox: flume::Sender<WorkerToNet>,
    sum: usize,
}

pub struct NetState {
    outbox: flume::Receiver<WorkerToNet>,
    inbox: flume::Sender<i32>,
}

fn create_state(cap: usize) -> (NetState, WorkerState) {
    let (outbox_send, outbox_recv) = flume::bounded(cap);
    let (inbox_send, inbox_recv) = flume::bounded(cap);
    let ws = WorkerState {
        inbox: inbox_recv,
        outbox: outbox_send,
        sum: 0,
    };
    let ns = NetState {
        inbox: inbox_send,
        outbox: outbox_recv,
    };
    (ns, ws)
}

enum WorkerToNet {
    MayResume,
    Yield,
    Finished,
    Out(i32),
}

async fn run_net(
    ns: NetState,
    recv: flume::Receiver<i32>,
    send: flume::Sender<i32>,
) -> anyhow::Result<()> {
    loop {
        let mut pending_message = None;
        // let mut yieled = true;
        tokio::select! {
            next = recv.recv_async(), if pending_message.is_none( )=> {
                let msg = next?;
                // if yielded {
                //     yielded = false;
                //     notify_worker();
                // }
                if let Err(msg) = ns.inbox.try_send(msg) {
                    pending_message.insert(msg.into_inner());
                }
            }
            out = ns.outbox.recv_async() => {
                let out = out?;
                match out {
                    WorkerToNet::MayResume => {
                        if let Some(msg) = pending_message.take() {
                            ns.inbox.send_async(msg).await?;
                        }
                    }
                    WorkerToNet::Out(msg) => {
                        send.send_async(msg).await?;
                    }
                    WorkerToNet::Finished => break,
                    WorkerToNet::Yield => {
                        // yielded = true;
                    }
                }
            }
        }
    }
    Ok(())
}

// struct SharedState

impl Reconciler {
    pub fn run_worker(&mut self) {
        let mut gen = Gen::new(|co| Self::producer(co));
        loop {
            match gen.resume_with(&mut self.state) {
                GeneratorState::Yielded(val) => {
                    info!("Yielded: {val:?}")
                }
                GeneratorState::Complete(res) => {
                    info!("Complete: {res:?}")
                }
            }
        }
    }

    pub fn push_inbox(&mut self, msg: i32) -> bool {
        self.state.inbox.push_back(msg);
        if self.state.inbox.len() == 2 {
            false
        } else {
            true
        }
    }

    pub fn drain_outbox(&mut self) -> impl Iterator<Item = i32> + '_ {
        self.state.outbox.drain(..)
    }

    async fn producer(co: Co<Yield, &mut State>) -> Result<(), Error> {
        loop {
            let state = co.yield_(Yield::Init).await;
            // exit condition
            if state.count > 6 {
                co.yield_(Yield::AllDone(state.count)).await;
                return Ok(());
            }

            let next = state.inbox.pop_front();
            match next {
                None => {
                    co.yield_(Yield::InboxEmpty).await;
                    continue;
                }
                Some(msg) => {
                    state.outbox.push_back(msg * 17);
                    if state.outbox.len() == 3 {
                        co.yield_(Yield::OutboxFull).await;
                    }
                }
            }
        }
    }
}
