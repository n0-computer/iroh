use std::{
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, Result};
use cid::Cid;
use crossbeam::channel::{Receiver, Sender};
use libp2p::{ping::PingResult, PeerId};

use crate::{message::BitswapMessage, BitswapEvent};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SEND_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MIN_SEND_TIMEOUT: Duration = Duration::from_secs(2);
// 100kbit/s
const MIN_SEND_RATE: usize = (100 * 1000) / 8;

#[derive(Debug, Clone)]
pub struct Network {
    network_out_receiver: Receiver<OutEvent>,
    network_out_sender: Sender<OutEvent>,
    self_id: PeerId,
}

pub enum OutEvent {
    Dial(PeerId, Sender<std::result::Result<(), String>>),
    SendMessage(
        PeerId,
        BitswapMessage,
        Sender<std::result::Result<(), String>>,
    ),
    GenerateEvent(BitswapEvent),
}

impl Network {
    pub fn new(self_id: PeerId) -> Self {
        let (network_out_sender, network_out_receiver) = crossbeam::channel::bounded(1024);

        Network {
            network_out_receiver,
            network_out_sender,
            self_id,
        }
    }

    pub fn self_id(&self) -> &PeerId {
        &self.self_id
    }

    pub fn ping(&self, peer: &PeerId) -> PingResult {
        todo!()
    }

    pub fn latency(&self, peer: &PeerId) -> Duration {
        // weighted average of latency of this peers from all pings
        todo!()
    }

    pub fn stop(self) {
        // nothing to do yet
    }

    fn dial(&self, peer: PeerId) -> Result<()> {
        let (s, r) = crossbeam::channel::bounded(1);
        self.network_out_sender
            .send(OutEvent::Dial(peer, s))
            .map_err(|e| anyhow!("channel send: {:?}", e))?;
        let res = r.recv()?.map_err(|e| anyhow!("Dial Error: {}", e))?;
        Ok(res)
    }

    pub fn send_message(&self, peer: PeerId, message: BitswapMessage) -> Result<()> {
        let (s, r) = crossbeam::channel::bounded(1);
        self.network_out_sender
            .send(OutEvent::SendMessage(peer, message, s))
            .map_err(|e| anyhow!("channel send: {:?}", e))?;

        let res = r.recv()?.map_err(|e| anyhow!("Send Error: {}", e))?;
        Ok(res)
    }

    pub fn provide(&self, key: Cid) -> Result<()> {
        self.network_out_sender
            .send(OutEvent::GenerateEvent(BitswapEvent::Provide { key }))
            .map_err(|e| anyhow!("channel send: {:?}", e))?;

        Ok(())
    }

    pub fn poll(&mut self, _cx: &mut Context) -> Poll<OutEvent> {
        if let Ok(event) = self.network_out_receiver.try_recv() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}

pub struct MessageSender {}

impl MessageSender {
    pub fn supports_have(&self) -> bool {
        todo!()
    }

    pub fn send_msg(&self, message: &BitswapMessage) -> Result<()> {
        todo!()
    }
}
