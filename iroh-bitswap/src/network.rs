use std::{
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, Result};
use cid::Cid;
use crossbeam::channel::{Receiver, Sender};
use libp2p::{
    ping::PingResult,
    swarm::{NetworkBehaviourAction, NotifyHandler},
    PeerId,
};

use crate::{
    handler::{BitswapHandler, BitswapHandlerIn},
    message::BitswapMessage,
    BitswapEvent,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SEND_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MIN_SEND_TIMEOUT: Duration = Duration::from_secs(2);
// 100kbit/s
const MIN_SEND_RATE: usize = (100 * 1000) / 8;

#[derive(Debug, Clone)]
pub struct Network {
    network_out_receiver: Receiver<NetworkBehaviourAction<BitswapEvent, BitswapHandler>>,
    network_out_sender: Sender<NetworkBehaviourAction<BitswapEvent, BitswapHandler>>,
    self_id: PeerId,
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

    pub fn send_message(&self, peer: PeerId, message: BitswapMessage) -> Result<()> {
        self.network_out_sender
            .send(NetworkBehaviourAction::NotifyHandler {
                peer_id: peer,
                handler: NotifyHandler::Any,
                event: BitswapHandlerIn::Message(message),
            })
            .map_err(|e| anyhow!("channel send: {:?}", e))?;

        Ok(())
    }

    pub fn provide(&self, key: Cid) -> Result<()> {
        todo!()
    }

    pub fn poll(
        &mut self,
        _cx: &mut Context,
    ) -> Poll<NetworkBehaviourAction<BitswapEvent, BitswapHandler>> {
        if let Ok(event) = self.network_out_receiver.try_recv() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}
