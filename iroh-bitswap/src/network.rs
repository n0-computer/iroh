use std::{
    collections::HashSet,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use cid::Cid;
use crossbeam::channel::{Receiver, Sender};
use libp2p::{core::connection::ConnectionId, PeerId};
use tracing::{debug, info};

use crate::{message::BitswapMessage, protocol::ProtocolId, BitswapEvent};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SEND_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MIN_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const SEND_LATENCY: Duration = Duration::from_secs(2);
// 100kbit/s
const MIN_SEND_RATE: u64 = (100 * 1000) / 8;

#[derive(Debug, Clone)]
pub struct Network {
    network_out_receiver: Receiver<OutEvent>,
    network_out_sender: Sender<OutEvent>,
    self_id: PeerId,
}

pub enum OutEvent {
    Dial(PeerId, Sender<std::result::Result<ConnectionId, String>>),
    SendMessage {
        peer: PeerId,
        message: BitswapMessage,
        response: Sender<std::result::Result<(), SendError>>,
        connection_id: Option<ConnectionId>,
    },
    GenerateEvent(BitswapEvent),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SendError {
    #[error("protocol not supported")]
    ProtocolNotSupported,
    #[error("{0}")]
    Other(String),
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

    pub fn ping(&self, peer: &PeerId) -> Result<Duration> {
        let timeout = crossbeam::channel::after(Duration::from_secs(30));
        let (s, r) = crossbeam::channel::bounded(1);
        self.network_out_sender
            .send(OutEvent::GenerateEvent(BitswapEvent::Ping {
                peer: *peer,
                response: s,
            }))
            .map_err(|e| anyhow!("channel send: {:?}", e))?;

        crossbeam::channel::select! {
            recv(timeout) -> _ => {
                bail!("ping {} timeout", peer);
            }
            recv(r) -> res => {
                let res = res?.ok_or_else(|| anyhow!("no ping available"))?;
                Ok(res)
            }
        }
    }

    pub fn stop(self) {
        // nothing to do yet
    }

    pub fn send_message_with_retry_and_timeout(
        &self,
        peer: PeerId,
        connection_id: Option<ConnectionId>,
        message: BitswapMessage,
        retries: usize,
        timeout: Duration,
        backoff: Duration,
    ) -> Result<()> {
        let timeout = crossbeam::channel::after(timeout);
        let (s, r) = crossbeam::channel::bounded(1);
        self.network_out_sender
            .send(OutEvent::SendMessage {
                peer,
                message,
                response: s,
                connection_id,
            })
            .map_err(|e| anyhow!("channel send: {:?}", e))?;

        let mut errors = Vec::new();
        for i in 0..retries {
            crossbeam::channel::select! {
                recv(timeout) -> _ => {
                    bail!("timeout");
                }
                recv(r) -> res => {
                    let res = res?;
                    match res {
                        Ok(res) => {
                            return Ok(res);
                        }
                        err @ Err(SendError::ProtocolNotSupported) => {
                            return err.map_err(Into::into);
                        }
                        Err(other) => {
                            debug!("try {}/{} failed with: {:?}", i, retries, other);
                            errors.push(other);
                            if i < retries - 1 {
                                // backoff until we retry
                                std::thread::sleep(backoff);
                            }
                        }
                    }
                }
            }
        }

        bail!("Failed to send message to {}: {:?}", peer, errors);
    }

    pub fn find_providers(
        &self,
        key: Cid,
    ) -> Result<Receiver<std::result::Result<HashSet<PeerId>, String>>> {
        let (s, r) = crossbeam::channel::bounded(16);
        let (s_tokio, mut r_tokio) = tokio::sync::mpsc::channel(16);
        self.network_out_sender
            .send(OutEvent::GenerateEvent(BitswapEvent::FindProviders {
                key,
                response: s_tokio,
            }))
            .map_err(|e| anyhow!("channel send: {:?}", e))?;

        // Sad face. Adapter into async world.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                while let Some(res) = r_tokio.recv().await {
                    if s.send(res).is_err() {
                        break;
                    }
                }
            });
        });

        Ok(r)
    }

    pub fn dial(&self, peer: PeerId, timeout: Duration) -> Result<ConnectionId> {
        let timeout_r = crossbeam::channel::after(timeout);
        let (s, r) = crossbeam::channel::bounded(1);
        self.network_out_sender
            .send(OutEvent::Dial(peer, s))
            .map_err(|e| anyhow!("channel send: {:?}", e))?;

        crossbeam::channel::select! {
            recv(timeout_r) -> _ => {
                bail!("Dialing {} timeout ({}s)", peer, timeout.as_secs_f32());
            }
            recv(r) -> res => {
                let res = res?.map_err(|e| anyhow!("Dial Error: {}", e))?;
                Ok(res)
            }
        }
    }

    pub fn new_message_sender(
        &self,
        to: PeerId,
        config: MessageSenderConfig,
    ) -> Result<MessageSender> {
        let connection_id = self.dial(to, CONNECT_TIMEOUT)?;

        Ok(MessageSender {
            to,
            config,
            network: self.clone(),
            connection_id,
            protocol_id: None,
        })
    }

    pub fn send_message(&self, peer: PeerId, message: BitswapMessage) -> Result<()> {
        self.dial(peer, CONNECT_TIMEOUT)?;
        let timeout = send_timeout(message.encoded_len());
        self.send_message_with_retry_and_timeout(
            peer,
            None,
            message,
            1,
            timeout,
            Duration::from_millis(0),
        )
    }

    pub fn provide(&self, key: Cid) -> Result<()> {
        self.network_out_sender
            .send(OutEvent::GenerateEvent(BitswapEvent::Provide { key }))
            .map_err(|e| anyhow!("channel send: {:?}", e))?;

        Ok(())
    }

    pub fn tag_peer(&self, peer: &PeerId, tag: &str, value: usize) {
        // TODO: is this needed?
        info!("tag {}: {} - {}", peer, tag, value);
    }

    pub fn untag_peer(&self, peer: &PeerId, tag: &str) {
        // TODO: is this needed?
        info!("untag {}: {}", peer, tag);
    }

    pub fn protect_peer(&self, peer: &PeerId, tag: &str) {
        // TODO: is this needed?
        info!("protect {}: {}", peer, tag);
    }

    pub fn unprotect_peer(&self, peer: &PeerId, tag: &str) -> bool {
        // TODO: is this needed?
        info!("unprotect {}: {}", peer, tag);
        false
    }

    pub fn poll(&mut self, _cx: &mut Context) -> Poll<OutEvent> {
        if let Ok(event) = self.network_out_receiver.try_recv() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSenderConfig {
    pub max_retries: usize,
    pub send_timeout: Duration,
    pub send_error_backoff: Duration,
}

impl Default for MessageSenderConfig {
    fn default() -> Self {
        MessageSenderConfig {
            max_retries: 3,
            send_timeout: MAX_SEND_TIMEOUT,
            send_error_backoff: Duration::from_millis(100),
        }
    }
}

/// Calculates an appropriate timeout based on the message size.
fn send_timeout(size: usize) -> Duration {
    let mut timeout = SEND_LATENCY;
    timeout += Duration::from_secs(size as u64 / MIN_SEND_RATE);
    if timeout > MAX_SEND_TIMEOUT {
        MAX_SEND_TIMEOUT
    } else if timeout < MIN_SEND_TIMEOUT {
        MIN_SEND_TIMEOUT
    } else {
        timeout
    }
}

#[derive(Debug)]
pub struct MessageSender {
    to: PeerId,
    network: Network,
    config: MessageSenderConfig,
    connection_id: ConnectionId,
    protocol_id: Option<ProtocolId>,
}

impl MessageSender {
    pub fn supports_have(&self) -> bool {
        self.protocol_id
            .map(|p| p.supports_have())
            .unwrap_or_default()
    }

    pub fn send_message(&self, message: BitswapMessage) -> Result<()> {
        self.network.send_message_with_retry_and_timeout(
            self.to,
            Some(self.connection_id),
            message,
            self.config.max_retries,
            self.config.send_timeout,
            self.config.send_error_backoff,
        )
    }
}
