use std::{
    collections::HashSet,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use cid::Cid;
use futures::Stream;
use iroh_metrics::core::MRecorder;
use iroh_metrics::{bitswap::BitswapMetrics, inc};
use libp2p::{core::connection::ConnectionId, PeerId};
use tokio::sync::{mpsc, oneshot};
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
    network_out_receiver: async_channel::Receiver<OutEvent>,
    network_out_sender: async_channel::Sender<OutEvent>,
    self_id: PeerId,
}

#[derive(Debug)]
pub enum OutEvent {
    Dial(
        PeerId,
        oneshot::Sender<std::result::Result<(ConnectionId, Option<ProtocolId>), String>>,
    ),
    Disconnect(PeerId, oneshot::Sender<()>),
    SendMessage {
        peer: PeerId,
        message: BitswapMessage,
        response: oneshot::Sender<std::result::Result<(), SendError>>,
        connection_id: ConnectionId,
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
        let (network_out_sender, network_out_receiver) = async_channel::bounded(1024);

        Network {
            network_out_receiver,
            network_out_sender,
            self_id,
        }
    }

    pub fn self_id(&self) -> &PeerId {
        &self.self_id
    }

    pub async fn ping(&self, peer: &PeerId) -> Result<Duration> {
        let (s, r) = oneshot::channel();
        let res = tokio::time::timeout(Duration::from_secs(30), async {
            self.network_out_sender
                .send(OutEvent::GenerateEvent(BitswapEvent::Ping {
                    peer: *peer,
                    response: s,
                }))
                .await
                .map_err(|e| anyhow!("channel send: {:?}", e))?;

            let r = r.await?.ok_or_else(|| anyhow!("no ping available"))?;
            Ok::<Duration, anyhow::Error>(r)
        })
        .await??;
        Ok(res)
    }

    pub fn stop(self) {
        // nothing to do yet
    }

    pub async fn send_message_with_retry_and_timeout(
        &self,
        peer: PeerId,
        connection_id: ConnectionId,
        message: BitswapMessage,
        retries: usize,
        timeout: Duration,
        backoff: Duration,
    ) -> Result<()> {
        info!("sending message to {} ({:?})", peer, message);
        inc!(BitswapMetrics::MessagesSent);
        let res = tokio::time::timeout(timeout, async {
            let mut errors: Vec<anyhow::Error> = Vec::new();
            for i in 0..retries {
                debug!("try {}/{}", i, retries);
                let (s, r) = oneshot::channel();
                self.network_out_sender
                    .send(OutEvent::SendMessage {
                        peer,
                        message: message.clone(),
                        response: s,
                        connection_id,
                    })
                    .await
                    .map_err(|e| anyhow!("channel send failed: {:?}", e))?;

                match r.await {
                    Ok(Ok(res)) => {
                        info!("message sent to {}", peer);
                        return Ok(res);
                    }
                    Ok(Err(SendError::ProtocolNotSupported)) => {
                        // No point in using this peer if they don't speak our protocol.
                        self.disconnect(peer).await?;
                        return Err(SendError::ProtocolNotSupported.into());
                    }
                    Err(channel_err) => {
                        debug!("try {}/{} failed with: {:?}", i, retries, channel_err);
                        errors.push(channel_err.into());
                        if i < retries - 1 {
                            // backoff until we retry
                            tokio::time::sleep(backoff).await;
                        }
                    }
                    Ok(Err(other)) => {
                        debug!("try {}/{} failed with: {:?}", i, retries, other);
                        errors.push(other.into());
                        if i < retries - 1 {
                            // backoff until we retry
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }
            }
            bail!("Failed to send message to {}: {:?}", peer, errors);
        })
        .await??;

        Ok(res)
    }

    pub async fn find_providers(
        &self,
        key: Cid,
    ) -> Result<mpsc::Receiver<std::result::Result<HashSet<PeerId>, String>>> {
        let (s, r) = mpsc::channel(16);
        self.network_out_sender
            .send(OutEvent::GenerateEvent(BitswapEvent::FindProviders {
                key,
                response: s,
            }))
            .await
            .map_err(|e| anyhow!("channel send: {:?}", e))?;

        Ok(r)
    }

    pub async fn dial(
        &self,
        peer: PeerId,
        timeout: Duration,
    ) -> Result<(ConnectionId, Option<ProtocolId>)> {
        inc!(BitswapMetrics::AttemptedDials);
        debug!("dialing {}", peer);
        let res = tokio::time::timeout(timeout, async move {
            let (s, r) = oneshot::channel();
            self.network_out_sender
                .send(OutEvent::Dial(peer, s))
                .await
                .map_err(|e| anyhow!("channel send: {:?}", e))?;

            let res = r.await?.map_err(|e| anyhow!("Dial Error: {}", e))?;
            Ok::<_, anyhow::Error>(res)
        })
        .await??;

        Ok(res)
    }

    pub async fn new_message_sender(
        &self,
        to: PeerId,
        config: MessageSenderConfig,
    ) -> Result<MessageSender> {
        let (connection_id, protocol_id) = self.dial(to, CONNECT_TIMEOUT).await?;

        Ok(MessageSender {
            to,
            config,
            network: self.clone(),
            connection_id,
            protocol_id,
        })
    }

    pub async fn send_message(&self, peer: PeerId, message: BitswapMessage) -> Result<()> {
        let (connection_id, _) = self.dial(peer, CONNECT_TIMEOUT).await?;
        let timeout = send_timeout(message.encoded_len());
        self.send_message_with_retry_and_timeout(
            peer,
            connection_id,
            message,
            1,
            timeout,
            Duration::from_millis(0),
        )
        .await
    }

    pub async fn disconnect(&self, peer: PeerId) -> Result<()> {
        let (s, r) = oneshot::channel();
        self.network_out_sender
            .send(OutEvent::Disconnect(peer, s))
            .await
            .map_err(|e| anyhow!("channel send: {:?}", e))?;
        r.await?;

        Ok(())
    }

    pub async fn provide(&self, key: Cid) -> Result<()> {
        self.network_out_sender
            .send(OutEvent::GenerateEvent(BitswapEvent::Provide { key }))
            .await
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

    pub fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<OutEvent> {
        match Pin::new(&mut self.network_out_receiver).poll_next(cx) {
            Poll::Ready(Some(ev)) => Poll::Ready(ev),
            Poll::Ready(None) => Poll::Pending,
            Poll::Pending => Poll::Pending,
        }
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

    pub async fn send_message(&self, message: BitswapMessage) -> Result<()> {
        self.network
            .send_message_with_retry_and_timeout(
                self.to,
                self.connection_id,
                message,
                self.config.max_retries,
                self.config.send_timeout,
                self.config.send_error_backoff,
            )
            .await
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.network.disconnect(self.to).await
    }
}
