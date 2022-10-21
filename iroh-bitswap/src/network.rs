use std::{
    collections::HashSet,
    pin::Pin,
    sync::{atomic::AtomicUsize, Arc},
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use cid::Cid;
use futures::Stream;
use iroh_metrics::{bitswap::BitswapMetrics, inc};
use iroh_metrics::{core::MRecorder, record};
use libp2p::{core::connection::ConnectionId, PeerId};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, trace};

use crate::{message::BitswapMessage, protocol::ProtocolId, BitswapEvent};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SEND_TIMEOUT: Duration = Duration::from_secs(3 * 60 + 5);
const MIN_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const SEND_LATENCY: Duration = Duration::from_secs(2);
// 100kbit/s
const MIN_SEND_RATE: u64 = (100 * 1000) / 8;

#[derive(Debug, Clone)]
pub struct Network {
    network_out_receiver: async_channel::Receiver<OutEvent>,
    network_out_sender: async_channel::Sender<OutEvent>,
    self_id: PeerId,
    dial_id: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub enum OutEvent {
    Dial {
        peer: PeerId,
        response: oneshot::Sender<std::result::Result<(ConnectionId, Option<ProtocolId>), String>>,
        id: usize,
    },
    Disconnect(PeerId, oneshot::Sender<()>),
    SendMessage {
        peer: PeerId,
        message: BitswapMessage,
        response: oneshot::Sender<std::result::Result<(), SendError>>,
        connection_id: ConnectionId,
    },
    GenerateEvent(BitswapEvent),
    ProtectPeer {
        peer: PeerId,
    },
    UnprotectPeer {
        peer: PeerId,
        response: oneshot::Sender<bool>,
    },
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
            dial_id: Arc::new(AtomicUsize::new(0)),
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
        debug!("send:{}: start: {:#?}", peer, message);
        inc!(BitswapMetrics::MessagesAttempted);

        let num_blocks = message.blocks().count();
        let num_block_bytes = message.blocks().map(|b| b.data.len() as u64).sum();

        tokio::time::timeout(timeout, async {
            let mut errors: Vec<anyhow::Error> = Vec::new();
            for i in 1..=retries {
                debug!("send:{}: try {}/{}", peer, i, retries);
                let (s, r) = oneshot::channel();
                record!(
                    BitswapMetrics::MessageBytesOut,
                    message.clone().encoded_len() as u64
                );
                self.network_out_sender
                    .send(OutEvent::SendMessage {
                        peer,
                        message: message.clone(),
                        response: s,
                        connection_id,
                    })
                    .await
                    .map_err(|e| anyhow!("send:{}: channel send failed: {:?}", peer, e))?;

                match r.await {
                    Ok(Ok(res)) => {
                        info!("send:{}: message sent", peer);
                        return Ok(res);
                    }
                    Ok(Err(SendError::ProtocolNotSupported)) => {
                        // No point in using this peer if they don't speak our protocol.
                        self.disconnect(peer).await?;
                        return Err(SendError::ProtocolNotSupported.into());
                    }
                    Err(channel_err) => {
                        debug!(
                            "send:{}: try {}/{} failed with channel: {:?}",
                            peer, i, retries, channel_err
                        );
                        return Err(anyhow!("send:{}: channel gone: {:?}", peer, channel_err));
                    }
                    Ok(Err(other)) => {
                        debug!(
                            "send:{}: try {}/{} failed with: {:?}",
                            peer, i, retries, other
                        );
                        errors.push(other.into());
                        if i < retries - 1 {
                            // backoff until we retry
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }
            }
            bail!("send:{}: failed {:?}", peer, errors);
        })
        .await
        .map_err(|e| anyhow!("send:{}: {:?}", peer, e))??;

        debug!("send:{}: success", peer);
        // Record successfull stats

        inc!(BitswapMetrics::MessagesSent);
        for _ in 0..num_blocks {
            inc!(BitswapMetrics::BlocksOut);
        }
        record!(BitswapMetrics::SentBlockBytes, num_block_bytes);

        Ok(())
    }

    pub async fn find_providers(
        &self,
        key: Cid,
        limit: usize,
    ) -> Result<mpsc::Receiver<std::result::Result<HashSet<PeerId>, String>>> {
        let (s, r) = mpsc::channel(limit);
        self.network_out_sender
            .send(OutEvent::GenerateEvent(BitswapEvent::FindProviders {
                key,
                response: s,
                limit,
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
        let dial_id = self
            .dial_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        inc!(BitswapMetrics::AttemptedDials);
        debug!("dial:{}: peer {}", dial_id, peer);
        let res = tokio::time::timeout(timeout, async move {
            let (s, r) = oneshot::channel();
            self.network_out_sender
                .send(OutEvent::Dial {
                    peer,
                    response: s,
                    id: dial_id,
                })
                .await
                .map_err(|e| anyhow!("dial:{}: channel send: {:?}", dial_id, e))?;

            let res = r
                .await?
                .map_err(|e| anyhow!("dial:{} failed: {}", dial_id, e))?;
            Ok::<_, anyhow::Error>(res)
        })
        .await
        .map_err(|e| anyhow!("dial:{} error: {:?}", dial_id, e))??;

        debug!("dial:{}: success {}", dial_id, peer);
        inc!(BitswapMetrics::Dials);

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
        trace!("tag {}: {} - {}", peer, tag, value);
    }

    pub fn untag_peer(&self, peer: &PeerId, tag: &str) {
        // TODO: is this needed?
        trace!("untag {}: {}", peer, tag);
    }

    pub async fn protect_peer(&self, peer: PeerId) {
        trace!("protect {}", peer);
        let _ = self.network_out_sender.send(OutEvent::ProtectPeer { peer });
    }

    pub async fn unprotect_peer(&self, peer: PeerId) -> bool {
        trace!("unprotect {}", peer);

        let (s, r) = oneshot::channel();
        let _ = self
            .network_out_sender
            .send(OutEvent::UnprotectPeer { peer, response: s });

        r.await.unwrap_or_default()
    }

    pub fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<OutEvent> {
        inc!(BitswapMetrics::NetworkPollTick);
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
        self.protocol_id.map(|p| p.supports_have()).unwrap_or(true) // optimisticallly assume haves are supported
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
