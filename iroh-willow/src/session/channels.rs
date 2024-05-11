use tracing::debug;

use crate::{
    actor::WakeableCo,
    proto::wgps::{LogicalChannel, Message},
    util::channel::{ReadError, Receiver, Sender, WriteError},
};

#[derive(Debug, Clone)]
pub struct LogicalChannelReceivers {
    pub reconciliation: Receiver<Message>,
    pub static_tokens: Receiver<Message>,
}
impl LogicalChannelReceivers {
    pub fn close(&self) {
        self.reconciliation.close();
        self.static_tokens.close();
    }
}

#[derive(Debug, Clone)]
pub struct LogicalChannelSenders {
    pub reconciliation: Sender<Message>,
    pub static_tokens: Sender<Message>,
}
impl LogicalChannelSenders {
    pub fn close(&self) {
        self.reconciliation.close();
        self.static_tokens.close();
    }
}

#[derive(Debug, Clone)]
pub struct Channels {
    pub control_send: Sender<Message>,
    pub control_recv: Receiver<Message>,
    pub logical_send: LogicalChannelSenders,
    pub logical_recv: LogicalChannelReceivers,
}

impl Channels {
    pub fn close_all(&self) {
        self.control_send.close();
        self.control_recv.close();
        self.logical_send.close();
        self.logical_recv.close();
    }
    pub fn close_send(&self) {
        self.control_send.close();
        self.logical_send.close();
    }
    pub fn sender(&self, channel: LogicalChannel) -> &Sender<Message> {
        match channel {
            LogicalChannel::Control => &self.control_send,
            LogicalChannel::Reconciliation => &self.logical_send.reconciliation,
            LogicalChannel::StaticToken => &self.logical_send.static_tokens,
        }
    }
    pub fn receiver(&self, channel: LogicalChannel) -> &Receiver<Message> {
        match channel {
            LogicalChannel::Control => &self.control_recv,
            LogicalChannel::Reconciliation => &self.logical_recv.reconciliation,
            LogicalChannel::StaticToken => &self.logical_recv.static_tokens,
        }
    }

    pub async fn send_co(
        &self,
        co: &WakeableCo,
        message: impl Into<Message>,
    ) -> Result<(), WriteError> {
        let message = message.into();
        let channel = message.logical_channel();
        co.yield_wake(self.sender(channel).send_message(&message))
            .await?;
        debug!(%message, ch=%channel.fmt_short(), "send");
        Ok(())
    }

    pub async fn recv_co(
        &self,
        co: &WakeableCo,
        channel: LogicalChannel,
    ) -> Option<Result<Message, ReadError>> {
        let message = co.yield_wake(self.receiver(channel).recv_message()).await;
        if let Some(Ok(message)) = &message {
            debug!(%message, ch=%channel.fmt_short(),"recv");
        }
        message
    }
}
