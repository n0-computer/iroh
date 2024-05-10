use tracing::debug;

use crate::{
    proto::wgps::{LogicalChannel, Message},
    actor::WakeableCo,
    util::channel::{ReadError, Receiver, Sender, WriteError},
};

#[derive(Debug, Clone)]
pub struct Channels {
    pub control_send: Sender<Message>,
    pub control_recv: Receiver<Message>,
    pub reconciliation_send: Sender<Message>,
    pub reconciliation_recv: Receiver<Message>,
}

impl Channels {
    pub fn close_all(&self) {
        self.control_send.close();
        self.control_recv.close();
        self.reconciliation_send.close();
        self.reconciliation_recv.close();
    }
    pub fn close_send(&self) {
        self.control_send.close();
        self.reconciliation_send.close();
    }
    pub fn sender(&self, channel: LogicalChannel) -> &Sender<Message> {
        match channel {
            LogicalChannel::Control => &self.control_send,
            LogicalChannel::Reconciliation => &self.reconciliation_send,
        }
    }
    pub fn receiver(&self, channel: LogicalChannel) -> &Receiver<Message> {
        match channel {
            LogicalChannel::Control => &self.control_recv,
            LogicalChannel::Reconciliation => &self.reconciliation_recv,
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
