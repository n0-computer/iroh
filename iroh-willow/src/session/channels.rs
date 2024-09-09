use std::{
    marker::PhantomData,
    pin::Pin,
    task::{self, ready, Poll},
};

use futures_lite::Stream;
use tracing::trace;

use crate::{
    proto::wgps::{
        Channel, DataMessage, IntersectionMessage, LogicalChannel, Message, ReconciliationMessage,
        SetupBindAreaOfInterest, SetupBindReadCapability, SetupBindStaticToken,
    },
    util::channel::{Receiver, Sender, WriteError},
};

use super::Error;

#[derive(Debug)]
pub struct MessageReceiver<T> {
    inner: Receiver<Message>,
    _phantom: PhantomData<T>,
}

impl<T: TryFrom<Message>> MessageReceiver<T> {
    // pub async fn recv(&mut self) -> Option<Result<T, Error>> {
    //     poll_fn(|cx| self.poll_recv(cx)).await
    // }

    // pub fn close(&self) {
    //     self.inner.close()
    // }

    pub fn poll_recv(&mut self, cx: &mut task::Context<'_>) -> Poll<Option<Result<T, Error>>> {
        let message = ready!(Pin::new(&mut self.inner).poll_next(cx));
        let message = match message {
            None => None,
            Some(Err(err)) => Some(Err(err.into())),
            Some(Ok(message)) => {
                trace!(%message, "recv");
                let message = message.try_into().map_err(|_| Error::WrongChannel);
                Some(message)
            }
        };
        Poll::Ready(message)
    }
}

impl<T: TryFrom<Message> + Unpin> Stream for MessageReceiver<T> {
    type Item = Result<T, Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_recv(cx)
    }
}

impl<T: TryFrom<Message>> From<Receiver<Message>> for MessageReceiver<T> {
    fn from(inner: Receiver<Message>) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct LogicalChannelReceivers {
    pub intersection_recv: MessageReceiver<IntersectionMessage>,
    pub reconciliation_recv: MessageReceiver<ReconciliationMessage>,
    pub static_tokens_recv: MessageReceiver<SetupBindStaticToken>,
    pub capability_recv: MessageReceiver<SetupBindReadCapability>,
    pub aoi_recv: MessageReceiver<SetupBindAreaOfInterest>,
    pub data_recv: MessageReceiver<DataMessage>,
}

impl LogicalChannelReceivers {
    // pub fn close(&self) {
    //     self.intersection_recv.close();
    //     self.reconciliation_recv.close();
    //     self.static_tokens_recv.close();
    //     self.capability_recv.close();
    //     self.aoi_recv.close();
    //     self.data_recv.close();
    // }
}

#[derive(Debug, Clone)]
pub struct LogicalChannelSenders {
    pub intersection_send: Sender<Message>,
    pub reconciliation_send: Sender<Message>,
    pub static_tokens_send: Sender<Message>,
    pub aoi_send: Sender<Message>,
    pub capability_send: Sender<Message>,
    pub data_send: Sender<Message>,
}
impl LogicalChannelSenders {
    pub fn close(&self) {
        self.intersection_send.close();
        self.reconciliation_send.close();
        self.static_tokens_send.close();
        self.aoi_send.close();
        self.capability_send.close();
        self.data_send.close();
    }

    pub fn get(&self, channel: LogicalChannel) -> &Sender<Message> {
        match channel {
            LogicalChannel::Intersection => &self.intersection_send,
            LogicalChannel::Reconciliation => &self.reconciliation_send,
            LogicalChannel::StaticToken => &self.static_tokens_send,
            LogicalChannel::Capability => &self.capability_send,
            LogicalChannel::AreaOfInterest => &self.aoi_send,
            LogicalChannel::Data => &self.data_send,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChannelSenders {
    pub control_send: Sender<Message>,
    pub logical_send: LogicalChannelSenders,
}

#[derive(Debug)]
pub struct ChannelReceivers {
    pub control_recv: Receiver<Message>,
    pub logical_recv: LogicalChannelReceivers,
}

#[derive(Debug)]
pub struct Channels {
    pub send: ChannelSenders,
    pub recv: ChannelReceivers,
}

impl ChannelSenders {
    pub fn close_all(&self) {
        self.control_send.close();
        self.logical_send.close();
    }
    pub fn get(&self, channel: Channel) -> &Sender<Message> {
        match channel {
            Channel::Control => &self.control_send,
            Channel::Logical(channel) => self.get_logical(channel),
        }
    }

    pub fn get_logical(&self, channel: LogicalChannel) -> &Sender<Message> {
        self.logical_send.get(channel)
    }

    pub async fn send(&self, message: impl Into<Message>) -> Result<(), WriteError> {
        let message: Message = message.into();
        let channel = message.channel();
        self.get(channel).send_message(&message).await?;
        trace!(%message, ch=%channel.fmt_short(), "sent");
        Ok(())
    }
}
