use std::{
    marker::PhantomData,
    pin::Pin,
    task::{self, ready, Poll},
};

use futures_lite::Stream;
use tracing::trace;

use crate::{
    proto::wgps::{
        DataMessage, IntersectionMessage, LogicalChannel, Message, ReconciliationMessage,
        SetupBindAreaOfInterest, SetupBindReadCapability, SetupBindStaticToken,
    },
    util::channel::{GuaranteesHandle, Receiver, Sender, WriteError},
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
    pub static_token_recv: MessageReceiver<SetupBindStaticToken>,
    pub capability_recv: MessageReceiver<SetupBindReadCapability>,
    pub aoi_recv: MessageReceiver<SetupBindAreaOfInterest>,
    pub data_recv: MessageReceiver<DataMessage>,
}

#[derive(Debug)]
pub struct LogicalChannelSenders {
    pub intersection_send: MessageSender<IntersectionMessage>,
    pub reconciliation_send: MessageSender<ReconciliationMessage>,
    pub static_token_send: MessageSender<SetupBindStaticToken>,
    pub capability_send: MessageSender<SetupBindReadCapability>,
    pub aoi_send: MessageSender<SetupBindAreaOfInterest>,
    pub data_send: MessageSender<DataMessage>,
}

impl LogicalChannelSenders {
    pub fn guarantees_handle(&self) -> SendersGuarantees {
        SendersGuarantees {
            intersection: self.intersection_send.guarantees_handle(),
            reconciliation: self.reconciliation_send.guarantees_handle(),
            static_token: self.static_token_send.guarantees_handle(),
            capability: self.capability_send.guarantees_handle(),
            aoi: self.aoi_send.guarantees_handle(),
            data: self.data_send.guarantees_handle(),
        }
    }
}

#[derive(Debug)]
pub struct ChannelSenders {
    pub control_send: Sender,
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

#[derive(Debug, derive_more::From, derive_more::Into)]
pub struct MessageSender<T = Message>(Sender, PhantomData<T>);

impl<T> From<Sender> for MessageSender<T> {
    fn from(sender: Sender) -> Self {
        Self(sender, PhantomData)
    }
}

impl<T: Into<Message>> MessageSender<T> {
    pub async fn send(&mut self, message: T) -> Result<(), WriteError> {
        let message: Message = message.into();
        self.0.send(&message).await
    }

    pub fn guarantees_handle(&self) -> GuaranteesHandle {
        self.0.guarantees_handle()
    }
}

#[derive(Debug)]
pub struct SendersGuarantees {
    pub intersection: GuaranteesHandle,
    pub reconciliation: GuaranteesHandle,
    pub static_token: GuaranteesHandle,
    pub capability: GuaranteesHandle,
    pub aoi: GuaranteesHandle,
    pub data: GuaranteesHandle,
}

impl SendersGuarantees {
    pub fn add_guarantees(&self, channel: LogicalChannel, amount: u64) {
        let ch = match channel {
            LogicalChannel::Intersection => &self.intersection,
            LogicalChannel::Capability => &self.capability,
            LogicalChannel::AreaOfInterest => &self.aoi,
            LogicalChannel::StaticToken => &self.static_token,
            LogicalChannel::Reconciliation => &self.reconciliation,
            LogicalChannel::Data => &self.data,
        };
        ch.add_guarantees(amount);
    }
}
