use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_lite::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

/// Wrapper around [`Stream`] that takes a cancel token to cancel the stream.
///
/// Once the cancel token is cancelled, this stream will continue to yield all items which are
/// ready immediately and then return [`None`].
#[derive(Debug)]
pub struct Cancelable<S> {
    stream: S,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    is_cancelled: bool,
}

impl<S> Cancelable<S> {
    pub fn new(stream: S, cancel_token: CancellationToken) -> Self {
        Self {
            stream,
            cancelled: Box::pin(cancel_token.cancelled_owned()),
            is_cancelled: false,
        }
    }
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Stream + Unpin> Stream for Cancelable<S> {
    type Item = S::Item;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.stream).poll_next(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => {
                if self.is_cancelled {
                    return Poll::Ready(None);
                }
                match Pin::new(&mut self.cancelled).poll(cx) {
                    Poll::Ready(()) => {
                        self.is_cancelled = true;
                        Poll::Ready(None)
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

/// Wrapper around [`ReceiverStream`] that can be closed with a [`CancellationToken`].
#[derive(Debug)]
pub struct CancelableReceiver<T> {
    receiver: ReceiverStream<T>,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    is_cancelled: bool,
}

impl<T> CancelableReceiver<T> {
    pub fn new(receiver: ReceiverStream<T>, cancel_token: CancellationToken) -> Self {
        let is_cancelled = cancel_token.is_cancelled();
        Self {
            receiver,
            cancelled: Box::pin(cancel_token.cancelled_owned()),
            is_cancelled,
        }
    }

    pub fn into_inner(self) -> ReceiverStream<T> {
        self.receiver
    }
}

impl<T: Send + 'static> Stream for CancelableReceiver<T> {
    type Item = T;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.receiver).poll_next(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => {
                if !self.is_cancelled {
                    match Pin::new(&mut self.cancelled).poll(cx) {
                        Poll::Ready(()) => {
                            self.receiver.close();
                            self.is_cancelled = true;
                            Poll::Ready(None)
                        }
                        Poll::Pending => Poll::Pending,
                    }
                } else {
                    Poll::Pending
                }
            }
        }
    }
}
